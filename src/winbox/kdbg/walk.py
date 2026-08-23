"""Windows-aware kernel walkers built on the memory + symbol primitives.

Two walks for now, both standard kernel list traversals:

* ``list_processes`` — starts at ``PsActiveProcessHead``, walks the
  ``_EPROCESS.ActiveProcessLinks`` circular list, returns
  ``ProcessRecord`` entries.
* ``list_modules`` — starts at ``PsLoadedModuleList``, walks the
  ``_KLDR_DATA_TABLE_ENTRY`` list via ``InLoadOrderLinks``, returns
  ``ModuleRecord`` entries.

Both use ``read_virt_cr3`` with whatever CR3 the kernel happens to be in,
so they work against a live (non-halted) VM as well. The linked lists
live in the kernel half of the address space, which is the same mapping
regardless of which process was scheduled at halt time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

import logging
import threading

from winbox.kdbg.debugger.reader import current_snapshot, snapshot_operation
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import (
    PageWalkError,
    WalkCache,
    read_cstr,
    read_u32,
    read_u64,
    read_unicode_string,
    read_virt_cr3,
)
from winbox.kdbg.store import SymbolStoreError

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore


MAX_PROCESSES = 4096
MAX_MODULES = 1024
MAX_USER_MODULES = 1024

# A kernel CR3 is a boot-scoped translation anchor, not cached process state.
# PID 4's DirectoryTableBase remains valid for the lifetime of a Windows boot;
# every list and structure is still read fresh on every call.  A failed probe
# invalidates it, covering reboot, snapshot restore, and VM replacement.
_kernel_cr3_by_vm: dict[str, int] = {}
_kernel_cr3_lock = threading.Lock()


@dataclass
class ProcessRecord:
    pid: int
    name: str
    eprocess: int           # VA of the EPROCESS struct
    directory_table_base: int
    user_directory_table_base: int = 0  # KPROCESS.UserDirectoryTableBase (KVA Shadow);
                                        # 0 if the field is absent (pre-KPTI struct) or
                                        # the read failed. Either way the daemon falls
                                        # back to filtering on directory_table_base alone.


@dataclass(frozen=True)
class _ProcessSpan:
    start: int
    size: int


@dataclass(frozen=True)
class _ProcessLayout:
    """Offsets and compact read spans needed to decode one EPROCESS."""

    active_links: int
    image_name: int
    pid: int
    dtb: int
    user_dtb: int | None
    spans: tuple[_ProcessSpan, ...]


@dataclass
class ModuleRecord:
    name: str
    base: int               # DllBase
    size: int               # SizeOfImage
    entry: int              # VA of the KLDR_DATA_TABLE_ENTRY


@dataclass
class UserModuleRecord:
    """A loaded user-mode module discovered via PEB.Ldr.

    ``base`` is a *user* VA in the target process's address space (only
    valid against ``directory_table_base`` of the target). ``full_path``
    is the FullDllName from LDR_DATA_TABLE_ENTRY — useful for locating
    the binary on disk inside the VM.
    """

    name: str
    base: int               # DllBase (user VA in target's address space)
    size: int               # SizeOfImage
    full_path: str          # FullDllName, e.g. "C:\\Windows\\System32\\ntdll.dll"
    entry: int              # VA of the LDR_DATA_TABLE_ENTRY
    architecture: str = "x64"


# ── Shared helpers ──────────────────────────────────────────────────────


def _cpu_cr3(vm_name: str) -> int:
    snapshot = current_snapshot(vm_name)
    if snapshot is None:
        raise HmpError("no active RSP snapshot for CR3 read")
    return snapshot.current_cr3


def _cpu_cr3_candidates(vm_name: str) -> list[int]:
    """Return CR3 from every halted vCPU through the active RSP snapshot."""
    snapshot = current_snapshot(vm_name)
    if snapshot is None:
        raise HmpError("no active RSP snapshot for vCPU CR3 reads")
    candidates = list(snapshot.cr3_candidates)
    if not candidates:
        raise HmpError("gdbstub returned no vCPU CR3 candidates")
    return candidates


def _cached_kernel_cr3(vm_name: str) -> int | None:
    with _kernel_cr3_lock:
        return _kernel_cr3_by_vm.get(vm_name)


def _remember_kernel_cr3(vm_name: str, cr3: int) -> None:
    # DirectoryTableBase is a physical PML4 address. Ignore corrupt/stale
    # structure reads instead of poisoning every future walk.
    if cr3 == 0 or cr3 & 0xFFF or cr3 >= (1 << 52):
        return
    with _kernel_cr3_lock:
        _kernel_cr3_by_vm[vm_name] = cr3


def _forget_kernel_cr3(vm_name: str, cr3: int | None = None) -> None:
    with _kernel_cr3_lock:
        if cr3 is None or _kernel_cr3_by_vm.get(vm_name) == cr3:
            _kernel_cr3_by_vm.pop(vm_name, None)


def _kernel_read_candidates(vm_name: str, explicit_cr3: int | None) -> list[int]:
    """Build ordered kernel-CR3 candidates for a list-head probe."""
    if explicit_cr3 is not None:
        sampled = [explicit_cr3]
    else:
        sampled = _cpu_cr3_candidates(vm_name)

    candidates: list[int] = []
    for candidate in sampled:
        # On KPTI builds the kernel/user PML4 roots are commonly adjacent.
        for variant in (candidate, candidate ^ 0x1000):
            if variant not in candidates:
                candidates.append(variant)
    return candidates


def _read_kernel_list_head(
    vm_name: str,
    head: int,
    explicit_cr3: int | None,
) -> tuple[int, int, WalkCache]:
    """Find a CR3 that maps ``head`` and return ``(cr3, flink, cache)``."""
    def valid_flink(flink: int) -> bool:
        # Both kernel lists live in canonical high-half virtual memory and
        # LIST_ENTRY is pointer-aligned. During reboot, freed/transitioning
        # pages commonly contain 0xFA poison; successful translation alone
        # must not make such data a trusted bootstrap anchor.
        # PsActiveProcessHead can never be empty (PID 4 exists), and the
        # loaded-module list always contains nt itself. A self-link here is
        # therefore stale-symbol/reboot data, not a legitimate empty list.
        return (
            flink not in (0, head)
            and flink & 0x7 == 0
            and flink >> 48 == 0xFFFF
        )

    cached = None if explicit_cr3 is not None else _cached_kernel_cr3(vm_name)
    last_error: HmpError | None = None
    if cached is not None:
        # Fast path: do not sample volatile vCPU state at all once PID 4 gave
        # us a boot-stable root. Try its KPTI partner too for defensive
        # compatibility with stores created by older versions.
        for candidate in (cached, cached ^ 0x1000):
            candidate_cache = WalkCache()
            try:
                flink = _read_u64(vm_name, candidate, head, candidate_cache)
            except (HmpError, PageWalkError) as exc:
                last_error = exc
                continue
            if not valid_flink(flink):
                last_error = HmpError(
                    f"invalid kernel list pointer 0x{flink:x} via CR3 0x{candidate:x}"
                )
                continue
            return candidate, flink, candidate_cache
        _forget_kernel_cr3(vm_name, cached)

    for candidate in _kernel_read_candidates(vm_name, explicit_cr3):
        candidate_cache = WalkCache()
        try:
            flink = _read_u64(vm_name, candidate, head, candidate_cache)
        except (HmpError, PageWalkError) as exc:
            last_error = exc
            continue
        if not valid_flink(flink):
            last_error = HmpError(
                f"invalid kernel list pointer 0x{flink:x} via CR3 0x{candidate:x}"
            )
            continue
        return candidate, flink, candidate_cache
    if last_error is not None:
        raise last_error
    raise HmpError("no kernel CR3 candidates available")


# Thin compat shims so the rest of this module reads as it did pre-K3.
# Concrete primitives now live in winbox.kdbg.memory.

def _read_u64(vm_name: str, cr3: int, va: int, cache: WalkCache) -> int:
    return read_u64(vm_name, cr3, va, cache)


def _read_u32(vm_name: str, cr3: int, va: int, cache: WalkCache) -> int:
    return read_u32(vm_name, cr3, va, cache)


def _read_cstr(
    vm_name: str,
    cr3: int,
    va: int,
    length: int,
    cache: WalkCache,
) -> str:
    return read_cstr(vm_name, cr3, va, length, cache)


def _read_unicode_string(
    vm_name: str,
    cr3: int,
    va: int,
    store: SymbolStore,
    cache: WalkCache,
) -> str:
    """Read a ``_UNICODE_STRING`` at ``va``, looking up field offsets from
    the symbol store and delegating the actual reads to memory.read_unicode_string."""
    fields = store.struct("_UNICODE_STRING")["fields"]
    return read_unicode_string(
        vm_name, cr3, va,
        length_off=fields["Length"]["off"],
        buffer_off=fields["Buffer"]["off"],
        cache=cache,
    )


# ── Process list ────────────────────────────────────────────────────────


def _process_layout(store: SymbolStore) -> _ProcessLayout:
    eproc = store.struct("_EPROCESS")
    eproc_fields = eproc["fields"]
    kproc_fields = store.struct("_KPROCESS")["fields"]
    active_links = int(eproc_fields["ActiveProcessLinks"]["off"])
    image_name = int(eproc_fields["ImageFileName"]["off"])
    pid = int(eproc_fields["UniqueProcessId"]["off"])
    dtb = int(kproc_fields["DirectoryTableBase"]["off"])
    raw_user_dtb = kproc_fields.get("UserDirectoryTableBase", {}).get("off")
    user_dtb = int(raw_user_dtb) if raw_user_dtb is not None else None

    fields = [(active_links, 8), (image_name, 15), (pid, 8), (dtb, 8)]
    if user_dtb is not None:
        fields.append((user_dtb, 8))
    field_start = min(offset for offset, _ in fields)
    field_end = max(offset + size for offset, size in fields)
    eproc_size = int(eproc.get("size") or 0)
    if field_start < 0 or field_end <= field_start:
        raise HmpError("invalid negative/empty EPROCESS field span")
    if eproc_size and field_end > eproc_size:
        raise HmpError(
            f"EPROCESS field span 0x{field_start:x}-0x{field_end:x} exceeds "
            f"struct size 0x{eproc_size:x}"
        )
    # A corrupt/stale symbol map must not turn one process record into an
    # unbounded debugger read even if its struct size is missing.
    if field_end - field_start > 0x10000:
        raise HmpError(
            f"EPROCESS field span is implausibly large: 0x{field_end - field_start:x}"
        )

    # Merge fields only when they are adjacent or separated by a tiny hole.
    # Real EPROCESS layouts place PID and ActiveProcessLinks together but DTB,
    # UserDirectoryTableBase, and ImageFileName hundreds of bytes apart. One
    # min/max read over those holes transfers ~1.4 KiB per process and is
    # measurably slower than compact RSP reads despite fewer packets.
    spans: list[_ProcessSpan] = []
    for offset, size in sorted(fields):
        if spans and offset <= spans[-1].start + spans[-1].size + 32:
            previous = spans[-1]
            end = max(previous.start + previous.size, offset + size)
            spans[-1] = _ProcessSpan(previous.start, end - previous.start)
        else:
            spans.append(_ProcessSpan(offset, size))
    return _ProcessLayout(
        active_links=active_links,
        image_name=image_name,
        pid=pid,
        dtb=dtb,
        user_dtb=user_dtb,
        spans=tuple(spans),
    )


def _read_process_entry(
    vm_name: str,
    cr3: int,
    eprocess: int,
    layout: _ProcessLayout,
    cache: WalkCache,
) -> tuple[ProcessRecord, int]:
    """Decode one EPROCESS, coalescing adjacent fields into compact reads."""
    chunks: list[tuple[_ProcessSpan, bytes]] = []
    for span in layout.spans:
        raw = read_virt_cr3(
            vm_name,
            cr3,
            eprocess + span.start,
            span.size,
            cache=cache,
        )
        if len(raw) != span.size:
            raise HmpError(
                f"short EPROCESS read at 0x{eprocess + span.start:x}: "
                f"expected {span.size}, got {len(raw)}"
            )
        chunks.append((span, raw))

    def field(offset: int, size: int) -> bytes:
        for span, raw in chunks:
            if span.start <= offset and offset + size <= span.start + span.size:
                start = offset - span.start
                return raw[start:start + size]
        raise HmpError(f"EPROCESS field at +0x{offset:x} is outside read spans")

    pid = int.from_bytes(field(layout.pid, 8), "little")
    dtb = int.from_bytes(field(layout.dtb, 8), "little")
    name = field(layout.image_name, 15).split(b"\x00", 1)[0].decode(
        "latin-1", errors="replace",
    )
    next_flink = int.from_bytes(field(layout.active_links, 8), "little")
    user_dtb = 0
    if layout.user_dtb is not None:
        raw_user_dtb = int.from_bytes(field(layout.user_dtb, 8), "little")
        if (
            raw_user_dtb != 0
            and (raw_user_dtb & 0xFFF) == 0
            and raw_user_dtb < (1 << 52)
        ):
            user_dtb = raw_user_dtb
    return ProcessRecord(
        pid=pid,
        name=name,
        eprocess=eprocess,
        directory_table_base=dtb,
        user_directory_table_base=user_dtb,
    ), next_flink


def _iter_processes(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> Iterator[ProcessRecord]:
    """Yield live processes while the caller owns one debugger snapshot."""
    explicit_cr3 = cr3

    head = store.resolve("PsActiveProcessHead")
    layout = _process_layout(store)

    # Probe a cached PID 4 kernel DTB first, then every live vCPU CR3 and its
    # KPTI partner. Each candidate gets a fresh page-table cache so failed
    # translations cannot contaminate the successful walk.
    cr3, flink, cache = _read_kernel_list_head(vm_name, head, explicit_cr3)
    count = 0
    seen: set[int] = set()
    while flink != head and flink != 0 and count < MAX_PROCESSES:
        if flink in seen:
            break
        seen.add(flink)
        eproc = flink - layout.active_links
        try:
            record, next_flink = _read_process_entry(
                vm_name, cr3, eproc, layout, cache,
            )
        except (HmpError, PageWalkError) as e:
            # Bare `except Exception` here used to silently truncate the walk
            # mid-list — callers thought they had the full process table.
            # Surface the partial-truncation reason in logs (still partial
            # data is returned so the UI shows what we did get).
            logger.warning(
                "list_processes: walk truncated at EPROCESS 0x%x (%d returned): %s",
                eproc, count, e,
            )
            break
        count += 1
        # KPTI stabilization: System (first EPROCESS, PID 4) always has
        # a valid kernel CR3. Switch to it for the rest of the walk to
        # avoid mid-walk KPTI CR3 races on a running VM.
        if count == 1 and record.pid == 4 and record.directory_table_base != cr3:
            cr3 = record.directory_table_base
            cache = WalkCache()
        if record.pid == 4 and explicit_cr3 is None:
            _remember_kernel_cr3(vm_name, record.directory_table_base)
        # Stabilize/cache PID 4 before yielding so an early-exit lookup keeps
        # the same boot-scoped CR3 invariant as a complete process walk.
        yield record
        flink = next_flink
    if count >= MAX_PROCESSES:
        logger.warning(
            "list_processes: hit MAX_PROCESSES=%d cap; result is truncated",
            MAX_PROCESSES,
        )


@snapshot_operation
def list_processes(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ProcessRecord]:
    """Walk ``PsActiveProcessHead`` and return every live process."""
    return list(_iter_processes(vm_name, store, cr3=cr3, cache=cache))


@snapshot_operation
def find_process(
    vm_name: str,
    store: SymbolStore,
    *,
    pid: int | None = None,
    name: str | None = None,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> ProcessRecord | None:
    """Return the first matching process, or None.

    Name matches are against ``EPROCESS.ImageFileName``, a 15-byte kernel field
    — so ``proc.name`` is truncated to 15 chars and a requested name of 16+
    chars (``SecurityHealthService.exe``, ``MpDefenderCoreService.exe``) could
    never match its full form. We compare against the same 15-char truncation
    of the request; this makes the match a 15-char-prefix match, which is
    inherently ambiguous for names sharing that prefix — the first is returned.
    """
    wanted_name = name.lower()[:15] if name is not None else None
    for proc in _iter_processes(vm_name, store, cr3=cr3, cache=cache):
        if pid is not None and proc.pid == pid:
            return proc
        if wanted_name is not None and proc.name.lower() == wanted_name:
            return proc
    return None


# ── Module list ─────────────────────────────────────────────────────────


@snapshot_operation
def list_modules(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ModuleRecord]:
    """Walk ``PsLoadedModuleList`` and return every loaded kernel module."""
    explicit_cr3 = cr3

    head = store.resolve("PsLoadedModuleList")
    ldr_fields = store.struct("_KLDR_DATA_TABLE_ENTRY")["fields"]
    # _KLDR_DATA_TABLE_ENTRY starts with InLoadOrderLinks at offset 0.
    inload_off = ldr_fields.get("InLoadOrderLinks", {}).get("off", 0)
    dll_base_off = ldr_fields["DllBase"]["off"]
    size_off = ldr_fields["SizeOfImage"]["off"]
    base_name_off = ldr_fields["BaseDllName"]["off"]

    cr3, flink, cache = _read_kernel_list_head(vm_name, head, explicit_cr3)
    results: list[ModuleRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_MODULES:
        if flink in seen:
            break
        seen.add(flink)
        entry = flink - inload_off
        try:
            base = _read_u64(vm_name, cr3, entry + dll_base_off, cache)
            size = _read_u32(vm_name, cr3, entry + size_off, cache)
            name = _read_unicode_string(vm_name, cr3, entry + base_name_off, store, cache)
        except (HmpError, PageWalkError) as e:
            logger.warning(
                "list_modules: walk truncated at LDR_DATA_TABLE_ENTRY 0x%x (%d returned): %s",
                entry, len(results), e,
            )
            break
        results.append(ModuleRecord(name=name, base=base, size=size, entry=entry))
        flink = _read_u64(vm_name, cr3, flink, cache)
    if len(results) >= MAX_MODULES:
        logger.warning(
            "list_modules: hit MAX_MODULES=%d cap; result is truncated",
            MAX_MODULES,
        )
    return results


# ── User-mode module list (PEB.Ldr walker) ──────────────────────────────


def is_wow64(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    cache: WalkCache | None = None,
) -> bool:
    """True when ``EPROCESS.WoW64Process`` names a live 32-bit PEB."""
    if cache is None:
        cache = WalkCache()
    target_cr3 = target.directory_table_base
    try:
        return _wow64_peb(vm_name, store, target, cache) != 0
    except (HmpError, PageWalkError, SymbolStoreError):
        return False


def _wow64_peb(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    cache: WalkCache,
) -> int:
    """Return the 32-bit PEB VA from EPROCESS -> EWOW64PROCESS."""
    eproc = store.struct("_EPROCESS")["fields"]
    wow64_off = eproc.get("WoW64Process", {}).get("off")
    if wow64_off is None:
        raise SymbolStoreError("_EPROCESS.WoW64Process is absent from nt types")
    wow64 = _read_u64(
        vm_name, target.directory_table_base,
        target.eprocess + int(wow64_off), cache,
    )
    if wow64 == 0:
        return 0
    wow_fields = store.struct("_EWOW64PROCESS")["fields"]
    peb_off = wow_fields.get("Peb", {}).get("off")
    if peb_off is None:
        raise SymbolStoreError("_EWOW64PROCESS.Peb is absent from nt types")
    peb32 = _read_u64(
        vm_name, target.directory_table_base, wow64 + int(peb_off), cache,
    )
    # A 32-bit PEB must be representable in the WoW64 address space.  Reject
    # corrupt kernel metadata before using it as a list-walk root.
    if peb32 >= (1 << 32):
        raise PageWalkError(f"invalid WoW64 PEB pointer 0x{peb32:x}")
    return peb32


def _read_unicode_string32(
    vm_name: str, cr3: int, va: int, cache: WalkCache,
) -> str:
    """Read a 32-bit UNICODE_STRING with strict, bounded metadata."""
    header = read_virt_cr3(vm_name, cr3, va, 8, cache=cache)
    if len(header) != 8:
        raise PageWalkError("short UNICODE_STRING32 header")
    length = int.from_bytes(header[0:2], "little")
    maximum = int.from_bytes(header[2:4], "little")
    buffer = int.from_bytes(header[4:8], "little")
    if length == 0:
        return ""
    if length & 1 or length > maximum or length > 0x2000 or buffer == 0:
        raise PageWalkError(
            f"invalid UNICODE_STRING32 length={length} maximum={maximum}"
        )
    raw = read_virt_cr3(vm_name, cr3, buffer, length, cache=cache)
    if len(raw) != length:
        raise PageWalkError(f"short UNICODE_STRING32 payload {len(raw)}/{length}")
    return raw.decode("utf-16-le", errors="replace")


def _list_wow64_modules(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    cache: WalkCache,
    *,
    limit: int,
) -> list[UserModuleRecord]:
    """Walk the documented 32-bit PEB loader layout of a WoW64 process."""
    peb = _wow64_peb(vm_name, store, target, cache)
    if peb == 0 or limit <= 0:
        return []
    cr3 = target.directory_table_base
    # Stable Win32 ABI layouts (PEB32/PEB_LDR_DATA32/LDR_DATA_TABLE_ENTRY32).
    ldr = _read_u32(vm_name, cr3, peb + 0x0C, cache)
    if ldr == 0:
        return []
    head = ldr + 0x0C
    flink = _read_u32(vm_name, cr3, head, cache)
    results: list[UserModuleRecord] = []
    seen: set[int] = set()
    while flink not in (0, head) and len(results) < limit:
        if flink in seen or flink >= (1 << 32):
            break
        seen.add(flink)
        entry = flink
        try:
            base = _read_u32(vm_name, cr3, entry + 0x18, cache)
            size = _read_u32(vm_name, cr3, entry + 0x20, cache)
            full = _read_unicode_string32(vm_name, cr3, entry + 0x24, cache)
            name = _read_unicode_string32(vm_name, cr3, entry + 0x2C, cache)
            next_flink = _read_u32(vm_name, cr3, flink, cache)
        except (HmpError, PageWalkError) as exc:
            logger.warning(
                "list_user_modules: WoW64 walk truncated at 0x%x in pid %d: %s",
                entry, target.pid, exc,
            )
            break
        if base:
            results.append(UserModuleRecord(
                name=name, base=base, size=size, full_path=full, entry=entry,
                architecture="x86",
            ))
        flink = next_flink
    return results


@snapshot_operation
def list_user_modules(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    cache: WalkCache | None = None,
) -> list[UserModuleRecord]:
    """Walk PEB.Ldr.InLoadOrderModuleList for ``target``.

    Reads the user-mode loader's view of mapped PE images: the EXE plus
    every loaded DLL, in the order Windows mapped them. Mirrors
    ``list_modules`` but lives in user space — every read uses the
    target's CR3 (``target.directory_table_base``).

    The list head sits inside PEB.Ldr (a kernel-allocated PEB_LDR_DATA
    struct that's mapped read-write into the target's user space).

    WoW64 processes return both loader views.  Native support modules are
    labelled ``x64`` and the 32-bit PEB list is labelled ``x86``.
    """
    if cache is None:
        cache = WalkCache()
    target_cr3 = target.directory_table_base

    # Resolve struct offsets up-front so failures surface as a clear
    # SymbolStoreError (caller can hint the user to re-run kdbg symbols)
    # instead of a mid-walk read fault.
    eproc_fields = store.struct("_EPROCESS")["fields"]
    peb_off = eproc_fields["Peb"]["off"]

    peb_fields = store.struct("_PEB")["fields"]
    ldr_field_off = peb_fields["Ldr"]["off"]

    ldrdata_fields = store.struct("_PEB_LDR_DATA")["fields"]
    inload_head_off = ldrdata_fields["InLoadOrderModuleList"]["off"]

    ldr_fields = store.struct("_LDR_DATA_TABLE_ENTRY")["fields"]
    inload_off = ldr_fields.get("InLoadOrderLinks", {}).get("off", 0)
    dll_base_off = ldr_fields["DllBase"]["off"]
    size_off = ldr_fields["SizeOfImage"]["off"]
    base_name_off = ldr_fields["BaseDllName"]["off"]
    full_name_off = ldr_fields["FullDllName"]["off"]

    # EPROCESS lives in the kernel half of the address space (mapped in
    # every CR3), so reading EPROCESS.Peb works regardless of which
    # process is currently on-CPU. The Peb pointer itself is a *user*
    # VA — only valid against the target's CR3.
    peb_va = _read_u64(vm_name, target_cr3, target.eprocess + peb_off, cache)
    if peb_va == 0:
        # System idle, kernel-only processes (System, Registry) have no PEB.
        return []

    # PEB.Ldr is a user VA pointing at PEB_LDR_DATA. Empty Ldr means the
    # process is mid-tear-down or hasn't finished initial loader setup.
    ldr_va = _read_u64(vm_name, target_cr3, peb_va + ldr_field_off, cache)
    if ldr_va == 0:
        return []

    head = ldr_va + inload_head_off
    # Flink of the list head points at the first entry's InLoadOrderLinks.
    try:
        flink = _read_u64(vm_name, target_cr3, head, cache)
    except (HmpError, PageWalkError) as e:
        logger.warning(
            "list_user_modules: could not read PEB.Ldr list head for pid %d: %s",
            target.pid, e,
        )
        return []

    results: list[UserModuleRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_USER_MODULES:
        if flink in seen:
            break
        seen.add(flink)
        entry = flink - inload_off
        try:
            base = _read_u64(vm_name, target_cr3, entry + dll_base_off, cache)
            size = _read_u32(vm_name, target_cr3, entry + size_off, cache)
            name = _read_unicode_string(
                vm_name, target_cr3, entry + base_name_off, store, cache,
            )
            full = _read_unicode_string(
                vm_name, target_cr3, entry + full_name_off, store, cache,
            )
        except (HmpError, PageWalkError) as e:
            # Mid-walk page fault is normal during teardown / paging;
            # log and return what we have rather than raise.
            logger.warning(
                "list_user_modules: walk truncated at LDR_DATA_TABLE_ENTRY 0x%x "
                "in pid %d (%d returned): %s",
                entry, target.pid, len(results), e,
            )
            break
        # Skip entries with a zero base — those are placeholder ldr
        # entries Windows leaves around for unloaded modules.
        if base != 0:
            results.append(UserModuleRecord(
                name=name, base=base, size=size, full_path=full, entry=entry,
                architecture="x64",
            ))
        flink = _read_u64(vm_name, target_cr3, flink, cache)
    if len(results) >= MAX_USER_MODULES:
        logger.warning(
            "list_user_modules: hit MAX_USER_MODULES=%d cap; result is truncated",
            MAX_USER_MODULES,
        )
    if len(results) < MAX_USER_MODULES:
        try:
            wow64_modules = _list_wow64_modules(
                vm_name, store, target, cache,
                limit=MAX_USER_MODULES - len(results),
            )
            # The native WoW64 loader view commonly contains a compatibility
            # entry for the 32-bit main EXE at the exact same base/name.  The
            # 32-bit PEB is authoritative for that image; keeping both would
            # mislabel the native-view copy as x64 and make symbol selection
            # spuriously ambiguous.
            x86_identities = {
                (module.base, module.name.casefold()) for module in wow64_modules
            }
            results = [
                module for module in results
                if (module.base, module.name.casefold()) not in x86_identities
            ]
            results.extend(wow64_modules)
        except SymbolStoreError:
            # Old stores are upgraded by MCP/CLI before calling this function;
            # direct library callers retain the native list until upgraded.
            pass
    return results
