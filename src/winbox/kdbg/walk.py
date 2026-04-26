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
from typing import TYPE_CHECKING

import logging

from winbox.kdbg.hmp import HmpError, read_cpu_state
from winbox.kdbg.memory import (
    PageWalkError,
    WalkCache,
    read_cstr,
    read_u32,
    read_u64,
    read_unicode_string,
    read_virt_cr3,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore


MAX_PROCESSES = 4096
MAX_MODULES = 1024
MAX_USER_MODULES = 1024


@dataclass
class ProcessRecord:
    pid: int
    name: str
    eprocess: int           # VA of the EPROCESS struct
    directory_table_base: int


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


# ── Shared helpers ──────────────────────────────────────────────────────


def _cpu_cr3(vm_name: str) -> int:
    return read_cpu_state(vm_name)["CR3"]


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


def list_processes(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ProcessRecord]:
    """Walk ``PsActiveProcessHead`` and return every live process."""
    if cr3 is None:
        cr3 = _cpu_cr3(vm_name)
    if cache is None:
        cache = WalkCache()

    head = store.resolve("PsActiveProcessHead")
    eproc_fields = store.struct("_EPROCESS")["fields"]
    apl_off = eproc_fields["ActiveProcessLinks"]["off"]
    img_off = eproc_fields["ImageFileName"]["off"]
    pid_off = eproc_fields["UniqueProcessId"]["off"]
    kproc_fields = store.struct("_KPROCESS")["fields"]
    dtb_off = kproc_fields["DirectoryTableBase"]["off"]

    # Flink of PsActiveProcessHead points at the first EPROCESS.ActiveProcessLinks.
    flink = _read_u64(vm_name, cr3, head, cache)
    results: list[ProcessRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_PROCESSES:
        if flink in seen:
            break
        seen.add(flink)
        eproc = flink - apl_off
        try:
            pid = _read_u64(vm_name, cr3, eproc + pid_off, cache)
            dtb = _read_u64(vm_name, cr3, eproc + dtb_off, cache)
            name = _read_cstr(vm_name, cr3, eproc + img_off, 15, cache)
        except (HmpError, PageWalkError) as e:
            # Bare `except Exception` here used to silently truncate the walk
            # mid-list — callers thought they had the full process table.
            # Surface the partial-truncation reason in logs (still partial
            # data is returned so the UI shows what we did get).
            logger.warning(
                "list_processes: walk truncated at EPROCESS 0x%x (%d returned): %s",
                eproc, len(results), e,
            )
            break
        results.append(ProcessRecord(
            pid=pid, name=name, eprocess=eproc, directory_table_base=dtb,
        ))
        flink = _read_u64(vm_name, cr3, flink, cache)
    if len(results) >= MAX_PROCESSES:
        logger.warning(
            "list_processes: hit MAX_PROCESSES=%d cap; result is truncated",
            MAX_PROCESSES,
        )
    return results


def find_process(
    vm_name: str,
    store: SymbolStore,
    *,
    pid: int | None = None,
    name: str | None = None,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> ProcessRecord | None:
    """Return the first matching process, or None."""
    for proc in list_processes(vm_name, store, cr3=cr3, cache=cache):
        if pid is not None and proc.pid == pid:
            return proc
        if name is not None and proc.name.lower() == name.lower():
            return proc
    return None


# ── Module list ─────────────────────────────────────────────────────────


def list_modules(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ModuleRecord]:
    """Walk ``PsLoadedModuleList`` and return every loaded kernel module."""
    if cr3 is None:
        cr3 = _cpu_cr3(vm_name)
    if cache is None:
        cache = WalkCache()

    head = store.resolve("PsLoadedModuleList")
    ldr_fields = store.struct("_KLDR_DATA_TABLE_ENTRY")["fields"]
    # _KLDR_DATA_TABLE_ENTRY starts with InLoadOrderLinks at offset 0.
    inload_off = ldr_fields.get("InLoadOrderLinks", {}).get("off", 0)
    dll_base_off = ldr_fields["DllBase"]["off"]
    size_off = ldr_fields["SizeOfImage"]["off"]
    base_name_off = ldr_fields["BaseDllName"]["off"]

    flink = _read_u64(vm_name, cr3, head, cache)
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

    x86-64 only. WoW64 (32-bit-on-64-bit) processes have a separate
    32-bit Ldr at PEB.Wow64Process — not handled here yet; for those
    processes this walker will return the 64-bit DLLs only (ntdll.dll,
    wow64.dll, etc.), not the 32-bit ones.
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
            ))
        flink = _read_u64(vm_name, target_cr3, flink, cache)
    if len(results) >= MAX_USER_MODULES:
        logger.warning(
            "list_user_modules: hit MAX_USER_MODULES=%d cap; result is truncated",
            MAX_USER_MODULES,
        )
    return results
