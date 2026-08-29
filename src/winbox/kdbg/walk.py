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

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Iterator

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
MAX_THREADS_PER_PROCESS = 8192
_MAX_PDB_STRUCT_SIZE = 1 << 20


# Values from nt!KTHREAD_STATE / nt!KWAIT_REASON.  The raw byte is always
# returned too: new Windows builds can add a value without making a correct
# walker suddenly lie about the thread's state.
_KTHREAD_STATES = {
    0: "Initialized",
    1: "Ready",
    2: "Running",
    3: "Standby",
    4: "Terminated",
    5: "Waiting",
    6: "Transition",
    7: "DeferredReady",
    8: "GateWait",
}

_KWAIT_REASONS = {
    0: "Executive",
    1: "FreePage",
    2: "PageIn",
    3: "PoolAllocation",
    4: "DelayExecution",
    5: "Suspended",
    6: "UserRequest",
    7: "WrExecutive",
    8: "WrFreePage",
    9: "WrPageIn",
    10: "WrPoolAllocation",
    11: "WrDelayExecution",
    12: "WrSuspended",
    13: "WrUserRequest",
    14: "WrEventPair",
    15: "WrQueue",
    16: "WrLpcReceive",
    17: "WrLpcReply",
    18: "WrVirtualMemory",
    19: "WrPageOut",
    20: "WrRendezvous",
    21: "Spare2",
    22: "Spare3",
    23: "Spare4",
    24: "Spare5",
    25: "WrCalloutStack",
    26: "WrKernel",
    27: "WrResource",
    28: "WrPushLock",
    29: "WrMutex",
    30: "WrQuantumEnd",
    31: "WrDispatchInt",
    32: "WrPreempted",
    33: "WrYieldExecution",
    34: "WrFastMutex",
    35: "WrGuardedMutex",
    36: "WrRundown",
    37: "WrAlertByThreadId",
    38: "WrDeferredPreempt",
    39: "WrPhysicalFault",
    40: "WrIoRing",
    41: "WrMdlCache",
    42: "WrRcu",
    43: "WrSparse",
    44: "WrSilo",
}

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
    create_time: int = 0       # EPROCESS.CreateTime when present in exact types
    exit_time: int = 0         # EPROCESS.ExitTime; non-zero means termination began


@dataclass(frozen=True)
class ProcessWalkTruncation:
    """Bounded provenance for a partial active-process-list walk."""

    stage: str
    reason: str
    returned: int
    link: int | None = None
    eprocess: int | None = None

    def public(self) -> dict[str, int | str | None]:
        return {
            "stage": self.stage,
            "link": f"0x{self.link:016x}" if self.link is not None else None,
            "eprocess": f"0x{self.eprocess:016x}" if self.eprocess is not None else None,
            "returned": self.returned,
            "reason": self.reason,
        }


@dataclass
class ProcessWalkResult:
    processes: list[ProcessRecord]
    complete: bool
    truncated_reason: str | None = None
    truncation: ProcessWalkTruncation | None = None


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
    create_time: int | None
    exit_time: int | None
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


@dataclass
class ThreadRecord:
    """One thread reached through ``EPROCESS.ThreadListHead``.

    This is metadata read from the stopped kernel's scheduler structures; it
    intentionally does *not* claim to provide registers or a stack for an
    arbitrary non-running thread.  ``kernel_stack`` is the KTHREAD field, not
    an asserted saved RSP.
    """

    tid: int
    ethread: int
    state: int
    state_name: str | None
    wait_reason: int
    wait_reason_name: str | None
    priority: int
    base_priority: int
    context_switches: int
    teb: int
    kernel_stack: int
    stack_limit: int
    stack_base: int
    start_address: int
    win32_start_address: int
    create_time: int
    exit_status: int


@dataclass
class ThreadWalkResult:
    """Result of a bounded process-thread walk.

    Existing legacy walkers predate a machine-readable partial-result
    contract.  Threads are new, so make any malformed link, read failure, or
    cap explicit to callers instead of passing a plausible partial list off as
    complete.
    """

    threads: list[ThreadRecord]
    complete: bool
    truncated_reason: str | None = None
    truncation: "ThreadWalkTruncation | None" = None


@dataclass(frozen=True)
class ThreadWalkTruncation:
    """Machine-safe provenance for a validated but incomplete thread prefix."""

    stage: str
    reason: str
    returned: int
    link: int | None = None
    ethread: int | None = None

    def public(self) -> dict[str, int | str | None]:
        return {
            "stage": self.stage,
            "link": f"0x{self.link:016x}" if self.link is not None else None,
            "ethread": f"0x{self.ethread:016x}" if self.ethread is not None else None,
            "returned": self.returned,
            "reason": self.reason,
        }


class ThreadWalkIncomplete(HmpError):
    """Strict callers refused a partial kernel-thread prefix."""

    code = "incomplete_result"
    retryable = True

    def __init__(self, result: ThreadWalkResult) -> None:
        self.result = result
        evidence = thread_walk_truncation(result) or {}
        self.details = {"truncation": evidence}
        super().__init__(
            "thread walk is incomplete; retry after the kernel list is stable "
            "or omit require_complete to inspect the validated prefix"
        )


def thread_walk_truncation(
    result: ThreadWalkResult,
) -> dict[str, int | str | None] | None:
    """Return structured partial evidence, including legacy/manual results."""
    if result.complete:
        return None
    if result.truncation is not None:
        return result.truncation.public()
    return {
        "stage": "unknown",
        "link": None,
        "ethread": None,
        "returned": len(result.threads),
        "reason": result.truncated_reason or "thread walk is incomplete",
    }


class ThreadFilterError(HmpError):
    """A bounded thread-view request is malformed."""


@dataclass(frozen=True)
class ThreadSelection:
    """A presentation-bounded view of a complete-or-partial raw walk.

    ``walk_complete`` always describes the ETHREAD traversal, while
    ``output_truncated`` only describes an intentional client-facing limit.
    Keeping them separate prevents a compact response from masquerading as a
    corrupt kernel list, or vice versa.
    """

    threads: tuple[ThreadRecord, ...]
    total_count: int
    matched_count: int
    filtered_out: int
    output_truncated: bool
    state_counts: dict[str, int]
    wait_reason_counts: dict[str, int]


@dataclass(frozen=True)
class ThreadAddressAttribution:
    """One conservative attribution of a thread-start virtual address."""

    address: int
    mapping: str
    module: str | None = None
    module_base: int | None = None
    module_size: int | None = None
    rva: int | None = None
    architecture: str | None = None
    symbol: str | None = None
    symbol_offset: int | None = None
    # The loader result is deliberately retained even when a selected lead is
    # checked against the VAD tree.  A loader miss and a private/image VAD are
    # different kernel facts, not competing verdicts.
    vad: dict[str, Any] | None = None


@dataclass(frozen=True)
class ThreadStartAttribution:
    start_address: ThreadAddressAttribution
    win32_start_address: ThreadAddressAttribution


@dataclass(frozen=True)
class CurrentVcpuRecord:
    """One halted vCPU's validated scheduler-thread identity."""

    vcpu: int
    status: str
    ethread: int | None = None
    eprocess: int | None = None
    pid: int | None = None
    process_name: str | None = None
    tid: int | None = None
    in_target_process: bool = False
    reason: str | None = None


_THREAD_SORTS = {
    "tid", "state", "wait", "priority", "context-switches", "start",
    "win32-start", "create-time",
}


def _enum_filter(value: str | int | None, names: dict[int, str], label: str) -> int | None:
    """Parse a raw or symbolic scheduler filter without version guessing."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ThreadFilterError(f"{label} must be a raw byte or known enum name")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        try:
            parsed = int(text, 0)
        except ValueError:
            wanted = "".join(char for char in text.casefold() if char.isalnum())
            matches = [
                raw for raw, name in names.items()
                if "".join(char for char in name.casefold() if char.isalnum()) == wanted
            ]
            if len(matches) != 1:
                choices = ", ".join(names.values())
                raise ThreadFilterError(
                    f"invalid {label} {value!r}; use a raw byte or one of: {choices}"
                )
            return matches[0]
    else:
        raise ThreadFilterError(f"{label} must be a raw byte or known enum name")
    if not 0 <= parsed <= 0xFF:
        raise ThreadFilterError(f"{label} raw value must be between 0 and 255")
    return parsed


def select_threads(
    threads: list[ThreadRecord],
    *,
    state: str | int | None = None,
    wait_reason: str | int | None = None,
    sort: str = "tid",
    limit: int = 256,
) -> ThreadSelection:
    """Filter/sort a raw thread walk and intentionally bound returned rows."""
    wanted_state = _enum_filter(state, _KTHREAD_STATES, "state")
    wanted_wait = _enum_filter(wait_reason, _KWAIT_REASONS, "wait_reason")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1024:
        raise ThreadFilterError("limit must be an integer between 1 and 1024")
    sort = sort.strip().lower()
    if sort not in _THREAD_SORTS:
        choices = ", ".join(sorted(_THREAD_SORTS))
        raise ThreadFilterError(f"sort must be one of: {choices}")

    state_counts: dict[str, int] = {}
    wait_counts: dict[str, int] = {}
    for thread in threads:
        state_key = thread.state_name or f"unknown({thread.state})"
        state_counts[state_key] = state_counts.get(state_key, 0) + 1
        if thread.state == 5:
            wait_key = thread.wait_reason_name or f"unknown({thread.wait_reason})"
            wait_counts[wait_key] = wait_counts.get(wait_key, 0) + 1

    matched = [
        thread for thread in threads
        if (wanted_state is None or thread.state == wanted_state)
        and (
            wanted_wait is None
            or (thread.state == 5 and thread.wait_reason == wanted_wait)
        )
    ]
    if sort == "tid":
        matched.sort(key=lambda thread: (thread.tid, thread.ethread))
    elif sort == "state":
        matched.sort(key=lambda thread: (thread.state, thread.tid, thread.ethread))
    elif sort == "wait":
        matched.sort(key=lambda thread: (thread.state != 5, thread.wait_reason, thread.tid))
    elif sort == "priority":
        matched.sort(key=lambda thread: (-thread.priority, thread.tid, thread.ethread))
    elif sort == "context-switches":
        matched.sort(key=lambda thread: (-thread.context_switches, thread.tid, thread.ethread))
    elif sort == "start":
        matched.sort(key=lambda thread: (thread.start_address, thread.tid, thread.ethread))
    elif sort == "win32-start":
        matched.sort(key=lambda thread: (thread.win32_start_address, thread.tid, thread.ethread))
    else:  # create-time
        matched.sort(key=lambda thread: (thread.create_time, thread.tid, thread.ethread))

    return ThreadSelection(
        threads=tuple(matched[:limit]),
        total_count=len(threads),
        matched_count=len(matched),
        filtered_out=len(threads) - len(matched),
        output_truncated=len(matched) > limit,
        state_counts=state_counts,
        wait_reason_counts=wait_counts,
    )


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
    layout = _layout_struct(store, "_UNICODE_STRING")
    return read_unicode_string(
        vm_name, cr3, va,
        length_off=_layout_field(layout, "_UNICODE_STRING", "Length", 2).offset,
        buffer_off=_layout_field(layout, "_UNICODE_STRING", "Buffer", 8).offset,
        cache=cache,
    )


def _layout_int(raw: object, label: str, *, maximum: int = _MAX_PDB_STRUCT_SIZE) -> int:
    """Normalize an untrusted JSON PDB numeric field or fail closed.

    Symbol-store JSON is cached across versions and can be manually edited.
    ``bool`` is deliberately rejected even though Python considers it an int:
    accepting ``true`` as an offset of one is exactly the sort of polished
    nonsense a kernel walker must not produce.
    """
    if isinstance(raw, bool):
        raise SymbolStoreError(f"invalid {label} in nt types")
    try:
        value = int(raw, 0) if isinstance(raw, str) else int(raw)
    except (TypeError, ValueError) as exc:
        raise SymbolStoreError(f"invalid {label} in nt types") from exc
    if not 0 <= value <= maximum:
        raise SymbolStoreError(f"implausible {label} 0x{value:x} in nt types")
    return value


def _layout_struct(store: SymbolStore, name: str) -> dict[str, Any]:
    """Return one exact layout after validating its outer JSON shape."""
    try:
        layout = store.struct(name)
    except (KeyError, TypeError, ValueError, SymbolStoreError) as exc:
        raise SymbolStoreError(
            f"{name} is absent or malformed in nt types — re-run `winbox kdbg symbols`"
        ) from exc
    if not isinstance(layout, dict) or not isinstance(layout.get("fields"), dict):
        raise SymbolStoreError(f"invalid {name} layout in nt types")
    size = _layout_int(layout.get("size"), f"{name}.size")
    if size == 0:
        raise SymbolStoreError(f"invalid zero {name}.size in nt types")
    return layout


def _field_declared_width(entry: object) -> int | None:
    """Infer a width only where llvm-pdbutil exposed an unambiguous type."""
    if not isinstance(entry, dict):
        return None
    hint = entry.get("type")
    if not isinstance(hint, str) or not hint.strip():
        return None
    normalized = " ".join(hint.casefold().replace("*", " * ").split())
    if "[" in normalized or "]" in normalized:
        return None
    if "*" in normalized:
        return 8
    if "__int64" in normalized or "long long" in normalized:
        return 8
    if "short" in normalized or "wchar_t" in normalized:
        return 2
    if "char" in normalized or "bool" in normalized:
        return 1
    # Windows PDB `long` and `int` are fixed-width 32-bit scalar types.
    if "long" in normalized or normalized in {"int", "unsigned int"}:
        return 4
    return None


def _layout_field(
    layout: dict[str, Any],
    struct_name: str,
    field_name: str,
    size: int,
    *,
    base: int = 0,
) -> _ThreadField:
    """Validate a fixed-width field before it can become a memory read."""
    fields = layout.get("fields")
    entry = fields.get(field_name) if isinstance(fields, dict) else None
    if not isinstance(entry, dict) or "off" not in entry:
        raise SymbolStoreError(
            f"{struct_name}.{field_name} is absent from nt types — "
            "re-run `winbox kdbg symbols`"
        )
    relative_offset = _layout_int(entry.get("off"), f"{struct_name}.{field_name}.off")
    struct_size = _layout_int(layout.get("size"), f"{struct_name}.size")
    if size <= 0 or relative_offset + size > struct_size:
        raise SymbolStoreError(f"invalid {struct_name}.{field_name} span in nt types")
    declared_width = _field_declared_width(entry)
    if declared_width is not None and declared_width != size:
        raise SymbolStoreError(
            f"{struct_name}.{field_name} declares {declared_width} bytes, "
            f"expected {size}"
        )
    offset = relative_offset + base
    if offset < base or offset > _MAX_PDB_STRUCT_SIZE:
        raise SymbolStoreError(f"invalid {struct_name}.{field_name} offset in nt types")
    return _ThreadField(field_name, offset, size)


def _require_x64_four_level_store(store: SymbolStore) -> None:
    """Reject a symbol store we cannot safely decode with this x64 walker.

    Test doubles intentionally need only ``struct()``. Real SymbolStore
    instances expose ``load()`` and must declare their architecture; silently
    assuming x64 after an x86/ARM store was selected is worse than refusing.
    """
    load = getattr(store, "load", None)
    if not callable(load):
        return
    try:
        data = load("nt")
    except (OSError, ValueError, TypeError, SymbolStoreError) as exc:
        raise SymbolStoreError("cannot validate nt symbol-store architecture") from exc
    if not isinstance(data, dict):
        raise SymbolStoreError("invalid nt symbol-store record")
    architecture = str(data.get("architecture") or "").casefold()
    if architecture not in {"x64", "amd64"}:
        raise SymbolStoreError(
            f"unsupported nt symbol-store architecture {architecture or 'unknown'!r}; "
            "this walker requires x64 four-level paging"
        )


# ── Process list ────────────────────────────────────────────────────────


def _process_layout(store: SymbolStore) -> _ProcessLayout:
    _require_x64_four_level_store(store)
    eproc = _layout_struct(store, "_EPROCESS")
    kproc = _layout_struct(store, "_KPROCESS")
    # DirectoryTableBase belongs to the embedded KPROCESS.  Its offset is
    # meaningful relative to EPROCESS only when Pcb is proven to start at 0.
    pcb = _layout_field(eproc, "_EPROCESS", "Pcb", 1)
    if pcb.offset != 0:
        raise SymbolStoreError(
            f"unsupported _EPROCESS.Pcb offset 0x{pcb.offset:x} — "
            "refusing to treat PKPROCESS offsets as EPROCESS offsets"
        )
    active_links = _layout_field(eproc, "_EPROCESS", "ActiveProcessLinks", 16).offset
    image_name = _layout_field(eproc, "_EPROCESS", "ImageFileName", 15).offset
    pid = _layout_field(eproc, "_EPROCESS", "UniqueProcessId", 8).offset
    dtb = _layout_field(kproc, "_KPROCESS", "DirectoryTableBase", 8).offset
    kproc_fields = kproc["fields"]
    raw_user_dtb = kproc_fields.get("UserDirectoryTableBase", {}).get("off")
    user_dtb = (
        _layout_field(kproc, "_KPROCESS", "UserDirectoryTableBase", 8).offset
        if raw_user_dtb is not None else None
    )
    eproc_fields = eproc["fields"]
    raw_create_time = eproc_fields.get("CreateTime", {}).get("off")
    raw_exit_time = eproc_fields.get("ExitTime", {}).get("off")
    create_time = (
        _layout_field(eproc, "_EPROCESS", "CreateTime", 8).offset
        if raw_create_time is not None else None
    )
    exit_time = (
        _layout_field(eproc, "_EPROCESS", "ExitTime", 8).offset
        if raw_exit_time is not None else None
    )

    fields = [(active_links, 16), (image_name, 15), (pid, 8), (dtb, 8)]
    if user_dtb is not None:
        fields.append((user_dtb, 8))
    if create_time is not None:
        fields.append((create_time, 8))
    if exit_time is not None:
        fields.append((exit_time, 8))
    field_start = min(offset for offset, _ in fields)
    field_end = max(offset + size for offset, size in fields)
    eproc_size = _layout_int(eproc.get("size"), "_EPROCESS.size")
    if field_start < 0 or field_end <= field_start:
        raise HmpError("invalid negative/empty EPROCESS field span")
    if field_end > eproc_size:
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
        create_time=create_time,
        exit_time=exit_time,
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
    create_time = (
        int.from_bytes(field(layout.create_time, 8), "little")
        if layout.create_time is not None else 0
    )
    exit_time = (
        int.from_bytes(field(layout.exit_time, 8), "little")
        if layout.exit_time is not None else 0
    )
    return ProcessRecord(
        pid=pid,
        name=name,
        eprocess=eprocess,
        directory_table_base=dtb,
        user_directory_table_base=user_dtb,
        create_time=create_time,
        exit_time=exit_time,
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
def list_processes_detailed(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> ProcessWalkResult:
    """Walk the active process list with an explicit partial-result contract.

    ``list_processes`` remains a compatibility list API. New global research
    views need to know whether their process scope was complete, so they use
    this additive variant rather than inferring completion from a count.
    """
    head = store.resolve("PsActiveProcessHead")
    layout = _process_layout(store)
    cr3, flink, cache = _read_kernel_list_head(vm_name, head, cr3)
    records: list[ProcessRecord] = []
    seen: set[int] = set()

    def partial(
        stage: str, reason: str, *, link: int | None = None, eprocess: int | None = None,
    ) -> ProcessWalkResult:
        return ProcessWalkResult(
            records, False, reason,
            ProcessWalkTruncation(
                stage=stage, reason=reason, returned=len(records),
                link=link, eprocess=eprocess,
            ),
        )

    while flink != head:
        if flink == 0:
            return partial("link", "PsActiveProcessHead contained a null link", link=flink)
        if not _is_kernel_pointer(flink):
            return partial("link", f"invalid EPROCESS list pointer 0x{flink:x}", link=flink)
        if flink in seen:
            return partial("link", f"cycle detected at EPROCESS list entry 0x{flink:x}", link=flink)
        if len(records) >= MAX_PROCESSES:
            return partial("cap", f"hit MAX_PROCESSES={MAX_PROCESSES}", link=flink)
        seen.add(flink)
        eprocess = flink - layout.active_links
        if not _is_kernel_pointer(eprocess):
            return partial(
                "entry", f"invalid EPROCESS pointer 0x{eprocess:x}",
                link=flink, eprocess=eprocess,
            )
        try:
            record, flink = _read_process_entry(vm_name, cr3, eprocess, layout, cache)
        except (HmpError, PageWalkError) as exc:
            return partial("entry", str(exc), link=flink, eprocess=eprocess)
        records.append(record)
        if len(records) == 1 and record.pid == 4 and record.directory_table_base != cr3:
            cr3 = record.directory_table_base
            cache = WalkCache()
        if record.pid == 4 and cr3 is not None:
            _remember_kernel_cr3(vm_name, record.directory_table_base)
    return ProcessWalkResult(records, True)


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


@snapshot_operation
def read_process_identity(
    vm_name: str,
    store: SymbolStore,
    *,
    eprocess: int,
    cache: WalkCache | None = None,
) -> ProcessRecord:
    """Read one captured EPROCESS directly, including create/exit evidence.

    This remains useful after ActiveProcessLinks has been unlinked. Callers
    must still compare the returned PID, EPROCESS address, and create time to
    their captured identity before trusting it.
    """
    if not isinstance(eprocess, int) or eprocess <= 0:
        raise HmpError("invalid captured EPROCESS address")
    layout = _process_layout(store)
    head = store.resolve("PsActiveProcessHead")
    kernel_cr3, _, selected_cache = _read_kernel_list_head(vm_name, head, None)
    record, _ = _read_process_entry(
        vm_name, kernel_cr3, eprocess, layout, cache or selected_cache,
    )
    return record


# ── Per-process thread list (EPROCESS.ThreadListHead) ───────────────────


@dataclass(frozen=True)
class _ThreadField:
    """One fixed-width field in the ETHREAD/KTHREAD prefix."""

    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class _ThreadLayout:
    thread_list_head: int
    thread_list_entry: int
    eprocess_pcb: int
    fields: dict[str, _ThreadField]
    spans: tuple[_ProcessSpan, ...]


@dataclass(frozen=True)
class _WaitLayout:
    """The small exact-PDB subset needed for conservative wait evidence."""

    thread: _ThreadLayout
    wait_block_list: _ThreadField
    embedded_wait_block: int
    wait_block_thread: _ThreadField
    wait_block_object: _ThreadField
    dispatcher_type: _ThreadField
    mutant_owner_thread: _ThreadField


MAX_WAIT_OBJECT_THREADS = 128
MAX_WAIT_OWNER_DEPTH = 4

# KOBJECTS / DISPATCHER_HEADER.Type values. These byte values are stable
# scheduler metadata, but only Mutant has an owner field we resolve here.
_DISPATCHER_OBJECT_TYPES = {
    0: "notification_event",
    1: "synchronization_event",
    2: "mutant",
    3: "process",
    4: "queue",
    5: "semaphore",
    6: "thread",
    7: "gate",
    8: "notification_timer",
    9: "synchronization_timer",
}


def _thread_field(
    struct: dict,
    struct_name: str,
    field_name: str,
    size: int,
    *,
    base: int = 0,
) -> _ThreadField:
    """Resolve and validate one exact-PDB field before reading memory."""
    return _layout_field(struct, struct_name, field_name, size, base=base)


def _compact_spans(fields: list[_ThreadField]) -> tuple[_ProcessSpan, ...]:
    """Coalesce nearby thread fields without sparse ETHREAD over-reads."""
    spans: list[_ProcessSpan] = []
    for field in sorted(fields, key=lambda value: value.offset):
        if spans and field.offset <= spans[-1].start + spans[-1].size + 32:
            previous = spans[-1]
            end = max(previous.start + previous.size, field.offset + field.size)
            spans[-1] = _ProcessSpan(previous.start, end - previous.start)
        else:
            spans.append(_ProcessSpan(field.offset, field.size))
    return tuple(spans)


def _thread_layout(store: SymbolStore) -> _ThreadLayout:
    """Return validated offsets for the thread walker.

    ETHREAD starts with its embedded KTHREAD (``Tcb``).  The exact PDB tells
    us both offsets, and the walker rejects a non-zero Tcb instead of assuming
    a layout it has not verified.
    """
    _require_x64_four_level_store(store)
    eproc = _layout_struct(store, "_EPROCESS")
    ethread = _layout_struct(store, "_ETHREAD")
    kthread = _layout_struct(store, "_KTHREAD")
    thread_list_head = _layout_field(
        eproc, "_EPROCESS", "ThreadListHead", 16,
    ).offset

    pcb = _layout_field(eproc, "_EPROCESS", "Pcb", 1)
    eprocess_pcb = pcb.offset
    if eprocess_pcb != 0:
        raise SymbolStoreError(
            f"unsupported _EPROCESS.Pcb offset 0x{eprocess_pcb:x} — "
            "refusing to equate PKPROCESS with EPROCESS"
        )

    tcb = _layout_field(ethread, "_ETHREAD", "Tcb", 1).offset
    if tcb != 0:
        raise SymbolStoreError(
            f"unsupported _ETHREAD.Tcb offset 0x{tcb:x} — refusing to guess KTHREAD base"
        )
    ethread_size = _layout_int(ethread.get("size"), "_ETHREAD.size")
    kthread_size = _layout_int(kthread.get("size"), "_KTHREAD.size")
    if kthread_size > ethread_size:
        raise SymbolStoreError("_KTHREAD exceeds _ETHREAD in nt types")

    fields = {
        "thread_list_entry": _thread_field(
            ethread, "_ETHREAD", "ThreadListEntry", 16,
        ),
        # CLIENT_ID is a documented pair of pointer-width HANDLEs on x64.
        # It is embedded in ETHREAD; the PDB parser intentionally stores
        # field offsets rather than nested type trees, so read its bounded
        # 16-byte native layout directly.
        "cid": _thread_field(ethread, "_ETHREAD", "Cid", 16),
        "start_address": _thread_field(ethread, "_ETHREAD", "StartAddress", 8),
        "win32_start_address": _thread_field(
            ethread, "_ETHREAD", "Win32StartAddress", 8,
        ),
        "create_time": _thread_field(ethread, "_ETHREAD", "CreateTime", 8),
        # ETHREAD.ExitTime aliases KeyedWaitChain in current public PDBs.
        # Without decoding the controlling union state it is often a kernel
        # pointer on live threads, so exposing it as a timestamp would be a
        # polished lie.  Do not add it back as a naked field.
        "exit_status": _thread_field(ethread, "_ETHREAD", "ExitStatus", 4),
        "state": _thread_field(kthread, "_KTHREAD", "State", 1, base=tcb),
        "wait_reason": _thread_field(
            kthread, "_KTHREAD", "WaitReason", 1, base=tcb,
        ),
        "priority": _thread_field(kthread, "_KTHREAD", "Priority", 1, base=tcb),
        "base_priority": _thread_field(
            kthread, "_KTHREAD", "BasePriority", 1, base=tcb,
        ),
        "context_switches": _thread_field(
            kthread, "_KTHREAD", "ContextSwitches", 4, base=tcb,
        ),
        "teb": _thread_field(kthread, "_KTHREAD", "Teb", 8, base=tcb),
        "kernel_stack": _thread_field(
            kthread, "_KTHREAD", "KernelStack", 8, base=tcb,
        ),
        "stack_limit": _thread_field(
            kthread, "_KTHREAD", "StackLimit", 8, base=tcb,
        ),
        "stack_base": _thread_field(
            kthread, "_KTHREAD", "StackBase", 8, base=tcb,
        ),
        # KTHREAD.Process is a PKPROCESS; EPROCESS embeds KPROCESS at offset
        # zero on supported x64 Windows.  It gives us an ownership invariant
        # independent of the list membership and client PID.
        "process": _thread_field(kthread, "_KTHREAD", "Process", 8, base=tcb),
    }
    return _ThreadLayout(
        thread_list_head=thread_list_head,
        thread_list_entry=fields["thread_list_entry"].offset,
        eprocess_pcb=eprocess_pcb,
        fields=fields,
        spans=_compact_spans(list(fields.values())),
    )


def _wait_layout(store: SymbolStore) -> _WaitLayout:
    """Load only wait fields whose exact type/layout is available.

    ``WaitBlockList`` may refer to an external block for multi-object waits.
    This implementation intentionally refuses to chase that arbitrary list:
    it resolves the one embedded KTHREAD.WaitBlock only after the pointer
    proves it is the active block.  That yields real object/owner facts for
    ordinary waits without turning a corrupted object queue into a fake
    deadlock graph.
    """
    thread = _thread_layout(store)
    kthread = _layout_struct(store, "_KTHREAD")
    wait_block = _layout_struct(store, "_KWAIT_BLOCK")
    header = _layout_struct(store, "_DISPATCHER_HEADER")
    mutant = _layout_struct(store, "_KMUTANT")
    return _WaitLayout(
        thread=thread,
        wait_block_list=_layout_field(kthread, "_KTHREAD", "WaitBlockList", 8),
        embedded_wait_block=_layout_field(kthread, "_KTHREAD", "WaitBlock", 1).offset,
        wait_block_thread=_layout_field(wait_block, "_KWAIT_BLOCK", "Thread", 8),
        wait_block_object=_layout_field(wait_block, "_KWAIT_BLOCK", "Object", 8),
        dispatcher_type=_layout_field(header, "_DISPATCHER_HEADER", "Type", 1),
        mutant_owner_thread=_layout_field(mutant, "_KMUTANT", "OwnerThread", 8),
    )


def _is_kernel_pointer(value: int) -> bool:
    return value != 0 and value & 0x7 == 0 and value >> 48 == 0xFFFF


def _read_thread_entry(
    vm_name: str,
    cr3: int,
    ethread: int,
    target: ProcessRecord,
    layout: _ThreadLayout,
    cache: WalkCache,
    previous_link: int,
) -> tuple[ThreadRecord, int]:
    """Read one ETHREAD/KTHREAD prefix in compact, exact-PDB spans."""
    chunks: list[tuple[_ProcessSpan, bytes]] = []
    for span in layout.spans:
        raw = read_virt_cr3(
            vm_name, cr3, ethread + span.start, span.size, cache=cache,
        )
        if len(raw) != span.size:
            raise HmpError(
                f"short ETHREAD read at 0x{ethread + span.start:x}: "
                f"expected {span.size}, got {len(raw)}"
            )
        chunks.append((span, raw))

    def field(name: str) -> bytes:
        wanted = layout.fields[name]
        for span, raw in chunks:
            if span.start <= wanted.offset and wanted.offset + wanted.size <= span.start + span.size:
                start = wanted.offset - span.start
                return raw[start:start + wanted.size]
        raise HmpError(f"ETHREAD field {name} is outside read spans")

    list_entry = field("thread_list_entry")
    next_flink = int.from_bytes(list_entry[:8], "little")
    previous_blink = int.from_bytes(list_entry[8:], "little")
    if next_flink != target.eprocess + layout.thread_list_head and not _is_kernel_pointer(next_flink):
        raise HmpError(f"invalid ETHREAD list pointer 0x{next_flink:x}")
    if previous_blink != previous_link:
        raise HmpError(
            f"ETHREAD list Blink 0x{previous_blink:x} at link "
            f"0x{ethread + layout.thread_list_entry:x}, expected 0x{previous_link:x}"
        )

    cid = field("cid")
    client_pid = int.from_bytes(cid[:8], "little")
    tid = int.from_bytes(cid[8:], "little")
    if client_pid != target.pid:
        raise HmpError(
            f"ETHREAD 0x{ethread:x} belongs to pid {client_pid}, expected {target.pid}"
        )
    if tid == 0:
        raise HmpError(f"ETHREAD 0x{ethread:x} has a zero client thread id")

    owner = int.from_bytes(field("process"), "little")
    if owner != target.eprocess:
        raise HmpError(
            f"ETHREAD 0x{ethread:x} KTHREAD.Process=0x{owner:x}, "
            f"expected EPROCESS 0x{target.eprocess:x}"
        )

    state = int.from_bytes(field("state"), "little")
    wait_reason = int.from_bytes(field("wait_reason"), "little")
    return ThreadRecord(
        tid=tid,
        ethread=ethread,
        state=state,
        state_name=_KTHREAD_STATES.get(state),
        wait_reason=wait_reason,
        # KWAIT_REASON is meaningful only while the scheduler state is
        # Waiting. Preserve its raw byte for forensics, but do not decorate a
        # Ready/Running thread with a stale-looking wait reason.
        wait_reason_name=_KWAIT_REASONS.get(wait_reason) if state == 5 else None,
        priority=int.from_bytes(field("priority"), "little", signed=True),
        base_priority=int.from_bytes(field("base_priority"), "little", signed=True),
        context_switches=int.from_bytes(field("context_switches"), "little"),
        teb=int.from_bytes(field("teb"), "little"),
        kernel_stack=int.from_bytes(field("kernel_stack"), "little"),
        stack_limit=int.from_bytes(field("stack_limit"), "little"),
        stack_base=int.from_bytes(field("stack_base"), "little"),
        start_address=int.from_bytes(field("start_address"), "little"),
        win32_start_address=int.from_bytes(field("win32_start_address"), "little"),
        create_time=int.from_bytes(field("create_time"), "little"),
        exit_status=int.from_bytes(field("exit_status"), "little", signed=True),
    ), next_flink


@snapshot_operation
def list_threads(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    cache: WalkCache | None = None,
    max_threads: int | None = None,
) -> ThreadWalkResult:
    """Walk one process's ``EPROCESS.ThreadListHead`` safely.

    The caller supplies a process record obtained in the same coherent RSP
    snapshot.  Kernel metadata is read through a separately verified kernel
    CR3; using a process's user-side KPTI root here would make the result
    depend on where the scheduler happened to stop.
    """
    if target.pid <= 0 or target.eprocess <= 0:
        raise HmpError("invalid target process record for thread walk")
    if max_threads is not None and (
        not isinstance(max_threads, int) or isinstance(max_threads, bool)
        or not 1 <= max_threads <= MAX_THREADS_PER_PROCESS
    ):
        raise ThreadFilterError(
            f"max_threads must be an integer between 1 and {MAX_THREADS_PER_PROCESS}"
        )
    thread_cap = max_threads or MAX_THREADS_PER_PROCESS
    layout = _thread_layout(store)
    process_head = store.resolve("PsActiveProcessHead")
    kernel_cr3, _, selected_cache = _read_kernel_list_head(
        vm_name, process_head, None,
    )
    cache = cache or selected_cache
    head = target.eprocess + layout.thread_list_head
    try:
        flink = _read_u64(vm_name, kernel_cr3, head, cache)
    except (HmpError, PageWalkError) as exc:
        reason = f"could not read ThreadListHead: {exc}"
        return _partial_thread_walk([], "head", reason, link=head)

    try:
        head_blink = _read_u64(vm_name, kernel_cr3, head + 8, cache)
    except (HmpError, PageWalkError) as exc:
        reason = f"could not read ThreadListHead Blink: {exc}"
        return _partial_thread_walk([], "head", reason, link=head)

    results: list[ThreadRecord] = []
    seen: set[int] = set()
    seen_tids: set[int] = set()
    previous_link = head
    while flink != head:
        if flink == 0:
            return _partial_thread_walk(
                results, "link", "ThreadListHead contained a null link", link=flink,
            )
        if not _is_kernel_pointer(flink):
            return _partial_thread_walk(
                results, "link", f"invalid ETHREAD list pointer 0x{flink:x}", link=flink,
            )
        if flink in seen:
            return _partial_thread_walk(
                results, "link", f"cycle detected at ETHREAD list entry 0x{flink:x}", link=flink,
            )
        if len(results) >= thread_cap:
            return _partial_thread_walk(
                results, "cap", f"hit thread cap={thread_cap}", link=flink,
            )
        seen.add(flink)
        ethread = flink - layout.thread_list_entry
        if not _is_kernel_pointer(ethread):
            return _partial_thread_walk(
                results, "entry", f"invalid ETHREAD pointer 0x{ethread:x}",
                link=flink, ethread=ethread,
            )
        try:
            record, flink = _read_thread_entry(
                vm_name, kernel_cr3, ethread, target, layout, cache, previous_link,
            )
        except (HmpError, PageWalkError, SymbolStoreError) as exc:
            return _partial_thread_walk(
                results, "entry", str(exc), link=flink, ethread=ethread,
            )
        if record.tid in seen_tids:
            return _partial_thread_walk(
                results, "identity",
                f"duplicate live ETHREAD client thread id {record.tid}",
                link=flink, ethread=ethread,
            )
        seen_tids.add(record.tid)
        results.append(record)
        previous_link = ethread + layout.thread_list_entry
    if head_blink != previous_link:
        return _partial_thread_walk(
            results, "head",
            f"ThreadListHead Blink 0x{head_blink:x}, expected 0x{previous_link:x}",
            link=head,
        )
    return ThreadWalkResult(results, True)


def _partial_thread_walk(
    threads: list[ThreadRecord],
    stage: str,
    reason: str,
    *,
    link: int | None = None,
    ethread: int | None = None,
) -> ThreadWalkResult:
    return ThreadWalkResult(
        threads, False, reason,
        ThreadWalkTruncation(
            stage=stage, reason=reason, returned=len(threads), link=link, ethread=ethread,
        ),
    )


def _wait_identity(
    vm_name: str,
    cr3: int,
    ethread: int,
    layout: _WaitLayout,
    cache: WalkCache,
) -> dict[str, int] | None:
    """Return a minimal owner identity only after its ETHREAD fields agree."""
    cid = read_virt_cr3(
        vm_name, cr3, ethread + layout.thread.fields["cid"].offset, 16, cache=cache,
    )
    process = read_virt_cr3(
        vm_name, cr3, ethread + layout.thread.fields["process"].offset, 8, cache=cache,
    )
    state = read_virt_cr3(
        vm_name, cr3, ethread + layout.thread.fields["state"].offset, 1, cache=cache,
    )
    if len(cid) != 16 or len(process) != 8 or len(state) != 1:
        raise HmpError(f"short owner ETHREAD identity read at 0x{ethread:x}")
    pid = int.from_bytes(cid[:8], "little")
    tid = int.from_bytes(cid[8:], "little")
    owner_process = int.from_bytes(process, "little")
    if pid == 0 or tid == 0 or not _is_kernel_pointer(owner_process):
        return None
    return {"ethread": ethread, "pid": pid, "tid": tid, "state": state[0]}


def _wait_block_for_thread(
    vm_name: str,
    cr3: int,
    ethread: int,
    layout: _WaitLayout,
    cache: WalkCache,
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve one proven embedded wait block; never chase external pointers."""
    active_raw = read_virt_cr3(
        vm_name, cr3, ethread + layout.wait_block_list.offset, 8, cache=cache,
    )
    if len(active_raw) != 8:
        raise HmpError(f"short KTHREAD.WaitBlockList read at 0x{ethread:x}")
    active = int.from_bytes(active_raw, "little")
    embedded = ethread + layout.embedded_wait_block
    if active != embedded:
        return None, (
            "WaitBlockList does not reference this thread's embedded KWAIT_BLOCK; "
            "external/multi-object wait blocks are not chased"
        )
    thread_raw = read_virt_cr3(
        vm_name, cr3, embedded + layout.wait_block_thread.offset, 8, cache=cache,
    )
    object_raw = read_virt_cr3(
        vm_name, cr3, embedded + layout.wait_block_object.offset, 8, cache=cache,
    )
    if len(thread_raw) != 8 or len(object_raw) != 8:
        raise HmpError(f"short KWAIT_BLOCK read at 0x{embedded:x}")
    block_thread = int.from_bytes(thread_raw, "little")
    object_address = int.from_bytes(object_raw, "little")
    if block_thread != ethread:
        return None, "KWAIT_BLOCK.Thread does not identify the waiting ETHREAD"
    if not _is_kernel_pointer(object_address):
        return None, f"KWAIT_BLOCK.Object is not a canonical kernel pointer (0x{object_address:x})"
    kind_raw = read_virt_cr3(
        vm_name, cr3, object_address + layout.dispatcher_type.offset, 1, cache=cache,
    )
    if len(kind_raw) != 1:
        raise HmpError(f"short DISPATCHER_HEADER.Type read at 0x{object_address:x}")
    kind = kind_raw[0]
    return {
        "wait_block": embedded,
        "object": object_address,
        "dispatcher_type_raw": kind,
        "dispatcher_type": _DISPATCHER_OBJECT_TYPES.get(kind),
    }, None


@snapshot_operation
def resolve_thread_wait_objects(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    threads: tuple[ThreadRecord, ...] | list[ThreadRecord],
    *,
    cache: WalkCache | None = None,
    limit: int = 32,
    owner_depth: int = 2,
) -> dict[str, Any]:
    """Return bounded, exact-PDB wait-object and mutant-owner evidence.

    This is intentionally an opt-in annotation for already selected Waiting
    rows.  It does not infer a dispatcher type from an arbitrary pointer, does
    not chase external/multi-object wait blocks, and follows only an exact
    ``_KMUTANT.OwnerThread`` relation.  Every unavailable edge stays visible
    as a reason rather than becoming a speculative deadlock claim.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_WAIT_OBJECT_THREADS:
        raise ThreadFilterError(
            f"wait_object_limit must be an integer between 1 and {MAX_WAIT_OBJECT_THREADS}"
        )
    if not isinstance(owner_depth, int) or isinstance(owner_depth, bool) or not 1 <= owner_depth <= MAX_WAIT_OWNER_DEPTH:
        raise ThreadFilterError(
            f"wait_owner_depth must be an integer between 1 and {MAX_WAIT_OWNER_DEPTH}"
        )
    if target.eprocess <= 0 or target.pid <= 0:
        raise HmpError("invalid target process record for wait-object evidence")

    layout = _wait_layout(store)
    cache = cache or WalkCache()
    head = target.eprocess + layout.thread.thread_list_head
    kernel_cr3, _, kernel_cache = _read_kernel_list_head(vm_name, head, None)
    if cache is not kernel_cache:
        # The verified CR3's page-table cache is intentionally retained. The
        # passed cache may have originated from the same target but through a
        # provisional KPTI root.
        cache = kernel_cache

    waiting = sorted(
        (thread for thread in threads if thread.state == 5),
        key=lambda thread: (thread.tid, thread.ethread),
    )
    selected = waiting[:limit]
    records: dict[int, dict[str, Any]] = {}
    for thread in selected:
        evidence: dict[str, Any] = {
            "tid": thread.tid,
            "ethread": f"0x{thread.ethread:016x}",
            "state": {"raw": thread.state, "name": thread.state_name},
            "complete": False,
            "wait_block": None,
            "object": None,
            "owner_chain": [],
            "reason": None,
        }
        current = thread.ethread
        seen = {current}
        for depth in range(owner_depth):
            try:
                block, reason = _wait_block_for_thread(
                    vm_name, kernel_cr3, current, layout, cache,
                )
            except (HmpError, PageWalkError, SymbolStoreError) as exc:
                evidence["reason"] = f"wait evidence read failed: {exc}"
                break
            if block is None:
                evidence["reason"] = reason
                break
            object_view = {
                "address": f"0x{block['object']:016x}",
                "dispatcher_type": {
                    "raw": block["dispatcher_type_raw"],
                    "name": block["dispatcher_type"],
                },
            }
            if depth == 0:
                evidence["wait_block"] = f"0x{block['wait_block']:016x}"
                evidence["object"] = object_view
            if block["dispatcher_type_raw"] != 2:
                evidence["reason"] = (
                    "dispatcher object type has no proven owner relation"
                    if block["dispatcher_type"] is not None
                    else "unknown dispatcher object type; owner was not inferred"
                )
                break
            try:
                owner_raw = read_virt_cr3(
                    vm_name, kernel_cr3,
                    block["object"] + layout.mutant_owner_thread.offset,
                    8, cache=cache,
                )
            except (HmpError, PageWalkError) as exc:
                evidence["reason"] = f"KMUTANT.OwnerThread read failed: {exc}"
                break
            if len(owner_raw) != 8:
                evidence["reason"] = "short KMUTANT.OwnerThread read"
                break
            owner = int.from_bytes(owner_raw, "little")
            if owner == 0:
                evidence["complete"] = True
                evidence["reason"] = "mutant has no owner (unowned or abandoned)"
                break
            if not _is_kernel_pointer(owner):
                evidence["reason"] = f"KMUTANT.OwnerThread is not a kernel pointer (0x{owner:x})"
                break
            if owner in seen:
                evidence["reason"] = "owner chain cycle detected"
                break
            try:
                identity = _wait_identity(vm_name, kernel_cr3, owner, layout, cache)
            except (HmpError, PageWalkError) as exc:
                evidence["reason"] = f"owner ETHREAD identity read failed: {exc}"
                break
            if identity is None:
                evidence["reason"] = "owner ETHREAD identity is invalid or stale"
                break
            owner_view = {
                "ethread": f"0x{owner:016x}",
                "pid": identity["pid"],
                "tid": identity["tid"],
                "state": {
                    "raw": identity["state"],
                    "name": _KTHREAD_STATES.get(identity["state"]),
                },
                "via_object": object_view,
            }
            evidence["owner_chain"].append(owner_view)
            if identity["state"] != 5:
                evidence["complete"] = True
                evidence["reason"] = "owner is not waiting"
                break
            seen.add(owner)
            current = owner
        else:
            evidence["reason"] = f"owner chain reached configured depth={owner_depth}"
        records[thread.ethread] = evidence

    return {
        "enabled": True,
        "scope": {
            "waiting_threads": len(waiting),
            "examined": len(selected),
            "output_truncated": len(waiting) > len(selected),
            "wait_object_limit": limit,
            "wait_owner_depth": owner_depth,
            "external_wait_blocks": "not_chased",
            "owner_relation": "mutant_only",
        },
        "records": records,
    }


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
    _require_x64_four_level_store(store)
    explicit_cr3 = cr3

    head = store.resolve("PsLoadedModuleList")
    ldr = _layout_struct(store, "_KLDR_DATA_TABLE_ENTRY")
    ldr_fields = ldr["fields"]
    # _KLDR_DATA_TABLE_ENTRY starts with InLoadOrderLinks at offset 0.
    inload_off = _layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", 16).offset
    dll_base_off = _layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "DllBase", 8).offset
    size_off = _layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "SizeOfImage", 4).offset
    base_name_off = _layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "BaseDllName", 16).offset

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
    _require_x64_four_level_store(store)
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


# ── Thread start attribution and current-vCPU mapping ───────────────────


def _module_containing(address: int, modules: list[ModuleRecord | UserModuleRecord]):
    for module in modules:
        if module.base <= address < module.base + module.size:
            return module
    return None


def _symbol_store_names(module: ModuleRecord | UserModuleRecord, *, kernel: bool) -> tuple[str, ...]:
    """Return only plausible local-store keys; no network or symbol loads."""
    stem = module.name.rsplit(".", 1)[0].casefold()
    if kernel and module.name.casefold() in {"ntoskrnl.exe", "ntkrnlmp.exe"}:
        return ("nt", stem)
    if isinstance(module, UserModuleRecord) and module.architecture == "x86":
        return (f"{stem}_x86", stem)
    return (stem,)


def _nearest_symbol(store: SymbolStore, module: ModuleRecord | UserModuleRecord, rva: int, *, kernel: bool) -> tuple[str, int] | None:
    """Find one nearest known public without trusting a stale stored base."""
    list_known = getattr(store, "list_modules", None)
    load = getattr(store, "load", None)
    if not callable(list_known) or not callable(load):
        return None
    try:
        available = {str(name).casefold() for name in list_known()}
    except (OSError, SymbolStoreError):
        return None
    for name in _symbol_store_names(module, kernel=kernel):
        if name.casefold() not in available:
            continue
        try:
            symbols = load(name).get("symbols", {})
        except (OSError, SymbolStoreError, ValueError, TypeError):
            continue
        nearest: tuple[int, str] | None = None
        for symbol, raw_rva in symbols.items():
            try:
                symbol_rva = int(raw_rva)
            except (TypeError, ValueError):
                continue
            if 0 <= symbol_rva <= rva and (
                nearest is None or symbol_rva > nearest[0]
            ):
                nearest = (symbol_rva, str(symbol))
        if nearest is not None:
            return nearest[1], rva - nearest[0]
    return None


def _attribute_thread_address(
    address: int,
    *,
    kernel_modules: list[ModuleRecord],
    user_modules: list[UserModuleRecord],
    store: SymbolStore,
) -> ThreadAddressAttribution:
    if address == 0:
        return ThreadAddressAttribution(address=0, mapping="null")
    # Code addresses need only be canonical high-half; unlike linked-list
    # pointers they are not required to be eight-byte aligned.
    kernel = address >> 48 == 0xFFFF
    module = _module_containing(address, kernel_modules if kernel else user_modules)
    if module is None:
        # The PEB loader tells us only which images are loaded. Do not call an
        # unmatched low VA "private" or "JIT" without a VAD walk to prove it.
        return ThreadAddressAttribution(
            address=address,
            mapping="kernel_unmapped" if kernel else "user_not_in_loader_module",
        )
    rva = address - module.base
    symbol = _nearest_symbol(store, module, rva, kernel=kernel)
    return ThreadAddressAttribution(
        address=address,
        mapping="kernel_module" if kernel else "user_module",
        module=module.name,
        module_base=module.base,
        module_size=module.size,
        rva=rva,
        architecture=None if kernel else module.architecture,
        symbol=symbol[0] if symbol is not None else None,
        symbol_offset=symbol[1] if symbol is not None else None,
    )


@snapshot_operation
def resolve_thread_start_addresses(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    threads: list[ThreadRecord] | tuple[ThreadRecord, ...],
    *,
    cache: WalkCache | None = None,
    kernel_modules: list[ModuleRecord] | None = None,
    user_modules: list[UserModuleRecord] | None = None,
) -> tuple[dict[int, ThreadStartAttribution], tuple[str, ...]]:
    """Resolve selected start VAs against live loaded-module views.

    This is deliberately opt-in and only receives presentation-bounded rows.
    Missing PEB metadata is reported as a warning while kernel attribution and
    the raw ETHREAD walk remain usable.
    """
    cache = cache or WalkCache()
    warnings: list[str] = []
    if kernel_modules is None:
        try:
            kernel_modules = list_modules(vm_name, store, cache=cache)
        except (HmpError, PageWalkError, SymbolStoreError) as exc:
            kernel_modules = []
            warnings.append(f"kernel module attribution unavailable: {exc}")
    if user_modules is None:
        try:
            user_modules = list_user_modules(vm_name, store, target, cache=cache)
        except (HmpError, PageWalkError, SymbolStoreError) as exc:
            user_modules = []
            warnings.append(f"user module attribution unavailable: {exc}")
    resolved: dict[int, ThreadStartAttribution] = {}
    unmatched_user_addresses: list[int] = []
    for thread in threads:
        start = _attribute_thread_address(
            thread.start_address, kernel_modules=kernel_modules,
            user_modules=user_modules, store=store,
        )
        win32_start = _attribute_thread_address(
            thread.win32_start_address, kernel_modules=kernel_modules,
            user_modules=user_modules, store=store,
        )
        resolved[thread.ethread] = ThreadStartAttribution(start, win32_start)
        for value in (start, win32_start):
            if value.mapping == "user_not_in_loader_module" and value.address not in unmatched_user_addresses:
                unmatched_user_addresses.append(value.address)

    # VAD lookup remains presentation-bounded: selected rows contribute at
    # most 128 distinct user addresses.  VAD type extraction is intentionally
    # expected to happen before the caller starts the RSP snapshot; a missing
    # layout therefore degrades this enrichment to a visible warning rather
    # than invalidating the already-proven ETHREAD/loader result.
    vad_by_address: dict[int, Any] = {}
    if unmatched_user_addresses:
        if len(unmatched_user_addresses) > 128:
            warnings.append(
                f"VAD enrichment limited to 128 of {len(unmatched_user_addresses)} unmatched user starts"
            )
        try:
            from winbox.kdbg.vad import VadError, lookup_addresses

            vad_by_address = lookup_addresses(
                vm_name, store, target, unmatched_user_addresses[:128], cache=cache,
            )
        except (
            VadError, HmpError, PageWalkError, SymbolStoreError,
            AttributeError, KeyError, TypeError, ValueError,
        ) as exc:
            warnings.append(f"VAD enrichment unavailable: {exc}")

    def add_vad(value: ThreadAddressAttribution) -> ThreadAddressAttribution:
        if value.mapping != "user_not_in_loader_module":
            return value
        if value.address not in vad_by_address:
            return replace(value, vad={"status": "not_checked"})
        record = vad_by_address[value.address]
        return replace(value, vad={
            "status": "not_found" if record is None else "mapped",
            "record": None if record is None else record.public(),
        })

    return {
        ethread: ThreadStartAttribution(
            add_vad(value.start_address), add_vad(value.win32_start_address),
        )
        for ethread, value in resolved.items()
    }, tuple(warnings)


@dataclass(frozen=True)
class _CurrentVcpuLayout:
    kpcr_self: _ThreadField
    kpcr_current_prcb: _ThreadField
    kprcb_current_thread: _ThreadField


def _current_vcpu_layout(store: SymbolStore) -> _CurrentVcpuLayout:
    kpcr = store.struct("_KPCR")
    kprcb = store.struct("_KPRCB")
    return _CurrentVcpuLayout(
        kpcr_self=_thread_field(kpcr, "_KPCR", "Self", 8),
        kpcr_current_prcb=_thread_field(kpcr, "_KPCR", "CurrentPrcb", 8),
        kprcb_current_thread=_thread_field(
            kprcb, "_KPRCB", "CurrentThread", 8,
        ),
    )


@snapshot_operation
def list_current_vcpu_threads(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    threads: list[ThreadRecord] | tuple[ThreadRecord, ...] = (),
    cache: WalkCache | None = None,
) -> list[CurrentVcpuRecord]:
    """Map every halted vCPU to its validated current ETHREAD.

    RSP exposes vCPU register sets, not Windows thread contexts. We recover
    the scheduler identity only via exact-PDB KPCR/KPRCB fields and validate
    the resulting KTHREAD's process and CLIENT_ID before exposing it.
    """
    snapshot = current_snapshot(vm_name)
    if snapshot is None:
        raise HmpError("no active RSP snapshot for current-vCPU walk")
    per_vcpu = tuple(getattr(snapshot, "vcpu_kernel_gs_bases", ()))
    if not per_vcpu:
        return []
    layout = _current_vcpu_layout(store)
    thread_layout = _thread_layout(store)
    process_layout = _process_layout(store)
    process_head = store.resolve("PsActiveProcessHead")
    kernel_cr3, _, selected_cache = _read_kernel_list_head(vm_name, process_head, None)
    cache = cache or selected_cache
    target_threads = {thread.ethread: thread for thread in threads}
    results: list[CurrentVcpuRecord] = []

    for raw_vcpu, raw_candidates in per_vcpu:
        try:
            vcpu = int(raw_vcpu)
            candidates = tuple(int(candidate) for candidate in raw_candidates)
        except (TypeError, ValueError):
            continue
        errors: list[str] = []
        resolved: CurrentVcpuRecord | None = None
        for kpcr in candidates:
            try:
                if not _is_kernel_pointer(kpcr):
                    raise HmpError(f"invalid KPCR candidate 0x{kpcr:x}")
                if _read_u64(vm_name, kernel_cr3, kpcr + layout.kpcr_self.offset, cache) != kpcr:
                    raise HmpError("KPCR self pointer mismatch")
                prcb = _read_u64(
                    vm_name, kernel_cr3, kpcr + layout.kpcr_current_prcb.offset, cache,
                )
                if not _is_kernel_pointer(prcb):
                    raise HmpError(f"invalid KPRCB pointer 0x{prcb:x}")
                ethread = _read_u64(
                    vm_name, kernel_cr3, prcb + layout.kprcb_current_thread.offset, cache,
                )
                if not _is_kernel_pointer(ethread):
                    raise HmpError(f"invalid current ETHREAD pointer 0x{ethread:x}")
                owner = _read_u64(
                    vm_name, kernel_cr3, ethread + thread_layout.fields["process"].offset, cache,
                )
                if not _is_kernel_pointer(owner):
                    raise HmpError(f"invalid KTHREAD.Process pointer 0x{owner:x}")
                process, _ = _read_process_entry(
                    vm_name, kernel_cr3, owner, process_layout, cache,
                )
                if process.eprocess != owner or process.pid < 0:
                    raise HmpError("current KTHREAD owner identity is invalid")
                cid = read_virt_cr3(
                    vm_name, kernel_cr3, ethread + thread_layout.fields["cid"].offset,
                    16, cache=cache,
                )
                if len(cid) != 16:
                    raise HmpError("short current ETHREAD CLIENT_ID read")
                client_pid = int.from_bytes(cid[:8], "little")
                tid = int.from_bytes(cid[8:], "little")
                if process.pid == 0:
                    # Each processor's IdleThread is a legitimate current
                    # KTHREAD but deliberately has a zero CLIENT_ID. It is
                    # scheduler state, not a user-visible thread handle.
                    if client_pid != 0 or tid != 0:
                        raise HmpError("idle ETHREAD CLIENT_ID is not zero")
                    resolved = CurrentVcpuRecord(
                        vcpu=vcpu,
                        status="idle",
                        ethread=ethread,
                        eprocess=owner,
                        pid=0,
                        process_name=process.name,
                        tid=0,
                    )
                    break
                if client_pid != process.pid or tid == 0:
                    raise HmpError("current ETHREAD CLIENT_ID does not match owning process")
                listed = target_threads.get(ethread)
                in_target = owner == target.eprocess
                if in_target and (listed is None or listed.tid != tid):
                    raise HmpError("current target ETHREAD is absent from validated ThreadListHead")
                resolved = CurrentVcpuRecord(
                    vcpu=vcpu,
                    status="current",
                    ethread=ethread,
                    eprocess=owner,
                    pid=process.pid,
                    process_name=process.name,
                    tid=tid,
                    in_target_process=in_target,
                )
                break
            except (HmpError, PageWalkError, SymbolStoreError) as exc:
                errors.append(f"0x{kpcr:x}: {exc}")
        if resolved is None:
            results.append(CurrentVcpuRecord(
                vcpu=vcpu,
                status="unavailable",
                reason="; ".join(errors[:2])[:512] or "no KPCR candidate",
            ))
        else:
            results.append(resolved)
    return results
