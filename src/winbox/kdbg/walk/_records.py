"""Dataclasses, error types, constants, and thread filters for walk results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from winbox.kdbg.hmp import HmpError


MAX_PROCESSES = 4096
MAX_MODULES = 1024
MAX_USER_MODULES = 1024
MAX_THREADS_PER_PROCESS = 8192
_MAX_PDB_STRUCT_SIZE = 1 << 20

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


@dataclass
class ProcessRecord:
    pid: int
    name: str
    eprocess: int
    directory_table_base: int
    user_directory_table_base: int = 0
    create_time: int = 0
    exit_time: int = 0


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
    base: int
    size: int
    entry: int


@dataclass
class UserModuleRecord:
    """A loaded user-mode module discovered via PEB.Ldr."""

    name: str
    base: int
    size: int
    full_path: str
    entry: int
    architecture: str = "x64"


@dataclass
class ThreadRecord:
    """One thread reached through ``EPROCESS.ThreadListHead``."""

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


