"""Thread list walking via EPROCESS.ThreadListHead."""

from __future__ import annotations

from typing import TYPE_CHECKING

from winbox.kdbg.debugger.reader import snapshot_operation
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import PageWalkError, WalkCache, read_virt_cr3
from winbox.kdbg.store import SymbolStoreError

from winbox.kdbg.walk._records import (
    MAX_THREADS_PER_PROCESS,
    ProcessRecord,
    ThreadFilterError,
    ThreadRecord,
    ThreadWalkResult,
    ThreadWalkTruncation,
    _KTHREAD_STATES,
    _KWAIT_REASONS,
)
from winbox.kdbg.walk import _layout

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore


def _read_thread_entry(
    vm_name: str,
    cr3: int,
    ethread: int,
    target: ProcessRecord,
    layout,
    cache: WalkCache,
    previous_link: int,
) -> tuple[ThreadRecord, int]:
    chunks = []
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
    if next_flink != target.eprocess + layout.thread_list_head and not _layout._is_kernel_pointer(next_flink):
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
    layout = _layout._thread_layout(store)
    process_head = store.resolve("PsActiveProcessHead")
    kernel_cr3, _, selected_cache = _layout._read_kernel_list_head(
        vm_name, process_head, None,
    )
    cache = cache or selected_cache
    head = target.eprocess + layout.thread_list_head
    try:
        flink = _layout._read_u64(vm_name, kernel_cr3, head, cache)
    except (HmpError, PageWalkError) as exc:
        reason = f"could not read ThreadListHead: {exc}"
        return _partial_thread_walk([], "head", reason, link=head)

    try:
        head_blink = _layout._read_u64(vm_name, kernel_cr3, head + 8, cache)
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
        if not _layout._is_kernel_pointer(flink):
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
        if not _layout._is_kernel_pointer(ethread):
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
