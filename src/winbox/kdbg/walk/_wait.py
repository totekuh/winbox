"""Wait object resolution for Waiting threads."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from winbox.kdbg.debugger.reader import snapshot_operation
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import PageWalkError, WalkCache, read_virt_cr3
from winbox.kdbg.store import SymbolStoreError

from winbox.kdbg.walk._records import (
    ProcessRecord,
    ThreadFilterError,
    ThreadRecord,
    _KTHREAD_STATES,
)
from winbox.kdbg.walk import _layout

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore

MAX_WAIT_OBJECT_THREADS = 128
MAX_WAIT_OWNER_DEPTH = 4

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


def _wait_identity(
    vm_name: str,
    cr3: int,
    ethread: int,
    layout,
    cache: WalkCache,
) -> dict[str, int] | None:
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
    if pid == 0 or tid == 0 or not _layout._is_kernel_pointer(owner_process):
        return None
    return {"ethread": ethread, "pid": pid, "tid": tid, "state": state[0]}


def _wait_block_for_thread(
    vm_name: str,
    cr3: int,
    ethread: int,
    layout,
    cache: WalkCache,
) -> tuple[dict[str, Any] | None, str | None]:
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
    if not _layout._is_kernel_pointer(object_address):
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

    layout = _layout._wait_layout(store)
    cache = cache or WalkCache()
    head = target.eprocess + layout.thread.thread_list_head
    kernel_cr3, _, kernel_cache = _layout._read_kernel_list_head(vm_name, head, None)
    if cache is not kernel_cache:
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
            if not _layout._is_kernel_pointer(owner):
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
