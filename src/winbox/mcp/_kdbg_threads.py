"""kdbg thread listing, baseline, and diff tools."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import _get_state, _research_ok, _research_error
from winbox.mcp._kdbg_infra import _kdbg_get_store

from winbox.vm import VMState
from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStoreError as _KdbgStoreError,
    WalkCache as _KdbgWalkCache,
    ensure_types_loaded as _kdbg_ensure_types_loaded,
)
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.kdbg.presentation import (
    filetime_utc as _kdbg_filetime_utc,
    thread_presentation_fields as _kdbg_thread_presentation_fields,
)
from winbox.kdbg.thread_baseline import (
    ThreadBaselineError as _KdbgThreadBaselineError,
    ThreadBaselineStore as _KdbgThreadBaselineStore,
    capture_threads as _kdbg_capture_thread_baseline,
)
from winbox.kdbg.vad import (
    VadError as _KdbgVadError,
    ensure_vad_layouts as _kdbg_ensure_vad_layouts,
)
from winbox.kdbg.debugger.reader import (
    debug_snapshot as _kdbg_debug_snapshot,
    snapshot_metadata as _kdbg_snapshot_metadata,
)
from winbox.kdbg.walk import (
    ThreadWalkIncomplete as _KdbgThreadWalkIncomplete,
    find_process as _kdbg_find_process,
    list_current_vcpu_threads as _kdbg_list_current_vcpu_threads,
    list_threads as _kdbg_list_threads,
    resolve_thread_start_addresses as _kdbg_resolve_thread_start_addresses,
    resolve_thread_wait_objects as _kdbg_resolve_thread_wait_objects,
    select_threads as _kdbg_select_threads,
    thread_walk_truncation as _kdbg_thread_walk_truncation,
)


def _kdbg_thread_address(attribution: Any) -> dict[str, Any]:
    result = {
        "address": f"0x{attribution.address:016x}",
        "mapping": attribution.mapping,
        "module": attribution.module,
        "module_base": (
            f"0x{attribution.module_base:016x}"
            if attribution.module_base is not None else None
        ),
        "module_size": (
            f"0x{attribution.module_size:x}"
            if attribution.module_size is not None else None
        ),
        "rva": f"0x{attribution.rva:x}" if attribution.rva is not None else None,
        "architecture": attribution.architecture,
        "symbol": attribution.symbol,
        "symbol_offset": (
            f"0x{attribution.symbol_offset:x}"
            if attribution.symbol_offset is not None else None
        ),
    }
    if getattr(attribution, "vad", None) is not None:
        result["vad"] = attribution.vad
    return result


def _kdbg_current_vcpu_record(record: Any) -> dict[str, Any]:
    return {
        "vcpu": record.vcpu,
        "status": record.status,
        "ethread": f"0x{record.ethread:016x}" if record.ethread is not None else None,
        "eprocess": f"0x{record.eprocess:016x}" if record.eprocess is not None else None,
        "pid": record.pid,
        "process_name": record.process_name,
        "tid": record.tid,
        "in_target_process": record.in_target_process,
        "reason": record.reason,
    }


def _kdbg_thread_record(
    thread: Any, *, attribution: Any = None, running_on_vcpus: tuple[int, ...] | list[int] = (),
    wait_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize ThreadRecord with both stable raw and best-effort enum names."""
    result = {
        "tid": thread.tid,
        "ethread": f"0x{thread.ethread:016x}",
        "state": {"raw": thread.state, "name": thread.state_name},
        "wait_reason": {
            "raw": thread.wait_reason,
            "name": thread.wait_reason_name,
        },
        "priority": thread.priority,
        "base_priority": thread.base_priority,
        "context_switches": thread.context_switches,
        "teb": f"0x{thread.teb:016x}",
        "kernel_stack": f"0x{thread.kernel_stack:016x}",
        "stack_limit": f"0x{thread.stack_limit:016x}",
        "stack_base": f"0x{thread.stack_base:016x}",
        "start_address": f"0x{thread.start_address:016x}",
        "win32_start_address": f"0x{thread.win32_start_address:016x}",
        "create_time": thread.create_time,
        "exit_status": thread.exit_status,
    }
    result.update(_kdbg_thread_presentation_fields(thread))
    if attribution is not None:
        result["start_attribution"] = {
            "start_address": _kdbg_thread_address(attribution.start_address),
            "win32_start_address": _kdbg_thread_address(
                attribution.win32_start_address,
            ),
        }
    if running_on_vcpus:
        result["running_on_vcpus"] = list(running_on_vcpus)
    if wait_evidence is not None:
        result["wait_object"] = wait_evidence
    return result


@mcp.tool()
def kdbg_threads(
    pid: int,
    detail: str = "full",
    state: str = "",
    wait_reason: str = "",
    sort: str = "tid",
    limit: int = 256,
    resolve: bool = False,
    include_current: bool = True,
    wait_objects: bool = False,
    wait_object_limit: int = 32,
    wait_owner_depth: int = 2,
    require_complete: bool = False,
) -> dict[str, Any]:
    """Walk one process's kernel thread list without injecting into the guest.

    Returns bounded scheduler metadata, ETHREAD identity, thread start
    addresses, TEB, and stack bounds from ``EPROCESS.ThreadListHead``.
    ``kernel_stack`` is the raw KTHREAD field, not an asserted saved RSP;
    use ``kdbg_context`` only for the currently stopped debugger thread.

    Each ``state`` and ``wait_reason`` reports an invariant raw byte plus a
    best-effort current-Windows enum name; wait-reason names are intentionally
    omitted unless the scheduler state is ``Waiting``. A malformed list/read
    or the hard safety cap returns the validated prefix with ``complete=false``
    and a truthful ``truncated_reason`` plus structured ``truncation`` evidence.
    Set ``require_complete=true`` to reject that prefix with typed
    ``incomplete_result`` instead. ``limit`` only bounds returned detail
    rows: ``walk_complete`` remains independent, and summary metadata reports
    all walked/matching/filtered rows. ``resolve`` maps returned start VAs to
    live modules and already-local symbols without downloading anything.

    Args:
        pid: Target process ID (find it with ``kdbg_ps`` first).
        detail: ``full`` returns bounded rows; ``summary`` returns counts only.
        state: Optional raw scheduler-state byte or enum name (e.g. Waiting).
        wait_reason: Optional raw wait byte or enum name; matches Waiting only.
        sort: ``tid``, ``state``, ``wait``, ``priority``, ``context-switches``,
            ``start``, ``win32-start``, or ``create-time``.
        limit: Maximum returned detailed rows (1..1024; default 256).
        resolve: Attribute returned start addresses against live module lists.
        include_current: Return validated current ETHREAD identity per halted vCPU.
        wait_objects: Add bounded exact-PDB wait-object and mutant-owner evidence.
        wait_object_limit: Maximum Waiting detail rows inspected (1..128).
        wait_owner_depth: Maximum proven mutant-owner hops per row (1..4).
        require_complete: Refuse an incomplete kernel-list prefix instead of returning it.
    """
    cfg, vm, _ = _get_state()
    vm_state = vm.state()
    if vm_state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {vm_state.value})", operation="kdbg_threads"
        )
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgHmpError("require_complete must be a boolean")
        if not isinstance(wait_objects, bool):
            raise _KdbgHmpError("wait_objects must be a boolean")
        if detail not in {"full", "summary"}:
            raise _KdbgHmpError("detail must be 'full' or 'summary'")
        if wait_objects and detail != "full":
            raise _KdbgHmpError("wait_objects requires detail='full'")
        if (not isinstance(wait_object_limit, int) or isinstance(wait_object_limit, bool)
                or not 1 <= wait_object_limit <= 128):
            raise _KdbgHmpError("wait_object_limit must be an integer between 1 and 128")
        if (not isinstance(wait_owner_depth, int) or isinstance(wait_owner_depth, bool)
                or not 1 <= wait_owner_depth <= 4):
            raise _KdbgHmpError("wait_owner_depth must be an integer between 1 and 4")
        if wait_objects:
            _kdbg_ensure_types_loaded(
                cfg, _kdbg_get_store(),
                ["_KWAIT_BLOCK", "_DISPATCHER_HEADER", "_KMUTANT"], module="nt",
            )
        if resolve:
            try:
                _kdbg_ensure_vad_layouts(cfg, _kdbg_get_store())
            except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError):
                pass
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(f"pid {pid} not found", operation="kdbg_threads")
            walked = _kdbg_list_threads(
                cfg.vm_name, store, target, cache=cache,
            )
            if require_complete and not walked.complete:
                raise _KdbgThreadWalkIncomplete(walked)
            selected = _kdbg_select_threads(
                walked.threads, state=state or None, wait_reason=wait_reason or None,
                sort=sort, limit=limit,
            )
            displayed = selected.threads if detail == "full" else ()
            attributions: dict[int, Any] = {}
            attribution_warnings: tuple[str, ...] = ()
            if resolve:
                attributions, attribution_warnings = _kdbg_resolve_thread_start_addresses(
                    cfg.vm_name, store, target, displayed, cache=cache,
                )
            wait_view: dict[str, Any] = {"enabled": False}
            wait_records: dict[int, dict[str, Any]] = {}
            if wait_objects:
                wait_result = _kdbg_resolve_thread_wait_objects(
                    cfg.vm_name, store, target, displayed, cache=cache,
                    limit=wait_object_limit, owner_depth=wait_owner_depth,
                )
                wait_view = {"enabled": True, **wait_result["scope"]}
                wait_records = wait_result["records"]
            current_vcpus: list[Any] = []
            current_vcpus_error: str | None = None
            if include_current:
                try:
                    current_vcpus = _kdbg_list_current_vcpu_threads(
                        cfg.vm_name, store, target, threads=walked.threads, cache=cache,
                    )
                except (_KdbgStoreError, _KdbgHmpError) as exc:
                    current_vcpus_error = str(exc)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
    except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_threads")
    running_by_ethread: dict[int, list[int]] = {}
    for current in current_vcpus:
        if current.status == "current" and current.in_target_process and current.ethread is not None:
            running_by_ethread.setdefault(current.ethread, []).append(current.vcpu)
    response = {
        "pid": target.pid,
        "name": target.name,
        "eprocess": f"0x{target.eprocess:016x}",
        "process_create_time": target.create_time,
        "process_create_time_filetime": target.create_time,
        "process_create_time_utc": _kdbg_filetime_utc(target.create_time),
        "threads": [
            _kdbg_thread_record(
                thread,
                attribution=attributions.get(thread.ethread),
                running_on_vcpus=running_by_ethread.get(thread.ethread, ()),
                wait_evidence=wait_records.get(thread.ethread),
            )
            for thread in displayed
        ],
        "count": len(displayed),
        "total_count": selected.total_count,
        "matched_count": selected.matched_count,
        "filtered_out": selected.filtered_out,
        "returned": len(displayed),
        "output_truncated": selected.output_truncated,
        "detail_rows_omitted": detail == "summary" and selected.matched_count > 0,
        "detail": detail,
        "summary": {
            "states": selected.state_counts,
            "wait_reasons": selected.wait_reason_counts,
        },
        "complete": walked.complete,
        "walk_complete": walked.complete,
        "truncated_reason": walked.truncated_reason,
        "truncation": _kdbg_thread_walk_truncation(walked),
        "current_vcpus": [_kdbg_current_vcpu_record(current) for current in current_vcpus],
        "wait_objects": wait_view,
        "snapshot_metadata": snapshot_metadata,
    }
    if attribution_warnings:
        response["attribution_warnings"] = list(attribution_warnings)
    if current_vcpus_error is not None:
        response["current_vcpus_error"] = current_vcpus_error
    return _research_ok(response)


@mcp.tool()
def kdbg_thread_baseline(pid: int, name: str = "default") -> dict[str, Any]:
    """Save one explicit complete host-side ETHREAD baseline for ``pid``.

    This performs one CET-gated RSP snapshot and writes a bounded baseline only
    when the complete kernel list validates.  The identity binds VM, active nt
    symbol-store revision, boot/System process, target PID/EPROCESS/CreateTime,
    and each ETHREAD/CreateTime; a later diff cannot accidentally compare a
    reboot, PID reuse, or changed symbol store.

    Args:
        pid: Target process ID.
        name: Baseline label (default ``default``; letters/digits/dot/dash/underscore).
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_thread_baseline",
        )
    baseline = _KdbgThreadBaselineStore(cfg)
    try:
        baseline.validate_name(name)
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            capture = _kdbg_capture_thread_baseline(cfg, store, pid)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
        result = baseline.save(name, capture)
        result["snapshot_metadata"] = snapshot_metadata
        return _research_ok(result)
    except (_KdbgThreadBaselineError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_thread_baseline")


@mcp.tool()
def kdbg_thread_diff(
    pid: int, name: str = "default", limit: int = 128,
) -> dict[str, Any]:
    """Compare one explicit current ETHREAD snapshot to a named baseline.

    Returns bounded created, exited, and changed categories.  A changed thread
    reports raw scheduler transitions and a 32-bit ContextSwitches delta with
    explicit counter-wrap status.  It does not poll: every call is one fresh,
    CET-gated snapshot.  Missing/incompatible baselines produce typed errors
    rather than a potentially cross-boot comparison.

    Args:
        pid: Target process ID, which must still match the saved EPROCESS/CreateTime.
        name: Existing baseline label (default ``default``).
        limit: Maximum returned rows per created/exited/changed category (1..1024).
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1024:
        return _research_error(
            "limit must be an integer between 1 and 1024", operation="kdbg_thread_diff",
        )
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_thread_diff",
        )
    baseline = _KdbgThreadBaselineStore(cfg)
    try:
        baseline.load(name)
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            capture = _kdbg_capture_thread_baseline(cfg, store, pid)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
        result = baseline.diff(name, capture, limit=limit)
        result["snapshot_metadata"] = snapshot_metadata
        return _research_ok(result)
    except (_KdbgThreadBaselineError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_thread_diff")
