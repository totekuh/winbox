"""kdbg triage and global thread-triage tools."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp._common import _get_state, _research_ok, _research_error
from winbox.mcp._kdbg_infra import _kdbg_get_store
from winbox.mcp._kdbg_threads import (
    _kdbg_thread_record,
    _kdbg_current_vcpu_record,
)

from winbox.vm import VMState
from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStoreError as _KdbgStoreError,
    WalkCache as _KdbgWalkCache,
    ensure_types_loaded as _kdbg_ensure_types_loaded,
)
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.kdbg.presentation import filetime_utc as _kdbg_filetime_utc
from winbox.kdbg.thread_triage import (
    GlobalThreadTriageError as _KdbgGlobalThreadTriageError,
    GlobalThreadTriageIncomplete as _KdbgGlobalThreadTriageIncomplete,
    triage_all_process_threads as _kdbg_triage_all_process_threads,
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
    list_modules as _kdbg_list_modules,
    list_threads as _kdbg_list_threads,
    list_user_modules as _kdbg_list_user_modules,
    resolve_thread_start_addresses as _kdbg_resolve_thread_start_addresses,
    select_threads as _kdbg_select_threads,
    thread_walk_truncation as _kdbg_thread_walk_truncation,
)


def _kdbg_triage_module(module: Any) -> dict[str, Any]:
    return {
        "base": f"0x{module.base:016x}",
        "size": f"0x{module.size:x}",
        "name": module.name,
        "full_path": getattr(module, "full_path", None),
        "architecture": getattr(module, "architecture", "kernel"),
    }


def _kdbg_triage_unmapped_rows(threads: Any, attributions: dict[int, Any]) -> list[dict[str, Any]]:
    """Conservative module/loader mismatches: leads, not a verdict."""
    rows: list[dict[str, Any]] = []
    for thread in threads:
        attribution = attributions.get(thread.ethread)
        if attribution is None:
            continue
        for field, value in (
            ("start_address", attribution.start_address),
            ("win32_start_address", attribution.win32_start_address),
        ):
            if value.mapping not in {"kernel_unmapped", "user_not_in_loader_module"}:
                continue
            rows.append({
                "tid": thread.tid,
                "ethread": f"0x{thread.ethread:016x}",
                "field": field,
                "address": f"0x{value.address:016x}",
                "mapping": value.mapping,
            })
    return rows


@mcp.tool()
def kdbg_triage(
    pid: int, thread_limit: int = 16, require_complete: bool = False,
) -> dict[str, Any]:
    """Capture one bounded, coherent process-research snapshot.

    One RSP stop collects process identity, the complete ETHREAD walk and its
    scheduler summary, the busiest bounded thread rows, current-vCPU ETHREAD
    identities, and a capped PEB module view.  Start mappings are resolved
    only for those top rows; ``unmapped_starts_scope`` makes that boundary
    explicit.  ``user_not_in_loader_module`` is a lead (JIT/private/VAD work
    may explain it), not a malware classification.

    Args:
        pid: Target process ID.
        thread_limit: Top context-switch rows to resolve and return (1..64).
        require_complete: Refuse an incomplete kernel-list prefix instead of returning it.
    """
    if not 1 <= thread_limit <= 64:
        return _research_error(
            "thread_limit must be between 1 and 64", operation="kdbg_triage",
        )
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_triage",
        )
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgHmpError("require_complete must be a boolean")
        try:
            _kdbg_ensure_vad_layouts(cfg, _kdbg_get_store())
        except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError):
            pass
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(f"pid {pid} not found", operation="kdbg_triage")
            walked = _kdbg_list_threads(cfg.vm_name, store, target, cache=cache)
            if require_complete and not walked.complete:
                raise _KdbgThreadWalkIncomplete(walked)
            selected = _kdbg_select_threads(
                walked.threads, sort="context-switches", limit=thread_limit,
            )
            kernel_modules = _kdbg_list_modules(cfg.vm_name, store, cache=cache)
            module_error: str | None = None
            try:
                _kdbg_ensure_types_loaded(
                    cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt",
                )
                user_modules = _kdbg_list_user_modules(
                    cfg.vm_name, store, target, cache=cache,
                )
            except (_KdbgStoreError, _KdbgSymbolLoadError, _KdbgHmpError) as exc:
                user_modules = []
                module_error = str(exc)
            attributions, attribution_warnings = _kdbg_resolve_thread_start_addresses(
                cfg.vm_name, store, target, selected.threads, cache=cache,
                kernel_modules=kernel_modules, user_modules=user_modules,
            )
            current_vcpus: list[Any] = []
            current_vcpus_error: str | None = None
            try:
                current_vcpus = _kdbg_list_current_vcpu_threads(
                    cfg.vm_name, store, target, threads=walked.threads, cache=cache,
                )
            except (_KdbgStoreError, _KdbgHmpError) as exc:
                current_vcpus_error = str(exc)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
    except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_triage")

    running_by_ethread: dict[int, list[int]] = {}
    for current in current_vcpus:
        if current.status == "current" and current.in_target_process and current.ethread is not None:
            running_by_ethread.setdefault(current.ethread, []).append(current.vcpu)
    module_limit = 64
    result: dict[str, Any] = {
        "snapshot": "single_rsp_stop",
        "process": {
            "pid": target.pid, "name": target.name,
            "eprocess": f"0x{target.eprocess:016x}",
            "dtb": f"0x{target.directory_table_base:012x}",
            "create_time": target.create_time,
            "create_time_filetime": target.create_time,
            "create_time_utc": _kdbg_filetime_utc(target.create_time),
        },
        "thread_summary": {
            "total_count": selected.total_count,
            "walk_complete": walked.complete,
            "truncated_reason": walked.truncated_reason,
            "truncation": _kdbg_thread_walk_truncation(walked),
            "states": selected.state_counts,
            "wait_reasons": selected.wait_reason_counts,
            "top_rows_returned": len(selected.threads),
            "top_rows_truncated": selected.output_truncated,
            "sort": "context-switches",
        },
        "threads": [
            _kdbg_thread_record(
                thread, attribution=attributions.get(thread.ethread),
                running_on_vcpus=running_by_ethread.get(thread.ethread, ()),
            ) for thread in selected.threads
        ],
        "current_vcpus": [_kdbg_current_vcpu_record(current) for current in current_vcpus],
        "user_modules": {
            "count": len(user_modules),
            "returned": min(len(user_modules), module_limit),
            "output_truncated": len(user_modules) > module_limit,
            "modules": [_kdbg_triage_module(module) for module in user_modules[:module_limit]],
        },
        "unmapped_starts": _kdbg_triage_unmapped_rows(selected.threads, attributions),
        "unmapped_starts_scope": "top_rows_only",
        "snapshot_metadata": snapshot_metadata,
    }
    if module_error:
        result["user_modules"]["error"] = module_error
    if attribution_warnings:
        result["attribution_warnings"] = list(attribution_warnings)
    if current_vcpus_error:
        result["current_vcpus_error"] = current_vcpus_error
    return _research_ok(result)


@mcp.tool()
def kdbg_thread_triage(
    process_cap: int = 128,
    total_thread_cap: int = 4096,
    sample_per_process: int = 8,
    result_limit: int = 32,
    resolve: bool = True,
    require_complete: bool = False,
) -> dict[str, Any]:
    """Rank bounded process-wide scheduler evidence from one coherent RSP stop.

    Returns compact rankings by thread/runnable counts, newest threads, high
    context-switch samples, and module/loader-unmapped starts. Start mapping
    only examines the top context-switch rows per process. Every process,
    thread-budget, malformed-list, and attribution boundary is explicit in
    ``scope``; this never presents a capped subset as the entire kernel.

    Args:
        process_cap: Active-process records to examine (1..256).
        total_thread_cap: ETHREAD records examined across that process scope (1..8192).
        sample_per_process: Top context-switch rows sampled per process (1..32).
        result_limit: Rows returned in each ranking (1..64).
        resolve: Resolve only bounded start samples against live module loaders.
        require_complete: Reject a cap- or corruption-limited scope with typed
            ``incomplete_result`` rather than returning its validated prefix.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_thread_triage",
        )
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgGlobalThreadTriageError("require_complete must be a boolean")
        if resolve:
            try:
                _kdbg_ensure_vad_layouts(cfg, _kdbg_get_store())
            except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError):
                pass
        with _kdbg_debug_snapshot(cfg) as snapshot:
            result = _kdbg_triage_all_process_threads(
                cfg.vm_name, _kdbg_get_store(), cache=_KdbgWalkCache(),
                process_cap=process_cap, total_thread_cap=total_thread_cap,
                sample_per_process=sample_per_process, result_limit=result_limit,
                resolve=resolve,
            )
            if require_complete and not result["scope"]["complete"]:
                raise _KdbgGlobalThreadTriageIncomplete(result)
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
    except (
        _KdbgGlobalThreadTriageError, _KdbgGlobalThreadTriageIncomplete,
        _KdbgVadError, _KdbgStoreError, _KdbgHmpError,
    ) as exc:
        return _research_error(exc, operation="kdbg_thread_triage")
    return _research_ok(result)
