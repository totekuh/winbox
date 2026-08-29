"""Bounded, one-stop process-wide scheduler triage."""

from __future__ import annotations

from typing import Any

from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import PageWalkError, WalkCache
from winbox.kdbg.store import SymbolStoreError
from winbox.kdbg.walk import (
    MAX_THREADS_PER_PROCESS,
    ThreadFilterError,
    list_modules,
    list_processes_detailed,
    list_threads,
    resolve_thread_start_addresses,
    select_threads,
    thread_walk_truncation,
)


DEFAULT_PROCESS_CAP = 128
DEFAULT_TOTAL_THREAD_CAP = 4096
DEFAULT_SAMPLE_PER_PROCESS = 8
DEFAULT_RESULT_LIMIT = 32
MAX_PROCESS_CAP = 256
MAX_TOTAL_THREAD_CAP = 8192
MAX_SAMPLE_PER_PROCESS = 32
MAX_RESULT_LIMIT = 64


class GlobalThreadTriageError(ThreadFilterError):
    """A bounded all-process scheduler triage request is malformed."""


class GlobalThreadTriageIncomplete(HmpError):
    """Strict callers refused a globally incomplete scheduler scope."""

    code = "incomplete_result"
    retryable = True

    def __init__(self, result: dict[str, Any]) -> None:
        scope = result.get("scope", {})
        if not isinstance(scope, dict):
            scope = {}
        self.details = {
            "scope_complete": bool(scope.get("complete")),
            "scope_reasons": list(scope.get("reasons", []))[:16],
            "process_cap": scope.get("process_cap"),
            "processes_examined": scope.get("processes_examined"),
            "total_thread_cap": scope.get("total_thread_cap"),
            "total_threads_examined": scope.get("total_threads_examined"),
        }
        super().__init__(
            "global thread triage is incomplete; raise explicit caps or retry after "
            "the kernel lists are stable"
        )


def _bounded(value: int, *, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise GlobalThreadTriageError(f"{name} must be an integer between {low} and {high}")
    return value


def _thread_ref(thread: Any, *, process: Any, attribution: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "pid": process.pid,
        "process_name": process.name,
        "tid": thread.tid,
        "ethread": f"0x{thread.ethread:016x}",
        "state": {"raw": thread.state, "name": thread.state_name},
        "wait_reason": {"raw": thread.wait_reason, "name": thread.wait_reason_name},
        "context_switches": thread.context_switches,
        "create_time": thread.create_time,
    }
    if attribution is not None:
        result["start_attribution"] = {
            "start_address": _address(attribution.start_address),
            "win32_start_address": _address(attribution.win32_start_address),
        }
    return result


def _address(value: Any) -> dict[str, Any]:
    result = {
        "address": f"0x{value.address:016x}",
        "mapping": value.mapping,
        "module": value.module,
        "rva": f"0x{value.rva:x}" if value.rva is not None else None,
        "architecture": value.architecture,
        "symbol": value.symbol,
        "symbol_offset": (
            f"0x{value.symbol_offset:x}" if value.symbol_offset is not None else None
        ),
    }
    if getattr(value, "vad", None) is not None:
        result["vad"] = value.vad
    return result


def _suspicious_starts(
    process: Any,
    threads: tuple[Any, ...],
    attributions: dict[int, Any],
    *,
    kernel_trusted: bool,
    user_trusted: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for thread in threads:
        attribution = attributions.get(thread.ethread)
        if attribution is None:
            continue
        for field, value in (
            ("start_address", attribution.start_address),
            ("win32_start_address", attribution.win32_start_address),
        ):
            if value.mapping == "kernel_unmapped" and kernel_trusted:
                rows.append({
                    "pid": process.pid, "process_name": process.name,
                    "tid": thread.tid, "ethread": f"0x{thread.ethread:016x}",
                    "field": field, "address": f"0x{value.address:016x}",
                    "mapping": value.mapping,
                })
            elif value.mapping == "user_not_in_loader_module" and user_trusted:
                rows.append({
                    "pid": process.pid, "process_name": process.name,
                    "tid": thread.tid, "ethread": f"0x{thread.ethread:016x}",
                    "field": field, "address": f"0x{value.address:016x}",
                    "mapping": value.mapping,
                })
    return rows


def triage_all_process_threads(
    vm_name: str,
    store: Any,
    *,
    cache: WalkCache | None = None,
    process_cap: int = DEFAULT_PROCESS_CAP,
    total_thread_cap: int = DEFAULT_TOTAL_THREAD_CAP,
    sample_per_process: int = DEFAULT_SAMPLE_PER_PROCESS,
    result_limit: int = DEFAULT_RESULT_LIMIT,
    resolve: bool = True,
) -> dict[str, Any]:
    """Return bounded process rankings and explicitly scoped suspicious starts.

    The caller owns the RSP snapshot.  This function does not attach, poll,
    or claim that the selected process subset is global when a cap fires.
    """
    process_cap = _bounded(process_cap, name="process_cap", low=1, high=MAX_PROCESS_CAP)
    total_thread_cap = _bounded(
        total_thread_cap, name="total_thread_cap", low=1, high=MAX_TOTAL_THREAD_CAP,
    )
    sample_per_process = _bounded(
        sample_per_process, name="sample_per_process", low=1, high=MAX_SAMPLE_PER_PROCESS,
    )
    result_limit = _bounded(result_limit, name="result_limit", low=1, high=MAX_RESULT_LIMIT)
    if not isinstance(resolve, bool):
        raise GlobalThreadTriageError("resolve must be a boolean")

    cache = cache or WalkCache()
    process_walk = list_processes_detailed(vm_name, store, cache=cache)
    selected_processes = process_walk.processes[:process_cap]
    selection_truncated = len(process_walk.processes) > process_cap
    try:
        kernel_modules = list_modules(vm_name, store, cache=cache) if resolve else []
        kernel_error = None
    except (HmpError, PageWalkError, SymbolStoreError) as exc:
        kernel_modules = []
        kernel_error = str(exc)

    rows: list[dict[str, Any]] = []
    newest: list[dict[str, Any]] = []
    busiest: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    attribution_warnings: list[str] = []
    partial_processes: list[dict[str, Any]] = []
    total_threads = 0
    runnable = 0
    waiting = 0
    terminated = 0
    processed = 0
    budget_exhausted = False

    for process in selected_processes:
        remaining = total_thread_cap - total_threads
        if remaining <= 0:
            budget_exhausted = True
            break
        walked = list_threads(
            vm_name, store, process, cache=cache,
            max_threads=min(remaining, MAX_THREADS_PER_PROCESS),
        )
        processed += 1
        total_threads += len(walked.threads)
        selected = select_threads(
            walked.threads, sort="context-switches", limit=sample_per_process,
        )
        attributions: dict[int, Any] = {}
        warnings: tuple[str, ...] = ()
        if resolve:
            try:
                attributions, warnings = resolve_thread_start_addresses(
                    vm_name, store, process, selected.threads, cache=cache,
                    kernel_modules=kernel_modules,
                )
            except (HmpError, PageWalkError, SymbolStoreError) as exc:
                warnings = (f"start attribution unavailable: {exc}",)
        attribution_warnings.extend(
            f"pid {process.pid}: {warning}" for warning in warnings
        )
        kernel_trusted = resolve and kernel_error is None and not any(
            warning.startswith("kernel module attribution unavailable") for warning in warnings
        )
        user_trusted = resolve and not any(
            warning.startswith("user module attribution unavailable") for warning in warnings
        )
        process_runnable = sum(thread.state in {1, 2, 3, 7} for thread in walked.threads)
        process_waiting = sum(thread.state == 5 for thread in walked.threads)
        process_terminated = sum(thread.state == 4 for thread in walked.threads)
        runnable += process_runnable
        waiting += process_waiting
        terminated += process_terminated
        process_newest = max(walked.threads, key=lambda thread: thread.create_time, default=None)
        row = {
            "pid": process.pid,
            "name": process.name,
            "eprocess": f"0x{process.eprocess:016x}",
            "thread_count": len(walked.threads),
            "runnable_count": process_runnable,
            "waiting_count": process_waiting,
            "terminated_count": process_terminated,
            "walk_complete": walked.complete,
            "truncated_reason": walked.truncated_reason,
            "truncation": thread_walk_truncation(walked),
            "newest_thread": (
                _thread_ref(process_newest, process=process) if process_newest is not None else None
            ),
        }
        rows.append(row)
        if process_newest is not None:
            newest.append(_thread_ref(process_newest, process=process))
        busiest.extend(
            _thread_ref(
                thread, process=process, attribution=attributions.get(thread.ethread),
            ) for thread in selected.threads
        )
        suspicious.extend(_suspicious_starts(
            process, selected.threads, attributions,
            kernel_trusted=kernel_trusted, user_trusted=user_trusted,
        ))
        if not walked.complete:
            partial_processes.append({
                "pid": process.pid, "name": process.name,
                "truncation": thread_walk_truncation(walked),
            })
        if total_threads >= total_thread_cap:
            budget_exhausted = processed < len(selected_processes)
            break

    scope_complete = bool(
        process_walk.complete
        and not selection_truncated
        and not budget_exhausted
        and not partial_processes
        and processed == len(selected_processes)
    )
    scope_reasons: list[str] = []
    if not process_walk.complete:
        scope_reasons.append("active process list is incomplete")
    if selection_truncated:
        scope_reasons.append(f"process_cap={process_cap} selected a prefix")
    if budget_exhausted:
        scope_reasons.append(f"total_thread_cap={total_thread_cap} exhausted")
    if partial_processes:
        scope_reasons.append("one or more selected process thread lists are incomplete")

    rows_by_threads = sorted(rows, key=lambda row: (-row["thread_count"], row["pid"]))
    rows_by_runnable = sorted(rows, key=lambda row: (-row["runnable_count"], row["pid"]))
    newest.sort(key=lambda row: (-row["create_time"], row["pid"], row["tid"]))
    busiest.sort(key=lambda row: (-row["context_switches"], row["pid"], row["tid"]))
    suspicious.sort(key=lambda row: (row["pid"], row["tid"], row["field"]))
    return {
        "schema": "winbox.kdbg-global-thread-triage/1",
        "scope": {
            "complete": scope_complete,
            "reasons": scope_reasons,
            "process_cap": process_cap,
            "processes_returned_by_kernel": len(process_walk.processes),
            "processes_examined": processed,
            "process_selection_truncated": selection_truncated,
            "process_list_complete": process_walk.complete,
            "process_list_truncation": (
                process_walk.truncation.public() if process_walk.truncation else None
            ),
            "total_thread_cap": total_thread_cap,
            "total_threads_examined": total_threads,
            "thread_budget_exhausted": budget_exhausted,
            "sample_per_process": sample_per_process,
            "start_attribution_scope": "top_context_switch_rows_only" if resolve else "disabled",
        },
        "totals": {
            "runnable_threads": runnable,
            "waiting_threads": waiting,
            "terminated_threads": terminated,
            "partial_processes": len(partial_processes),
        },
        "rankings": {
            "by_thread_count": rows_by_threads[:result_limit],
            "by_runnable_count": rows_by_runnable[:result_limit],
            "newest_threads": newest[:result_limit],
            "high_context_switch_threads": busiest[:result_limit],
            "suspicious_starts": suspicious[:result_limit],
        },
        "partial_processes": partial_processes[:result_limit],
        "attribution_warnings": attribution_warnings[:result_limit],
        "kernel_module_attribution_error": kernel_error,
    }
