from __future__ import annotations

from types import SimpleNamespace

import pytest

from winbox.kdbg.thread_triage import (
    GlobalThreadTriageError,
    triage_all_process_threads,
)
from winbox.kdbg.walk import (
    ProcessRecord,
    ProcessWalkResult,
    ThreadRecord,
    ThreadWalkResult,
    ThreadWalkTruncation,
)


def _process(pid: int, name: str) -> ProcessRecord:
    return ProcessRecord(pid, name, 0xffffe00100000000 + pid * 0x1000, 0x1AE000)


def _thread(tid: int, *, state: int, switches: int, created: int) -> ThreadRecord:
    return ThreadRecord(
        tid=tid, ethread=0xffffe00110000000 + tid * 0x1000,
        state=state, state_name={1: "Ready", 4: "Terminated", 5: "Waiting"}.get(state),
        wait_reason=6, wait_reason_name="UserRequest" if state == 5 else None,
        priority=8, base_priority=8, context_switches=switches,
        teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
        start_address=0xFFFFF80010001000, win32_start_address=0x7FF700001000,
        create_time=created, exit_status=0,
    )


def test_global_triage_ranks_bounded_complete_process_scope(monkeypatch):
    from winbox.kdbg import thread_triage

    alpha = _process(100, "alpha.exe")
    beta = _process(200, "beta.exe")
    threads = {
        alpha.pid: ThreadWalkResult([
            _thread(1, state=5, switches=10, created=20),
            _thread(2, state=1, switches=70, created=40),
        ], True),
        beta.pid: ThreadWalkResult([
            _thread(3, state=1, switches=30, created=60),
        ], True),
    }
    monkeypatch.setattr(
        thread_triage, "list_processes_detailed",
        lambda *_args, **_kwargs: ProcessWalkResult([alpha, beta], True),
    )
    monkeypatch.setattr(thread_triage, "list_modules", lambda *_args, **_kwargs: [])
    calls = []

    def listed(_vm, _store, process, **kwargs):
        calls.append((process.pid, kwargs["max_threads"]))
        return threads[process.pid]

    monkeypatch.setattr(thread_triage, "list_threads", listed)

    result = triage_all_process_threads(
        "vm", object(), process_cap=2, total_thread_cap=8,
        sample_per_process=2, result_limit=4, resolve=False,
    )

    assert result["scope"]["complete"] is True
    assert result["scope"]["total_threads_examined"] == 3
    assert result["totals"] == {
        "runnable_threads": 2, "waiting_threads": 1,
        "terminated_threads": 0, "partial_processes": 0,
    }
    assert [row["pid"] for row in result["rankings"]["by_thread_count"]] == [100, 200]
    assert [row["tid"] for row in result["rankings"]["newest_threads"]] == [3, 2]
    assert result["rankings"]["high_context_switch_threads"][0]["tid"] == 2
    assert calls == [(100, 8), (200, 6)]


def test_global_triage_exposes_process_and_thread_cap_boundaries(monkeypatch):
    from winbox.kdbg import thread_triage

    alpha = _process(100, "alpha.exe")
    beta = _process(200, "beta.exe")
    gamma = _process(300, "gamma.exe")
    partial = ThreadWalkResult(
        [_thread(1, state=5, switches=10, created=20)], False,
        "hit thread cap=1",
        ThreadWalkTruncation("cap", "hit thread cap=1", 1, link=0xffffe00112340000),
    )
    monkeypatch.setattr(
        thread_triage, "list_processes_detailed",
        lambda *_args, **_kwargs: ProcessWalkResult([alpha, beta, gamma], True),
    )
    monkeypatch.setattr(thread_triage, "list_modules", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(thread_triage, "list_threads", lambda *_args, **_kwargs: partial)

    result = triage_all_process_threads(
        "vm", object(), process_cap=2, total_thread_cap=1,
        sample_per_process=1, result_limit=2, resolve=False,
    )

    assert result["scope"]["complete"] is False
    assert result["scope"]["process_selection_truncated"] is True
    assert result["scope"]["thread_budget_exhausted"] is True
    assert result["scope"]["processes_examined"] == 1
    assert result["partial_processes"] == [{
        "pid": 100, "name": "alpha.exe",
        "truncation": partial.truncation.public(),
    }]


def test_global_triage_handles_an_empty_complete_process_scope(monkeypatch):
    from winbox.kdbg import thread_triage

    monkeypatch.setattr(
        thread_triage, "list_processes_detailed",
        lambda *_args, **_kwargs: ProcessWalkResult([], True),
    )

    result = triage_all_process_threads("vm", object(), resolve=False)

    assert result["scope"]["complete"] is True
    assert result["scope"]["processes_examined"] == 0
    assert result["totals"]["partial_processes"] == 0
    assert all(not rows for rows in result["rankings"].values())


def test_global_triage_only_flags_unmapped_starts_with_trusted_attribution(monkeypatch):
    from winbox.kdbg import thread_triage

    process = _process(100, "alpha.exe")
    thread = _thread(1, state=1, switches=10, created=20)
    monkeypatch.setattr(
        thread_triage, "list_processes_detailed",
        lambda *_args, **_kwargs: ProcessWalkResult([process], True),
    )
    monkeypatch.setattr(thread_triage, "list_modules", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        thread_triage, "list_threads", lambda *_args, **_kwargs: ThreadWalkResult([thread], True),
    )
    value = SimpleNamespace(
        address=0x7FF700001000, mapping="user_not_in_loader_module",
        module=None, rva=None, architecture=None, symbol=None, symbol_offset=None,
    )
    attribution = SimpleNamespace(start_address=value, win32_start_address=value)
    monkeypatch.setattr(
        thread_triage, "resolve_thread_start_addresses",
        lambda *_args, **_kwargs: ({thread.ethread: attribution}, ()),
    )

    result = triage_all_process_threads("vm", object(), resolve=True)

    assert len(result["rankings"]["suspicious_starts"]) == 2
    assert {row["field"] for row in result["rankings"]["suspicious_starts"]} == {
        "start_address", "win32_start_address",
    }


@pytest.mark.parametrize("kwargs", [
    {"process_cap": 0}, {"total_thread_cap": 8193},
    {"sample_per_process": True}, {"result_limit": 65}, {"resolve": "yes"},
])
def test_global_triage_rejects_invalid_bounds(kwargs):
    with pytest.raises(GlobalThreadTriageError):
        triage_all_process_threads("vm", object(), **kwargs)
