"""Pure contract tests for explicit host-side ETHREAD baseline/diff state."""

from __future__ import annotations

from dataclasses import replace

import pytest

from winbox.config import Config
from winbox.kdbg.presentation import (
    KERNEL_STACK_SEMANTICS,
    filetime_utc,
    ntstatus_hex,
    ntstatus_name,
    thread_presentation_fields,
)
from winbox.kdbg.thread_baseline import (
    BaselineExpiredError,
    BaselineIncompleteError,
    BaselineNotFoundError,
    ThreadBaselineError,
    ThreadBaselineStore,
    ThreadCapture,
    capture_threads,
)
from winbox.kdbg.walk import ProcessRecord, ThreadRecord, ThreadWalkResult


FILETIME = 132537600000000000  # 2020-12-30T00:00:00Z


def _thread(
    tid: int,
    ethread: int,
    *,
    create_time: int = FILETIME,
    state: int = 5,
    state_name: str | None = "Waiting",
    wait_reason: int = 6,
    wait_reason_name: str | None = "UserRequest",
    priority: int = 8,
    base_priority: int = 8,
    context_switches: int = 10,
    exit_status: int = 259,
) -> ThreadRecord:
    return ThreadRecord(
        tid=tid, ethread=ethread, state=state, state_name=state_name,
        wait_reason=wait_reason, wait_reason_name=wait_reason_name,
        priority=priority, base_priority=base_priority,
        context_switches=context_switches, teb=0, kernel_stack=0,
        stack_limit=0, stack_base=0, start_address=0, win32_start_address=0,
        create_time=create_time, exit_status=exit_status,
    )


def _target(*, pid: int = 4242, eprocess: int = 0xFFFFE001_00100000,
            create_time: int = FILETIME) -> ProcessRecord:
    return ProcessRecord(
        pid=pid, name="target.exe", eprocess=eprocess,
        directory_table_base=0x12345000, create_time=create_time,
    )


def _capture(
    threads: tuple[ThreadRecord, ...] | list[ThreadRecord],
    *,
    target: ProcessRecord | None = None,
    boot: dict | None = None,
    symbols: dict | None = None,
) -> ThreadCapture:
    target = target or _target()
    return ThreadCapture(
        vm_name="winbox",
        target=target,
        boot_identity=boot or {
            "system": {
                "pid": 4, "name": "System", "eprocess": "0xffffe00100000000",
                "create_time": FILETIME - 1, "create_time_utc": filetime_utc(FILETIME - 1),
            },
            "nt_base": "0xfffff80000000000",
        },
        symbol_identity=symbols or {
            "build": "build-a", "path": "nt_build-a.json", "symbol_count": 10,
            "type_count": 4, "mtime_ns": 123,
        },
        threads=tuple(threads),
        captured_at="2026-08-27T00:00:00.000000Z",
    )


def _store(tmp_path) -> ThreadBaselineStore:
    return ThreadBaselineStore(Config(winbox_dir=tmp_path / ".winbox"))


def test_normalized_thread_fields_keep_raw_values_and_mark_unavailable_pointers():
    thread = _thread(1, 0xFFFFE001_00001000)
    fields = thread_presentation_fields(thread)

    assert filetime_utc(FILETIME) == "2020-12-30T00:00:00.000000Z"
    assert filetime_utc(0) is None
    assert filetime_utc(-1) is None
    assert fields["create_time_filetime"] == FILETIME
    assert fields["create_time_utc"] == "2020-12-30T00:00:00.000000Z"
    assert fields["exit_status_ntstatus"] == "0x00000103"
    assert fields["exit_status_name"] == "STATUS_PENDING"
    assert fields["pointer_values"] == {
        "teb": None, "kernel_stack": None, "stack_limit": None,
        "stack_base": None, "start_address": None, "win32_start_address": None,
    }
    assert fields["kernel_stack_semantics"] == KERNEL_STACK_SEMANTICS
    assert ntstatus_hex(-1073741819) == "0xc0000005"
    assert ntstatus_name(-1073741819) == "STATUS_ACCESS_VIOLATION"
    assert ntstatus_name(0x12345678) is None


def test_baseline_diff_reports_created_exited_transitions_and_wrapped_counter(tmp_path):
    store = _store(tmp_path)
    stable_old = _thread(1, 0xFFFFE001_00001000, context_switches=0xFFFFFFFE)
    exited = _thread(2, 0xFFFFE001_00002000, create_time=FILETIME + 10)
    saved = store.save("case-1", _capture([stable_old, exited]))
    assert saved["thread_count"] == 2

    stable_new = replace(
        stable_old, state=1, state_name="Ready", wait_reason=0,
        wait_reason_name=None, priority=13, context_switches=3,
        exit_status=0,
    )
    created = _thread(3, 0xFFFFE001_00003000, create_time=FILETIME + 20)
    result = store.diff("case-1", _capture([stable_new, created]), limit=1)

    assert (result["created_count"], result["exited_count"], result["changed_count"]) == (1, 1, 1)
    assert result["created"][0]["tid"] == 3
    assert result["exited"][0]["tid"] == 2
    changes = result["changed"][0]["changes"]
    assert changes["state"] == {
        "before": {"raw": 5, "name": "Waiting"},
        "after": {"raw": 1, "name": "Ready"},
    }
    assert changes["priority"] == {"before": 8, "after": 13}
    assert changes["exit_status"] == {"before": 259, "after": 0}
    assert changes["context_switches"] == {
        "before": 0xFFFFFFFE, "after": 3, "delta": 5, "wrapped": True,
    }
    assert not result["created_truncated"]


@pytest.mark.parametrize("mutator", [
    lambda capture: replace(capture, target=_target(eprocess=0xFFFFE001_00900000)),
    lambda capture: replace(capture, boot_identity={**capture.boot_identity, "nt_base": "0xfffff80010000000"}),
    lambda capture: replace(capture, symbol_identity={**capture.symbol_identity, "mtime_ns": 124}),
])
def test_baseline_expires_on_process_boot_or_symbol_identity_change(tmp_path, mutator):
    store = _store(tmp_path)
    capture = _capture([_thread(1, 0xFFFFE001_00001000)])
    store.save("case", capture)
    with pytest.raises(BaselineExpiredError, match="baseline expired"):
        store.diff("case", mutator(capture), limit=8)


def test_baseline_rejects_zero_thread_create_time_and_missing_name(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ThreadBaselineError, match="ETHREAD.CreateTime"):
        store.save("case", _capture([_thread(1, 0xFFFFE001_00001000, create_time=0)]))
    with pytest.raises(BaselineNotFoundError, match="not found"):
        store.load("absent")
    with pytest.raises(ThreadBaselineError, match="baseline name"):
        store.path("../../not-a-baseline")


def test_diff_bounds_each_category_without_losing_total_counts(tmp_path):
    store = _store(tmp_path)
    old = [_thread(i, 0xFFFFE001_00100000 + i * 0x1000, create_time=FILETIME + i)
           for i in range(1, 4)]
    store.save("bounded", _capture(old))
    new = [_thread(i + 10, 0xFFFFE001_00200000 + i * 0x1000, create_time=FILETIME + 100 + i)
           for i in range(1, 4)]
    result = store.diff("bounded", _capture(new), limit=1)

    assert result["created_count"] == result["exited_count"] == 3
    assert len(result["created"]) == len(result["exited"]) == 1
    assert result["created_truncated"] is True
    assert result["exited_truncated"] is True


def test_capture_refuses_partial_walk_before_any_baseline_can_be_written(monkeypatch, tmp_path):
    import winbox.kdbg.thread_baseline as baseline_mod

    target = _target()
    monkeypatch.setattr(baseline_mod, "find_process", lambda *_a, **_k: target)
    monkeypatch.setattr(
        baseline_mod, "list_threads",
        lambda *_a, **_k: ThreadWalkResult([], False, "cycle detected"),
    )
    with pytest.raises(BaselineIncompleteError, match="cycle detected"):
        capture_threads(Config(winbox_dir=tmp_path / ".winbox"), object(), target.pid)


def test_capture_binds_system_boot_and_exact_symbol_store_revision(monkeypatch, tmp_path):
    import winbox.kdbg.thread_baseline as baseline_mod

    target = _target()
    system = ProcessRecord(
        pid=4, name="System", eprocess=0xFFFFE001_00000000,
        directory_table_base=0x12345000, create_time=FILETIME - 1,
    )
    symbol_path = tmp_path / "nt_build-a.json"
    symbol_path.write_text("{}")

    class Store:
        def info(self, _module):
            return type("Info", (), {
                "build": "build-a", "base": 0xFFFFF80000000000,
                "path": symbol_path, "symbol_count": 10, "type_count": 4,
            })()

    def find(_vm, _store, *, pid, **_kwargs):
        return target if pid == target.pid else system if pid == 4 else None

    monkeypatch.setattr(baseline_mod, "find_process", find)
    monkeypatch.setattr(
        baseline_mod, "list_threads",
        lambda *_a, **_k: ThreadWalkResult([_thread(1, 0xFFFFE001_00001000)], True),
    )
    capture = capture_threads(Config(winbox_dir=tmp_path / ".winbox"), Store(), target.pid)

    assert capture.boot_identity["system"]["eprocess"] == "0xffffe00100000000"
    assert capture.symbol_identity["build"] == "build-a"
    assert capture.symbol_identity["mtime_ns"] == symbol_path.stat().st_mtime_ns
