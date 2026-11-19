"""Opt-in live walker checks through the Winbox CLI and Python API."""

from __future__ import annotations

import json
import os
import re
import subprocess

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.vm import VM, GuestAgent, VMState


pytestmark = pytest.mark.integration

_runner = CliRunner()


def _run(*args: str):
    return _runner.invoke(cli, list(args))


@pytest.fixture(scope="module")
def cfg(bootstrapped_vm):
    return Config.load()


@pytest.fixture(scope="module")
def vm(cfg):
    return VM(cfg)


@pytest.fixture(scope="module")
def ga(cfg):
    return GuestAgent(cfg)


@pytest.fixture(scope="module", autouse=True)
def _require_safe_vm(cfg, vm, ga):
    if vm.state() != VMState.RUNNING:
        pytest.skip("VM not running")
    try:
        require_safe(cfg, ga)
    except CetSafetyError:
        pytest.skip("CET not safe for debugging")


def test_live_process_walk_survives_repeated_coherent_snapshots():
    counts: set[int] = set()
    for _ in range(10):
        result = _run("kdbg", "ps")
        assert result.exit_code == 0, result.output
        assert " System\n" in result.output
        footer = result.output.rsplit("(", 1)[-1].split(" processes)", 1)[0]
        counts.add(int(footer))

    assert min(counts) > 10


def test_live_parallel_walkers_get_visible_nonqueueing_admission():
    walkers = [
        subprocess.Popen(
            ["winbox", "kdbg", "threads", "4", "--detail", "summary", "--json"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(4)
    ]
    completed = [
        (*walker.communicate(timeout=30), walker.returncode)
        for walker in walkers
    ]
    accepted = [
        json.loads(stdout) for stdout, _stderr, returncode in completed
        if returncode == 0
    ]
    busy = [
        (stdout, stderr) for stdout, stderr, returncode in completed
        if returncode != 0 and "snapshot is busy" in (stdout + stderr)
    ]
    assert accepted, completed
    assert busy, completed
    for payload in accepted:
        metadata = payload["snapshot_metadata"]
        assert metadata["admission"] == "accepted"
        assert metadata["snapshot_id"]
        assert metadata["queue_delay_ms"] == 0.0
        assert metadata["stop_duration_ms"] >= 0


def test_live_pid4_lookup_exits_after_first_eprocess(cfg, monkeypatch):
    """A single-PID lookup must not materialize the live process table."""
    from winbox.kdbg import walk
    from winbox.kdbg.walk import _processes
    from winbox.kdbg.debugger.reader import debug_snapshot
    from winbox.kdbg.store import SymbolStore

    store = SymbolStore(cfg.symbols_dir)
    # Patch the name _iter_processes actually calls — the one bound in the
    # _processes module globals. Patching the walk package re-export would not
    # intercept the call and the counter would never advance.
    original = _processes._read_process_entry
    reads = 0

    def counted(*args, **kwargs):
        nonlocal reads
        reads += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(_processes, "_read_process_entry", counted)
    with debug_snapshot(cfg):
        system = walk.find_process(cfg.vm_name, store, pid=4)

    assert system is not None and system.name == "System"
    assert reads == 1


def test_live_thread_walk_is_complete_and_returns_unique_validated_threads():
    """Exercise the CLI through several real RSP snapshots.

    System always has threads, avoids guest-side test-process setup, and the
    assertions intentionally stick to invariants the kernel walker can prove:
    target PID identity, distinct CIDs, canonical ETHREAD addresses, and an
    explicitly complete list rather than an optimistic partial result.
    """
    ps = _run("kdbg", "ps")
    assert ps.exit_code == 0, ps.output
    match = re.search(
        r"^\s*4\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+System\s*$",
        ps.output,
        re.MULTILINE,
    )
    assert match, ps.output

    observed_counts: set[int] = set()
    for _ in range(3):
        result = _run("kdbg", "threads", "4", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["pid"] == 4
        assert payload["name"] == "System"
        assert payload["complete"] is True, payload
        assert payload["truncated_reason"] is None
        assert payload["count"] > 0
        assert payload["count"] == len(payload["threads"])
        tids = [thread["tid"] for thread in payload["threads"]]
        assert len(tids) == len(set(tids))
        for thread in payload["threads"]:
            assert thread["tid"] > 0
            assert thread["ethread"].startswith("0xffff")
            assert isinstance(thread["state"]["raw"], int)
            assert isinstance(thread["wait_reason"]["raw"], int)
            assert thread["kernel_stack"].startswith("0x")
            assert thread["stack_limit"].startswith("0x")
            assert thread["stack_base"].startswith("0x")
        observed_counts.add(payload["count"])

    assert observed_counts


def test_live_thread_research_view_is_bounded_resolved_and_vcpu_aware():
    """Exercise the selected top-three thread research surface through CLI."""
    summary = _run("kdbg", "threads", "4", "--detail", "summary", "--json")
    assert summary.exit_code == 0, summary.output
    compact = json.loads(summary.output)
    assert compact["pid"] == 4
    assert compact["threads"] == []
    assert compact["detail_rows_omitted"] is True
    assert compact["walk_complete"] is True
    assert compact["total_count"] == compact["matched_count"] > 0
    assert compact["summary"]["states"]
    assert compact["current_vcpus"]
    assert compact["snapshot_metadata"]["admission"] == "accepted"
    assert compact["snapshot_metadata"]["snapshot_id"]
    assert {current["status"] for current in compact["current_vcpus"]} <= {
        "current", "idle", "unavailable",
    }

    detailed = _run(
        "kdbg", "threads", "4", "--json", "--resolve", "--limit", "8",
        "--sort", "context-switches",
    )
    assert detailed.exit_code == 0, detailed.output
    payload = json.loads(detailed.output)
    assert payload["walk_complete"] is True, payload
    assert payload["returned"] == payload["count"] == len(payload["threads"]) == 8
    assert payload["total_count"] >= payload["matched_count"] > payload["returned"]
    assert payload["output_truncated"] is True
    starts = [thread["start_attribution"]["start_address"] for thread in payload["threads"]]
    assert any(
        start["mapping"] == "kernel_module" and start["module"]
        for start in starts
    ), starts


def test_live_wait_object_evidence_is_bounded_and_never_infers_an_owner():
    """Exercise the optional PDB evidence path against a real Waiting row."""
    result = _run(
        "kdbg", "threads", "4", "--json", "--detail", "full",
        "--state", "Waiting", "--limit", "1", "--no-current",
        "--wait-objects", "--wait-object-limit", "1", "--wait-owner-depth", "2",
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["walk_complete"] is True, payload
    assert payload["wait_objects"] == {
        "enabled": True, "waiting_threads": 1, "examined": 1,
        "output_truncated": False, "wait_object_limit": 1,
        "wait_owner_depth": 2, "external_wait_blocks": "not_chased",
        "owner_relation": "mutant_only",
    }
    evidence = payload["threads"][0]["wait_object"]
    assert evidence["ethread"] == payload["threads"][0]["ethread"]
    assert evidence["state"]["name"] == "Waiting"
    assert isinstance(evidence["owner_chain"], list)
    if evidence["owner_chain"]:
        assert evidence["object"]["dispatcher_type"]["raw"] == 2
        assert all("via_object" in owner for owner in evidence["owner_chain"])
    else:
        assert evidence["reason"]
    metadata = payload["snapshot_metadata"]
    assert metadata["budget_exhausted"] is False
    assert metadata["read_count"] > 0
    assert metadata["bytes_read"] > 0


def test_live_reader_budget_expiry_resumes_the_guest_with_typed_evidence(cfg, vm):
    """Deliberately spend a one-read RSP budget; Windows must resume."""
    from contextlib import suppress
    from winbox.kdbg.debugger.reader import (
        ReaderError, SnapshotBudget, _RemoteSnapshot, ensure_reader, stop_reader,
    )

    stop_reader(cfg)
    ensure_reader(cfg)
    snapshot = _RemoteSnapshot.connect(
        cfg, budget=SnapshotBudget(max_duration_ms=1_000, max_reads=1, max_bytes=16),
    )
    try:
        assert len(snapshot.read_physical(0, 1)) == 1
        with pytest.raises(ReaderError) as raised:
            snapshot.read_physical(0, 1)
        assert getattr(raised.value, "code", None) == "snapshot_budget_exceeded"
        assert raised.value.details["reason"] == "read_count"
        metadata = snapshot.operation_metadata()
        assert metadata["budget_exhausted"] is True
        assert (metadata["read_count"], metadata["bytes_read"]) == (1, 1)
    finally:
        with suppress(ReaderError):
            snapshot.close()

    assert vm.state() == VMState.RUNNING


def test_live_doctor_and_triage_are_bounded_and_leave_a_usable_vm():
    """CLI-only smoke for the one-call operator views on the installed build."""
    doctor = _run("kdbg", "doctor", "--json")
    assert doctor.exit_code == 0, doctor.output
    report = json.loads(doctor.output)
    assert report["vm"]["running"] is True
    assert report["guest_agent"]["responding"] is True
    assert report["cet"]["safe_for_debug"] is True
    assert report["symbols"]["nt"]["available"] is True
    assert report["symbols"]["nt"]["live_base"] == "not_checked"
    assert report["mcp"]["catalog_revision"]
    assert report["capabilities"]["snapshot_research"]["available"] is True
    assert report["capabilities"]["live_decompilation"]["cold_policy"] == "warm_required"
    assert "version_consistent" in report["runtime"]

    triage = _run("kdbg", "triage", "4", "--json", "--thread-limit", "8")
    assert triage.exit_code == 0, triage.output
    payload = json.loads(triage.output)
    assert payload["snapshot"] == "single_rsp_stop"
    assert payload["process"]["pid"] == 4
    assert payload["thread_summary"]["walk_complete"] is True, payload
    assert 0 < len(payload["threads"]) <= 8
    assert payload["current_vcpus"]
    assert payload["unmapped_starts_scope"] == "top_rows_only"
    assert payload["snapshot_metadata"]["admission"] == "accepted"


def test_live_global_thread_triage_is_bounded_and_strictly_scope_aware():
    complete = _run(
        "kdbg", "thread-triage", "--json", "--process-cap", "128",
        "--total-thread-cap", "2048", "--sample-per-process", "1",
        "--limit", "8", "--no-resolve", "--require-complete",
    )
    assert complete.exit_code == 0, complete.output
    payload = json.loads(complete.output)
    assert payload["schema"] == "winbox.kdbg-global-thread-triage/1"
    assert payload["scope"]["complete"] is True, payload
    assert payload["scope"]["process_list_complete"] is True
    assert payload["scope"]["processes_examined"] > 1
    assert payload["scope"]["total_threads_examined"] > 0
    assert payload["rankings"]["by_thread_count"]
    assert payload["snapshot_metadata"]["admission"] == "accepted"

    strict_partial = _run(
        "kdbg", "thread-triage", "--json", "--process-cap", "1",
        "--total-thread-cap", "2048", "--no-resolve", "--require-complete",
    )
    assert strict_partial.exit_code == 1
    error = json.loads(strict_partial.output)
    assert error["error"]["code"] == "incomplete_result"
    assert error["error"]["details"]["scope_complete"] is False


def test_live_explicit_thread_baseline_and_diff_cleanup_exact_host_state(cfg):
    from winbox.kdbg.thread_baseline import ThreadBaselineStore

    store = ThreadBaselineStore(cfg)
    name = f"integration-thread-{os.getpid()}"
    store.delete(name)
    try:
        baseline = _run("kdbg", "thread-baseline", "4", "--name", name, "--json")
        assert baseline.exit_code == 0, baseline.output
        saved = json.loads(baseline.output)
        assert saved["process"]["pid"] == 4
        assert saved["thread_count"] > 0
        assert saved["snapshot_metadata"]["admission"] == "accepted"

        diff = _run("kdbg", "thread-diff", "4", "--name", name, "--limit", "8", "--json")
        assert diff.exit_code == 0, diff.output
        result = json.loads(diff.output)
        assert result["schema"] == "winbox.kdbg-thread-diff/1"
        assert result["process"]["pid"] == 4
        assert result["current"]["thread_count"] > 0
        assert result["limit"] == 8
        assert result["snapshot_metadata"]["admission"] == "accepted"
    finally:
        store.delete(name)
