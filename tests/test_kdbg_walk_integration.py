"""Opt-in live walker checks through the supported Winbox CLI boundary."""

from __future__ import annotations

import json
import re
import subprocess

import pytest


pytestmark = pytest.mark.integration


def _winbox(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["winbox", *args], capture_output=True, text=True, check=False, timeout=30,
    )


def _require_safe_live_vm() -> None:
    status = _winbox("status")
    if status.returncode != 0 or "running" not in status.stdout.lower():
        pytest.skip("configured Winbox VM is not running")
    cet = _winbox("kdbg", "cet-status")
    if cet.returncode != 0 or "SAFE" not in cet.stdout:
        pytest.skip("configured Winbox VM is not prepared for safe QEMU debugging")


def test_live_process_walk_survives_repeated_coherent_snapshots():
    _require_safe_live_vm()

    counts: set[int] = set()
    for _ in range(10):
        result = _winbox("kdbg", "ps")
        assert result.returncode == 0, result.stderr or result.stdout
        assert " System\n" in result.stdout
        footer = result.stdout.rsplit("(", 1)[-1].split(" processes)", 1)[0]
        counts.add(int(footer))

    # Process churn is allowed, but every walk must return a real table rather
    # than the one/two-entry partial lists seen during reboot races.
    assert min(counts) > 10


def test_live_parallel_walkers_are_serialized_across_cli_processes():
    _require_safe_live_vm()

    ps = subprocess.Popen(
        ["winbox", "kdbg", "ps"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    lm = subprocess.Popen(
        ["winbox", "kdbg", "lm"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    ps_out, ps_err = ps.communicate(timeout=30)
    lm_out, lm_err = lm.communicate(timeout=30)
    assert ps.returncode == 0, ps_err or ps_out
    assert lm.returncode == 0, lm_err or lm_out
    assert " processes)" in ps_out
    assert " modules)" in lm_out


def test_live_pid4_lookup_exits_after_first_eprocess(monkeypatch):
    """A single-PID lookup must not materialize the live process table."""
    _require_safe_live_vm()

    from winbox.config import Config
    from winbox.kdbg import walk
    from winbox.kdbg.debugger.reader import debug_snapshot
    from winbox.kdbg.store import SymbolStore

    cfg = Config.load()
    store = SymbolStore(cfg.symbols_dir)
    original = walk._read_process_entry
    reads = 0

    def counted(*args, **kwargs):
        nonlocal reads
        reads += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(walk, "_read_process_entry", counted)
    with debug_snapshot(cfg):
        system = walk.find_process(cfg.vm_name, store, pid=4)

    assert system is not None and system.name == "System"
    assert reads == 1


def test_live_thread_walk_is_complete_and_returns_unique_validated_threads():
    """Exercise the installed CLI through several real RSP snapshots.

    System always has threads, avoids guest-side test-process setup, and the
    assertions intentionally stick to invariants the kernel walker can prove:
    target PID identity, distinct CIDs, canonical ETHREAD addresses, and an
    explicitly complete list rather than an optimistic partial result.
    """
    _require_safe_live_vm()

    ps = _winbox("kdbg", "ps")
    assert ps.returncode == 0, ps.stderr or ps.stdout
    match = re.search(
        r"^\s*4\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+System\s*$",
        ps.stdout,
        re.MULTILINE,
    )
    assert match, ps.stdout

    observed_counts: set[int] = set()
    for _ in range(3):
        result = _winbox("kdbg", "threads", "4", "--json")
        assert result.returncode == 0, result.stderr or result.stdout
        payload = json.loads(result.stdout)
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

    # Scheduler churn is allowed; a real table on every coherent snapshot is
    # the contract. Keep the set assertion merely to make the accepted churn
    # explicit rather than accidentally requiring a static thread count.
    assert observed_counts


def test_live_thread_research_view_is_bounded_resolved_and_vcpu_aware():
    """Exercise the selected top-three thread research surface through CLI."""
    _require_safe_live_vm()

    summary = _winbox("kdbg", "threads", "4", "--detail", "summary", "--json")
    assert summary.returncode == 0, summary.stderr or summary.stdout
    compact = json.loads(summary.stdout)
    assert compact["pid"] == 4
    assert compact["threads"] == []
    assert compact["detail_rows_omitted"] is True
    assert compact["walk_complete"] is True
    assert compact["total_count"] == compact["matched_count"] > 0
    assert compact["summary"]["states"]
    assert compact["current_vcpus"]
    assert {current["status"] for current in compact["current_vcpus"]} <= {
        "current", "idle", "unavailable",
    }

    detailed = _winbox(
        "kdbg", "threads", "4", "--json", "--resolve", "--limit", "8",
        "--sort", "context-switches",
    )
    assert detailed.returncode == 0, detailed.stderr or detailed.stdout
    payload = json.loads(detailed.stdout)
    assert payload["walk_complete"] is True, payload
    assert payload["returned"] == payload["count"] == len(payload["threads"]) == 8
    assert payload["total_count"] >= payload["matched_count"] > payload["returned"]
    assert payload["output_truncated"] is True
    starts = [thread["start_attribution"]["start_address"] for thread in payload["threads"]]
    assert any(
        start["mapping"] == "kernel_module" and start["module"]
        for start in starts
    ), starts
