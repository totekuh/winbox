"""Opt-in live walker checks through the supported Winbox CLI boundary."""

from __future__ import annotations

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
