"""Opt-in live smoke coverage for the persistent RSP walker transport."""

from __future__ import annotations

import subprocess

import pytest


pytestmark = pytest.mark.integration


def test_live_installed_cli_can_reuse_reader_for_kernel_module_walks():
    status = subprocess.run(
        ["winbox", "status"], capture_output=True, text=True, check=False, timeout=15,
    )
    if status.returncode != 0 or "running" not in status.stdout.lower():
        pytest.skip("configured Winbox VM is not running")
    cet = subprocess.run(
        ["winbox", "kdbg", "cet-status"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if cet.returncode != 0 or "SAFE" not in cet.stdout:
        pytest.skip("configured Winbox VM is not prepared for safe QEMU debugging")

    for _ in range(2):
        result = subprocess.run(
            ["winbox", "kdbg", "lm"],
            capture_output=True, text=True, check=False, timeout=30,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert "ntoskrnl.exe" in result.stdout
        assert " modules)" in result.stdout
