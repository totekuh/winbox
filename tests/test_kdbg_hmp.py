"""Tests for the QEMU HMP wrapper's error handling."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from winbox.kdbg.hmp import HmpError, hmp


def test_hmp_timeout_is_wrapped_as_hmperror():
    """subprocess.run's TimeoutExpired must surface as HmpError — walkers catch
    (HmpError, PageWalkError) to log a truncation and return partial data; an
    unwrapped TimeoutExpired would instead crash the whole MCP tool call."""
    with patch(
        "winbox.kdbg.hmp.subprocess.run",
        side_effect=subprocess.TimeoutExpired("virsh", 15),
    ):
        with pytest.raises(HmpError, match="timed out"):
            hmp("winbox", "info registers")


def test_hmp_nonzero_exit_raises_hmperror():
    """A non-zero virsh exit still raises HmpError (unchanged behavior)."""
    class _R:
        returncode = 1
        stdout = ""
        stderr = "some monitor error"

    with patch("winbox.kdbg.hmp.subprocess.run", return_value=_R()):
        with pytest.raises(HmpError, match="some monitor error"):
            hmp("winbox", "info registers")
