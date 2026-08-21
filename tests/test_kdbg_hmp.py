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


def test_gdbstub_has_client_detects_established():
    """An ESTABLISHED connection to the gdbstub port means a client is attached."""
    from winbox.kdbg.hmp import gdbstub_has_client

    # Port 1234 = 0x04D2. /proc/net/tcp uses uppercase hex.
    fake_tcp = (
        "  sl  local_address rem_address   st ...\n"
        "   0: 0100007F:04D2 0100007F:9C40 01 ...\n"  # ESTABLISHED on port 1234
    )
    with patch("builtins.open", side_effect=lambda f, *a, **k:
               __import__("io").StringIO(fake_tcp) if "tcp" in f else (_ for _ in ()).throw(OSError)):
        assert gdbstub_has_client(1234) is True


def test_gdbstub_has_client_ignores_listen():
    """A LISTEN socket is not an attached client."""
    from winbox.kdbg.hmp import gdbstub_has_client

    fake_tcp = (
        "  sl  local_address rem_address   st ...\n"
        "   0: 0100007F:04D2 00000000:0000 0A ...\n"  # LISTEN on port 1234
    )
    with patch("builtins.open", side_effect=lambda f, *a, **k:
               __import__("io").StringIO(fake_tcp) if "tcp" in f else (_ for _ in ()).throw(OSError)):
        assert gdbstub_has_client(1234) is False


def test_gdbstub_has_client_no_match():
    """No connections on the port → no client."""
    from winbox.kdbg.hmp import gdbstub_has_client

    fake_tcp = (
        "  sl  local_address rem_address   st ...\n"
        "   0: 0100007F:1F90 0100007F:9C40 01 ...\n"  # ESTABLISHED on port 8080
    )
    with patch("builtins.open", side_effect=lambda f, *a, **k:
               __import__("io").StringIO(fake_tcp) if "tcp" in f else (_ for _ in ()).throw(OSError)):
        assert gdbstub_has_client(1234) is False
