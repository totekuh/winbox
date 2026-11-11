"""Tests for the QEMU HMP wrapper's error handling."""

from __future__ import annotations

import subprocess
import importlib
from unittest.mock import patch

import pytest

from winbox.kdbg.hmp import HmpError, hmp

hmp_module = importlib.import_module("winbox.kdbg.hmp")


@pytest.fixture(autouse=True)
def force_virsh_transport():
    """These legacy tests specifically exercise subprocess semantics."""
    with (
        patch.object(hmp_module, "_qmp_socket_paths", return_value=[]),
        patch.object(
            hmp_module,
            "_libvirt_hmp",
            side_effect=hmp_module._QmpUnavailable("disabled for test"),
        ),
    ):
        yield


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


def test_tcp6_decoder_preserves_address_family_and_word_order():
    assert hmp_module._hex_to_ipv6(
        "00000000000000000000000001000000"
    ) == "::1"
    assert hmp_module._hex_to_ipv6("not-hex") is None


def test_ipv6_listener_never_matches_ipv4_probe(monkeypatch):
    monkeypatch.setattr(
        hmp_module, "_listening_sockets", lambda: {("::", 1234), ("::1", 1235)},
    )
    assert hmp_module.probe_port("127.0.0.1", 1234) is False
    assert hmp_module.probe_port("::1", 1234) is True
    assert hmp_module.probe_port("::1", 1235) is True


def test_ipv4_listener_never_matches_ipv6_probe(monkeypatch):
    monkeypatch.setattr(
        hmp_module, "_listening_sockets",
        lambda: {("0.0.0.0", 1234), ("127.0.0.1", 1235)},
    )
    assert hmp_module.probe_port("::1", 1234) is False
    assert hmp_module.probe_port("127.0.0.1", 1234) is True
    assert hmp_module.probe_port("127.0.0.1", 1235) is True


def test_unparseable_listener_row_is_not_a_wildcard_match(monkeypatch):
    import io

    tcp = "sl local_address rem_address st\n"
    tcp6 = (
        "sl local_address rem_address st\n"
        "0: NOTHEX:04D2 00000000000000000000000000000000:0000 0A\n"
    )

    def opened(path, *_args, **_kwargs):
        return io.StringIO(tcp6 if str(path).endswith("tcp6") else tcp)

    monkeypatch.setattr("builtins.open", opened)
    assert hmp_module._listening_sockets() == set()
    assert hmp_module.probe_port("127.0.0.1", 1234) is False


# ── QMP connection protocol tests ──────────────────────────────────────

import json
import socket
import threading

from winbox.kdbg.hmp import _QmpConnection, _QmpCommandError, _QmpUnavailable


def _socketpair():
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return server, client


def _qmp_server_thread(server_sock, response_bytes):
    """Read one request, write one response."""
    try:
        server_sock.recv(4096)
        server_sock.sendall(response_bytes)
    finally:
        server_sock.close()


class TestQmpConnection:

    # ── _read_message ──────────────────────────────────────────────────

    def test_read_message_valid_json(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            server.sendall(b'{"QMP": {"version": {}}}\n')
            msg = conn._read_message()
            assert msg == {"QMP": {"version": {}}}
        finally:
            server.close()
            conn.close()

    def test_read_message_invalid_json(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            server.sendall(b'not json\n')
            with pytest.raises(_QmpUnavailable, match="invalid JSON"):
                conn._read_message()
        finally:
            server.close()
            conn.close()

    def test_read_message_non_dict(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            server.sendall(b'[1,2]\n')
            with pytest.raises(_QmpUnavailable, match="unexpected QMP message"):
                conn._read_message()
        finally:
            server.close()
            conn.close()

    def test_read_message_socket_closed(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        server.close()
        try:
            with pytest.raises(_QmpUnavailable, match="closed"):
                conn._read_message()
        finally:
            conn.close()

    def test_read_message_skips_empty_lines(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            server.sendall(b'\n\n{"ok":true}\n')
            msg = conn._read_message()
            assert msg == {"ok": True}
        finally:
            server.close()
            conn.close()

    # ── _execute ───────────────────────────────────────────────────────

    def test_execute_happy_path(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            t = threading.Thread(
                target=_qmp_server_thread,
                args=(server, b'{"return":"result","id":1}\n'),
            )
            t.start()
            result = conn._execute("test-cmd")
            t.join(timeout=2)
            assert result == "result"
        finally:
            conn.close()

    def test_execute_error_response(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            t = threading.Thread(
                target=_qmp_server_thread,
                args=(server, b'{"error":{"class":"GenericError","desc":"oops"},"id":1}\n'),
            )
            t.start()
            with pytest.raises(_QmpCommandError, match="oops"):
                conn._execute("test-cmd")
            t.join(timeout=2)
        finally:
            conn.close()

    def test_execute_mismatched_id(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            t = threading.Thread(
                target=_qmp_server_thread,
                args=(server, b'{"return":"x","id":999}\n'),
            )
            t.start()
            with pytest.raises(_QmpUnavailable, match="mismatched"):
                conn._execute("test-cmd")
            t.join(timeout=2)
        finally:
            conn.close()

    def test_execute_event_skipped(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            t = threading.Thread(
                target=_qmp_server_thread,
                args=(server, b'{"event":"STOP"}\n{"return":"ok","id":1}\n'),
            )
            t.start()
            result = conn._execute("test-cmd")
            t.join(timeout=2)
            assert result == "ok"
        finally:
            conn.close()

    def test_execute_send_failure(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        server.close()
        try:
            with pytest.raises(_QmpUnavailable, match="send failed|receive failed|closed"):
                conn._execute("test-cmd")
        finally:
            conn.close()

    # ── negotiate ──────────────────────────────────────────────────────

    def test_negotiate_happy_path(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            def play_server():
                server.sendall(b'{"QMP":{"version":{"qemu":{}}}}\n')
                server.recv(4096)
                server.sendall(b'{"return":{},"id":1}\n')
                server.close()
            t = threading.Thread(target=play_server)
            t.start()
            conn.negotiate()
            t.join(timeout=2)
        finally:
            conn.close()

    def test_negotiate_missing_greeting(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            server.sendall(b'{"something":"else"}\n')
            with pytest.raises(_QmpUnavailable, match="missing QMP greeting"):
                conn.negotiate()
        finally:
            server.close()
            conn.close()

    # ── hmp ────────────────────────────────────────────────────────────

    def test_hmp_happy_path(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            def play_server():
                server.sendall(b'{"QMP":{"version":{"qemu":{}}}}\n')
                server.recv(4096)
                server.sendall(b'{"return":{},"id":1}\n')
                server.recv(4096)
                server.sendall(b'{"return":"VM status: running","id":2}\n')
                server.close()
            t = threading.Thread(target=play_server)
            t.start()
            conn.negotiate()
            result = conn.hmp("info status", timeout=5)
            t.join(timeout=2)
            assert result == "VM status: running"
        finally:
            conn.close()

    def test_hmp_non_string_response(self):
        server, client = _socketpair()
        conn = _QmpConnection(client, "test")
        try:
            def play_server():
                server.sendall(b'{"QMP":{"version":{"qemu":{}}}}\n')
                server.recv(4096)
                server.sendall(b'{"return":{},"id":1}\n')
                server.recv(4096)
                server.sendall(b'{"return":42,"id":2}\n')
                server.close()
            t = threading.Thread(target=play_server)
            t.start()
            conn.negotiate()
            with pytest.raises(_QmpUnavailable, match="non-text"):
                conn.hmp("info status", timeout=5)
            t.join(timeout=2)
        finally:
            conn.close()
