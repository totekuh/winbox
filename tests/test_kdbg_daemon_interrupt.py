"""Transport-level tests for interrupting an in-flight ``cont``.

The existing daemon unit tests call ``handle_op`` directly, so they never
exercise the piece that actually broke: the serve loop is single-threaded,
and while it is inside a long ``cont`` it never reaches ``accept()``. A
second client (``winbox kdbg interrupt``) therefore sat unaccepted in the
listen backlog until its own socket timeout fired, and the interrupt was
dropped. These tests drive real sockets so that path is covered.
"""

from __future__ import annotations

import socket
from contextlib import suppress
import struct
import threading
import time

import pytest

from winbox.kdbg.debugger.daemon import DaemonSession, TargetInfo
from winbox.kdbg.debugger.protocol import decode, encode, read_line, request
from winbox.kdbg.debugger.rsp import RspError, StopReply


_CR3_OFFSET = 204
_BLOB_LEN = 608


def _blob(*, rip=0xfffff80608628780, cr3=0x4d6bb000) -> bytes:
    b = bytearray(_BLOB_LEN)
    struct.pack_into("<Q", b, 128, rip)
    struct.pack_into("<Q", b, _CR3_OFFSET, cr3)
    return bytes(b)


class SocketRsp:
    """RspClient stand-in backed by a real socketpair.

    The daemon selects on ``_sock``'s fileno to decide when the gdbstub has
    something for it, so the fake needs a genuine fd — a MagicMock would
    not reproduce the bug or the fix.
    """

    def __init__(self) -> None:
        self._sock, self._stub = socket.socketpair()
        self._inbuf = bytearray()
        self.continued = 0
        self.interrupted = 0
        self.regs_blob = _blob()

    # ── the bits the daemon touches ───────────────────────────────────
    def cont(self) -> None:
        self.continued += 1

    def interrupt(self) -> None:
        # What QEMU does with \x03 on a running VM: halt and punt a stop
        # reply onto the wire.
        self.interrupted += 1
        self._stub.sendall(b"T02")

    def wait_for_stop(self, *, timeout: float | None = None):
        self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(64)
        except socket.timeout as e:
            raise RspError("read timed out") from e
        if not data:
            raise RspError("connection closed by peer")
        return StopReply(signal=2, thread="01", stop_kind=None, raw="T02")

    def select_thread(self, t: str, *, op: str = "g") -> None:
        pass

    def read_registers(self) -> bytes:
        return self.regs_blob

    def close(self) -> None:
        self._sock.close()
        self._stub.close()


class FakeStore:
    def resolve(self, name: str) -> int:
        raise AssertionError("not used")

    def list_modules(self) -> list[str]:
        return []

    def load(self, name: str) -> dict:
        return {"module": name, "base": 0, "symbols": {}, "types": {}}


class FakeCfg:
    vm_name = "winbox"


@pytest.fixture
def session(tmp_path):
    rsp = SocketRsp()
    s = DaemonSession(
        cfg=FakeCfg(),
        rsp=rsp,
        target=TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe"),
        store=FakeStore(),
    )
    sock_path = str(tmp_path / "kdbg.sock")
    listen = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listen.bind(sock_path)
    listen.listen(4)
    listen.setblocking(False)
    s._listen_sock = listen
    s._sock_path = sock_path
    try:
        yield s
    finally:
        listen.close()
        rsp.close()


def _client_call(sock_path: str, op: str, *, delay: float, out: dict,
                 recv_timeout: float = 3.0, **args) -> threading.Thread:
    """Fire one request at the daemon from another thread."""

    def run() -> None:
        time.sleep(delay)
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(recv_timeout)
        try:
            c.connect(sock_path)
            c.sendall(encode(request(op, **args)))
            out["reply"] = decode(read_line(c))
        except Exception as e:  # noqa: BLE001 — the failure IS the result
            out["error"] = repr(e)
        finally:
            c.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_interrupt_is_served_while_cont_is_blocked(session):
    """The whole point: `kdbg interrupt` must reach the daemon and end the
    cont, not sit in the backlog until the client gives up."""
    out: dict = {}
    t = _client_call(session._sock_path, "interrupt", delay=0.2, out=out)

    started = time.monotonic()
    reply = session.op_cont(timeout=20.0)
    elapsed = time.monotonic() - started
    t.join(timeout=5.0)

    assert "error" not in out, out
    assert out["reply"]["ok"] is True
    # Returned because of the interrupt, not because the 20s budget ran out.
    assert reply["reason"] == "interrupt"
    assert elapsed < 5.0, f"cont ran {elapsed:.1f}s — interrupt did not land"
    assert session.rsp.interrupted >= 1
    # Flag consumed, so it cannot leak into the next cont.
    assert session._interrupt_pending is False


def test_heavy_op_gets_busy_instead_of_running_inside_cont(session):
    """The pump must not execute non-lightweight ops on the cont's stack —
    they would interleave RSP packets with the in-flight cont."""
    out: dict = {}
    t = _client_call(session._sock_path, "regs", delay=0.2, out=out)

    reply = session.op_cont(timeout=2.0)
    t.join(timeout=5.0)

    assert "error" not in out, out
    assert out["reply"]["ok"] is False
    assert "BUSY" in out["reply"]["error"]
    # cont was unaffected and ran out its own budget.
    assert reply["reason"] == "timeout"


def test_status_is_served_while_cont_is_blocked(session):
    """status is the other lightweight op — it must answer mid-cont too."""
    out: dict = {}
    t = _client_call(session._sock_path, "status", delay=0.2, out=out)

    reply = session.op_cont(timeout=2.0)
    t.join(timeout=5.0)

    assert "error" not in out, out
    assert out["reply"]["ok"] is True
    assert out["reply"]["result"]["target"]["name"] == "notepad.exe"
    assert reply["reason"] == "timeout"


def test_client_that_disconnects_immediately_does_not_break_cont(session):
    """A client that connects and hangs up is EOF — ProtocolError."""

    def run() -> None:
        time.sleep(0.2)
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(session._sock_path)
        c.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()

    reply = session.op_cont(timeout=2.0)
    t.join(timeout=5.0)
    assert reply["reason"] == "timeout"


def test_silent_client_times_out_without_killing_the_daemon(session, monkeypatch):
    """The case the OSError branch actually exists for.

    A client that connects and *holds* the socket without sending is not EOF —
    the read hits socket.timeout, an OSError. That used to escape serve() and
    take the daemon down with it, so `cont` never returned. Distinct from a
    client that hangs up, which raises ProtocolError and was always handled;
    reverting the branch to `except ProtocolError` leaves that test green and
    only this one red.
    """
    real_serve_one = session._serve_one

    def impatient(conn, *, read_timeout=60.0):
        # The production budget is 5s; shrink it so this stays a fast test
        # without changing which exception the read raises.
        return real_serve_one(conn, read_timeout=0.3)

    monkeypatch.setattr(session, "_serve_one", impatient)

    held = []

    def run() -> None:
        time.sleep(0.2)
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(session._sock_path)
        held.append(c)  # connect, then say nothing at all

    t = threading.Thread(target=run, daemon=True)
    t.start()

    reply = session.op_cont(timeout=2.0)
    t.join(timeout=5.0)
    for c in held:
        with suppress(OSError):
            c.close()

    # The daemon survived the silent client and completed its own wait.
    assert reply["reason"] == "timeout"


def test_cont_without_clients_still_times_out_cleanly(session):
    """Regression guard on the select-based wait: no client traffic at all
    must behave exactly like the old blocking wait_for_stop."""
    started = time.monotonic()
    reply = session.op_cont(timeout=1.0)
    elapsed = time.monotonic() - started
    assert reply["reason"] == "timeout"
    assert 0.9 <= elapsed < 4.0
    assert session.rsp.continued == 1
