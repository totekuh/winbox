"""Unit tests for the RSP client framing and high-level operations.

The client talks to a fake socket whose ``recv`` queue is pre-loaded
with packets a real QEMU gdbstub would emit. ``sendall`` just records
what we sent so tests can assert the wire format without needing a
live VM.
"""

from __future__ import annotations

from collections import deque

import pytest

from winbox.kdbg.debugger.rsp import (
    RspClient,
    RspError,
    StopReply,
    _checksum,
    _escape,
    _unescape,
)


# ── Fake socket ─────────────────────────────────────────────────────────


class FakeSocket:
    """Records sends, replays canned recv chunks."""

    def __init__(self, recv_chunks: list[bytes] | None = None) -> None:
        self._recv = deque(recv_chunks or [])
        self.sent: bytearray = bytearray()
        self.timeout: float | None = None
        self.closed = False

    def setsockopt(self, *args, **kwargs) -> None:
        pass

    def settimeout(self, t: float | None) -> None:
        self.timeout = t

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, n: int) -> bytes:
        if not self._recv:
            return b""
        chunk = self._recv.popleft()
        return chunk[:n] if n else chunk

    def close(self) -> None:
        self.closed = True


def _frame(body: bytes) -> bytes:
    """Build a valid RSP frame around ``body`` for use as a recv chunk."""
    return b"+$" + body + b"#" + f"{_checksum(body):02x}".encode("ascii")


def _client(recv_chunks: list[bytes]) -> tuple[RspClient, FakeSocket]:
    sock = FakeSocket(recv_chunks)
    return RspClient(sock), sock


# ── Framing primitives ──────────────────────────────────────────────────


def test_checksum_simple():
    # 'g' has ord 0x67
    assert _checksum(b"g") == 0x67


def test_escape_roundtrip_through_special_bytes():
    # All four escapable bytes plus a normal one.
    raw = b"a$b#c}d*e"
    esc = _escape(raw)
    assert _unescape(esc) == raw
    # Verify the escapes really happened.
    assert b"}\x04" in esc  # $ -> } 0x04 (0x24 ^ 0x20)


def test_escape_passes_normal_bytes_through():
    raw = b"hello world\x00\xff"
    assert _escape(raw) == raw


# ── Send/receive on a fake socket ───────────────────────────────────────


def test_send_packet_writes_dollar_body_hash_checksum():
    cli, sock = _client([b"+"])
    cli._send_packet(b"g")
    # Format: $g#67 (0x67 = ord('g'))
    assert bytes(sock.sent) == b"$g#67"


def test_read_packet_strips_frame_and_returns_body():
    cli, sock = _client([_frame(b"OK")])
    body = cli._read_packet()
    assert body == b"OK"
    # Client should have ack'd with '+'.
    assert sock.sent.endswith(b"+")


def test_read_packet_rejects_bad_checksum():
    cli, sock = _client([b"+$ok#00"])  # 'OK' would be 9f, not 00
    with pytest.raises(RspError, match="checksum mismatch"):
        cli._read_packet()


def test_read_packet_unescapes_body():
    body = b"foo}\x04bar"  # } 0x04 represents '$'
    cli, _ = _client([_frame(body)])
    assert cli._read_packet() == b"foo$bar"


# ── handshake / qSupported ──────────────────────────────────────────────


def test_handshake_parses_features_and_enables_noack():
    feat_body = b"swbreak+;hwbreak+;PacketSize=4000;multiprocess-"
    chunks = [
        _frame(feat_body),  # response to qSupported
        _frame(b"OK"),       # response to QStartNoAckMode
    ]
    cli, sock = _client(chunks)
    features = cli.handshake()

    assert features["swbreak"] == "1"
    assert features["hwbreak"] == "1"
    assert features["multiprocess"] == "0"
    assert features["PacketSize"] == "4000"
    assert cli._noack is True


def test_handshake_falls_back_when_noack_rejected():
    feat_body = b"swbreak+;PacketSize=400"
    chunks = [
        _frame(feat_body),
        _frame(b""),  # empty reply to QStartNoAckMode = unsupported
    ]
    cli, _ = _client(chunks)
    cli.handshake()
    assert cli._noack is False


# ── breakpoint commands ─────────────────────────────────────────────────


def test_insert_breakpoint_sw_emits_z0():
    cli, sock = _client([b"+", _frame(b"OK")])
    cli.insert_breakpoint(0xFFFFF80608800000, kind=1)
    assert b"$Z0,fffff80608800000,1#" in bytes(sock.sent)


def test_insert_breakpoint_hw_emits_z1():
    cli, sock = _client([b"+", _frame(b"OK")])
    cli.insert_breakpoint(0x401000, kind=1, hardware=True)
    assert b"$Z1,401000,1#" in bytes(sock.sent)


def test_remove_breakpoint_emits_lowercase_z():
    cli, sock = _client([b"+", _frame(b"OK")])
    cli.remove_breakpoint(0x401000)
    assert b"$z0,401000,1#" in bytes(sock.sent)


def test_breakpoint_install_raises_on_error_response():
    cli, sock = _client([b"+", _frame(b"E22")])
    with pytest.raises(RspError, match="failed"):
        cli.insert_breakpoint(0xDEADBEEF)


# ── memory ops ──────────────────────────────────────────────────────────


def test_read_memory_returns_decoded_bytes():
    cli, sock = _client([b"+", _frame(b"deadbeef")])
    data = cli.read_memory(0x1000, 4)
    assert data == b"\xde\xad\xbe\xef"
    assert b"$m1000,4#" in bytes(sock.sent)


def test_read_memory_raises_on_error_reply():
    cli, _ = _client([b"+", _frame(b"E14")])
    with pytest.raises(RspError, match="m failed"):
        cli.read_memory(0xDEAD, 16)


def test_write_memory_emits_M_with_hex_payload():
    cli, sock = _client([b"+", _frame(b"OK")])
    cli.write_memory(0x2000, b"\xcc\x90")
    sent = bytes(sock.sent)
    assert b"$M2000,2:cc90#" in sent


# ── thread / register ops ──────────────────────────────────────────────


def test_select_thread_emits_Hg():
    cli, sock = _client([b"+", _frame(b"OK")])
    cli.select_thread("3")
    assert b"$Hg3#" in bytes(sock.sent)


def test_list_threads_consumes_qf_then_qs_until_l():
    chunks = [
        b"+", _frame(b"m1,2"),
        b"+", _frame(b"m3"),
        b"+", _frame(b"l"),
    ]
    cli, _ = _client(chunks)
    assert cli.list_threads() == ["1", "2", "3"]


def test_read_registers_returns_raw_bytes():
    chunks = [b"+", _frame(b"01020304")]
    cli, _ = _client(chunks)
    assert cli.read_registers() == b"\x01\x02\x03\x04"


# ── stop replies ────────────────────────────────────────────────────────


def test_parse_stop_reply_swbreak_with_thread():
    sr = RspClient._parse_stop_reply(b"T05swbreak:;thread:2;")
    assert sr == StopReply(signal=5, thread="2", stop_kind="swbreak", raw="T05swbreak:;thread:2;")


def test_parse_stop_reply_minimal_S():
    sr = RspClient._parse_stop_reply(b"S05")
    assert sr.signal == 5
    assert sr.thread is None
    assert sr.stop_kind is None


def test_parse_stop_reply_rejects_unexpected_prefix():
    with pytest.raises(RspError):
        RspClient._parse_stop_reply(b"W00")


def test_wait_for_stop_returns_parsed_reply():
    cli, _ = _client([_frame(b"T05swbreak:;thread:1;")])
    sr = cli.wait_for_stop(timeout=0.1)
    assert sr.thread == "1"
    assert sr.stop_kind == "swbreak"


# ── continue / interrupt / step (no response expected) ──────────────────


def test_cont_emits_vCont_c():
    cli, sock = _client([b"+"])
    cli.cont()
    assert b"$vCont;c#" in bytes(sock.sent)


def test_step_with_thread_includes_id():
    cli, sock = _client([b"+"])
    cli.step("3")
    assert b"$vCont;s:3#" in bytes(sock.sent)


def test_interrupt_sends_raw_ctrl_c():
    cli, sock = _client([])
    cli.interrupt()
    assert bytes(sock.sent) == b"\x03"
