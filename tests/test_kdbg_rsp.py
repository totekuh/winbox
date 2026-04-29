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
        if n and len(chunk) > n:
            # Re-queue the leftover so a chunk larger than the requested
            # size doesn't silently drop bytes — the real socket would
            # return them on the next recv().
            self._recv.appendleft(chunk[n:])
            return chunk[:n]
        return chunk

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


def test_read_memory_preserves_partial_bytes_on_chunk_failure():
    """Regression: prior to the partial=… field, a mid-read failure on
    a multi-chunk read threw away every byte already harvested. Callers
    walking a struct boundary on the failed chunk had no way to recover
    what already came back. RspError now carries the partial buffer."""
    # First chunk OK (4080 bytes worth), second chunk errors. Ask for
    # more than _MEM_CHUNK so we exercise the chunked path.
    good_hex = b"aa" * 0xFF0
    cli, _ = _client([b"+", _frame(good_hex), b"+", _frame(b"E14")])
    with pytest.raises(RspError) as ei:
        cli.read_memory(0x1000, 0xFF0 + 16)
    assert ei.value.partial == b"\xaa" * 0xFF0
    # Existing callers that don't use .partial still see RspError.
    assert "after" in str(ei.value)


def test_rsp_error_default_partial_is_empty_bytes():
    """RspError without an explicit ``partial=`` exposes b''. Catches
    a regression where tests/callers blindly read e.partial."""
    err = RspError("boom")
    assert err.partial == b""


def test_read_byte_with_none_timeout_calls_settimeout_none():
    """Regression: ``_read_byte(timeout=None)`` used to leave the socket
    timeout at whatever a prior call set, which silently broke
    ``wait_for_stop(timeout=None)`` (caller asks to block forever; socket
    still has a 10s timeout from a prior read). Verify settimeout(None)
    is now issued explicitly."""
    cli, sock = _client([b"X"])
    sock.timeout = 10.0  # leftover from a hypothetical prior op
    cli._read_byte(timeout=None)
    assert sock.timeout is None


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


# ── PacketSize advertisement ────────────────────────────────────────────


def test_handshake_advertises_64kib_packet_size():
    """PacketSize=10000 (hex, 65536 bytes) lets QEMU return op_mem's
    full 64 KiB cap in one ``m`` reply. Smaller values silently
    truncated large reads / rejected large writes with E22."""
    feat_body = b"swbreak+;PacketSize=10000"
    chunks = [
        _frame(feat_body),
        _frame(b"OK"),
    ]
    cli, sock = _client(chunks)
    cli.handshake()
    sent = bytes(sock.sent)
    assert b"PacketSize=10000" in sent
    # Sanity: must not regress to the pre-fix 0x4000 cap.
    assert b"PacketSize=4000" not in sent


# ── Memory chunking ─────────────────────────────────────────────────────


def test_read_memory_chunks_above_chunk_threshold():
    """Reads larger than _MEM_CHUNK get split across multiple ``m``
    requests and the bytes are concatenated in order."""
    chunk_size = RspClient._MEM_CHUNK  # 0xFF0
    total = chunk_size + 0x100  # forces exactly two requests
    # First reply: chunk_size bytes (all 0xAA), second: 0x100 bytes (0xBB).
    first = (b"\xAA" * chunk_size).hex().encode("ascii")
    second = (b"\xBB" * 0x100).hex().encode("ascii")
    cli, sock = _client([_frame(first), _frame(second)])
    data = cli.read_memory(0x1000, total)
    assert len(data) == total
    assert data[:chunk_size] == b"\xAA" * chunk_size
    assert data[chunk_size:] == b"\xBB" * 0x100
    sent = bytes(sock.sent)
    # First request asks for the full chunk; second asks for the remainder.
    assert f"$m1000,{chunk_size:x}#".encode("ascii") in sent
    second_addr = 0x1000 + chunk_size
    assert f"$m{second_addr:x},100#".encode("ascii") in sent


def test_read_memory_under_threshold_uses_single_request():
    """Small reads stay one packet — chunking adds no extra round-trip."""
    cli, sock = _client([_frame(b"deadbeef")])
    data = cli.read_memory(0x1000, 4)
    assert data == b"\xde\xad\xbe\xef"
    # Exactly one ``m`` packet on the wire.
    sent = bytes(sock.sent)
    assert sent.count(b"$m") == 1


def test_read_memory_short_chunk_advances_correctly():
    """If a chunk reply returns fewer bytes than asked, advance by the
    actual returned length and continue from there. Defends against a
    stub that hands back partial chunks."""
    chunk_size = RspClient._MEM_CHUNK
    total = chunk_size + 0x10
    # Advertise full chunk request, but reply with chunk_size - 0x10 bytes.
    short = chunk_size - 0x10
    first = (b"\xAA" * short).hex().encode("ascii")
    rest = total - short
    second = (b"\xBB" * rest).hex().encode("ascii")
    cli, sock = _client([_frame(first), _frame(second)])
    data = cli.read_memory(0x2000, total)
    assert len(data) == total
    assert data[:short] == b"\xAA" * short
    assert data[short:] == b"\xBB" * rest
    sent = bytes(sock.sent)
    # Second request must start where the actual read ended.
    second_addr = 0x2000 + short
    assert f"$m{second_addr:x},{rest:x}#".encode("ascii") in sent


def test_read_memory_empty_reply_raises():
    """Empty reply from server (non-error, but zero bytes) means we
    can't make progress — raise rather than infinite-loop."""
    cli, _ = _client([_frame(b"")])
    with pytest.raises(RspError, match="empty m reply"):
        cli.read_memory(0x1000, 16)


def test_write_memory_chunks_above_chunk_threshold():
    """Writes larger than _MEM_CHUNK split into multiple ``M`` packets."""
    chunk_size = RspClient._MEM_CHUNK
    total = chunk_size + 0x40
    payload = b"\xCC" * total
    chunks = [_frame(b"OK"), _frame(b"OK")]
    cli, sock = _client(chunks)
    cli.write_memory(0x3000, payload)
    sent = bytes(sock.sent)
    # First write at base addr for chunk_size bytes.
    assert f"$M3000,{chunk_size:x}:".encode("ascii") in sent
    # Second write at advanced addr for the remainder.
    second_addr = 0x3000 + chunk_size
    assert f"$M{second_addr:x},40:".encode("ascii") in sent


def test_write_memory_under_threshold_uses_single_packet():
    cli, sock = _client([_frame(b"OK")])
    cli.write_memory(0x4000, b"\xCC\x90")
    sent = bytes(sock.sent)
    assert sent.count(b"$M") == 1
    assert b"$M4000,2:cc90#" in sent
