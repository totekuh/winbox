"""Tests for the daemon ↔ CLI wire protocol."""

from __future__ import annotations

import io
import socket

import pytest

from winbox.kdbg.debugger.protocol import (
    OPS,
    ProtocolError,
    decode,
    encode,
    read_line,
    reply_err,
    reply_ok,
    request,
)


# ── encoding roundtrip ──────────────────────────────────────────────────


def test_encode_appends_newline():
    out = encode({"ok": True})
    assert out.endswith(b"\n")
    assert out.count(b"\n") == 1


def test_decode_roundtrip():
    payload = {"op": "bp_add", "args": {"target": "notepad!Save"}}
    line = encode(payload).rstrip(b"\n")
    assert decode(line) == payload


def test_decode_rejects_non_object_top_level():
    with pytest.raises(ProtocolError, match="not an object"):
        decode(b"[1, 2, 3]")


def test_decode_rejects_bad_json():
    with pytest.raises(ProtocolError, match="bad JSON"):
        decode(b"{not valid json")


def test_decode_rejects_invalid_utf8():
    with pytest.raises(ProtocolError, match="bad JSON"):
        decode(b"\xff\xfe garbage")


# ── request builder validates op ────────────────────────────────────────


def test_request_rejects_unknown_op():
    with pytest.raises(ValueError, match="unknown op"):
        request("not_a_real_op")


def test_request_includes_op_and_args():
    r = request("bp_add", target="notepad!Save")
    assert r == {"op": "bp_add", "args": {"target": "notepad!Save"}}


def test_request_with_no_args():
    r = request("status")
    assert r == {"op": "status", "args": {}}


# ── reply builders ──────────────────────────────────────────────────────


def test_reply_ok_default_is_empty_result():
    assert reply_ok() == {"ok": True, "result": {}}


def test_reply_ok_with_result():
    assert reply_ok({"id": 0}) == {"ok": True, "result": {"id": 0}}


def test_reply_err_includes_message():
    assert reply_err("nope") == {"ok": False, "error": "nope"}


def test_reply_err_stringifies_non_str():
    e = RuntimeError("boom")
    assert reply_err(e) == {"ok": False, "error": "boom"}


# ── ops set is a frozen set with expected verbs ─────────────────────────


def test_ops_contains_core_verbs():
    for v in ("status", "bp_add", "bp_list", "bp_remove",
              "cont", "step", "interrupt",
              "regs", "mem", "write_mem", "stack", "bt",
              "detach"):
        assert v in OPS, f"missing op: {v}"


def test_ops_is_frozen():
    with pytest.raises((AttributeError, TypeError)):
        OPS.add("evil")  # frozenset has no add()


# ── read_line over a fake socket ────────────────────────────────────────


class FakeSocket:
    """Minimal stand-in: serves a queue of bytes via recv()."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def recv(self, n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


def test_read_line_returns_data_without_terminator():
    s = FakeSocket([b'{"ok":true}\n'])
    assert read_line(s) == b'{"ok":true}'


def test_read_line_handles_chunked_recv():
    s = FakeSocket([b'{"ok"', b':true', b'}\n', b'extra'])
    assert read_line(s) == b'{"ok":true}'


def test_read_line_raises_on_premature_close():
    s = FakeSocket([b'partial'])
    with pytest.raises(ProtocolError, match="closed before newline"):
        read_line(s)


def test_read_line_caps_oversize_payload():
    big = b"a" * 2_000_000  # > 1 MB cap
    s = FakeSocket([big])
    with pytest.raises(ProtocolError, match="line too long"):
        read_line(s, max_bytes=1024)
