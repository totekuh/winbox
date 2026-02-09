"""Tests for winbox.guest — base64 decoding and ExecResult."""

import base64

import pytest

from winbox.guest import ExecResult, _decode_b64


class TestDecodeB64:
    def test_normal_string(self):
        encoded = base64.b64encode(b"hello world").decode()
        assert _decode_b64(encoded) == "hello world"

    def test_empty_string(self):
        assert _decode_b64("") == ""

    def test_none_like_falsy(self):
        # The function checks `if not data`, so empty/falsy => ""
        assert _decode_b64("") == ""

    def test_multiline_output(self):
        text = "line one\nline two\nline three\n"
        encoded = base64.b64encode(text.encode()).decode()
        assert _decode_b64(encoded) == text

    def test_unicode_content(self):
        text = "hello \u2603 snowman"
        encoded = base64.b64encode(text.encode("utf-8")).decode()
        assert _decode_b64(encoded) == text

    def test_invalid_base64_returns_empty(self):
        assert _decode_b64("!!!not-base64!!!") == ""

    def test_windows_line_endings(self):
        text = "line one\r\nline two\r\n"
        encoded = base64.b64encode(text.encode()).decode()
        assert _decode_b64(encoded) == text

    def test_binary_with_replacement(self):
        # Invalid UTF-8 bytes should be replaced, not crash
        raw = b"\x80\x81\x82"
        encoded = base64.b64encode(raw).decode()
        result = _decode_b64(encoded)
        assert isinstance(result, str)
        assert len(result) > 0  # replacement chars

    def test_large_output(self):
        text = "A" * 100_000
        encoded = base64.b64encode(text.encode()).decode()
        assert _decode_b64(encoded) == text


class TestExecResult:
    def test_creation(self):
        r = ExecResult(exitcode=0, stdout="out", stderr="err")
        assert r.exitcode == 0
        assert r.stdout == "out"
        assert r.stderr == "err"

    def test_equality(self):
        r1 = ExecResult(exitcode=0, stdout="a", stderr="b")
        r2 = ExecResult(exitcode=0, stdout="a", stderr="b")
        assert r1 == r2

    def test_nonzero_exit(self):
        r = ExecResult(exitcode=1, stdout="", stderr="error msg")
        assert r.exitcode == 1
        assert r.stderr == "error msg"
