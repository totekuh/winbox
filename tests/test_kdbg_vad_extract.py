"""Contracts for one-stop bounded VAD byte evidence artifacts."""

from __future__ import annotations

import hashlib

import pytest

from winbox.config import Config
from winbox.kdbg.debugger.rsp import RspError
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.vad import VadRecord
from winbox.kdbg.vad_extract import (
    SCHEMA,
    VadExtractError,
    VadExtractIncomplete,
    VadExtractStore,
    extract_vad_in_snapshot,
)
from winbox.kdbg.walk import ProcessRecord


_TARGET = ProcessRecord(
    pid=4242, name="target.exe", eprocess=0xFFFF_8000_0020_0000,
    directory_table_base=0x12345000, create_time=1,
)


def _vad(*, start=0x40000000, end=0x40002FFF) -> VadRecord:
    return VadRecord(
        node=0xFFFF_8000_0030_0000, start=start, end=end, flags=0,
        vad_type_raw=0, protection_raw=6, protection="execute_read_write",
        executable=True, writable=True, private_memory=True, kind="private",
        pe_header="mz",
    )


def _patch(monkeypatch, *, vad=None, reader=None):
    import winbox.kdbg.vad_extract as extract

    monkeypatch.setattr(extract, "lookup_vad", lambda *_args, **_kwargs: vad or _vad())
    if reader is not None:
        monkeypatch.setattr(extract, "read_virt_cr3", reader)


def test_extract_uses_one_proven_vad_and_merges_contiguous_pages(monkeypatch):
    calls = []

    def reader(_vm, cr3, address, length, **_kwargs):
        assert cr3 == _TARGET.directory_table_base
        calls.append((address, length))
        return bytes([address >> 12 & 0xFF]) * length

    _patch(monkeypatch, reader=reader)
    extraction = extract_vad_in_snapshot(
        "vm", object(), _TARGET, 0x40000000, length=8192,
    )

    manifest = extraction.manifest
    assert manifest["schema"] == SCHEMA
    assert manifest["complete"] is True
    assert manifest["range"] == {
        "address": "0x0000000040000000",
        "end": "0x0000000040001fff",
        "requested_bytes": 8192,
    }
    assert calls == [(0x40000000, 4096), (0x40001000, 4096)]
    assert len(manifest["segments"]) == 1
    assert manifest["segments"][0]["length"] == 8192
    assert manifest["segments"][0]["blob_offset"] == 0
    assert manifest["holes"] == []
    assert manifest["blob"] == {
        "size": 8192,
        "sha256": hashlib.sha256(extraction.blob).hexdigest(),
        "layout": "concatenated_successful_segments",
    }
    assert "bytes" not in manifest


def test_extract_keeps_holes_and_strict_mode_publishes_no_result(monkeypatch):
    def reader(_vm, _cr3, address, length, **_kwargs):
        if address == 0x40001000:
            raise HmpError("unmapped")
        return b"A" * length

    _patch(monkeypatch, reader=reader)
    extraction = extract_vad_in_snapshot(
        "vm", object(), _TARGET, 0x40000000, length=8192,
    )
    assert extraction.manifest["complete"] is False
    assert extraction.manifest["blob"]["size"] == 4096
    assert extraction.manifest["holes"] == [{
        "address": "0x0000000040001000", "length": 4096, "reason": "unreadable",
    }]

    with pytest.raises(VadExtractIncomplete, match="incomplete"):
        extract_vad_in_snapshot(
            "vm", object(), _TARGET, 0x40000000, length=8192,
            require_complete=True,
        )


def test_extract_reports_short_read_tail_without_laundering_it(monkeypatch):
    _patch(monkeypatch, reader=lambda *_args, **_kwargs: b"B" * 100)

    extraction = extract_vad_in_snapshot(
        "vm", object(), _TARGET, 0x40000000, length=4096,
    )

    assert extraction.manifest["complete"] is False
    assert extraction.manifest["segments"][0]["length"] == 100
    assert extraction.manifest["holes"] == [{
        "address": "0x0000000040000064", "length": 3996, "reason": "short_read",
    }]


def test_extract_preserves_rsp_partial_bytes_as_an_explicit_hole(monkeypatch):
    def reader(*_args, **_kwargs):
        raise RspError("gdbstub transport broke", partial=b"R" * 100)

    _patch(monkeypatch, reader=reader)
    extraction = extract_vad_in_snapshot(
        "vm", object(), _TARGET, 0x40000000, length=4096,
    )

    assert extraction.blob == b"R" * 100
    assert extraction.manifest["complete"] is False
    assert extraction.manifest["segments"] == [{
        "address": "0x0000000040000000",
        "length": 100,
        "blob_offset": 0,
        "sha256": hashlib.sha256(b"R" * 100).hexdigest(),
    }]
    assert extraction.manifest["holes"] == [{
        "address": "0x0000000040000064", "length": 3996, "reason": "rsp_partial",
    }]


def test_extract_accepts_an_rsp_partial_that_fulfils_the_request(monkeypatch):
    def reader(*_args, **_kwargs):
        raise RspError("gdbstub disconnected after the response", partial=b"S" * 4096)

    _patch(monkeypatch, reader=reader)
    extraction = extract_vad_in_snapshot(
        "vm", object(), _TARGET, 0x40000000, length=4096,
    )

    assert extraction.blob == b"S" * 4096
    assert extraction.manifest["complete"] is True
    assert extraction.manifest["holes"] == []


def test_extract_refuses_to_cross_the_proven_vad_boundary_before_read(monkeypatch):
    def reader(*_args, **_kwargs):
        raise AssertionError("range validation must happen before a byte read")

    _patch(monkeypatch, vad=_vad(end=0x4000000F), reader=reader)
    with pytest.raises(VadExtractError, match="past the validated VAD boundary"):
        extract_vad_in_snapshot(
            "vm", object(), _TARGET, 0x40000000, length=32,
        )


def test_immutable_store_writes_mode_0600_pair_and_detects_tampering(tmp_path, monkeypatch):
    _patch(monkeypatch, reader=lambda *_args, **_kwargs: b"C" * 4096)
    extraction = extract_vad_in_snapshot(
        "vm", object(), _TARGET, 0x40000000, length=4096,
    )
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    store = VadExtractStore(cfg)

    saved = store.save("private-rwx", extraction)

    assert saved["name"] == "private-rwx"
    assert store.path("private-rwx").stat().st_mode & 0o077 == 0
    assert store.blob_path("private-rwx").stat().st_mode & 0o077 == 0
    assert store.load("private-rwx")["artifact_name"] == "private-rwx"
    with pytest.raises(VadExtractError, match="immutable"):
        store.ensure_available("private-rwx")
    with pytest.raises(VadExtractError, match="immutable"):
        store.save("private-rwx", extraction)

    store.blob_path("private-rwx").write_bytes(b"X" * 4096)
    with pytest.raises(VadExtractError, match="digest"):
        store.load("private-rwx")


def test_store_rejects_unsafe_names_and_preserves_exact_pair_cleanup(tmp_path, monkeypatch):
    _patch(monkeypatch, reader=lambda *_args, **_kwargs: b"D" * 4096)
    extraction = extract_vad_in_snapshot("vm", object(), _TARGET, 0x40000000, length=4096)
    store = VadExtractStore(Config(winbox_dir=tmp_path / ".winbox"))
    with pytest.raises(VadExtractError, match="artifact name"):
        store.save("../../escape", extraction)
    store.save("case", extraction)
    store.delete("case")
    assert not store.path("case").exists()
    assert not store.blob_path("case").exists()
