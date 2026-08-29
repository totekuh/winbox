"""Immutable capture-store and offline-diff contracts."""

from __future__ import annotations

import json

import pytest

from winbox.config import Config
from winbox.kdbg.capture import (
    CaptureError, CaptureIdentityError, CaptureStore, SCHEMA, diff_captures,
)


def _capture(*, boot: int = 10, thread: str = "0xaaa", module: str = "0x1000", vad: str = "0x2000"):
    return {
        "schema": SCHEMA,
        "captured_at": "2026-08-29T00:00:00.000000Z",
        "vm_name": "winbox",
        "boot_identity": {"system": {"create_time": boot}, "nt": {"build": "build-a"}},
        "snapshot_metadata": {"snapshot_id": "id"},
        "capture": {
            "profile": "process", "complete": True,
            "threads": {"records": [{"ethread": thread, "tid": 1}]},
            "modules": {"user": [{"base": module, "name": "x.dll"}]},
            "executable_vads": {"records": [{"start": vad, "end": "0x2fff"}]},
        },
    }


def test_capture_store_uses_bounded_name_atomic_artifact(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    store = CaptureStore(cfg)

    saved = store.save("case-1", _capture())

    assert saved["name"] == "case-1"
    assert store.path("case-1").stat().st_mode & 0o077 == 0
    assert store.load("case-1")["schema"] == SCHEMA
    with pytest.raises(CaptureError, match="capture name"):
        store.save("../../escape", _capture())


def test_capture_store_refuses_corrupt_or_oversized_artifact(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    store = CaptureStore(cfg)
    path = store.path("bad")
    path.parent.mkdir(parents=True)
    path.write_text("[]")
    with pytest.raises(CaptureError, match="unsupported or corrupt"):
        store.load("bad")


def test_offline_capture_diff_has_no_vm_dependency_and_reports_categories():
    result = diff_captures(
        _capture(), _capture(thread="0xbbb", module="0x3000", vad="0x4000"),
    )

    assert result["identity_match"] is True
    assert result["threads"]["created"][0]["ethread"] == "0xbbb"
    assert result["threads"]["removed"][0]["ethread"] == "0xaaa"
    assert result["modules"]["created"][0]["base"] == "0x3000"
    assert result["executable_vads"]["created"][0]["start"] == "0x4000"


def test_capture_diff_refuses_cross_boot_unless_explicitly_requested():
    with pytest.raises(CaptureIdentityError, match="identity"):
        diff_captures(_capture(boot=1), _capture(boot=2))
    assert diff_captures(
        _capture(boot=1), _capture(boot=2), allow_identity_mismatch=True,
    )["identity_match"] is False


def test_capture_artifact_json_is_deterministically_serializable(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    store = CaptureStore(cfg)
    capture = _capture()
    store.save("one", capture)
    first = store.path("one").read_text()
    store.save("one", capture)
    assert store.path("one").read_text() == first
    assert json.loads(first)["capture"]["profile"] == "process"
