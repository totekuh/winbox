"""Immutable capture-store and offline-diff contracts."""

from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from winbox.config import Config
from winbox.kdbg.capture import (
    CaptureError, CaptureIdentityError, CaptureIncomplete, CaptureStore,
    SCHEMA, diff_captures,
    _boot_identity, _boot_identity_for_capture, _module_record,
    _process_record, _thread_record,
    capture_live, capture_process_in_snapshot, capture_system_in_snapshot,
)
from winbox.kdbg.objects import ObjectEvidenceError
from winbox.kdbg.vad import VadError


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


# ── Capture orchestration ──────────────────────────────────────────────


def _fake_process(**overrides):
    defaults = dict(
        pid=1234, name="test.exe", eprocess=0xFFFF800012340000,
        directory_table_base=0x1AA000, user_directory_table_base=0x1AB000,
        create_time=132000000000000000, exit_time=0,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_thread():
    return SimpleNamespace(
        tid=100, ethread=0xFFFF800056780000, state=5, state_name="Waiting",
        wait_reason=6, wait_reason_name="UserRequest", priority=8,
        base_priority=8, context_switches=42, teb=0x7FF000001000,
        kernel_stack=0xFFFFF80000001000, stack_limit=0xFFFFF80000000000,
        stack_base=0xFFFFF80000002000, start_address=0xFFFFF80600001000,
        win32_start_address=0x7FF6E2890000, create_time=132000000000000000,
        exit_status=0,
    )


def _fake_module(**overrides):
    defaults = dict(base=0xFFFFF80600000000, size=0x200000, name="ntoskrnl.exe")
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_store():
    store = MagicMock()
    store.info.return_value = SimpleNamespace(
        build="22621", base=0xFFFFF80600000000,
        path=SimpleNamespace(name="ntkrnlmp.pdb"),
        symbol_count=100, type_count=50,
    )
    return store


_UNSET = object()


def _patch_capture(monkeypatch, *, find_process_result=_UNSET):
    import winbox.kdbg.capture as mod
    proc = find_process_result if find_process_result is not _UNSET else _fake_process()
    monkeypatch.setattr(mod, "find_process", lambda *a, **k: proc)
    monkeypatch.setattr(mod, "list_threads", lambda *a, **k: SimpleNamespace(
        threads=[_fake_thread()], complete=True, truncated_reason=None,
    ))
    monkeypatch.setattr(mod, "list_modules", lambda *a, **k: [_fake_module()])
    monkeypatch.setattr(mod, "list_user_modules", lambda *a, **k: [])
    monkeypatch.setattr(mod, "list_vads", lambda *a, **k: SimpleNamespace(
        public=lambda: {"records": [], "returned": 0, "complete": True, "truncation": None},
    ))
    monkeypatch.setattr(mod, "token_evidence", lambda *a, **k: {"token": "present"})
    monkeypatch.setattr(mod, "handle_table_status", lambda *a, **k: {"handles": "present"})
    monkeypatch.setattr(mod, "snapshot_phase", lambda name: nullcontext())
    monkeypatch.setattr(mod, "list_processes_detailed", lambda *a, **k: SimpleNamespace(
        processes=[_fake_process(pid=4, name="System"), _fake_process()],
        complete=True, truncation=None, truncated_reason=None,
    ))
    monkeypatch.setattr(mod, "thread_presentation_fields", lambda t: {})
    monkeypatch.setattr(mod, "filetime_utc", lambda t: "2026-01-01T00:00:00Z")
    return mod


class TestCaptureOrchestration:

    # -- record helpers --

    def test_process_record_hex_format(self, monkeypatch):
        _patch_capture(monkeypatch)
        rec = _process_record(_fake_process())
        assert rec["pid"] == 1234
        assert rec["eprocess"].startswith("0x")
        assert rec["dtb"].startswith("0x")

    def test_thread_record_structure(self, monkeypatch):
        _patch_capture(monkeypatch)
        rec = _thread_record(_fake_thread())
        assert rec["tid"] == 100
        assert rec["ethread"].startswith("0x")
        assert isinstance(rec["state"], dict)
        assert rec["priority"] == 8

    def test_module_record_with_optional_fields(self):
        mod = _fake_module()
        rec = _module_record(mod)
        assert "path" not in rec
        assert "architecture" not in rec
        mod.path = "C:\\Windows\\System32\\ntoskrnl.exe"
        mod.architecture = "amd64"
        rec = _module_record(mod)
        assert rec["path"] == "C:\\Windows\\System32\\ntoskrnl.exe"
        assert rec["architecture"] == "amd64"

    # -- _boot_identity --

    def test_boot_identity_success(self, monkeypatch):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "find_process",
                            lambda *a, **k: _fake_process(pid=4, name="System"))
        store = _fake_store()
        result = _boot_identity("winbox", store, None)
        assert "system" in result
        assert result["system"]["pid"] == 4
        assert "nt" in result
        assert result["nt"]["build"] == "22621"

    def test_boot_identity_system_absent(self, monkeypatch):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "find_process", lambda *a, **k: None)
        with pytest.raises(CaptureError, match="System process is absent"):
            _boot_identity("winbox", _fake_store(), None)

    # -- capture_process_in_snapshot --

    def test_process_capture_happy_path(self, monkeypatch, tmp_path):
        _patch_capture(monkeypatch)
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        result = capture_process_in_snapshot(cfg, _fake_store(), 1234)
        assert result["profile"] == "process"
        assert result["complete"] is True
        assert len(result["threads"]["records"]) == 1
        assert result["token"] == {"token": "present"}
        assert result["handles"] == {"handles": "present"}

    def test_process_capture_pid_not_found(self, monkeypatch, tmp_path):
        _patch_capture(monkeypatch, find_process_result=None)
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        with pytest.raises(CaptureError, match="not found"):
            capture_process_in_snapshot(cfg, _fake_store(), 9999)

    def test_process_capture_user_modules_error(self, monkeypatch, tmp_path):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "list_user_modules",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("walk failed")))
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        result = capture_process_in_snapshot(cfg, _fake_store(), 1234)
        assert result["modules"]["user"] == []
        assert "walk failed" in result["modules"]["user_error"]

    def test_process_capture_vad_error(self, monkeypatch, tmp_path):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "list_vads",
                            lambda *a, **k: (_ for _ in ()).throw(VadError("vad walk broken")))
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        result = capture_process_in_snapshot(cfg, _fake_store(), 1234)
        assert result["executable_vads"]["records"] == []
        assert "vad walk broken" in result["vad_error"]

    def test_process_capture_token_error(self, monkeypatch, tmp_path):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "token_evidence",
                            lambda *a, **k: (_ for _ in ()).throw(ObjectEvidenceError("no token")))
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        result = capture_process_in_snapshot(cfg, _fake_store(), 1234)
        assert result["token"] is None
        assert "no token" in result["token_error"]

    def test_process_capture_handles_error(self, monkeypatch, tmp_path):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "handle_table_status",
                            lambda *a, **k: (_ for _ in ()).throw(ObjectEvidenceError("no handles")))
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        result = capture_process_in_snapshot(cfg, _fake_store(), 1234)
        assert result["handles"] is None
        assert "no handles" in result["handles_error"]

    def test_process_capture_require_complete_raises(self, monkeypatch, tmp_path):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "list_threads", lambda *a, **k: SimpleNamespace(
            threads=[], complete=False, truncated_reason="budget",
        ))
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        with pytest.raises(CaptureIncomplete, match="partial boundary") as exc_info:
            capture_process_in_snapshot(cfg, _fake_store(), 1234, require_complete=True)
        assert exc_info.value.details["thread_complete"] is False

    # -- capture_system_in_snapshot --

    def test_system_capture_happy_path(self, monkeypatch, tmp_path):
        _patch_capture(monkeypatch)
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        result = capture_system_in_snapshot(cfg, _fake_store())
        assert result["profile"] == "system"
        assert result["complete"] is True
        assert len(result["processes"]) == 2
        assert len(result["kernel_modules"]) == 1

    def test_system_capture_require_complete_raises(self, monkeypatch, tmp_path):
        mod = _patch_capture(monkeypatch)
        monkeypatch.setattr(mod, "list_processes_detailed", lambda *a, **k: SimpleNamespace(
            processes=[], complete=False,
            truncation=SimpleNamespace(public=lambda: {"reason": "budget"}),
            truncated_reason="budget",
        ))
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        with pytest.raises(CaptureIncomplete, match="incomplete"):
            capture_system_in_snapshot(cfg, _fake_store(), require_complete=True)

    # -- capture_live parameter validation --

    def test_capture_live_invalid_profile(self, tmp_path):
        with pytest.raises(CaptureError, match="must be"):
            capture_live(Config(winbox_dir=tmp_path), _fake_store(), profile="invalid")

    def test_capture_live_process_requires_pid(self, tmp_path):
        with pytest.raises(CaptureError, match="positive pid"):
            capture_live(Config(winbox_dir=tmp_path), _fake_store(), profile="process", pid=None)

    def test_capture_live_system_rejects_pid(self, tmp_path):
        with pytest.raises(CaptureError, match="does not accept"):
            capture_live(Config(winbox_dir=tmp_path), _fake_store(), profile="system", pid=123)

    # -- _boot_identity_for_capture --

    def test_boot_identity_for_capture_existing(self):
        identity = {"system": {"pid": 4}, "nt": {"build": "22621"}}
        payload = {"boot_identity": identity}
        result = _boot_identity_for_capture(payload, None, None)
        assert result is identity

    def test_boot_identity_for_capture_system_profile(self):
        payload = {
            "profile": "system",
            "processes": [{"pid": 4, "name": "System"}, {"pid": 1234, "name": "test.exe"}],
        }
        result = _boot_identity_for_capture(payload, None, _fake_store())
        assert result["system"]["pid"] == 4
        assert result["system_identity_scope"] == "captured"

    def test_boot_identity_for_capture_process_profile(self):
        payload = {"profile": "process"}
        result = _boot_identity_for_capture(payload, None, _fake_store())
        assert result["system"] is None
        assert result["system_identity_scope"] == "not_captured_by_profile"
        assert result["nt"]["build"] == "22621"
