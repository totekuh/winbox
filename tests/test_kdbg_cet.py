"""CET preparation, restoration, and debugger safety-gate tests."""

from __future__ import annotations

import base64
import json
import stat
from types import SimpleNamespace

import pytest

from winbox.config import Config
from winbox.kdbg import cet
from winbox.kdbg.cet import CetSafetyError


class FakeGa:
    def __init__(self, *outputs):
        self.outputs = list(outputs)
        self.scripts: list[str] = []

    def exec_powershell(self, script, timeout=30):
        self.scripts.append(script)
        output = self.outputs.pop(0)
        if isinstance(output, BaseException):
            raise output
        if isinstance(output, tuple):
            stdout, stderr, exitcode = output
        else:
            stdout, stderr, exitcode = output, "", 0
        return SimpleNamespace(stdout=stdout, stderr=stderr, exitcode=exitcode)


def _status(value="OFF", strict="OFF"):
    return json.dumps({"UserShadowStack": value, "StrictMode": strict})


def test_query_status_off_is_safe():
    status = cet.query_status(FakeGa(_status()))
    assert status.safe_for_debug is True
    assert status.user_shadow_stack == "OFF"


def test_require_safe_rejects_on_and_explains_prepare(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    with pytest.raises(CetSafetyError, match="kdbg prepare --confirm"):
        cet.require_safe(cfg, FakeGa(_status("ON", "NOTSET")))


def test_query_status_fails_closed_on_invalid_json():
    with pytest.raises(CetSafetyError, match="invalid JSON"):
        cet.query_status(FakeGa("not-json"))


def test_query_status_wraps_guest_agent_failure():
    with pytest.raises(CetSafetyError, match="agent unavailable"):
        cet.query_status(FakeGa(RuntimeError("agent unavailable")))


def test_prepare_is_noop_when_current_boot_is_already_safe(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    ga = FakeGa(_status("OFF"))
    assert cet.prepare(cfg, ga) is None
    assert len(ga.scripts) == 1
    assert not cet.backup_path(cfg).exists()


def test_prepare_saves_raw_registry_values_with_private_permissions(tmp_path):
    cfg = Config(winbox_dir=tmp_path, vm_name="box")
    options = base64.b64encode(b"\x01\x02").decode()
    ga = FakeGa(
        _status("NOTSET"),
        json.dumps({
            "saved": {
                "MitigationOptions": options,
                "MitigationAuditOptions": None,
            },
            "reboot_required": True,
        }),
    )
    path = cet.prepare(cfg, ga)
    assert path == cet.backup_path(cfg)
    data = json.loads(path.read_text())
    assert data["vm_name"] == "box"
    assert data["values"]["MitigationOptions"] == options
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "Set-ProcessMitigation" in ga.scripts[1]


def test_prepare_never_overwrites_existing_original_policy(tmp_path):
    cfg = Config(winbox_dir=tmp_path, vm_name="box")
    path = cet.backup_path(cfg)
    path.write_text(json.dumps({
        "vm_name": "box", "values": {
            "MitigationOptions": "ORIGINAL",
            "MitigationAuditOptions": None,
        },
    }))
    ga = FakeGa(_status("ON"), ("", "", 0))
    assert cet.prepare(cfg, ga) == path
    assert json.loads(path.read_text())["values"]["MitigationOptions"] == "ORIGINAL"


def test_prepare_rejects_invalid_registry_backup_without_writing_file(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    ga = FakeGa(
        _status("ON"),
        json.dumps({"saved": {"MitigationOptions": 123}}),
    )
    with pytest.raises(CetSafetyError, match="invalid saved CET registry value"):
        cet.prepare(cfg, ga)
    assert not cet.backup_path(cfg).exists()


def test_restore_recreates_present_value_removes_absent_and_deletes_backup(tmp_path):
    cfg = Config(winbox_dir=tmp_path, vm_name="box")
    encoded = base64.b64encode(b"\x00" * 16).decode()
    path = cet.backup_path(cfg)
    path.write_text(json.dumps({
        "vm_name": "box", "values": {
            "MitigationOptions": encoded,
            "MitigationAuditOptions": None,
        },
    }))
    ga = FakeGa('{"restored":true,"reboot_required":true}')
    cet.restore(cfg, ga)
    assert not path.exists()
    script = ga.scripts[0]
    assert encoded in script
    assert "New-ItemProperty" in script
    assert "Remove-ItemProperty" in script


def test_restore_rejects_backup_for_another_vm(tmp_path):
    cfg = Config(winbox_dir=tmp_path, vm_name="box")
    cet.backup_path(cfg).write_text(json.dumps({"vm_name": "other", "values": {}}))
    with pytest.raises(CetSafetyError, match="another VM"):
        cet.restore(cfg, FakeGa())


def test_restore_failure_preserves_recovery_backup(tmp_path):
    cfg = Config(winbox_dir=tmp_path, vm_name="box")
    path = cet.backup_path(cfg)
    path.write_text(json.dumps({
        "vm_name": "box",
        "values": {"MitigationOptions": None, "MitigationAuditOptions": None},
    }))
    with pytest.raises(CetSafetyError, match="registry write denied"):
        cet.restore(cfg, FakeGa(("", "registry write denied", 1)))
    assert path.exists(), "failed restore must retain the only recovery copy"


def test_reader_gate_runs_before_fork(monkeypatch, tmp_path):
    import winbox.kdbg.debugger.reader as reader

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(reader, "_reader_alive", lambda cfg: False)
    monkeypatch.setattr(
        "winbox.kdbg.debugger.client.DaemonClient.session_alive", lambda self: False,
    )
    events = []
    monkeypatch.setattr(cet, "require_safe", lambda cfg: events.append("gate"))
    monkeypatch.setattr(reader, "_fork_reader", lambda cfg, port: events.append("fork") or 1)
    monkeypatch.setattr(reader, "sock_path", lambda cfg: tmp_path / "ready.sock")
    # Make the post-fork readiness check succeed.
    (tmp_path / "ready.sock").touch()
    reader.ensure_reader(cfg)
    assert events == ["gate", "fork"]


def test_reader_gate_failure_prevents_fork(monkeypatch, tmp_path):
    import winbox.kdbg.debugger.reader as reader

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(reader, "_reader_alive", lambda cfg: False)
    monkeypatch.setattr(
        "winbox.kdbg.debugger.client.DaemonClient.session_alive", lambda self: False,
    )
    monkeypatch.setattr(
        cet, "require_safe", lambda cfg: (_ for _ in ()).throw(CetSafetyError("unsafe")),
    )
    fork = SimpleNamespace(called=False)
    monkeypatch.setattr(
        reader, "_fork_reader", lambda cfg, port: setattr(fork, "called", True),
    )
    with pytest.raises(reader.ReaderError, match="unsafe"):
        reader.ensure_reader(cfg)
    assert fork.called is False


def test_daemon_gate_failure_is_actionable_and_prevents_fork(monkeypatch, tmp_path):
    import winbox.kdbg.debugger.daemon as daemon

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(
        cet, "require_safe", lambda cfg: (_ for _ in ()).throw(CetSafetyError("unsafe")),
    )
    monkeypatch.setattr(
        daemon.os, "pipe", lambda: pytest.fail("must gate before creating daemon pipe"),
    )
    with pytest.raises(daemon.DaemonError, match="unsafe"):
        daemon.fork_daemon(cfg, 4)


def test_verified_running_reader_does_not_repeat_guest_query(monkeypatch, tmp_path):
    import winbox.kdbg.debugger.reader as reader

    cfg = Config(winbox_dir=tmp_path)
    reader.session_path(cfg).write_text(json.dumps({"cet_safe": True}))
    monkeypatch.setattr(reader, "_reader_alive", lambda cfg: True)
    monkeypatch.setattr(
        cet, "require_safe",
        lambda cfg: pytest.fail("verified reader must not re-query the guest"),
    )
    reader.ensure_reader(cfg)


def test_unverified_running_reader_is_replaced_and_gated(monkeypatch, tmp_path):
    import winbox.kdbg.debugger.reader as reader

    cfg = Config(winbox_dir=tmp_path)
    reader.session_path(cfg).write_text(json.dumps({"pid": 123}))
    alive = iter((True, False))
    monkeypatch.setattr(reader, "_reader_alive", lambda cfg: next(alive))
    monkeypatch.setattr(
        "winbox.kdbg.debugger.client.DaemonClient.session_alive", lambda self: False,
    )
    events = []
    monkeypatch.setattr(reader, "stop_reader", lambda cfg: events.append("stop"))
    monkeypatch.setattr(cet, "require_safe", lambda cfg: events.append("gate"))
    monkeypatch.setattr(reader, "_fork_reader", lambda cfg, port: events.append("fork"))
    monkeypatch.setattr(reader, "sock_path", lambda cfg: tmp_path / "ready.sock")
    (tmp_path / "ready.sock").touch()

    reader.ensure_reader(cfg)
    assert events == ["stop", "gate", "fork"]
