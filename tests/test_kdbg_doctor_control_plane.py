"""Capability and provenance assertions for the non-disruptive doctor view."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError
from winbox.kdbg.decomp.client import DecompError
from winbox.kdbg.doctor import collect_doctor
from winbox.kdbg.provenance import runtime_provenance
from winbox.vm import VMState


def _patch_healthy_doctor(monkeypatch, tmp_path, *, symbol_type_count=4):
    """Patch all doctor dependencies to the happy path (ready=True)."""
    import winbox.kdbg.doctor as doctor

    cfg = Config(winbox_dir=tmp_path / "state")
    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING
    ga = MagicMock()
    ga.ping.return_value = True
    symbol = SimpleNamespace(
        build="build", base=0xFFFFF80000000000,
        symbol_count=12, type_count=symbol_type_count,
    )
    monkeypatch.setattr(doctor.SymbolStore, "info", lambda *_a, **_k: symbol)
    monkeypatch.setattr(
        doctor, "query_status", lambda _ga: SimpleNamespace(safe_for_debug=True),
    )
    monkeypatch.setattr(doctor, "format_status", lambda _s: "SAFE")
    monkeypatch.setattr(doctor, "reader_info", lambda _cfg: None)
    monkeypatch.setattr(doctor.DaemonClient, "session_alive", lambda _self: False)
    monkeypatch.setattr(doctor, "probe_port", lambda *_a: False)
    monkeypatch.setattr(
        doctor.DecompClient, "status", lambda _self, **_k: {
            "backend": "docker", "docker_available": True,
            "image_installed": True, "health": "running", "busy": False,
        },
    )
    monkeypatch.setattr(
        doctor, "runtime_provenance", lambda *_a: {"version_consistent": True},
    )
    return doctor, cfg, vm, ga


def _call_doctor(cfg, vm, ga, tmp_path):
    return collect_doctor(
        cfg, vm, ga, catalog_revision="catalog", tool_count=85,
        version="1.6.1", package_file=str(tmp_path / "package.py"),
    )


def test_runtime_provenance_marks_editable_source_metadata_drift(monkeypatch, tmp_path):
    root = tmp_path / "source"
    package = root / "src" / "winbox"
    package.mkdir(parents=True)
    package_file = package / "__init__.py"
    package_file.write_text("", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'winbox'\nversion = '1.6.2'\n", encoding="utf-8",
    )
    monkeypatch.setattr(
        "winbox.kdbg.provenance.importlib.metadata.version", lambda _: "1.6.1",
    )

    result = runtime_provenance(str(package_file), "1.6.1")

    assert result["source_manifest_version"] == "1.6.2"
    assert result["distribution_version"] == "1.6.1"
    assert result["version_consistent"] is False


def test_doctor_separates_basic_kdbg_from_unavailable_decomp(monkeypatch, tmp_path):
    doctor, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    monkeypatch.setattr(
        doctor.DecompClient, "status", lambda _self, **_k: {
            "backend": "docker", "docker_available": True,
            "image_installed": False, "health": "stopped", "busy": False,
        },
    )
    monkeypatch.setattr(
        doctor, "runtime_provenance", lambda *_a: {"version_consistent": False},
    )

    report = _call_doctor(cfg, vm, ga, tmp_path)

    assert report["ready"] is True
    assert report["research_ready"] is False
    assert report["capabilities"]["thread_research"]["available"] is True
    assert report["capabilities"]["live_decompilation"]["available"] is False
    assert report["decomp"] == {
        "available": False,
        "reason": "managed PyGhidra image is not installed",
        "next_action": "run kdbg_ghidra_install",
        "backend": "docker",
        "health": "stopped",
        "busy": False,
        "admission": None,
    }


@pytest.mark.parametrize("broken_field,blocker_fragment", [
    ("vm_off", "VM is not running"),
    ("agent_down", "guest agent is not responding"),
    ("cet_unsafe", "CET safety is not confirmed"),
    ("no_symbols", "nt symbols are unavailable"),
    ("interactive", "interactive debugger session"),
])
def test_ready_requires_all_conditions(monkeypatch, tmp_path, broken_field, blocker_fragment):
    doctor, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)

    if broken_field == "vm_off":
        vm.state.return_value = VMState.SHUTOFF
    elif broken_field == "agent_down":
        ga.ping.return_value = False
    elif broken_field == "cet_unsafe":
        monkeypatch.setattr(
            doctor, "query_status",
            lambda _ga: SimpleNamespace(safe_for_debug=False),
        )
    elif broken_field == "no_symbols":
        from winbox.kdbg.store import SymbolStoreError
        monkeypatch.setattr(
            doctor.SymbolStore, "info",
            lambda *_a, **_k: (_ for _ in ()).throw(SymbolStoreError("missing")),
        )
    elif broken_field == "interactive":
        monkeypatch.setattr(doctor.DaemonClient, "session_alive", lambda _self: True)

    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["ready"] is False
    all_blockers = []
    for cap in report["capabilities"].values():
        all_blockers.extend(cap.get("blockers", []))
    assert any(blocker_fragment in b for b in all_blockers)


def test_thread_research_blocked_when_types_unavailable(monkeypatch, tmp_path):
    _, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path, symbol_type_count=0)
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["capabilities"]["thread_research"]["available"] is False
    assert any("type layouts" in b for b in report["capabilities"]["thread_research"]["blockers"])


def test_decomp_capability_docker_available(monkeypatch, tmp_path):
    _, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["decomp"]["available"] is True
    assert report["decomp"]["reason"] == "ready"
    assert report["decomp"]["next_action"] is None


def test_decomp_capability_host_pyghidra_unavailable(monkeypatch, tmp_path):
    doctor, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    monkeypatch.setattr(
        doctor.DecompClient, "status", lambda _self, **_k: {
            "backend": "host", "pyghidra_available": False,
        },
    )
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["decomp"]["available"] is False
    assert "PyGhidra" in report["decomp"]["reason"]


def test_decomp_capability_exception_path(monkeypatch, tmp_path):
    doctor, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    monkeypatch.setattr(
        doctor.DecompClient, "status",
        lambda _self, **_k: (_ for _ in ()).throw(DecompError("socket gone")),
    )
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["decomp"]["available"] is False
    assert "unavailable" in report["decomp"]["reason"]


def test_guest_agent_exception_path(monkeypatch, tmp_path):
    _, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    ga.ping.side_effect = ConnectionError("transport broken")
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["guest_agent"]["responding"] is False
    assert "transport broken" in report["guest_agent"]["error"]


def test_cet_safety_error_path(monkeypatch, tmp_path):
    doctor, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    monkeypatch.setattr(
        doctor, "query_status",
        lambda _ga: (_ for _ in ()).throw(CetSafetyError("reg query failed")),
    )
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["cet"]["error"] == "reg query failed"


def test_offline_preparation_available(monkeypatch, tmp_path):
    _, cfg, vm, ga = _patch_healthy_doctor(monkeypatch, tmp_path)
    report = _call_doctor(cfg, vm, ga, tmp_path)
    assert report["capabilities"]["offline_preparation"]["available"] is True
    assert report["capabilities"]["offline_preparation"]["blockers"] == []
