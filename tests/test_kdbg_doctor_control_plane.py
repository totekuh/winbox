"""Capability and provenance assertions for the non-disruptive doctor view."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from winbox.config import Config
from winbox.kdbg.doctor import collect_doctor
from winbox.kdbg.provenance import runtime_provenance
from winbox.vm import VMState


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
    import winbox.kdbg.doctor as doctor

    cfg = Config(winbox_dir=tmp_path / "state")
    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING
    ga = MagicMock()
    ga.ping.return_value = True
    symbol = SimpleNamespace(
        build="build", base=0xFFFFF80000000000,
        symbol_count=12, type_count=4,
    )
    monkeypatch.setattr(doctor.SymbolStore, "info", lambda *_args, **_kwargs: symbol)
    monkeypatch.setattr(
        doctor, "query_status", lambda _ga: SimpleNamespace(safe_for_debug=True),
    )
    monkeypatch.setattr(doctor, "format_status", lambda _status: "SAFE")
    monkeypatch.setattr(doctor, "reader_info", lambda _cfg: None)
    monkeypatch.setattr(doctor.DaemonClient, "session_alive", lambda _self: False)
    monkeypatch.setattr(doctor, "probe_port", lambda *_args: False)
    monkeypatch.setattr(
        doctor.DecompClient, "status", lambda _self, **_kwargs: {
            "backend": "docker", "docker_available": True,
            "image_installed": False, "health": "stopped", "busy": False,
        },
    )
    monkeypatch.setattr(
        doctor, "runtime_provenance", lambda *_args: {"version_consistent": False},
    )

    report = collect_doctor(
        cfg, vm, ga, catalog_revision="catalog", tool_count=85,
        version="1.6.1", package_file=str(tmp_path / "package.py"),
    )

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
