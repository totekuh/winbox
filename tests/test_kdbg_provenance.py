from __future__ import annotations

import importlib.metadata
import os
import subprocess

import pytest

from winbox.kdbg.provenance import (
    _git_identity,
    _manifest_version,
    _source_root,
    runtime_provenance,
)


def test_source_root_returns_none_when_no_pyproject(tmp_path):
    leaf = tmp_path / "deep" / "nested" / "file.py"
    leaf.parent.mkdir(parents=True)
    leaf.write_text("")
    assert _source_root(str(leaf)) is None


def test_manifest_version_returns_none_when_root_is_none():
    assert _manifest_version(None) is None


def test_manifest_version_parses_toml(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1.2.3"\n', encoding="utf-8",
    )
    assert _manifest_version(tmp_path) == "1.2.3"


def test_manifest_version_falls_back_to_regex(monkeypatch, tmp_path):
    monkeypatch.setattr("winbox.kdbg.provenance.tomllib", None)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "4.5.6"\n', encoding="utf-8",
    )
    assert _manifest_version(tmp_path) == "4.5.6"


@pytest.mark.skipif(os.getuid() == 0, reason="root ignores file permissions")
def test_manifest_version_returns_none_on_read_error(tmp_path):
    toml = tmp_path / "pyproject.toml"
    toml.write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    toml.chmod(0o000)
    try:
        assert _manifest_version(tmp_path) is None
    finally:
        toml.chmod(0o644)


def test_git_identity_no_git_dir(tmp_path):
    assert _git_identity(tmp_path) == {
        "available": False, "revision": None, "dirty": None,
    }


def test_git_identity_with_real_git_dir(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.name", "test"], cwd=tmp_path,
        capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@test"], cwd=tmp_path,
        capture_output=True, check=True,
    )
    (tmp_path / "f.txt").write_text("x")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=tmp_path,
        capture_output=True, check=True,
    )

    result = _git_identity(tmp_path)
    assert result["available"] is True
    assert isinstance(result["revision"], str) and len(result["revision"]) > 0
    assert result["dirty"] is False

    (tmp_path / "new.txt").write_text("y")
    assert _git_identity(tmp_path)["dirty"] is True


def test_git_identity_subprocess_timeout(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()

    def timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1.0)

    monkeypatch.setattr("winbox.kdbg.provenance.subprocess.run", timeout_run)
    assert _git_identity(tmp_path) == {
        "available": False, "revision": None, "dirty": None,
    }


def test_runtime_provenance_package_not_found(monkeypatch, tmp_path):
    package_file = tmp_path / "__init__.py"
    package_file.write_text("")
    monkeypatch.setattr(
        "winbox.kdbg.provenance.importlib.metadata.version",
        lambda _: (_ for _ in ()).throw(importlib.metadata.PackageNotFoundError("winbox")),
    )
    result = runtime_provenance(str(package_file), "1.0.0")
    assert result["distribution_version"] is None


def test_runtime_provenance_all_versions_match(monkeypatch, tmp_path):
    root = tmp_path / "src" / "winbox"
    root.mkdir(parents=True)
    package_file = root / "__init__.py"
    package_file.write_text("")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "1.0.0"\n', encoding="utf-8",
    )
    monkeypatch.setattr(
        "winbox.kdbg.provenance.importlib.metadata.version", lambda _: "1.0.0",
    )
    result = runtime_provenance(str(package_file), "1.0.0")
    assert result["version_consistent"] is True
    assert result["source_manifest_version"] == "1.0.0"
    assert result["distribution_version"] == "1.0.0"
