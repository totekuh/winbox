"""Runtime/source provenance for truthful local control-plane reporting."""

from __future__ import annotations

import importlib.metadata
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:  # Python 3.11+; winbox still supports 3.10.
    import tomllib
except ImportError:  # pragma: no cover - exercised on Python 3.10 only
    tomllib = None


def _source_root(package_file: str) -> Path | None:
    path = Path(package_file).resolve()
    for candidate in (path, *path.parents):
        manifest = candidate / "pyproject.toml"
        if manifest.is_file() and not manifest.is_symlink():
            return candidate
    return None


def _manifest_version(root: Path | None) -> str | None:
    if root is None:
        return None
    try:
        manifest = root / "pyproject.toml"
        if tomllib is not None:
            with manifest.open("rb") as source:
                value = tomllib.load(source)
            version = value.get("project", {}).get("version")
            return str(version) if isinstance(version, str) else None
        # The fallback intentionally recognizes only the simple PEP 621 form
        # used by this project; it never treats arbitrary TOML as executable.
        match = re.search(
            r"(?ms)^\[project\].*?^version\s*=\s*[\"']([^\"']+)[\"']",
            manifest.read_text(encoding="utf-8", errors="replace"),
        )
        return match.group(1) if match else None
    except (OSError, ValueError, TypeError):
        return None


def _git_identity(root: Path | None) -> dict[str, Any]:
    if root is None or not (root / ".git").exists():
        return {"available": False, "revision": None, "dirty": None}
    try:
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=12", "HEAD"],
            text=True, capture_output=True, timeout=1.0, check=False,
        )
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            text=True, capture_output=True, timeout=1.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "revision": None, "dirty": None}
    if revision.returncode:
        return {"available": False, "revision": None, "dirty": None}
    return {
        "available": True,
        "revision": revision.stdout.strip()[:64] or None,
        "dirty": bool(dirty.returncode == 0 and dirty.stdout.strip()),
    }


def runtime_provenance(package_file: str, runtime_version: str) -> dict[str, Any]:
    """Describe the executable/distribution/source relationship without guessing."""
    root = _source_root(package_file)
    try:
        distribution_version = importlib.metadata.version("winbox")
    except importlib.metadata.PackageNotFoundError:
        distribution_version = None
    manifest_version = _manifest_version(root)
    versions = {item for item in (runtime_version, distribution_version, manifest_version) if item}
    return {
        "python": sys.executable,
        "package_file": str(Path(package_file).resolve()),
        "distribution_version": distribution_version,
        "runtime_version": runtime_version,
        "source_manifest_version": manifest_version,
        "source_checkout": root is not None,
        "source_root": str(root) if root is not None else None,
        "version_consistent": len(versions) <= 1,
        "git": _git_identity(root),
        "pid": os.getpid(),
    }
