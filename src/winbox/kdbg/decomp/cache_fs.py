"""Bounded filesystem traversal helpers for decomp cache inventory."""

from __future__ import annotations

import contextlib
import math
import os
import re
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import backend, project_dir as host_project_dir
from winbox.kdbg.decomp.docker import project_dir

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROJECT = re.compile(r"^[A-Za-z0-9_]+$")
_MAX_UNATTRIBUTED = 100
_MAX_METADATA_BYTES = 64 * 1024


def _safe_float(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return result if math.isfinite(result) else 0.0


def _binary_for_digest(root: Path, digest: str) -> Path | None:
    return next((
        path for path in [root / digest, *root.glob(f"{digest}.*")]
        if path.is_file() and not path.is_symlink()
        and not path.name.endswith((".lock", ".part"))
    ), None)


def _tree_size(path: Path) -> int:
    if path.is_symlink():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    try:
        for root, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
            for name in files:
                candidate = Path(root) / name
                if not candidate.is_symlink():
                    with contextlib.suppress(OSError):
                        total += candidate.stat().st_size
    except OSError:
        pass
    return total


def _regular_files(path: Path) -> set[Path]:
    """Return regular files below ``path`` without following symlinks."""
    if path.is_symlink():
        return set()
    if path.is_file():
        return {path}
    files: set[Path] = set()
    try:
        for walk_root, dirs, names in os.walk(path, followlinks=False):
            base = Path(walk_root)
            dirs[:] = [name for name in dirs if not (base / name).is_symlink()]
            for name in names:
                candidate = base / name
                if candidate.is_file() and not candidate.is_symlink():
                    files.add(candidate)
    except OSError:
        pass
    return files


def _files_size(paths: set[Path]) -> int:
    total = 0
    for path in paths:
        with contextlib.suppress(OSError):
            total += path.stat().st_size
    return total


def _entry_files(
    root: Path, projects: Path, digest: str, project_names: list[str],
) -> set[Path]:
    paths: set[Path] = set()
    for directory in (root / "binaries", root / "verified-binaries"):
        for path in [directory / digest, *directory.glob(f"{digest}.*")]:
            paths.update(_regular_files(path))
    paths.update(_regular_files(root / "metadata" / f"{digest}.json"))
    for directory in ("provenance", "enrichment", "enrichment-results"):
        for path in (root / directory).glob(f"*_{digest}.json"):
            paths.update(_regular_files(path))
    paths.update(_regular_files(root / "binaries" / f"{digest}.stage.lock"))
    for name in project_names:
        if not _PROJECT.fullmatch(name):
            continue
        for suffix in (".gpr", ".rep", ".lock", ".lock~"):
            paths.update(_regular_files(projects / f"{name}{suffix}"))
    return paths


def _unattributed_inventory(
    cache_root: Path, projects: Path, owned: set[Path],
) -> tuple[list[dict[str, Any]], int, int]:
    records: list[dict[str, Any]] = []
    total_count = 0
    total_bytes = 0
    for label, root in (("cache", cache_root), ("projects", projects)):
        for path in sorted(_regular_files(root), key=lambda item: str(item)):
            if path in owned:
                continue
            total_count += 1
            try:
                size = path.stat().st_size
                relative = str(path.relative_to(root))
            except (OSError, ValueError):
                continue
            total_bytes += size
            if len(records) < _MAX_UNATTRIBUTED:
                records.append({"root": label, "path": relative[:1024], "size_bytes": size})
    return records, total_count, total_bytes


def _project_names(root: Path, digest: str, preferred: str = "") -> list[str]:
    names = []
    if _PROJECT.fullmatch(preferred):
        names.append(preferred)
    for path in root.glob(f"*_{digest}.gpr"):
        if _PROJECT.fullmatch(path.stem) and path.stem not in names:
            names.append(path.stem)
    return names


def _active_project_dir(cfg: Config) -> Path:
    """Match the project root used by the selected worker backend."""
    return project_dir(cfg) if backend() == "docker" else host_project_dir()
