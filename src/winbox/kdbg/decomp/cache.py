"""Bounded inventory and explicit LRU pruning for Ghidra analysis state."""

from __future__ import annotations

import json
import contextlib
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError, cache_dir
from winbox.kdbg.decomp.docker import project_dir

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROJECT = re.compile(r"^[A-Za-z0-9_]+$")


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


def _project_names(root: Path, digest: str, preferred: str = "") -> list[str]:
    names = []
    if _PROJECT.fullmatch(preferred):
        names.append(preferred)
    for path in root.glob(f"*_{digest}.gpr"):
        if _PROJECT.fullmatch(path.stem) and path.stem not in names:
            names.append(path.stem)
    return names


def cache_inventory(cfg: Config) -> dict[str, Any]:
    root = cache_dir(cfg)
    binaries = root / "binaries"
    projects = project_dir(cfg)
    entries = []
    known: set[str] = set()
    metadata = root / "metadata"
    for path in sorted(metadata.glob("*.json"))[:10_000]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            digest = str(value["sha256"])
            if not _DIGEST.fullmatch(digest):
                continue
        except (OSError, ValueError, KeyError, TypeError):
            continue
        known.add(digest)
        binary = _binary_for_digest(binaries, digest)
        verified = _binary_for_digest(root / "verified-binaries", digest)
        name = str(value.get("project_name") or "")
        project_names = _project_names(projects, digest, name)
        project_paths = [
            path for project in project_names
            for path in (projects / f"{project}.gpr", projects / f"{project}.rep")
        ]
        size = sum(_tree_size(p) for p in (binary, verified) if p is not None)
        size += sum(_tree_size(p) for p in project_paths)
        entries.append({
            "sha256": digest, "binary_name": value.get("binary_name"),
            "project_name": name or None, "last_used": value.get("last_used"),
            "related_projects": project_names,
            "size_bytes": size, "binary_present": binary is not None,
            "verified_snapshot_present": verified is not None,
            "project_present": any(p.exists() for p in project_paths),
            "analysis_profile": value.get("analysis_profile"),
            "ghidra_version": value.get("ghidra_version"),
        })
    # Older worker APIs did not emit metadata. Recover useful inventory from
    # the full digest embedded in immutable binary and project names.
    discovered: set[str] = set()
    for path in binaries.glob("*"):
        digest = path.name.split(".", 1)[0]
        if (path.is_file() and not path.name.endswith((".lock", ".part"))
                and _DIGEST.fullmatch(digest)):
            discovered.add(digest)
    for path in projects.glob("*.gpr"):
        name = path.stem
        digest = name.rsplit("_", 1)[-1]
        if _DIGEST.fullmatch(digest):
            discovered.add(digest)
    for digest in discovered:
        if digest in known:
            continue
        binary = _binary_for_digest(binaries, digest)
        verified = _binary_for_digest(root / "verified-binaries", digest)
        project_names = _project_names(projects, digest)
        name = project_names[0] if project_names else None
        project_paths = [
            path for project in project_names
            for path in (projects / f"{project}.gpr", projects / f"{project}.rep")
        ]
        size = sum(_tree_size(p) for p in (binary, verified) if p is not None)
        size += sum(_tree_size(p) for p in project_paths)
        mtimes = []
        for path in [binary, verified, *project_paths]:
            if path is not None:
                with contextlib.suppress(OSError):
                    mtimes.append(path.stat().st_mtime)
        entries.append({
            "sha256": digest, "binary_name": binary.name if binary else None,
            "project_name": name, "last_used": max(mtimes) if mtimes else None,
            "related_projects": project_names,
            "size_bytes": size, "binary_present": binary is not None,
            "verified_snapshot_present": verified is not None,
            "project_present": any(p.exists() for p in project_paths),
            "analysis_profile": "legacy-unknown", "ghidra_version": None,
        })
    total = _tree_size(root) + _tree_size(projects)
    return {
        "schema": "winbox.decomp-cache/1", "total_bytes": total,
        "entry_count": len(entries), "entries": sorted(
            entries, key=lambda x: float(x.get("last_used") or 0), reverse=True
        ),
        "binary_dir": str(binaries), "project_dir": str(projects),
        "metadata_truncated": sum(1 for _ in zip(range(10_001), metadata.glob("*.json"))) > 10_000,
    }


def prune_cache(
    cfg: Config, *, max_bytes: int = 0, older_than_days: float = 0,
    dry_run: bool = True,
) -> dict[str, Any]:
    if max_bytes < 0 or older_than_days < 0:
        raise DecompError("cache prune limits must not be negative")
    if max_bytes == 0 and older_than_days == 0:
        raise DecompError("max_bytes or older_than_days must be supplied for cache prune")
    inventory = cache_inventory(cfg)
    entries = sorted(inventory["entries"], key=lambda x: float(x.get("last_used") or 0))
    now = time.time()
    remaining = int(inventory["total_bytes"])
    selected = []
    for entry in entries:
        old = bool(older_than_days and now - float(entry.get("last_used") or 0) >= older_than_days * 86400)
        oversized = bool(max_bytes and remaining > max_bytes)
        if not old and not oversized:
            continue
        selected.append(entry)
        remaining = max(0, remaining - int(entry["size_bytes"]))
    if not dry_run and selected and DecompClient(cfg).worker_alive():
        raise DecompError("stop the Ghidra worker before applying cache prune")
    removed = 0
    if not dry_run:
        root = cache_dir(cfg)
        projects = project_dir(cfg)
        for entry in selected:
            digest = str(entry["sha256"])
            names = entry.get("related_projects") or [entry.get("project_name")]
            if not _DIGEST.fullmatch(digest):
                continue
            for path in [root / "binaries" / digest, *(root / "binaries").glob(f"{digest}.*")]:
                if path.is_file() and not path.is_symlink():
                    path.unlink(missing_ok=True)
            for path in [root / "verified-binaries" / digest, *(root / "verified-binaries").glob(f"{digest}.*")]:
                if path.is_file() and not path.is_symlink():
                    path.unlink(missing_ok=True)
            for raw_name in names:
                name = str(raw_name or "")
                if _PROJECT.fullmatch(name):
                    (projects / f"{name}.gpr").unlink(missing_ok=True)
                    rep = projects / f"{name}.rep"
                    if rep.is_dir() and not rep.is_symlink():
                        shutil.rmtree(rep)
            (root / "metadata" / f"{digest}.json").unlink(missing_ok=True)
            for path in (root / "provenance").glob(f"*_{digest}.json"):
                path.unlink(missing_ok=True)
            removed += 1
    return {
        "schema": "winbox.decomp-cache-prune/1", "dry_run": bool(dry_run),
        "selected_count": len(selected), "removed_count": removed,
        "reclaimable_bytes": sum(int(e["size_bytes"]) for e in selected),
        "estimated_remaining_bytes": remaining,
        "selected": selected,
    }
