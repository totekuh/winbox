"""Bounded inventory and readiness checks for Ghidra analysis state."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.cache_fs import (
    _DIGEST, _PROJECT,
    _active_project_dir, _binary_for_digest, _entry_files, _files_size,
    _project_names, _safe_float, _tree_size, _unattributed_inventory,
)
from winbox.kdbg.decomp.client import cache_dir
from winbox.kdbg.decomp.docker import project_dir
from winbox.kdbg.decomp.enrichment import ANALYSIS_PROFILE


def analysis_readiness(cfg: Config, sha256: str) -> dict[str, Any]:
    """Whether an exact digest has a complete current-profile analysis project."""
    digest = str(sha256 or "").lower()
    result: dict[str, Any] = {
        "schema": "winbox.decomp-analysis-readiness/1",
        "sha256": digest,
        "ready": False,
        "reason": "invalid_digest",
        "analysis_profile": ANALYSIS_PROFILE,
        "project_name": None,
    }
    if not _DIGEST.fullmatch(digest):
        return result
    metadata_path = cache_dir(cfg) / "metadata" / f"{digest}.json"
    try:
        if metadata_path.is_symlink():
            result["reason"] = "metadata_symlink"
            return result
        if metadata_path.stat().st_size > 64 * 1024:
            result["reason"] = "metadata_oversized"
            return result
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result["reason"] = "metadata_missing"
        return result
    except (OSError, ValueError, TypeError):
        result["reason"] = "metadata_invalid"
        return result
    if not isinstance(metadata, dict) or metadata.get("sha256") != digest:
        result["reason"] = "metadata_identity_mismatch"
        return result
    name = str(metadata.get("project_name") or "")
    result["project_name"] = name or None
    if not _PROJECT.fullmatch(name):
        result["reason"] = "project_name_invalid"
        return result
    if metadata.get("analysis_profile") != ANALYSIS_PROFILE:
        result["reason"] = "analysis_profile_mismatch"
        result["cached_analysis_profile"] = str(metadata.get("analysis_profile") or "")[:128]
        return result
    root = _active_project_dir(cfg)
    project_file = root / f"{name}.gpr"
    project_repo = root / f"{name}.rep"
    if project_file.is_symlink() or project_repo.is_symlink():
        result["reason"] = "project_symlink"
        return result
    if not project_file.is_file() or not project_repo.is_dir():
        result["reason"] = "project_missing"
        return result
    result.update(
        ready=True,
        reason="ready",
        ghidra_version=str(metadata.get("ghidra_version") or "")[:128] or None,
    )
    return result


def cache_inventory(cfg: Config) -> dict[str, Any]:
    root = cache_dir(cfg)
    binaries = root / "binaries"
    projects = project_dir(cfg)
    entries = []
    owned_files: set[Path] = set()
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
        entry_files = _entry_files(root, projects, digest, project_names)
        owned_files.update(entry_files)
        size = _files_size(entry_files)
        entries.append({
            "sha256": digest, "binary_name": value.get("binary_name"),
            "project_name": name or None,
            "last_used": _safe_float(value.get("last_used")) or None,
            "related_projects": project_names,
            "size_bytes": size, "binary_present": binary is not None,
            "verified_snapshot_present": verified is not None,
            "project_present": any(p.exists() for p in project_paths),
            "analysis_profile": value.get("analysis_profile"),
            "ghidra_version": value.get("ghidra_version"),
        })
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
    for directory in ("enrichment", "enrichment-results", "provenance"):
        for path in (root / directory).glob("*.json"):
            if path.is_file() and not path.is_symlink():
                digest = path.stem.rsplit("_", 1)[-1]
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
        entry_files = _entry_files(root, projects, digest, project_names)
        owned_files.update(entry_files)
        size = _files_size(entry_files)
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
    unattributed, unattributed_count, unattributed_bytes = _unattributed_inventory(
        root, projects, owned_files,
    )
    owned_bytes = _files_size(owned_files)
    return {
        "schema": "winbox.decomp-cache/1", "total_bytes": total,
        "owned_bytes": owned_bytes,
        "overhead_bytes": max(0, total - owned_bytes),
        "entry_count": len(entries), "entries": sorted(
            entries, key=lambda x: _safe_float(x.get("last_used")), reverse=True
        ),
        "binary_dir": str(binaries), "project_dir": str(projects),
        "unattributed_files": unattributed,
        "unattributed_file_count": unattributed_count,
        "unattributed_bytes": unattributed_bytes,
        "unattributed_truncated": unattributed_count > len(unattributed),
        "metadata_truncated": sum(1 for _ in zip(range(10_001), metadata.glob("*.json"))) > 10_000,
    }


from winbox.kdbg.decomp.cache_prune import prune_cache, repair_cache  # noqa: E402, F401
