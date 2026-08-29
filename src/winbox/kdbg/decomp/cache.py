"""Bounded inventory and explicit LRU pruning for Ghidra analysis state."""

from __future__ import annotations

import json
import contextlib
import math
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import (
    DecompClient,
    DecompError,
    backend,
    cache_dir,
    maintenance_lock,
    project_dir as host_project_dir,
)
from winbox.kdbg.decomp.enrichment import ANALYSIS_PROFILE
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


def analysis_readiness(cfg: Config, sha256: str) -> dict[str, Any]:
    """Whether an exact digest has a complete current-profile analysis project.

    This is intentionally a cheap host-side assertion.  A missing/corrupt or
    profile-mismatched project is *not* treated as warm merely because some
    cache residue exists; callers can then avoid silently analyzing it while a
    debugger has the guest stopped.
    """
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
        if metadata_path.stat().st_size > _MAX_METADATA_BYTES:
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


def repair_cache(cfg: Config, *, sha256: str) -> dict[str, Any]:
    """Delete and rebuild exactly one digest-keyed project cache."""
    digest = str(sha256 or "").strip().lower()
    if not _DIGEST.fullmatch(digest):
        raise DecompError(
            f"invalid sha256 selector: {digest[:80]}", code="invalid_argument",
        )
    return DecompClient(cfg).call("repair", sha256=digest, timeout=900.0)


def prune_cache(
    cfg: Config, *, max_bytes: int = 0, older_than_days: float = 0,
    sha256: list[str] | tuple[str, ...] | str | None = None,
    project: list[str] | tuple[str, ...] | str | None = None,
    module: list[str] | tuple[str, ...] | str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    if max_bytes < 0 or older_than_days < 0:
        raise DecompError(
            "cache prune limits must not be negative", code="invalid_argument",
        )
    selectors = _normalize_selectors(sha256=sha256, project=project, module=module)
    if max_bytes == 0 and older_than_days == 0 and not any(selectors.values()):
        raise DecompError(
            "max_bytes, older_than_days, sha256, project, or module must be supplied "
            "for cache prune", code="invalid_argument",
        )
    if dry_run:
        return _prune_cache(
            cfg, max_bytes=max_bytes, older_than_days=older_than_days,
            selectors=selectors, dry_run=True,
        )
    with maintenance_lock(cfg):
        # Inventory, ownership validation, and deletion all occur under one
        # lock. Paths selected by a dry run are never trusted for an apply.
        return _prune_cache(
            cfg, max_bytes=max_bytes, older_than_days=older_than_days,
            selectors=selectors, dry_run=False,
        )


def _selector_values(value: list[str] | tuple[str, ...] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        raise DecompError("cache selectors must be strings or lists", code="invalid_argument")
    return [str(item).strip() for item in values if str(item).strip()]


def _normalize_selectors(*, sha256, project, module) -> dict[str, list[str]]:
    digests = [value.lower() for value in _selector_values(sha256)]
    projects = _selector_values(project)
    modules = _selector_values(module)
    invalid_digest = next((value for value in digests if not _DIGEST.fullmatch(value)), None)
    if invalid_digest is not None:
        raise DecompError(
            f"invalid sha256 selector: {invalid_digest[:80]}", code="invalid_argument",
        )
    invalid_project = next((value for value in projects if not _PROJECT.fullmatch(value)), None)
    if invalid_project is not None:
        raise DecompError(
            f"invalid project selector: {invalid_project[:80]}", code="invalid_argument",
        )
    invalid_module = next((value for value in modules if (
        len(value) > 260 or "\0" in value or "/" in value or "\\" in value
    )), None)
    if invalid_module is not None:
        raise DecompError(
            f"invalid module selector: {invalid_module[:80]}", code="invalid_argument",
        )
    return {
        "sha256": sorted(set(digests)),
        "project": sorted(set(projects)),
        "module": sorted(set(modules), key=str.lower),
    }


def _prune_cache(
    cfg: Config, *, max_bytes: int, older_than_days: float,
    selectors: dict[str, list[str]], dry_run: bool,
) -> dict[str, Any]:
    inventory = cache_inventory(cfg)
    entries = sorted(inventory["entries"], key=lambda x: _safe_float(x.get("last_used")))
    now = time.time()
    remaining = int(inventory["total_bytes"])
    remaining_owned = int(inventory["owned_bytes"])
    selected = []
    matched = {key: set() for key in selectors}
    for entry in entries:
        digest = str(entry.get("sha256") or "")
        project_names = {
            str(value) for value in (
                entry.get("related_projects") or [entry.get("project_name")]
            ) if value
        }
        binary_name = str(entry.get("binary_name") or "")
        exact = False
        if digest in selectors["sha256"]:
            matched["sha256"].add(digest)
            exact = True
        for value in selectors["project"]:
            if value in project_names:
                matched["project"].add(value)
                exact = True
        for value in selectors["module"]:
            if value.casefold() == binary_name.casefold():
                matched["module"].add(value)
                exact = True
        old = bool(
            older_than_days
            and now - _safe_float(entry.get("last_used")) >= older_than_days * 86400
        )
        oversized = bool(max_bytes and remaining > max_bytes)
        if not exact and not old and not oversized:
            continue
        selected.append(entry)
        remaining = max(0, remaining - int(entry["size_bytes"]))
        remaining_owned = max(0, remaining_owned - int(entry["size_bytes"]))
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
                    (projects / f"{name}.lock").unlink(missing_ok=True)
                    (projects / f"{name}.lock~").unlink(missing_ok=True)
                    rep = projects / f"{name}.rep"
                    if rep.is_dir() and not rep.is_symlink():
                        shutil.rmtree(rep)
            (root / "metadata" / f"{digest}.json").unlink(missing_ok=True)
            (root / "binaries" / f"{digest}.stage.lock").unlink(missing_ok=True)
            for directory in ("provenance", "enrichment", "enrichment-results"):
                for path in (root / directory).glob(f"*_{digest}.json"):
                    if path.is_file() and not path.is_symlink():
                        path.unlink(missing_ok=True)
            removed += 1
    return {
        "schema": "winbox.decomp-cache-prune/1", "dry_run": bool(dry_run),
        "selected_count": len(selected), "removed_count": removed,
        "reclaimable_bytes": sum(int(e["size_bytes"]) for e in selected),
        "estimated_remaining_bytes": remaining,
        "estimated_remaining_owned_bytes": remaining_owned,
        "estimated_remaining_overhead_bytes": int(inventory["overhead_bytes"]),
        "requested_max_bytes": max_bytes or None,
        "residual_bytes_above_limit": (
            max(0, remaining - max_bytes) if max_bytes else 0
        ),
        "selectors": selectors,
        "unmatched_selectors": {
            key: [value for value in values if value not in matched[key]]
            for key, values in selectors.items()
        },
        "selected": selected,
    }
