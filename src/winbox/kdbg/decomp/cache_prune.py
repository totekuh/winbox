"""Explicit LRU pruning and repair for the Ghidra decomp cache."""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

from winbox.kdbg.decomp.cache import cache_inventory
from winbox.kdbg.decomp.cache_fs import _DIGEST, _PROJECT, _safe_float
from winbox.kdbg.decomp.client import (
    DecompClient,
    DecompError,
    cache_dir,
    maintenance_lock,
)
from winbox.kdbg.decomp.docker import project_dir

from winbox.config import Config


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
