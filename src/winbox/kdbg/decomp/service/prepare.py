"""Synchronous module preparation and job file I/O primitives."""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError, cache_dir
from winbox.kdbg.store import SymbolStore, SymbolStoreError

MAX_PREPARE_MODULES = 256
PREPARE_JOB_SCHEMA = "winbox.decomp-prepare-job/2"
PREPARE_JOB_LEGACY_SCHEMA = "winbox.decomp-prepare-job/1"
PREPARE_JOB_MAX_BYTES = 2 * 1024 * 1024
PREPARE_JOB_MAX_RETAINED = 128
PREPARE_JOB_MAX_AGE = 30 * 86400
PREPARE_JOB_START_GRACE = 5.0
PREPARE_JOB_HEARTBEAT_STALE = 5.0
_PREPARE_TOKEN = re.compile(r"^[0-9a-f]{32}$")


def _prepare_modules(cfg: Config, module: str | list[str] | tuple[str, ...]) -> list[str]:
    store = SymbolStore(cfg.symbols_dir)
    available = store.list_modules()
    if isinstance(module, str):
        requested = [module]
    elif isinstance(module, (list, tuple)) and all(isinstance(x, str) for x in module):
        requested = list(module)
    else:
        raise DecompError("module must be a string or list of strings", code="invalid_argument")
    if len(requested) == 1 and requested[0].strip().lower() == "all":
        selected = available
    else:
        lookup = {name.lower(): name for name in available}
        selected = []
        for raw in requested:
            name = raw.strip()
            match = lookup.get(name.lower())
            if not name or match is None:
                raise DecompError(
                    f"symbol module is not loaded: {raw}", code="cache_entry_missing",
                )
            if match not in selected:
                selected.append(match)
    if not selected:
        raise DecompError("no exact symbol modules are available", code="cache_entry_missing")
    if len(selected) > MAX_PREPARE_MODULES:
        raise DecompError(
            f"prepare selection exceeds {MAX_PREPARE_MODULES} modules",
            code="invalid_argument",
        )
    return selected


def prepare_decomp(
    cfg: Config, *, module: str | list[str] | tuple[str, ...] = "all",
    analysis_timeout: int = 900, force_enrichment: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
    cancel_requested: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Analyze exact staged artifacts without requiring a debugger stop."""
    if isinstance(analysis_timeout, bool) or not isinstance(analysis_timeout, int):
        raise DecompError("analysis_timeout must be an integer", code="invalid_argument")
    if not 5 <= analysis_timeout <= 1800:
        raise DecompError(
            "analysis_timeout must be between 5 and 1800 seconds",
            code="invalid_argument",
        )
    selected = _prepare_modules(cfg, module)
    store = SymbolStore(cfg.symbols_dir)
    from winbox.kdbg.decomp.enrichment import build_enrichment
    client = DecompClient(cfg)
    started = time.monotonic()
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, name in enumerate(selected):
        if cancel_requested is not None and cancel_requested():
            failures.extend({
                "module": pending[:260], "code": "cancelled",
                "error": "background preparation was cancelled",
            } for pending in selected[index:])
            break
        request_id = ""
        if progress is not None:
            progress({
                "module": name, "index": index + 1, "total": len(selected),
                "request_id": "", "state": "extracting_enrichment",
            })
        try:
            record = store.load(name)
            sidecar, enrichment = build_enrichment(
                cfg, store, name, force=force_enrichment,
                cancel_requested=cancel_requested,
            )
            if cancel_requested is not None and cancel_requested():
                raise DecompError(
                    "background preparation was cancelled",
                    code="cancelled", retryable=True,
                )
            request_id = secrets.token_hex(16)
            if progress is not None:
                progress({
                    "module": name, "index": index + 1, "total": len(selected),
                    "request_id": request_id, "state": "module_started",
                })
            result = client.call(
                "prepare", timeout=float(analysis_timeout) + 90.0,
                request_id=request_id,
                binary=str(record.get("pe_path") or ""),
                binary_name=name,
                sha256=str(record.get("pe_sha256") or ""),
                analysis_timeout=analysis_timeout,
                enrichment=str(sidecar),
            )
            results.append({
                "module": name,
                "pdb_build": enrichment.get("pdb_build"),
                **result,
            })
        except (DecompError, SymbolStoreError, OSError, ValueError) as exc:
            failures.append({
                "module": name[:260],
                "code": str(getattr(exc, "code", None) or "operation_failed")[:64],
                "error": str(getattr(exc, "message", exc))[:512],
            })
        finally:
            if progress is not None:
                progress({
                    "module": name, "index": index + 1, "total": len(selected),
                    "request_id": "", "state": "module_finished",
                })
    return {
        "schema": "winbox.decomp-prepare-batch/1",
        "requested": len(selected),
        "prepared": len(results),
        "failed": len(failures),
        "results": results[:MAX_PREPARE_MODULES],
        "failures": failures[:64],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _prepare_job_dir(cfg: Config) -> Path:
    return cache_dir(cfg).parent / "prepare-jobs"


def _prepare_job_path(cfg: Config, token: str) -> Path:
    return _prepare_job_dir(cfg) / f"{token}.json"


def _write_prepare_job(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _process_start_ticks(pid: int) -> int | None:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None
    try:
        suffix = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1]
        return int(suffix.split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _process_identity(pid: Any, start_ticks: Any) -> str:
    try:
        expected_pid = int(pid)
        expected_ticks = int(start_ticks)
    except (TypeError, ValueError):
        return "unknown"
    observed = _process_start_ticks(expected_pid)
    if observed is None:
        return "dead"
    return "alive" if observed == expected_ticks else "replaced"


def _load_prepare_job(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise ValueError("prepare status must not be a symlink")
        if path.stat().st_size > PREPARE_JOB_MAX_BYTES:
            raise ValueError("prepare status exceeds size cap")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise DecompError(
            f"cannot read prepare status: {exc}", code="invalid_response",
        ) from exc
    if not isinstance(value, dict) or value.get("schema") not in {
        PREPARE_JOB_SCHEMA, PREPARE_JOB_LEGACY_SCHEMA,
    }:
        raise DecompError("invalid prepare status", code="invalid_response")
    token = str(value.get("token") or "")
    if not _PREPARE_TOKEN.fullmatch(token) or path.stem != token:
        raise DecompError("prepare status identity mismatch", code="identity_mismatch")
    if value.get("schema") == PREPARE_JOB_SCHEMA:
        nonce = str(value.get("nonce") or "")
        if not _PREPARE_TOKEN.fullmatch(nonce):
            raise DecompError("prepare job nonce is invalid", code="invalid_response")
    return value


def _lost_prepare_job(path: Path, value: dict[str, Any], reason: str) -> dict[str, Any]:
    lost = dict(value)
    lost.update({
        "state": "lost", "completed_at": time.time(),
        "error": {
            "code": "worker_lost",
            "message": reason[:2048],
        },
    })
    _write_prepare_job(path, lost)
    return lost
