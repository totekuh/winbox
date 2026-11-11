"""Background prepare job launch, status polling, and cancellation."""

from __future__ import annotations

import contextlib
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError, cache_dir
from winbox.kdbg.decomp.service.prepare import (
    PREPARE_JOB_HEARTBEAT_STALE,
    PREPARE_JOB_MAX_AGE,
    PREPARE_JOB_MAX_RETAINED,
    PREPARE_JOB_SCHEMA,
    PREPARE_JOB_START_GRACE,
    _PREPARE_TOKEN,
    _load_prepare_job,
    _lost_prepare_job,
    _prepare_job_dir,
    _prepare_job_path,
    _prepare_modules,
    _process_identity,
    _process_start_ticks,
    _write_prepare_job,
)


def _reconcile_prepare_job(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    if value.get("schema") != PREPARE_JOB_SCHEMA:
        result["process_liveness"] = "legacy-unknown"
        return result
    state = str(value.get("state") or "")
    now = time.time()
    heartbeat = float(value.get("heartbeat_at") or value.get("started_at") or 0)
    result["heartbeat_age_seconds"] = max(0.0, now - heartbeat) if heartbeat else None
    identity = "not-applicable"
    if state == "starting":
        identity = _process_identity(
            value.get("launcher_pid"), value.get("launcher_start_ticks"),
        )
        started = float(value.get("started_at") or 0)
        if identity in {"dead", "replaced"} and now - started >= PREPARE_JOB_START_GRACE:
            result = _lost_prepare_job(
                path, value, f"prepare launcher identity became {identity} before child startup",
            )
            identity = "dead"
    elif state in {"running", "cancelling"}:
        identity = _process_identity(value.get("pid"), value.get("process_start_ticks"))
        if (
            identity in {"dead", "replaced"}
            and now - heartbeat >= PREPARE_JOB_HEARTBEAT_STALE
        ):
            result = _lost_prepare_job(
                path, value, f"prepare child identity became {identity}",
            )
    result["process_liveness"] = identity
    cancel = path.with_suffix(".cancel")
    result["cancellation_state"] = (
        "requested" if cancel.is_file() and not cancel.is_symlink()
        else str(result.get("cancellation_state") or "not_requested")
    )
    return result


def _retain_prepare_jobs(cfg: Config) -> dict[str, int]:
    """Bound terminal job records; never remove active or untrusted paths."""
    root = _prepare_job_dir(cfg)
    now = time.time()
    terminal: list[tuple[float, Path]] = []
    for path in root.glob("*.json"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            value = _reconcile_prepare_job(path, _load_prepare_job(path))
            if value.get("state") in {"completed", "partial", "failed", "cancelled", "lost"}:
                terminal.append((path.stat().st_mtime, path))
        except (DecompError, OSError):
            continue
    terminal.sort(reverse=True)
    selected = [
        path for index, (mtime, path) in enumerate(terminal)
        if index >= PREPARE_JOB_MAX_RETAINED or now - mtime > PREPARE_JOB_MAX_AGE
    ]
    removed_bytes = 0
    for path in selected:
        for candidate in (path, path.with_suffix(".log"), path.with_suffix(".cancel")):
            if candidate.is_file() and not candidate.is_symlink():
                with contextlib.suppress(OSError):
                    removed_bytes += candidate.stat().st_size
                    candidate.unlink()
    return {"removed_jobs": len(selected), "removed_bytes": removed_bytes}


def start_prepare_background(
    cfg: Config, *, modules: list[str] | tuple[str, ...], analysis_timeout: int = 900,
    force_enrichment: bool = False,
) -> dict[str, Any]:
    """Launch an offline prepare child and persist a durable token."""
    if isinstance(analysis_timeout, bool) or not isinstance(analysis_timeout, int):
        raise DecompError("analysis_timeout must be an integer", code="invalid_argument")
    if not 5 <= analysis_timeout <= 1800:
        raise DecompError(
            "analysis_timeout must be between 5 and 1800 seconds",
            code="invalid_argument",
        )
    if not isinstance(force_enrichment, bool):
        raise DecompError("force_enrichment must be a boolean", code="invalid_argument")
    selected = _prepare_modules(cfg, list(modules))
    token = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    root = _prepare_job_dir(cfg)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    retention = _retain_prepare_jobs(cfg)
    initial_path = root / f"{token}.json"
    initial = {
        "schema": PREPARE_JOB_SCHEMA,
        "token": token, "state": "starting", "pid": None,
        "nonce": nonce, "modules": selected, "started_at": time.time(),
        "heartbeat_at": time.time(), "launcher_pid": os.getpid(),
        "launcher_start_ticks": _process_start_ticks(os.getpid()),
        "analysis_timeout": analysis_timeout,
        "force_enrichment": force_enrichment,
    }
    _write_prepare_job(initial_path, initial)
    command = [
        sys.executable, "-m", "winbox.kdbg.decomp.prewarm",
        "--state-root", str(cfg.winbox_dir), "--token", token,
        "--nonce", nonce,
        "--analysis-timeout", str(analysis_timeout),
    ]
    if force_enrichment:
        command.append("--force-enrichment")
    for name in selected:
        command.extend(["--module", name])
    log_path = root / f"{token}.log"
    try:
        with log_path.open("ab", buffering=0) as output:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                close_fds=True, start_new_session=True,
            )
    except OSError as exc:
        failed = {
            **initial,
            "token": token, "state": "failed", "pid": None,
            "modules": selected, "completed_at": time.time(),
            "error": {"code": "worker_start_failed", "message": str(exc)[:2048]},
        }
        _write_prepare_job(initial_path, failed)
        raise DecompError(
            f"could not start background preparation: {exc}",
            code="worker_start_failed", retryable=True,
        ) from exc
    threading.Thread(target=process.wait, daemon=True).start()
    return {
        "schema": PREPARE_JOB_SCHEMA,
        "token": token, "state": "starting", "pid": process.pid,
        "modules": selected, "analysis_timeout": analysis_timeout,
        "force_enrichment": force_enrichment,
        "retention": retention,
    }


def prepare_status(cfg: Config, *, token: str = "") -> dict[str, Any]:
    root = _prepare_job_dir(cfg)
    if token:
        if not _PREPARE_TOKEN.fullmatch(token):
            raise DecompError("invalid prepare token", code="invalid_argument")
        path = root / f"{token}.json"
    else:
        candidates = []
        for candidate in root.glob("*.json"):
            try:
                if candidate.is_file() and not candidate.is_symlink():
                    candidates.append((candidate.stat().st_mtime, candidate))
            except OSError:
                continue
        candidates.sort(reverse=True)
        if not candidates:
            return {"schema": PREPARE_JOB_SCHEMA, "state": "none"}
        path = candidates[0][1]
    return _reconcile_prepare_job(path, _load_prepare_job(path))


def cancel_prepare_job(cfg: Config, *, token: str) -> dict[str, Any]:
    if not _PREPARE_TOKEN.fullmatch(str(token or "")):
        raise DecompError("invalid prepare token", code="invalid_argument")
    path = _prepare_job_path(cfg, token)
    value = _reconcile_prepare_job(path, _load_prepare_job(path))
    if value.get("state") not in {"starting", "running", "cancelling"}:
        raise DecompError(
            f"prepare job is not active ({value.get('state', 'unknown')})",
            code="not_running",
        )
    marker = path.with_suffix(".cancel")
    if marker.is_symlink():
        raise DecompError("unsafe prepare cancellation marker", code="invalid_argument")
    _write_prepare_job(marker, {
        "schema": "winbox.decomp-prepare-cancel/1",
        "token": token, "nonce": value["nonce"], "requested_at": time.time(),
    })
    return {
        "schema": "winbox.decomp-prepare-cancel/1",
        "cancel_requested": True, "token": token,
        "state": value.get("state"), "pid": value.get("pid"),
    }
