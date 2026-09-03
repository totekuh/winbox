"""Composition layer joining a live kdbg stop to focused Ghidra output."""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError, cache_dir
from winbox.kdbg.decomp.identity import (
    IdentityError,
    parse_live_pe,
    parse_static_pe,
    static_bytes_at_rva,
    validate_identity,
)
from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.format import symbolicate_va
from winbox.kdbg.store import SymbolStore, SymbolStoreError


MAX_CONTEXT_LINES = 20
MAX_LIVE_READ = 64 * 1024
MAX_LINE_BATCH = 100
DETAIL_LEVELS = {"compact", "standard", "diagnostic"}
ASSEMBLY_MODES = {"nearby", "mapped"}


def _wrapped_decomp_error(prefix: str, exc: BaseException) -> DecompError:
    return DecompError(
        f"{prefix}: {getattr(exc, 'message', exc)}",
        code=getattr(exc, "code", None),
        retryable=bool(getattr(exc, "retryable", False)),
        details=getattr(exc, "details", {}),
    )


def worker_status(cfg: Config) -> dict[str, Any]:
    return DecompClient(cfg).status()


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


def cancel_decomp(
    cfg: Config, *, request_id: str = "", token: str = "",
) -> dict[str, Any]:
    if request_id and token:
        raise DecompError(
            "request_id and token are mutually exclusive", code="invalid_argument",
        )
    if token:
        return cancel_prepare_job(cfg, token=token)
    return DecompClient(cfg).cancel(request_id)


def install_service(cfg: Config, *, pull: bool = True) -> dict[str, Any]:
    """Build the pinned, self-contained PyGhidra image."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).install(pull=pull)
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def start_service(cfg: Config) -> dict[str, Any]:
    """Start the private Unix-socket API without loading the JVM yet."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    manager = DockerManager(cfg)
    try:
        # Do not stop a legacy host worker unless the replacement image is
        # definitely available.
        if manager.image_info() is None:
            raise DockerError(
                "PyGhidra image is not installed; run `winbox kdbg ghidra install`"
            )
        DecompClient(cfg).ensure_selected_backend()
        result = manager.start()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc
    # Prove the API, not merely Docker's process state.
    status = DecompClient(cfg).call("status", start=False, timeout=10.0)
    return {**result, "api": status}


def stop_service(cfg: Config) -> dict[str, Any]:
    """Stop and remove only the precisely labelled winbox container."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).stop()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def query_decomp(
    cfg: Config,
    *,
    addr: str = "",
    symbol: str = "",
    module: str = "",
    rva: str = "",
    cursor: str = "",
    before: int = 3,
    after: int = 5,
    full: bool = False,
    binary: str = "",
    timeout: int = 60,
    analysis_timeout: int = 900,
    detail: str = "compact",
    lines: str = "",
    assembly: str = "nearby",
    instruction_bytes: bool = False,
    runtime_vas: bool = False,
    callers: bool = False,
    callees: bool = False,
    allow_cold: bool = False,
    daemon_client: DaemonClient | None = None,
    decomp_client: DecompClient | None = None,
) -> dict[str, Any]:
    """Return focused pseudocode for ``addr`` (current RIP by default).

    The order is intentionally fail-closed: fresh live module resolution,
    exact PE identity validation, RVA mapping, and only then Ghidra. A stale
    same-named file never reaches the decompiler cache.
    """
    before = _bounded_int("before", before, 0, MAX_CONTEXT_LINES)
    after = _bounded_int("after", after, 0, MAX_CONTEXT_LINES)
    timeout = _bounded_int("timeout", timeout, 5, 300)
    analysis_timeout = _bounded_int("analysis_timeout", analysis_timeout, 5, 1800)
    detail = _detail_level(detail)
    cursor_data = _decode_cursor(cursor) if cursor else None
    coordinates = sum(bool(value and str(value).strip()) for value in (addr, symbol))
    coordinates += bool(module or rva)
    if cursor_data and (coordinates or lines):
        raise DecompError("cursor is mutually exclusive with address/symbol/module/lines")
    if coordinates > 1:
        raise DecompError("addr, symbol, and module+rva are mutually exclusive")
    if bool(module) != bool(rva):
        raise DecompError("module and rva must be supplied together")
    if module and not str(module).strip():
        raise DecompError("module must not be blank")
    line_range = _line_range(lines)
    if cursor_data:
        module = str(cursor_data["module"])
        rva = str(cursor_data["function_rva"])
        start = int(cursor_data["next_start"])
        page_size = int(cursor_data["page_size"])
        line_range = (start, start + page_size - 1)
    assembly = _assembly_mode(assembly)
    if not isinstance(callers, bool) or not isinstance(callees, bool):
        raise DecompError("callers and callees must be booleans", code="invalid_argument")
    if not isinstance(allow_cold, bool):
        raise DecompError("allow_cold must be a boolean", code="invalid_argument")
    daemon = daemon_client or DaemonClient(cfg)
    worker = decomp_client or DecompClient(cfg)

    store = SymbolStore(cfg.symbols_dir)
    if symbol:
        try:
            module, _ = store.parse_symbol(symbol)
            rva = f"0x{store.rva(symbol):x}"
        except SymbolStoreError as exc:
            raise DecompError(f"could not resolve symbol: {exc}") from exc

    try:
        snapshot_args: dict[str, Any] = {}
        if module:
            snapshot_args.update(module=module, rva=rva)
        elif addr and addr.strip():
            snapshot_args["va"] = addr.strip()
        snapshot = daemon.call(
            "decomp_snapshot", **snapshot_args
        )
        target = snapshot.get("target") or {}
        runtime_va = int(str(snapshot.get("runtime_va", "0")), 0)
        epoch_session = str(snapshot["session_id"])
        epoch_stop = int(snapshot["stop_id"])
        if cursor_data and (
            cursor_data["session_id"] != epoch_session
            or int(cursor_data["stop_id"]) != epoch_stop
        ):
            raise DecompError(
                "continuation no longer matches this debugger stop"
            )
        if runtime_va < 0 or runtime_va >= (1 << 64):
            raise ValueError("address outside uint64 range")
    except DecompError:
        raise
    except ClientError as exc:
        raise _wrapped_decomp_error("could not resolve live address", exc) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise DecompError(f"could not resolve live address: {exc}") from exc

    try:
        module = snapshot["module"]
        module_base = int(str(module["base"]), 0)
        module_size = int(module["size"])
        rva = runtime_va - module_base
    except (ClientError, KeyError, TypeError, ValueError) as exc:
        raise DecompError(f"could not resolve live module: {exc}") from exc
    if rva < 0 or rva >= module_size:
        raise DecompError(
            f"resolved RVA 0x{rva:x} lies outside {module.get('name')} "
            f"(size 0x{module_size:x})"
        )

    def live_read(address: int, length: int) -> bytes:
        if length < 0 or length > (1 << 20):
            raise IdentityError(f"invalid live read length: {length}")
        chunks: list[bytes] = []
        offset = 0
        while offset < length:
            size = min(MAX_LIVE_READ, length - offset)
            try:
                reply = daemon.call(
                    "mem", va=f"0x{address + offset:x}", length=size,
                    session_id=epoch_session, stop_id=epoch_stop,
                )
                chunk = bytes.fromhex(str(reply["bytes"]))
            except ClientError as exc:
                error = IdentityError(str(getattr(exc, "message", exc)))
                error.code = exc.code
                error.retryable = exc.retryable
                error.details = exc.details
                raise error from exc
            except (KeyError, ValueError) as exc:
                raise IdentityError(str(exc)) from exc
            if len(chunk) != size:
                raise IdentityError(f"short daemon memory read: {len(chunk)}/{size}")
            chunks.append(chunk)
            offset += size
        return b"".join(chunks)

    try:
        live_identity = parse_live_pe(live_read, module_base)
        binary_path, static_identity, identity_confidence = _resolve_verified_binary(
            cfg, str(module.get("name", "")), binary, live_identity, module_size,
        )
    except IdentityError as exc:
        raise _wrapped_decomp_error("could not verify live module", exc) from exc

    runtime_symbol = symbolicate_va(store, runtime_va)
    symbol_hint = _nearest_symbol_hint(
        store, str(module.get("name", "")), rva, build=live_identity.pdb_key,
    )

    from winbox.kdbg.decomp.cache import analysis_readiness
    readiness = analysis_readiness(cfg, static_identity.sha256)
    module_name = str(module.get("name") or "")[:260]
    if not readiness["ready"] and not allow_cold:
        raise DecompError(
            "exact Ghidra analysis is cold; refusing to hold the target stopped. "
            "Detach or continue the debugger, run kdbg_decomp_prepare for the "
            "verified module, then retry (or set allow_cold=true explicitly).",
            code="analysis_required", retryable=True,
            details={
                "module": module_name,
                "sha256": static_identity.sha256,
                "readiness": readiness,
                "next_action": "kdbg_decomp_prepare",
            },
        )

    from winbox.kdbg.decomp.enrichment import enrichment_path
    sidecar = enrichment_path(cfg, static_identity.sha256)
    result = worker.call(
        "decompile",
        timeout=float(timeout + analysis_timeout) + 90.0,
        binary=str(binary_path),
        binary_name=str(module.get("name") or binary_path.name),
        sha256=static_identity.sha256,
        rva=rva,
        before=before,
        after=after,
        full=bool(full),
        decompile_timeout=timeout,
        analysis_timeout=analysis_timeout,
        enrichment=str(sidecar) if sidecar.is_file() and not sidecar.is_symlink() else "",
        symbol_hint=symbol_hint,
        line_start=line_range[0] if line_range else None,
        line_end=line_range[1] if line_range else None,
        assembly=assembly,
    )
    _annotate_flow_symbols(
        result, store, str(module.get("name", "")), module_size
    )

    if cursor_data:
        if (
            cursor_data["binary_sha256"] != static_identity.sha256
            or cursor_data["ghidra_version"] != result.get("ghidra_version")
            or cursor_data["analysis_profile"] != result.get("analysis_profile")
        ):
            raise DecompError(
                "continuation no longer matches this debugger stop or analysis"
            )

    selection = (result.get("mapping") or {}).get("selection") or {}
    next_cursor = None
    if selection.get("has_more") and selection.get("next_start"):
        function_rva = int(str((result.get("function") or {})["rva"]), 0)
        page_size = max(1, int(selection["end"]) - int(selection["start"]) + 1)
        next_cursor = _encode_cursor({
            "module": str(snapshot["module"]["name"]),
            "function_rva": function_rva,
            "next_start": int(selection["next_start"]),
            "page_size": page_size,
            "session_id": epoch_session,
            "stop_id": epoch_stop,
            "binary_sha256": static_identity.sha256,
            "ghidra_version": result.get("ghidra_version"),
            "analysis_profile": result.get("analysis_profile"),
        })

    warnings: list[str] = []
    direct_calls: dict[str, Any] | None = None
    if callers or callees:
        from winbox.kdbg.static_search import StaticSearchError, direct_call_xrefs

        try:
            function_rva = int(str((result.get("function") or {})["rva"]), 0)
            direct_calls = direct_call_xrefs(
                binary_path,
                static_identity,
                rva=function_rva,
                callers=callers,
                callees=callees,
            )
        except (StaticSearchError, KeyError, TypeError, ValueError) as exc:
            direct_calls = {
                "schema": "winbox.kdbg-direct-call-xrefs/1",
                "available": False,
                "callers": [],
                "callees": [],
                "reason": str(exc)[:512],
            }
            warnings.append("static direct-call xrefs were unavailable for this function")
    if full and (result.get("analysis") or {}).get("code_truncated"):
        warnings.append(
            "full pseudocode was truncated; mapping and selected lines use the complete function"
        )
    if (result.get("mapping") or {}).get("assembly_truncated"):
        warnings.append(
            "mapped assembly was truncated at the bounded response limit"
        )
    instruction_match = "not_checked"
    current = next(
        (item for item in result.get("instructions", []) if item.get("current")),
        None,
    )
    if current is not None:
        try:
            static_instruction = bytes.fromhex(str(current.get("bytes", "")))
            instruction_address = int(str(current["address"]), 0)
            ghidra_base = int(str(result["ghidra_image_base"]), 0)
            instruction_rva = instruction_address - ghidra_base
            raw_file = static_bytes_at_rva(
                binary_path, static_identity, instruction_rva, len(static_instruction)
            )
            if raw_file and raw_file != static_instruction:
                warnings.append(
                    "Ghidra instruction bytes differ from the cached PE; "
                    "rebuild the analysis cache"
                )
            live_instruction = live_read(
                module_base + instruction_rva, len(static_instruction)
            )
            instruction_match = "match" if live_instruction == static_instruction else "mismatch"
            if instruction_match == "mismatch":
                warnings.append(
                    "live instruction bytes differ from the exact cached PE "
                    "(software breakpoint, hotpatch, runtime patch, or relocation)"
                )
        except (IdentityError, KeyError, TypeError, ValueError):
            warnings.append("could not compare live and static instruction bytes")

    try:
        final_status = daemon.call("status")
    except ClientError as exc:
        raise _wrapped_decomp_error(
            "could not revalidate debugger stop", exc,
        ) from exc
    if (
        final_status.get("state") != "halted"
        or final_status.get("session_id") != epoch_session
        or final_status.get("stop_id") != epoch_stop
    ):
        raise DecompError(
            "debugger stop changed during decompilation; retry at the new stop"
        )

    composed = {
        "target": {"pid": target.get("pid"), "name": target.get("name")},
        "stop_epoch": {"session_id": epoch_session, "stop_id": epoch_stop},
        "module": {
            **module,
            "runtime_va": f"0x{runtime_va:x}",
            "rva": f"0x{rva:x}",
            "binary": str(binary_path),
        },
        "identity": {
            "confidence": identity_confidence,
            "live": live_identity.public(),
            "static": static_identity.public(),
            "current_instruction_match": instruction_match,
        },
        "runtime_symbol": runtime_symbol,
        "symbol_hint": symbol_hint,
        "next_cursor": next_cursor,
        "analysis_admission": {
            "policy": "allow_cold" if allow_cold else "warm_required",
            "cache": readiness,
            "cold_analysis": not readiness["ready"],
        },
        **result,
        "direct_calls": direct_calls,
        "warnings": warnings,
    }
    return _format_result(
        composed, detail,
        instruction_bytes=bool(instruction_bytes),
        runtime_vas=bool(runtime_vas),
    )


def _format_result(
    result: dict[str, Any],
    detail: str,
    *,
    instruction_bytes: bool = True,
    runtime_vas: bool = True,
) -> dict[str, Any]:
    """Apply the public response envelope without weakening verification.

    The diagnostic form is the internal evidence record. Compact/standard
    forms retain the operational answer and truthful source mapping while
    avoiding repeated PE/PDB/cache provenance on every agent query.
    """
    if detail == "diagnostic":
        return result

    module = result.get("module") or {}
    identity = result.get("identity") or {}
    function = result.get("function") or {}
    mapping = result.get("mapping") or {}
    ghidra_base = _hex_int(result.get("ghidra_image_base"))
    module_base = _hex_int(module.get("base"))
    requested_rva = _hex_int(module.get("rva"))
    requested_static = (
        ghidra_base + requested_rva
        if ghidra_base is not None and requested_rva is not None
        else None
    )

    nearby_assembly: list[dict[str, Any]] = []
    for instruction in result.get("instructions") or []:
        nearby_assembly.append(
            _format_instruction(
                instruction, ghidra_base, module_base,
                instruction_bytes=instruction_bytes,
                runtime_vas=runtime_vas,
            )
        )

    kind, direction, distance = _mapping_relation(mapping, requested_static)
    selected_line = mapping.get("line")
    candidate_lines = list(mapping.get("candidate_lines") or [])
    if not candidate_lines and selected_line is not None:
        candidate_lines = [selected_line]

    pseudocode: list[dict[str, Any]] = []
    for source_line in mapping.get("excerpt") or []:
        item = {
            "line": source_line.get("line"),
            "text": source_line.get("text"),
        }
        ranges = source_line.get("address_ranges") or []
        if not ranges and source_line.get("line") == selected_line:
            # Compatibility with worker API 1 diagnostic responses. API 2+
            # supplies per-line ranges directly.
            addresses = [
                value for value in (
                    _hex_int(address) for address in mapping.get("addresses") or []
                ) if value is not None
            ]
            if addresses:
                ranges = [{"start": min(addresses), "end": max(addresses)}]
        rva_ranges: list[dict[str, str]] = []
        for address_range in ranges:
            start = _hex_int(address_range.get("start"))
            end = _hex_int(address_range.get("end"))
            if start is None or end is None or ghidra_base is None:
                continue
            rva_ranges.append({
                "start": f"0x{start - ghidra_base:x}",
                "end": f"0x{end - ghidra_base:x}",
            })
        if rva_ranges:
            item["rva_ranges"] = rva_ranges
        relation = source_line.get("relation")
        if relation is None and source_line.get("line") in candidate_lines:
            relation = kind
        if relation:
            item["relation"] = relation
        mapped = source_line.get("assembly") or []
        if mapped:
            item["assembly"] = [
                _format_instruction(
                    instruction, ghidra_base, module_base,
                    instruction_bytes=instruction_bytes,
                    runtime_vas=runtime_vas,
                )
                for instruction in mapped
            ]
        if "assembly_complete" in source_line:
            item["assembly_complete"] = bool(source_line["assembly_complete"])
        pseudocode.append(item)

    compact: dict[str, Any] = {
        "schema": "winbox.kdbg-decomp/5",
        "detail": detail,
        "target": result.get("target"),
        "stop_epoch": result.get("stop_epoch"),
        "location": {
            "symbol": result.get("runtime_symbol"),
            "va": module.get("runtime_va"),
            "rva": module.get("rva"),
        },
        "function": {
            "name": function.get("verified_name") or function.get("name"),
            "ghidra_name": function.get("name"),
            "name_source": function.get("name_source") or "ghidra",
            "signature": function.get("signature"),
            "entry_rva": function.get("rva"),
            "offset": function.get("offset"),
            "source": function.get("source"),
        },
        "assembly_mode": result.get("assembly_mode") or "nearby",
        "assembly_fields": {
            "instruction_bytes": instruction_bytes,
            "runtime_vas": runtime_vas,
        },
        "assembly": nearby_assembly,
        "pseudocode": pseudocode,
        "line_selection": mapping.get("selection"),
        "next_cursor": result.get("next_cursor"),
        "instruction_location": result.get("instruction_location"),
        "rip_mapping": {
            "kind": kind,
            "pseudocode_line": selected_line,
            "candidate_lines": candidate_lines,
            "distance_bytes": distance,
            "direction": direction,
            "reason": _mapping_reason(kind),
        },
        "verified": {
            "build_identity_match": True,
            "identity_method": identity.get("confidence"),
            "analyzed_file_sha256": (identity.get("static") or {}).get("sha256"),
            "current_instruction_match": identity.get("current_instruction_match"),
        },
        "cache_hit": result.get("cache_hit"),
        "decompile_cache_hit": result.get("decompile_cache_hit"),
        "analysis_admission": result.get("analysis_admission"),
        "operation_metadata": result.get("operation_metadata"),
        "warnings": result.get("warnings") or [],
    }
    if "code" in result:
        compact["code"] = result["code"]
    if result.get("direct_calls") is not None:
        compact["direct_calls"] = result["direct_calls"]
    if "code" in result and (result.get("analysis") or {}).get("code_truncated"):
        compact["code_truncated"] = True
    if detail == "standard":
        compact.update({
            "module": module,
            "identity": identity,
            "symbol_hint": result.get("symbol_hint"),
            "ghidra": {
                "version": result.get("ghidra_version"),
                "image_base": result.get("ghidra_image_base"),
                "address": result.get("ghidra_address"),
            },
            "analysis": result.get("analysis") or {},
        })
    return compact


def _format_instruction(
    instruction: dict[str, Any],
    ghidra_base: int | None,
    module_base: int | None,
    *,
    instruction_bytes: bool = True,
    runtime_vas: bool = True,
) -> dict[str, Any]:
    address = _hex_int(instruction.get("address"))
    item: dict[str, Any] = {"text": instruction.get("text")}
    if instruction_bytes:
        item["bytes"] = instruction.get("bytes")
    if address is not None and ghidra_base is not None:
        instruction_rva = address - ghidra_base
        item["rva"] = f"0x{instruction_rva:x}"
        if runtime_vas and module_base is not None:
            item["va"] = f"0x{module_base + instruction_rva:x}"
    if instruction.get("current"):
        item["current"] = True
    targets = []
    for target in instruction.get("flow_targets") or []:
        static_target = _hex_int(target)
        if static_target is None or ghidra_base is None:
            continue
        target_rva = static_target - ghidra_base
        if target_rva < 0:
            # Ghidra external/import address spaces use small synthetic offsets,
            # not image VAs. Presenting those as negative PE RVAs is misleading.
            continue
        target_item = {"rva": f"0x{target_rva:x}"}
        if runtime_vas:
            target_item["static_va"] = f"0x{static_target:x}"
        if runtime_vas and module_base is not None:
            target_item["runtime_va"] = f"0x{module_base + target_rva:x}"
        symbol = (instruction.get("flow_target_symbols") or {}).get(str(target))
        if symbol:
            target_item["symbol"] = symbol
        targets.append(target_item)
    if targets:
        item["flow_targets"] = targets
    return item


def _mapping_relation(
    mapping: dict[str, Any], requested_static: int | None
) -> tuple[str, str | None, int | None]:
    kind = str(mapping.get("kind") or "")
    direction = mapping.get("direction")
    distance = mapping.get("distance_bytes")
    if kind:
        return kind, direction, distance

    confidence = mapping.get("confidence")
    if confidence == "exact":
        return "exact", "overlap", 0
    if confidence == "function-only":
        return "unmapped", None, None
    addresses = [
        value for value in (
            _hex_int(address) for address in mapping.get("addresses") or []
        ) if value is not None
    ]
    if confidence == "nearest" and addresses and requested_static is not None:
        low, high = min(addresses), max(addresses)
        if requested_static < low:
            return "nearest-forward", "forward", low - requested_static
        if requested_static > high:
            return "nearest-backward", "backward", requested_static - high
        return "range", "overlap", 0
    return "unmapped", None, None


def _mapping_reason(kind: str) -> str:
    return {
        "exact": "RIP has direct single-address decompiler token provenance",
        "range": "RIP lies inside an address range contributing to this statement",
        "nearest-forward": "RIP has no direct pseudocode token; this is the next mapped statement",
        "nearest-backward": "RIP has no direct pseudocode token; this is the previous mapped statement",
        "ambiguous": "multiple pseudocode lines have equally valid address provenance",
        "unmapped": "Ghidra returned no defensible instruction-to-pseudocode mapping",
    }.get(kind, "mapping relationship reported by the decompiler")


def _hex_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str) -> dict[str, Any]:
    raw = str(value).strip()
    if not raw or len(raw) > 4096:
        raise DecompError("invalid or oversized continuation cursor")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.b64decode(
            padded, altchars=b"-_", validate=True
        ).decode("utf-8"))
        required = {
            "module", "function_rva", "next_start", "page_size",
            "session_id", "stop_id", "binary_sha256", "ghidra_version",
            "analysis_profile",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise ValueError("unexpected cursor fields")
        if (
            not isinstance(payload["module"], str)
            or not payload["module"].strip()
            or len(payload["module"]) > 260
            or "\0" in payload["module"]
        ):
            raise ValueError("empty module")
        for key in ("function_rva", "next_start", "page_size", "stop_id"):
            if isinstance(payload[key], bool) or not isinstance(payload[key], int):
                raise ValueError(f"{key} is not an integer")
        if not 0 <= payload["function_rva"] < (1 << 32):
            raise ValueError("function RVA out of range")
        if not 1 <= payload["next_start"] <= 1_000_000:
            raise ValueError("next line out of range")
        if not 1 <= payload["page_size"] <= MAX_LINE_BATCH:
            raise ValueError("line window out of range")
        if payload["stop_id"] < 1:
            raise ValueError("stop id out of range")
        if (
            not isinstance(payload["session_id"], str)
            or not 1 <= len(payload["session_id"]) <= 128
            or not isinstance(payload["binary_sha256"], str)
            or len(payload["binary_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in payload["binary_sha256"])
            or not isinstance(payload["ghidra_version"], str)
            or not 1 <= len(payload["ghidra_version"]) <= 64
            or not isinstance(payload["analysis_profile"], str)
            or not 1 <= len(payload["analysis_profile"]) <= 128
        ):
            raise ValueError("invalid cursor identity")
        return payload
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DecompError(f"invalid continuation cursor: {exc}") from exc


def _annotate_flow_symbols(
    result: dict[str, Any], store: SymbolStore, module_name: str, module_size: int
) -> None:
    """Attach reusable module-relative symbol labels to branch/call targets."""
    ghidra_base = _hex_int(result.get("ghidra_image_base"))
    if ghidra_base is None:
        return
    instructions = list(result.get("instructions") or [])
    for source_line in (result.get("mapping") or {}).get("excerpt") or []:
        instructions.extend(source_line.get("assembly") or [])
    for instruction in instructions:
        symbols = {}
        for target in instruction.get("flow_targets") or []:
            static_target = _hex_int(target)
            if static_target is None:
                continue
            target_rva = static_target - ghidra_base
            if not 0 <= target_rva < module_size:
                continue
            hint = _nearest_symbol_hint(store, module_name, target_rva)
            if hint is None:
                continue
            suffix = f"+0x{hint['offset']:x}" if hint["offset"] else ""
            symbols[str(target)] = f"{hint['module']}!{hint['name']}{suffix}"
        if symbols:
            instruction["flow_target_symbols"] = symbols


def _binary_candidates(cfg: Config, module_name: str, explicit: str) -> list[Path]:
    if explicit and explicit.strip():
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise DecompError(f"binary does not exist or is not a regular file: {path}")
        return [path]

    root = Path(cfg.symbols_dir)
    resolved_root = root.resolve()
    normalized = module_name.lower()
    candidates: list[Path] = []
    if normalized in {"ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "nt"}:
        candidates.append(root / "ntoskrnl.exe")
    candidates.extend((root / module_name, root / Path(module_name).name))
    try:
        candidates.extend(
            item for item in root.iterdir()
            if item.is_file() and item.name.lower() == normalized
        )
    except OSError:
        pass
    build_root = root / "pe" / Path(module_name).name.lower()
    if build_root.is_dir():
        candidates.extend(sorted(build_root.iterdir(), reverse=True))
    seen: set[Path] = set()
    result = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_relative_to(resolved_root) and resolved.is_file():
            result.append(resolved)
    if result:
        return result
    raise DecompError(
        f"no cached PE for live module {module_name!r}. Before attaching, run "
        "`kdbg_user_symbols_load` for that module, or pass `binary` as the "
        "exact host-side PE path."
    )


def _resolve_binary(cfg: Config, module_name: str, explicit: str) -> Path:
    """Compatibility helper returning the first eligible path before verification."""
    return _binary_candidates(cfg, module_name, explicit)[0]


def _snapshot_binary(cfg: Config, source: Path) -> Path:
    """Copy from one opened file into an immutable content-addressed input."""
    root = cache_dir(cfg) / "verified-binaries"
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    temporary = root / f".{os.getpid()}.{secrets.token_hex(8)}.part"
    digest = hashlib.sha256()
    try:
        with source.open("rb") as src, temporary.open("xb") as dst:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        suffix = source.suffix.lower()
        if len(suffix) > 16 or any(c not in ".abcdefghijklmnopqrstuvwxyz0123456789" for c in suffix):
            suffix = ".bin"
        target = root / f"{digest.hexdigest()}{suffix}"
        lock = root / f"{digest.hexdigest()}.lock"
        with lock.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            if not target.exists():
                os.chmod(temporary, 0o600)
                os.replace(temporary, target)
        return target
    except OSError as exc:
        raise DecompError(f"could not snapshot binary {source}: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _resolve_verified_binary(
    cfg: Config, module_name: str, explicit: str, live_identity,
    module_size: int,
) -> tuple[Path, Any, str]:
    failures = []
    for candidate in _binary_candidates(cfg, module_name, explicit):
        try:
            snapshot = _snapshot_binary(cfg, candidate)
            static = parse_static_pe(snapshot)
            confidence = validate_identity(
                live_identity, static, module_name=module_name or candidate.name,
                live_module_size=module_size,
            )
            return snapshot, static, confidence
        except (DecompError, IdentityError) as exc:
            failures.append(f"{candidate.name}: {exc}")
    detail = failures[-1] if failures else "no candidate"
    raise DecompError(f"no cached PE matches live {module_name!r}: {detail}")


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DecompError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise DecompError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _detail_level(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in DETAIL_LEVELS:
        choices = ", ".join(sorted(DETAIL_LEVELS))
        raise DecompError(f"detail must be one of: {choices}")
    return normalized


def _line_range(value: str) -> tuple[int, int] | None:
    raw = str(value).strip()
    if not raw:
        return None
    parts = [part.strip() for part in raw.split("-")]
    if len(parts) not in {1, 2} or any(not part.isdigit() for part in parts):
        raise DecompError("lines must be N or N-M (for example, 1-22)")
    start = int(parts[0])
    end = int(parts[-1])
    if start < 1 or end < start:
        raise DecompError("lines must be a positive ascending range")
    if end - start + 1 > MAX_LINE_BATCH:
        raise DecompError(f"lines may select at most {MAX_LINE_BATCH} lines")
    return start, end


def _assembly_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in ASSEMBLY_MODES:
        choices = ", ".join(sorted(ASSEMBLY_MODES))
        raise DecompError(f"assembly must be one of: {choices}")
    return normalized


def _nearest_symbol_hint(
    store: SymbolStore, module_name: str, rva: int, *, build: str | None = None,
) -> dict[str, object] | None:
    """Return a bounded PDB-public hint for Ghidra's missed-function case."""
    normalized = module_name.lower()
    if normalized.startswith("ntoskrnl") or normalized.startswith("ntkrnl"):
        keys = ["nt"]
    else:
        keys = [Path(normalized).stem, normalized]
    for key in keys:
        try:
            data = store.load_build(key, build) if build else store.load(key)
            symbols = data.get("symbols", {})
            function_symbols = set(data.get("function_symbols") or [])
        except Exception:
            continue
        best_name = None
        best_rva = -1
        for name, value in symbols.items():
            if isinstance(value, int) and best_rva < value <= rva:
                best_name, best_rva = name, value
        if best_name is None:
            continue
        offset = rva - best_rva
        # A far-away public is more likely the previous unrelated symbol than
        # a useful function boundary. Never let it create a giant function.
        if offset > 64 * 1024:
            return None
        return {
            "module": key,
            "name": best_name,
            "rva": best_rva,
            "offset": offset,
            "is_function": best_name in function_symbols,
        }
    return None
