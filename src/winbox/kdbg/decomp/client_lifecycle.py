"""Lifecycle and session management mixin for DecompClient."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from winbox.kdbg.errors import bounded_details, make_error_info, parse_error_info
from winbox.kdbg.decomp.client_paths import (
    DecompError, MAX_REQUEST_BYTES, WORKER_API,
    backend, cache_dir, discover_pyghidra_python, lock_path, log_path,
    maintenance_lock, open_program_limit, project_dir, protocol_family,
    runtime_dir, session_path, socket_path, _sha256,
)


class _DecompLifecycleMixin:
    """Worker startup, cancellation, session liveness, and binary staging."""

    def _start_worker(self) -> None:
        with maintenance_lock(self.cfg):
            if self.worker_alive():
                return
            self._enforce_cache_budget()
            if backend() == "docker":
                from winbox.kdbg.decomp.docker import DockerError, DockerManager

                try:
                    DockerManager(self.cfg).start()
                except DockerError as exc:
                    raise DecompError(str(exc)) from exc
                return
            self._start_host_worker()

    def _enforce_cache_budget(self) -> None:
        raw = os.environ.get("WINBOX_GHIDRA_CACHE_MAX_BYTES", "0").strip()
        try:
            maximum = int(raw)
        except ValueError as exc:
            raise DecompError("WINBOX_GHIDRA_CACHE_MAX_BYTES must be an integer") from exc
        if maximum < 0:
            raise DecompError("WINBOX_GHIDRA_CACHE_MAX_BYTES must not be negative")
        if maximum:
            from winbox.kdbg.decomp.cache import prune_cache
            prune_cache(self.cfg, max_bytes=maximum, dry_run=False)

    def _start_host_worker(self) -> None:
        root = runtime_dir(self.cfg)
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        interpreter = discover_pyghidra_python()
        worker = Path(__file__).with_name("worker.py").resolve()
        command = [
            str(interpreter), str(worker),
            "--socket", str(socket_path(self.cfg)),
            "--lock", str(lock_path(self.cfg)),
            "--session", str(session_path(self.cfg)),
            "--cache", str(cache_dir(self.cfg)),
            "--projects", str(project_dir()),
            "--max-open-programs", str(open_program_limit()),
        ]
        ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_dir:
            command.extend(["--ghidra-install-dir", ghidra_dir])
        log = log_path(self.cfg)
        with log.open("ab", buffering=0) as output:
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
                close_fds=True,
                start_new_session=True,
                env=os.environ.copy(),
            )
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if self.worker_alive() and socket_path(self.cfg).exists():
                try:
                    request_id = secrets.token_hex(16)
                    self._exchange(
                        json.dumps({"request_id": request_id, "op": "status", "args": {}},
                                   separators=(",", ":")).encode() + b"\n", timeout=1.0
                    )
                    return
                except (OSError, DecompError):
                    pass
            time.sleep(0.05)
        tail = ""
        try:
            tail = log.read_text(encoding="utf-8", errors="replace")[-2000:]
        except OSError:
            pass
        detail = f"; worker log tail: {tail.strip()}" if tail.strip() else ""
        raise DecompError(f"PyGhidra worker did not become ready within 30s{detail}")

    def _cancel_request(self, request_id: str) -> None:
        root = cache_dir(self.cfg) / "cancel"
        try:
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)
            now = time.time()
            markers = sorted(root.iterdir(), key=lambda p: p.stat().st_mtime)
            excess = max(0, len(markers) - 1023)
            for index, old in enumerate(markers):
                if old.is_file() and not old.is_symlink() and (
                    now - old.stat().st_mtime > 86400 or index < excess
                ):
                    old.unlink(missing_ok=True)
            marker = root / request_id
            marker.write_text(str(now), encoding="ascii")
            os.chmod(marker, 0o600)
        except OSError:
            pass

    def cancel(self, request_id: str = "") -> dict[str, Any]:
        """Request cooperative cancellation of the active bounded operation."""
        current = self._session_liveness().get("current_operation")
        if not isinstance(current, dict):
            raise DecompError("no active decompiler operation", code="not_running")
        active = str(current.get("request_id") or "")
        if request_id and request_id != active:
            raise DecompError(
                "request id does not match the active operation",
                code="identity_mismatch",
            )
        if not active:
            raise DecompError("active operation has no request identity", code="invalid_response")
        self._cancel_request(active)
        return {
            "schema": "winbox.decomp-cancel/1",
            "cancel_requested": True,
            "request_id": active,
            "operation": current.get("op"),
            "phase": current.get("phase"),
        }

    def request_cancel(self, request_id: str) -> None:
        """Place an exact cooperative marker without guessing active identity."""
        if not re.fullmatch(r"[0-9a-f]{32}", str(request_id or "")):
            raise DecompError(
                "request_id must be 32 lowercase hexadecimal characters",
                code="invalid_argument",
            )
        self._cancel_request(request_id)

    def _session_liveness(self, *, running: bool | None = None) -> dict[str, Any]:
        if running is None:
            running = self.worker_alive()
        parse_error = ""
        try:
            path = session_path(self.cfg)
            if path.stat().st_size > MAX_REQUEST_BYTES:
                raise ValueError("session heartbeat exceeds size limit")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            value = {}
        except ValueError as exc:
            value = {}
            parse_error = str(exc)
        else:
            parse_error = ""
        current = value.get("current_operation")
        if not isinstance(current, dict):
            current = None
        else:
            allowed = {
                "request_id", "op", "phase", "started_at", "phase_started_at",
                "last_progress_at", "cancellation_state", "binary_sha256",
                "binary_name", "progress",
            }
            current = {
                str(key): item for key, item in current.items()
                if key in allowed
            }
            current = bounded_details(current)
        started = current.get("started_at") if current is not None else None
        if current is not None and isinstance(started, (int, float)):
            current = {**current, "elapsed_seconds": max(0.0, time.time() - started)}
            phase_started = current.get("phase_started_at")
            last_progress = current.get("last_progress_at")
            if isinstance(phase_started, (int, float)):
                current["phase_elapsed_seconds"] = max(
                    0.0, time.time() - phase_started,
                )
            if isinstance(last_progress, (int, float)):
                current["progress_age_seconds"] = max(
                    0.0, time.time() - last_progress,
                )
        heartbeat = value.get("heartbeat_at")
        heartbeat_age = (
            max(0.0, time.time() - float(heartbeat))
            if isinstance(heartbeat, (int, float)) else None
        )
        result: dict[str, Any] = {
            "status_source": "heartbeat" if heartbeat_age is not None else "legacy_session",
            "current_operation": current,
            "heartbeat_age_seconds": heartbeat_age,
            "busy": bool(current),
            "responsive": False,
        }
        worker_state = bounded_details(value.get("worker_state"))
        for key in (
            "jvm_started", "ghidra_version", "open_programs", "max_open_programs",
        ):
            if key in worker_state:
                result[key] = worker_state[key]
        if isinstance(value.get("analysis_profile"), str):
            result["analysis_profile"] = value["analysis_profile"][:128]
        if isinstance(value.get("pid"), int) and value["pid"] > 0:
            result["worker_pid"] = value["pid"]
        last_failure = parse_error_info(value.get("last_failure"))
        if last_failure is not None:
            result["last_failure"] = last_failure
        if not running:
            result.update(health="stopped", busy=False)
        elif heartbeat_age is None:
            result["health"] = "unknown"
        elif heartbeat_age > 5.0:
            result.update(health="stale", heartbeat_stale=True)
            result["status_error"] = make_error_info(
                "decompiler worker heartbeat is stale",
                code="stale_heartbeat", retryable=True,
                details={"heartbeat_age_seconds": round(heartbeat_age, 3)},
            )
        else:
            result.update(
                health="busy" if current else "idle",
                heartbeat_stale=False,
                responsive=True,
            )
        if parse_error:
            result["status_error"] = make_error_info(
                parse_error, code="invalid_heartbeat", retryable=True,
            )
        return result

    def _stage_binary(self, source: Path, expected_sha: str) -> str:
        """Atomically copy one verified input into the container's read/write cache."""
        expected_sha = expected_sha.lower()
        if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
            raise DecompError("sha256 must be 64 lowercase hexadecimal characters")
        try:
            source = source.expanduser().resolve(strict=True)
        except OSError as exc:
            raise DecompError(f"binary does not exist: {source}") from exc
        if not source.is_file():
            raise DecompError(f"binary is not a regular file: {source}")
        binaries = cache_dir(self.cfg) / "binaries"
        binaries.mkdir(parents=True, exist_ok=True)
        os.chmod(binaries, 0o700)
        suffix = source.suffix.lower()
        if len(suffix) > 16 or any(c not in ".abcdefghijklmnopqrstuvwxyz0123456789" for c in suffix):
            suffix = ".bin"
        target = binaries / f"{expected_sha}{suffix}"
        stage_lock = binaries / f"{expected_sha}.stage.lock"
        with stage_lock.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if _sha256(source) != expected_sha:
                raise DecompError(
                    f"binary changed before staging: expected {expected_sha}"
                )
            if not target.is_symlink() and target.is_file() and _sha256(target) == expected_sha:
                return f"/cache/binaries/{target.name}"
            temporary = binaries / f".{target.name}.{os.getpid()}.part"
            try:
                shutil.copyfile(source, temporary)
                if _sha256(temporary) != expected_sha:
                    raise DecompError(
                        f"binary changed while staging: expected {expected_sha}"
                    )
                os.chmod(temporary, 0o600)
                os.replace(temporary, target)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        return f"/cache/binaries/{target.name}"

    def _container_enrichment_path(self, path: Path) -> str:
        """Validate a host sidecar and translate it into the Docker mount."""
        try:
            resolved = path.expanduser().resolve(strict=True)
            root = (cache_dir(self.cfg) / "enrichment").resolve(strict=True)
        except OSError as exc:
            raise DecompError(
                "PDB enrichment sidecar is missing", code="prerequisite_missing",
            ) from exc
        if path.is_symlink() or not resolved.is_file() or not resolved.is_relative_to(root):
            raise DecompError("unsafe PDB enrichment sidecar", code="invalid_argument")
        return f"/cache/enrichment/{resolved.name}"
