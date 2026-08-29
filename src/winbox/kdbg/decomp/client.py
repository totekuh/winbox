"""Client and lifecycle manager for the isolated PyGhidra worker."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.admission import OperationBusyError, active_admission, admit_operation
from winbox.kdbg.errors import bounded_details, make_error_info, parse_error_info
from winbox.kdbg.decomp.locking import exclusive_file_lock


class DecompError(RuntimeError):
    """PyGhidra is unavailable or the worker rejected a request."""

    def __init__(
        self,
        message: object,
        *,
        code: str | None = None,
        retryable: bool = False,
        details: Any = None,
    ) -> None:
        self.message = str(message)[:2048]
        super().__init__(self.message)
        self.code = code
        self.retryable = bool(retryable)
        self.details = bounded_details(details)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}" if self.code else self.message


MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
WORKER_API = "6"


def open_program_limit() -> int:
    raw = os.environ.get("WINBOX_GHIDRA_OPEN_PROGRAMS", "2")
    try:
        value = int(raw)
    except ValueError as exc:
        raise DecompError("WINBOX_GHIDRA_OPEN_PROGRAMS must be an integer") from exc
    if not 1 <= value <= 4:
        raise DecompError("WINBOX_GHIDRA_OPEN_PROGRAMS must be between 1 and 4")
    return value


def protocol_family() -> str:
    return f"api{WORKER_API}"


def runtime_dir(cfg: Config) -> Path:
    return Path(cfg.winbox_dir) / "decomp"


def socket_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / f"decomp-{protocol_family()}.sock"


def lock_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / f"decomp-{protocol_family()}.lock"


def session_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / f"decomp-{protocol_family()}.session.json"


def cache_dir(cfg: Config) -> Path:
    return runtime_dir(cfg) / "cache"


def log_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / f"decomp-{protocol_family()}.log"


def maintenance_lock_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / f"decomp-maintenance-{protocol_family()}.lock"


def maintenance_lock(cfg: Config):
    """Serialize cache mutation, worker startup, and project ownership."""
    return exclusive_file_lock(maintenance_lock_path(cfg))


def operation_admission(cfg: Config) -> dict[str, Any] | None:
    """Current non-queueing worker admission, independent of JVM heartbeat."""
    return active_admission(runtime_dir(cfg), f"decomp-{protocol_family()}")


def project_dir() -> Path:
    """Ghidra rejects project paths containing hidden ``.name`` elements."""
    override = os.environ.get("WINBOX_GHIDRA_PROJECT_DIR")
    if override:
        return Path(override).expanduser().absolute()
    return Path("/var/tmp") / f"winbox-ghidra-{os.getuid()}"


def backend() -> str:
    """Select the isolated Docker service; host mode is an explicit dev escape hatch."""
    value = os.environ.get("WINBOX_DECOMP_BACKEND", "docker").strip().lower()
    if value not in {"docker", "host"}:
        raise DecompError("WINBOX_DECOMP_BACKEND must be 'docker' or 'host'")
    return value


def discover_pyghidra_python() -> Path:
    """Find a Python interpreter containing PyGhidra without importing JVM code."""
    override = os.environ.get("WINBOX_PYGHIDRA_PYTHON")
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            # Do not resolve a venv's ``python`` symlink to /usr/bin/python:
            # the invocation path is how Python discovers pyvenv.cfg.
            return candidate.absolute()
        raise DecompError(
            f"WINBOX_PYGHIDRA_PYTHON is not an executable file: {candidate}"
        )

    launcher = shutil.which("pyghidra")
    if launcher:
        try:
            first = Path(launcher).read_text(encoding="utf-8", errors="replace").splitlines()[0]
        except (OSError, IndexError):
            first = ""
        if first.startswith("#!"):
            candidate = Path(first[2:].strip())
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.absolute()

    pipx = Path.home() / ".local/share/pipx/venvs/pyghidra/bin/python"
    if pipx.is_file() and os.access(pipx, os.X_OK):
        return pipx.absolute()
    if importlib.util.find_spec("pyghidra") is not None:
        return Path(sys.executable).resolve()
    raise DecompError(
        "PyGhidra is not installed. Install it with `pipx install pyghidra`, "
        "install Ghidra 11+, and set GHIDRA_INSTALL_DIR if Ghidra is not in "
        "its standard location. WINBOX_PYGHIDRA_PYTHON can select a specific "
        "PyGhidra interpreter."
    )


class DecompClient:
    """Stateless JSON-line client; a separate process owns the JVM."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def worker_alive(self) -> bool:
        path = lock_path(self.cfg)
        if not path.exists():
            return False
        try:
            fd = os.open(path, os.O_RDWR)
        except OSError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    def active_backend(self) -> str | None:
        """Identify the process holding the shared worker lock without probing it."""
        if not self.worker_alive():
            return None
        try:
            value = json.loads(session_path(self.cfg).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return None
        declared = value.get("backend")
        if declared in {"docker", "host"}:
            return declared
        # Compatibility with pre-container session records. PID 1 is the
        # worker entrypoint in Docker; an ordinary user host worker cannot be
        # PID 1.
        return "docker" if value.get("pid") == 1 else "host"

    def active_worker_api(self) -> str | None:
        """Return the protocol version declared by the lock owner."""
        if not self.worker_alive():
            return None
        try:
            value = json.loads(session_path(self.cfg).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return None
        declared = value.get("worker_api")
        return str(declared) if declared is not None else None

    def status(self, *, quick: bool = False) -> dict[str, Any]:
        selected = backend()
        if selected == "docker":
            from winbox.kdbg.decomp.docker import DockerManager, project_dir as docker_projects

            manager = DockerManager(self.cfg)
            # Doctor must stay a readiness probe, even with a wedged Docker
            # daemon. Full status keeps the normal diagnostic timeout.
            result = manager.status(timeout=2.0 if quick else 15.0)
            result.update({
                "running": self.worker_alive(),
                "active_backend": self.active_backend(),
                "active_worker_api": self.active_worker_api(),
                "responsive": False,
                "cache_dir": str(cache_dir(self.cfg)),
                "project_dir": str(docker_projects(self.cfg)),
            })
            result.update(self._session_liveness(running=result["running"]))
            admission = operation_admission(self.cfg)
            result["admission"] = admission
            result["busy"] = bool(result.get("busy") or admission)
            if result["running"] and not (
                result["active_backend"] in {None, "docker"}
                and result["active_worker_api"] == WORKER_API
            ):
                if result["active_worker_api"] != WORKER_API:
                    result["error"] = (
                        f"worker API {result['active_worker_api'] or 'legacy'} owns "
                        f"the {protocol_family()} socket; refusing automatic migration. "
                        "Reload/version-align the client and worker."
                    )
                else:
                    result["error"] = (
                        f"a {result['active_backend']} worker owns the decomp socket; "
                        "the next Docker query will migrate it"
                    )
            return result

        try:
            interpreter = str(discover_pyghidra_python())
            available = True
            discovery_error = None
        except DecompError as exc:
            interpreter = None
            available = False
            discovery_error = str(exc)
        result: dict[str, Any] = {
            "backend": "host",
            "running": self.worker_alive(),
            "active_backend": self.active_backend(),
            "active_worker_api": self.active_worker_api(),
            "responsive": False,
            "pyghidra_available": available,
            "pyghidra_python": interpreter,
            "ghidra_install_dir": os.environ.get("GHIDRA_INSTALL_DIR"),
            "cache_dir": str(cache_dir(self.cfg)),
            "project_dir": str(project_dir()),
        }
        result.update(self._session_liveness(running=result["running"]))
        admission = operation_admission(self.cfg)
        result["admission"] = admission
        result["busy"] = bool(result.get("busy") or admission)
        if discovery_error:
            result["error"] = discovery_error
        if result["running"] and not (
            result["active_backend"] in {None, "host"}
            and result["active_worker_api"] == WORKER_API
        ):
            if result["active_worker_api"] != WORKER_API:
                result["error"] = (
                    f"worker API {result['active_worker_api'] or 'legacy'} owns "
                    f"the {protocol_family()} socket; refusing automatic migration. "
                    "Reload/version-align the client and worker."
                )
            else:
                result["error"] = (
                    f"a {result['active_backend']} worker owns the decomp socket; "
                    "the next host query will migrate it"
                )
        return result

    def ensure_selected_backend(self) -> None:
        selected = backend()
        active = self.active_backend()
        if active is not None and active != selected:
            self._shutdown_conflicting_worker(active, selected)
        elif active is not None and self.active_worker_api() != WORKER_API:
            raise DecompError(
                f"worker API {self.active_worker_api() or 'legacy'} owns the "
                f"{protocol_family()} namespace; refusing automatic shutdown or "
                f"downgrade. Reload/version-align for API {WORKER_API}.",
                code="worker_version_mismatch",
            )

    def call(
        self,
        op: str,
        *,
        start: bool = True,
        timeout: float = 900.0,
        request_id: str = "",
        **args: Any,
    ) -> dict[str, Any]:
        """Run one worker operation with immediate, visible admission control."""
        if op == "status":
            return self._call(
                op, start=start, timeout=timeout, request_id=request_id, **args,
            )
        details = {
            "request_id": request_id[:64],
            "binary_sha256": str(args.get("sha256") or "")[:64],
            "binary_name": Path(str(args.get("binary_name") or "")).name[:260],
        }
        try:
            with admit_operation(
                runtime_dir(self.cfg), f"decomp-{protocol_family()}",
                operation=op, owner="decomp_worker", details=details,
            ) as lease:
                result = self._call(
                    op, start=start, timeout=timeout, request_id=request_id, **args,
                )
                result = dict(result)
                result["operation_metadata"] = lease.metadata()
                return result
        except OperationBusyError as exc:
            raise DecompError(
                exc, code=exc.code, retryable=exc.retryable, details=exc.details,
            ) from exc

    def _call(
        self,
        op: str,
        *,
        start: bool = True,
        timeout: float = 900.0,
        request_id: str = "",
        **args: Any,
    ) -> dict[str, Any]:
        selected_backend = backend()
        if request_id:
            if not re.fullmatch(r"[0-9a-f]{32}", request_id):
                raise DecompError(
                    "request_id must be 32 lowercase hexadecimal characters",
                    code="invalid_argument",
                )
        else:
            request_id = secrets.token_hex(16)
        active = self.active_backend()
        if active is not None and active != selected_backend:
            if not start:
                raise DecompError(
                    f"{active} worker is active but {selected_backend} backend was selected",
                    code="worker_backend_mismatch",
                )
            self._shutdown_conflicting_worker(active, selected_backend)
        elif active is not None and self.active_worker_api() != WORKER_API:
            raise DecompError(
                f"worker API {self.active_worker_api() or 'legacy'} owns the "
                f"{protocol_family()} namespace but API {WORKER_API} is required; "
                "refusing automatic shutdown or downgrade. Reload/version-align "
                "the client and worker.", code="worker_version_mismatch",
            )
        if op in {"decompile", "prepare"} and selected_backend == "docker":
            args = dict(args)
            args.setdefault("binary_name", Path(str(args.get("binary", ""))).name)
            # Keep the exact staged input alive through first-worker startup.
            # Once startup completes, worker_alive() makes applied pruning
            # refuse; the worker takes this same lock around project access.
            with maintenance_lock(self.cfg):
                args["binary"] = self._stage_binary(
                    Path(str(args.get("binary", ""))),
                    str(args.get("sha256", "")),
                )
                if args.get("enrichment"):
                    args["enrichment"] = self._container_enrichment_path(
                        Path(str(args["enrichment"])),
                    )
                if not self.worker_alive() and start:
                    self._start_worker()
        payload = json.dumps(
            {"request_id": request_id, "op": op, "args": args}, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        if len(payload) > MAX_REQUEST_BYTES:
            raise DecompError(
                f"decomp request exceeds {MAX_REQUEST_BYTES} bytes",
                code="invalid_argument",
            )
        last: BaseException | None = None
        for attempt in range(2):
            if not self.worker_alive():
                if not start:
                    raise DecompError(
                        "PyGhidra worker is not running",
                        code="worker_not_running", retryable=True,
                    )
                self._start_worker()
            try:
                if op == "status":
                    reply = self._exchange(payload, timeout=timeout)
                else:
                    # The transaction owns project import/open/save for its
                    # complete lifetime. Status remains non-mutating and does
                    # not queue behind cache maintenance.
                    with maintenance_lock(self.cfg):
                        reply = self._exchange(payload, timeout=timeout)
            except (OSError, DecompError) as exc:
                if op in {"decompile", "prepare"}:
                    self._cancel_request(request_id)
                last = exc
                # A stale socket or worker crash is recoverable once.  Do not
                # blindly retry an application-level reply, only transport.
                if attempt == 0 and not self.worker_alive():
                    continue
                raise DecompError(
                    f"PyGhidra worker communication failed: {exc}",
                    code="worker_communication", retryable=True,
                ) from exc
            if reply.get("request_id") != request_id:
                raise DecompError(
                    "PyGhidra worker returned a mismatched request id",
                    code="invalid_response", retryable=True,
                )
            if not reply.get("ok"):
                info = parse_error_info(reply.get("error_info"))
                if info is not None:
                    raise DecompError(
                        info["message"], code=info["code"],
                        retryable=info["retryable"], details=info["details"],
                    )
                raise DecompError(str(reply.get("error") or "PyGhidra worker failed"))
            result = reply.get("result")
            if not isinstance(result, dict):
                raise DecompError(
                    "PyGhidra worker returned a malformed result",
                    code="invalid_response", retryable=True,
                )
            if op == "shutdown":
                deadline = time.monotonic() + 10.0
                while self.worker_alive() and time.monotonic() < deadline:
                    time.sleep(0.05)
            return result
        raise DecompError(f"PyGhidra worker unavailable: {last}")

    def _shutdown_conflicting_worker(self, active: str, selected: str) -> None:
        request_id = secrets.token_hex(16)
        try:
            with maintenance_lock(self.cfg):
                reply = self._exchange(
                    json.dumps({
                        "request_id": request_id, "op": "shutdown", "args": {},
                    }, separators=(",", ":")).encode() + b"\n", timeout=10.0
                )
        except (OSError, DecompError) as exc:
            raise DecompError(
                f"could not migrate active {active} worker to {selected}: {exc}"
            ) from exc
        if not reply.get("ok"):
            raise DecompError(
                f"active {active} worker refused migration: {reply.get('error')}"
            )
        deadline = time.monotonic() + 10.0
        while self.worker_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if self.worker_alive():
            raise DecompError(f"active {active} worker did not stop for migration")

    def _exchange(self, payload: bytes, *, timeout: float) -> dict[str, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(max(0.1, float(timeout)))
            sock.connect(str(socket_path(self.cfg)))
            sock.sendall(payload)
            raw = _read_line(sock, MAX_RESPONSE_BYTES)
        finally:
            sock.close()
        try:
            reply = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DecompError(f"invalid worker JSON: {exc}") from exc
        if not isinstance(reply, dict):
            raise DecompError("worker reply is not an object")
        return reply

    def _start_worker(self) -> None:
        with maintenance_lock(self.cfg):
            # Re-check under the shared lock: another caller may have started
            # the worker while this caller waited.
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


def _read_line(sock: socket.socket, cap: int) -> bytes:
    value = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            raise DecompError("worker closed connection before newline")
        value.extend(chunk)
        newline = value.find(b"\n")
        if newline >= 0:
            return bytes(value[:newline])
        if len(value) > cap:
            raise DecompError(f"worker response exceeds {cap} bytes")


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()
