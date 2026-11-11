"""Client and lifecycle manager for the isolated PyGhidra worker."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import socket
import time
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.admission import OperationBusyError, admit_operation
from winbox.kdbg.errors import parse_error_info
from winbox.kdbg.decomp.client_paths import (  # noqa: F401 — re-exported
    DecompError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, WORKER_API,
    open_program_limit, protocol_family, runtime_dir, socket_path,
    lock_path, session_path, cache_dir, log_path, maintenance_lock_path,
    maintenance_lock, operation_admission, project_dir, backend,
    discover_pyghidra_python, _read_line, _sha256,
)
from winbox.kdbg.decomp.client_lifecycle import _DecompLifecycleMixin


class DecompClient(_DecompLifecycleMixin):
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
                    with maintenance_lock(self.cfg):
                        reply = self._exchange(payload, timeout=timeout)
            except (OSError, DecompError) as exc:
                if op in {"decompile", "prepare"}:
                    self._cancel_request(request_id)
                last = exc
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
