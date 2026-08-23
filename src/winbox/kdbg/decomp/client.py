"""Client and lifecycle manager for the isolated PyGhidra worker."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from winbox.config import Config


class DecompError(RuntimeError):
    """PyGhidra is unavailable or the worker rejected a request."""


MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def runtime_dir(cfg: Config) -> Path:
    return Path(cfg.winbox_dir) / "decomp"


def socket_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / "decomp.sock"


def lock_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / "decomp.lock"


def session_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / "decomp.session.json"


def cache_dir(cfg: Config) -> Path:
    return runtime_dir(cfg) / "cache"


def log_path(cfg: Config) -> Path:
    return runtime_dir(cfg) / "decomp.log"


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

    def status(self) -> dict[str, Any]:
        selected = backend()
        if selected == "docker":
            from winbox.kdbg.decomp.docker import DockerManager, project_dir as docker_projects

            manager = DockerManager(self.cfg)
            result = manager.status()
            result.update({
                "running": self.worker_alive(),
                "active_backend": self.active_backend(),
                "responsive": False,
                "cache_dir": str(cache_dir(self.cfg)),
                "project_dir": str(docker_projects(self.cfg)),
            })
            if result["running"] and result["active_backend"] in {None, "docker"}:
                try:
                    result.update(self.call("status", start=False, timeout=5.0))
                    result["responsive"] = True
                except DecompError as exc:
                    result["busy"] = True
                    result["error"] = str(exc)
            elif result["running"]:
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
            "responsive": False,
            "pyghidra_available": available,
            "pyghidra_python": interpreter,
            "ghidra_install_dir": os.environ.get("GHIDRA_INSTALL_DIR"),
            "cache_dir": str(cache_dir(self.cfg)),
            "project_dir": str(project_dir()),
        }
        if discovery_error:
            result["error"] = discovery_error
        if result["running"] and result["active_backend"] in {None, "host"}:
            try:
                result.update(self.call("status", start=False, timeout=5.0))
                result["responsive"] = True
            except DecompError as exc:
                # The worker is deliberately serialized; status can time out
                # behind first-use auto-analysis. The fcntl lock still proves
                # the process is alive, so report busy/unresponsive instead of
                # falsely claiming it stopped and spawning a competing JVM.
                result["busy"] = True
                result["error"] = str(exc)
        elif result["running"]:
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

    def call(
        self,
        op: str,
        *,
        start: bool = True,
        timeout: float = 900.0,
        **args: Any,
    ) -> dict[str, Any]:
        selected_backend = backend()
        if op == "decompile" and selected_backend == "docker":
            args = dict(args)
            args["binary"] = self._stage_binary(
                Path(str(args.get("binary", ""))), str(args.get("sha256", ""))
            )
        active = self.active_backend()
        if active is not None and active != selected_backend:
            if not start:
                raise DecompError(
                    f"{active} worker is active but {selected_backend} backend was selected"
                )
            self._shutdown_conflicting_worker(active, selected_backend)
        payload = json.dumps(
            {"op": op, "args": args}, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        if len(payload) > MAX_REQUEST_BYTES:
            raise DecompError(f"decomp request exceeds {MAX_REQUEST_BYTES} bytes")
        last: BaseException | None = None
        for attempt in range(2):
            if not self.worker_alive():
                if not start:
                    raise DecompError("PyGhidra worker is not running")
                self._start_worker()
            try:
                reply = self._exchange(payload, timeout=timeout)
            except (OSError, DecompError) as exc:
                last = exc
                # A stale socket or worker crash is recoverable once.  Do not
                # blindly retry an application-level reply, only transport.
                if attempt == 0 and not self.worker_alive():
                    continue
                raise DecompError(f"PyGhidra worker communication failed: {exc}") from exc
            if not reply.get("ok"):
                raise DecompError(str(reply.get("error") or "PyGhidra worker failed"))
            result = reply.get("result")
            if not isinstance(result, dict):
                raise DecompError("PyGhidra worker returned a malformed result")
            if op == "shutdown":
                deadline = time.monotonic() + 10.0
                while self.worker_alive() and time.monotonic() < deadline:
                    time.sleep(0.05)
            return result
        raise DecompError(f"PyGhidra worker unavailable: {last}")

    def _shutdown_conflicting_worker(self, active: str, selected: str) -> None:
        try:
            reply = self._exchange(
                b'{"op":"shutdown","args":{}}\n', timeout=10.0
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
        if backend() == "docker":
            from winbox.kdbg.decomp.docker import DockerError, DockerManager

            try:
                DockerManager(self.cfg).start()
            except DockerError as exc:
                raise DecompError(str(exc)) from exc
            return
        self._start_host_worker()

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
                    self._exchange(
                        b'{"op":"status","args":{}}\n', timeout=1.0
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
