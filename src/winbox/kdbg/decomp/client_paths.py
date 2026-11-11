"""Paths, constants, and non-class utilities for the decomp worker client."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.admission import active_admission
from winbox.kdbg.errors import bounded_details
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
