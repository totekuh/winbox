"""Non-queueing cross-process admission leases for expensive research work."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from winbox.kdbg.errors import bounded_details


_STATE_MAX_BYTES = 16 * 1024
_registry_guard = threading.Lock()
_process_locks: dict[str, threading.Lock] = {}


def _process_lock(path: Path) -> threading.Lock:
    with _registry_guard:
        return _process_locks.setdefault(str(path), threading.Lock())


class OperationBusyError(RuntimeError):
    """The single safe execution slot is already held by another request."""

    code = "busy"
    retryable = True

    def __init__(self, operation: str, active: dict[str, Any] | None = None) -> None:
        self.details = {"requested_operation": operation[:64]}
        if active:
            self.details["active"] = bounded_details(active)
        super().__init__(
            f"{operation} is busy; inspect the active operation and retry after it finishes"
        )


@dataclass
class OperationLease:
    """A held non-queueing operation slot with additive timing evidence."""

    token: str
    operation: str
    owner: str
    started_monotonic: float
    acquired_at: float
    state_path: Path

    def metadata(self) -> dict[str, Any]:
        return {
            "id": self.token,
            "owner": self.owner,
            "operation": self.operation,
            "admission": "accepted",
            "queue_delay_ms": 0.0,
            "elapsed_ms": round((time.monotonic() - self.started_monotonic) * 1000, 3),
        }


def _paths(root: Path, name: str) -> tuple[Path, Path]:
    safe = "".join(char if char.isalnum() or char in "-_" else "_" for char in name)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root / f"{safe}.admission.lock", root / f"{safe}.admission.json"


def _read_state(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or path.stat().st_size > _STATE_MAX_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != "winbox.operation-admission/1":
        return None
    return bounded_details(value)


def active_admission(root: Path, name: str) -> dict[str, Any] | None:
    """Return a verified active lease; stale state files never count as busy."""
    lock, state = _paths(root, name)
    process_lock = _process_lock(lock)
    if process_lock.locked():
        return _read_state(state) or {"schema": "winbox.operation-admission/1"}
    try:
        handle = lock.open("a+b")
    except OSError:
        return None
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return _read_state(state) or {"schema": "winbox.operation-admission/1"}
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return None
    finally:
        handle.close()


def _write_state(path: Path, value: dict[str, Any]) -> None:
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def admit_operation(
    root: Path,
    name: str,
    *,
    operation: str,
    owner: str,
    details: dict[str, Any] | None = None,
) -> Iterator[OperationLease]:
    """Hold one host-wide operation slot or return a typed, immediate busy error.

    There is deliberately no hidden FIFO backlog.  A request either owns the
    slot and can expose its timing/correlation ID, or it fails before it can
    halt a guest or wait behind an unbounded Ghidra operation.
    """
    lock, state = _paths(root, name)
    process_lock = _process_lock(lock)
    if not process_lock.acquire(blocking=False):
        raise OperationBusyError(operation, _read_state(state))
    handle = None
    try:
        handle = lock.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise OperationBusyError(operation, _read_state(state)) from exc
        started_monotonic = time.monotonic()
        acquired_at = time.time()
        lease = OperationLease(
            token=secrets.token_hex(16), operation=operation[:64], owner=owner[:64],
            started_monotonic=started_monotonic, acquired_at=acquired_at,
            state_path=state,
        )
        _write_state(state, {
            "schema": "winbox.operation-admission/1",
            "id": lease.token,
            "operation": lease.operation,
            "owner": lease.owner,
            "pid": os.getpid(),
            "started_at": acquired_at,
            "details": bounded_details(details or {}),
        })
        try:
            yield lease
        finally:
            with suppress(OSError):
                current = _read_state(state)
                if current is None or current.get("id") == lease.token:
                    state.unlink(missing_ok=True)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        if handle is not None:
            handle.close()
        process_lock.release()
