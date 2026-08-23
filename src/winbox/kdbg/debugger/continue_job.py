"""Durable host-side orchestration for long-running kdbg continue calls.

The debugger daemon deliberately remains single-threaded.  This module puts
the blocking ``cont`` client call in a tiny detached host process and persists
its bounded state atomically, so MCP transports may disconnect/reload while a
rare breakpoint is pending.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import secrets
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from winbox.config import Config
from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.debugger.daemon import sock_path


SCHEMA = "winbox.kdbg-cont/1"
MAX_TIMEOUT = 24 * 60 * 60
MAX_STATE_BYTES = 256 * 1024
MAX_RESULT_BYTES = 64 * 1024
ACTIVE_STATES = frozenset({"starting", "running", "cancel_requested"})


class ContinueJobError(RuntimeError):
    """The async continue request is invalid or conflicts with another job."""


def _root(cfg: Config) -> Path:
    return sock_path(cfg).parent


def state_path(cfg: Config) -> Path:
    return _root(cfg) / "kdbg.cont.json"


def lock_path(cfg: Config) -> Path:
    return _root(cfg) / "kdbg.cont.lock"


def log_path(cfg: Config) -> Path:
    return _root(cfg) / "kdbg.cont.log"


@contextmanager
def _locked(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / "kdbg.cont.lock"
    with path.open("a+b") as handle:
        os.chmod(path, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read(root: Path) -> dict[str, Any] | None:
    try:
        path = root / "kdbg.cont.json"
        if path.stat().st_size > MAX_STATE_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        return None
    return value


def _write(root: Path, value: dict[str, Any]) -> None:
    value = dict(value)
    value["schema"] = SCHEMA
    value["updated_at"] = time.time()
    path = root / "kdbg.cont.json"
    temporary = root / f".kdbg.cont.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _worker_alive(pid: Any, token: str) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return True
    joined = b"\0".join(cmdline)
    return b"winbox.kdbg.debugger.continue_job" in joined and token.encode() in joined


def _worker_starting(record: dict[str, Any]) -> bool:
    """Cover the tiny Popen-to-exec window without trusting old reused PIDs."""
    if record.get("state") != "starting":
        return False
    created = record.get("created_at")
    pid = record.get("worker_pid")
    if not isinstance(created, (int, float)) or time.time() - created > 5.0:
        return False
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _bounded_timeout(value: float) -> float:
    if isinstance(value, bool):
        raise ContinueJobError("timeout must be a finite number")
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ContinueJobError("timeout must be a finite number") from exc
    if not math.isfinite(timeout) or not 0.5 <= timeout <= MAX_TIMEOUT:
        raise ContinueJobError(
            f"timeout must be between 0.5 and {MAX_TIMEOUT} seconds"
        )
    return timeout


def start_continue(cfg: Config, *, timeout: float = 300.0) -> dict[str, Any]:
    """Start one detached continue operation and return its durable token."""
    timeout = _bounded_timeout(timeout)
    client = DaemonClient(cfg)
    try:
        status = client.call("status", sock_timeout=5.0)
    except ClientError as exc:
        raise ContinueJobError(str(exc)) from exc
    if status.get("state") != "halted":
        raise ContinueJobError(
            f"debugger must be halted before cont_start (state={status.get('state')})"
        )
    session_id = status.get("session_id")
    stop_id = status.get("stop_id")
    if not isinstance(session_id, str) or not session_id:
        raise ContinueJobError("debugger status omitted session_id")

    root = _root(cfg)
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _locked(root):
        previous = _read(root)
        if previous and previous.get("state") in ACTIVE_STATES:
            old_token = str(previous.get("token") or "")
            if (_worker_alive(previous.get("worker_pid"), old_token)
                    or _worker_starting(previous)):
                raise ContinueJobError(
                    f"continue job already active (token={old_token})"
                )
            previous.update(
                state="failed",
                error="continue worker exited without publishing a result",
                retryable=True,
            )
            _write(root, previous)
        record = {
            "schema": SCHEMA,
            "token": token,
            "state": "starting",
            "created_at": now,
            "updated_at": now,
            "timeout": timeout,
            "worker_pid": None,
            "daemon_session_id": session_id,
            "start_stop_id": stop_id,
            "result": None,
            "error": None,
            "retryable": False,
        }
        _write(root, record)

        command = [
            sys.executable, "-m", "winbox.kdbg.debugger.continue_job",
            f"--runtime-dir={root}", f"--token={token}",
            f"--timeout={timeout!r}", f"--session-id={session_id}",
        ]
        log = root / "kdbg.cont.log"
        with log.open("ab", buffering=0) as output:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
                close_fds=True,
                start_new_session=True,
            )
        record["worker_pid"] = process.pid
        _write(root, record)
    return _public(record)


def poll_continue(cfg: Config, *, token: str = "") -> dict[str, Any]:
    """Read the latest bounded job state and repair dead-worker state."""
    if not isinstance(token, str) or len(token) > 128:
        raise ContinueJobError("invalid continue token")
    root = _root(cfg)
    with _locked(root):
        record = _read(root)
        if record is None:
            return {"schema": SCHEMA, "state": "idle", "active": False}
        if token and token != record.get("token"):
            raise ContinueJobError("continue token does not match the current job")
        if (record.get("state") in ACTIVE_STATES
                and not _worker_alive(
                    record.get("worker_pid"), str(record.get("token") or "")
                )
                and not _worker_starting(record)):
            record.update(
                state="failed",
                error="continue worker exited without publishing a result",
                retryable=True,
            )
            _write(root, record)
        return _public(record)


def cancel_continue(cfg: Config, *, token: str = "") -> dict[str, Any]:
    """Request a cooperative halt; the worker publishes the final stop."""
    current = poll_continue(cfg, token=token)
    if current.get("state") not in ACTIVE_STATES:
        return current
    root = _root(cfg)
    with _locked(root):
        record = _read(root)
        if record is None or record.get("token") != current.get("token"):
            raise ContinueJobError("continue job changed while cancellation was requested")
        if record.get("state") not in ACTIVE_STATES:
            return _public(record)
        # Publish intent before sending the interrupt. The cont worker may
        # return immediately after that packet; prepublication guarantees it
        # labels the terminal result cancelled instead of racing to completed.
        record["state"] = "cancel_requested"
        _write(root, record)
    try:
        result = DaemonClient(cfg).call("interrupt", sock_timeout=5.0)
    except ClientError as exc:
        with _locked(root):
            record = _read(root)
            if (record and record.get("token") == current.get("token")
                    and record.get("state") == "cancel_requested"):
                record["state"] = "running"
                _write(root, record)
        raise ContinueJobError(str(exc)) from exc
    with _locked(root):
        record = _read(root)
        if record and record.get("token") == current.get("token"):
            if record.get("state") == "cancel_requested":
                record["cancel"] = result
                _write(root, record)
            return _public(record)
    raise ContinueJobError("continue job changed while cancellation was requested")


def wait_continue(
    cfg: Config, *, token: str = "", timeout: float = 5.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        result = poll_continue(cfg, token=token)
        if result.get("state") not in ACTIVE_STATES:
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(0.05)


def _public(record: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema", "token", "state", "created_at", "updated_at", "timeout",
        "worker_pid", "daemon_session_id", "start_stop_id", "result", "error",
        "retryable", "cancel",
    }
    result = {key: record[key] for key in allowed if key in record}
    result["active"] = result.get("state") in ACTIVE_STATES
    return result


def _bounded_result(result: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(result, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return {"truncated": True, "reason": "malformed daemon result"}
    if len(encoded) <= MAX_RESULT_BYTES:
        return result
    keep = {
        key: result[key] for key in (
            "reason", "state", "vcpu", "rip", "cr3", "session_id", "stop_id",
        ) if key in result
    }
    keep.update(truncated=True, original_bytes=len(encoded))
    return keep


def _run_worker(root: Path, token: str, timeout: float, session_id: str) -> int:
    cfg = SimpleNamespace(root_dir=root)
    with _locked(root):
        record = _read(root)
        if record is None or record.get("token") != token:
            return 2
        record.update(state="running", worker_pid=os.getpid())
        _write(root, record)

    try:
        client = DaemonClient(cfg)  # type: ignore[arg-type]
        status = client.call("status", sock_timeout=5.0)
        if status.get("session_id") != session_id:
            raise ContinueJobError("debugger session changed before continue started")
        result = client.call(
            "cont", sock_timeout=timeout + 10.0, timeout=timeout,
        )
        result = _bounded_result(result)
        error = None
    except (ClientError, ContinueJobError) as exc:
        result = None
        error = str(exc)[:2048]

    with _locked(root):
        record = _read(root)
        if record is None or record.get("token") != token:
            return 3
        if error is not None:
            record.update(state="failed", result=None, error=error, retryable=True)
        else:
            state = "cancelled" if record.get("state") == "cancel_requested" else "completed"
            record.update(state=state, result=result, error=None, retryable=False)
        _write(root, record)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args(argv)
    return _run_worker(
        args.runtime_dir, args.token, _bounded_timeout(args.timeout), args.session_id,
    )


if __name__ == "__main__":
    raise SystemExit(main())
