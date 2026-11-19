"""Reader fork, ensure, stop, and public snapshot context managers."""

from __future__ import annotations

import atexit
import json
import os
import signal
import socket
import time
from contextlib import contextmanager, suppress
from typing import Iterator

from winbox.config import Config
from winbox.kdbg.debugger.child_lifecycle import kill_pid_until_dead
from winbox.kdbg.debugger.rsp import RspClient
from winbox.kdbg.hmp import HmpError, gdbstub_has_client, hmp, probe_port
from winbox.kdbg.debugger.reader.types import (
    ReaderError,
    SnapshotBudget,
    SnapshotBudgetError,
    _DEFAULT_PORT,
    _READER_STARTUP_TIMEOUT,
    _STARTUP_STATUS_MAX_BYTES,
    _active_snapshot,
    _request,
    lock_path,
    log_path,
    session_path,
    sock_path,
)
from winbox.kdbg.debugger.reader.snapshot import DebugSnapshot, _RemoteSnapshot
from winbox.kdbg.debugger.reader.local import current_snapshot
from winbox.kdbg.debugger.reader.broker import _ReaderBroker, _reader_alive


def _acquire_lock(cfg: Config) -> int:
    fd = os.open(lock_path(cfg), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise ReaderError("another RSP reader owns the gdbstub") from exc
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())
    return fd


def _detach_to_log(cfg: Config) -> None:
    os.setsid()
    stream = open(log_path(cfg), "ab", buffering=0)
    os.dup2(stream.fileno(), 1)
    os.dup2(stream.fileno(), 2)
    with open(os.devnull, "rb") as devnull:
        os.dup2(devnull.fileno(), 0)


def _bind_listener(cfg: Config) -> socket.socket:
    path = sock_path(cfg)
    with suppress(OSError):
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)
    listener.listen(16)
    return listener


def _open_rsp(cfg: Config, port: int) -> RspClient:
    if gdbstub_has_client(port):
        raise ReaderError(
            "gdbstub already has a client; detach the interactive debugger first"
        )
    if not probe_port("127.0.0.1", port):
        rc, out, err = hmp(
            cfg.vm_name, f"gdbserver tcp:127.0.0.1:{port}", mode="tuple",
        )
        if rc:
            raise ReaderError(err or out or "failed to start gdbserver")
    rsp = RspClient.connect("127.0.0.1", port, timeout=5.0)
    try:
        rsp.handshake()
        rsp.query_halt_reason()
        return rsp
    except BaseException:
        with suppress(Exception):
            rsp.cont()
        with suppress(OSError):
            rsp._sock.close()
        raise


def _fork_reader(cfg: Config, port: int) -> int:
    from winbox.kdbg.debugger.child_lifecycle import (
        ChildStartupError,
        supervise_startup,
    )

    pipe_r, pipe_w = os.pipe()
    pid = os.fork()
    if pid:
        os.close(pipe_w)
        try:
            line = supervise_startup(
                pid,
                pipe_r,
                timeout=_READER_STARTUP_TIMEOUT,
                max_bytes=_STARTUP_STATUS_MAX_BYTES,
                label="RSP reader",
            )
        except ChildStartupError as exc:
            raise ReaderError(str(exc)) from exc
        status = line.decode(errors="replace")
        if status == "OK":
            return pid
        raise ReaderError(status.removeprefix("ERR: ") or "reader broker failed")

    os.close(pipe_r)
    class _StartupCancelled(Exception):
        pass

    def _cancel_startup(_signum, _frame):
        raise _StartupCancelled("reader startup cancelled by parent")

    signal.signal(signal.SIGTERM, _cancel_startup)
    signal.signal(signal.SIGINT, _cancel_startup)
    rsp: RspClient | None = None
    listener: socket.socket | None = None
    lock_fd: int | None = None
    exit_code = 0
    guest_running = False
    try:
        _detach_to_log(cfg)
        lock_fd = _acquire_lock(cfg)
        rsp = _open_rsp(cfg, port)
        rsp.cont()
        guest_running = True
        listener = _bind_listener(cfg)
        reader_session_path = session_path(cfg)
        reader_session_path.write_text(json.dumps({
            "pid": os.getpid(), "port": port, "vm_name": cfg.vm_name,
            "cet_safe": True,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }), encoding="utf-8")
        os.chmod(reader_session_path, 0o600)

        broker = _ReaderBroker(cfg, rsp, port)
        def _signal(_signum, _frame):
            broker.shutdown_requested = True

        signal.signal(signal.SIGTERM, _signal)
        signal.signal(signal.SIGINT, _signal)
        os.write(pipe_w, b"OK\n")
        os.close(pipe_w)
        pipe_w = -1

        broker.serve(listener)
        if broker.poisoned:
            exit_code = 2
    except BaseException as exc:
        if pipe_w >= 0:
            with suppress(OSError):
                os.write(pipe_w, f"ERR: {type(exc).__name__}: {exc}\n".encode())
        exit_code = 1
    finally:
        if listener is not None:
            with suppress(OSError):
                listener.close()
        if rsp is not None:
            if pipe_w >= 0 and not guest_running:
                with suppress(Exception):
                    rsp.cont()
            with suppress(OSError):
                rsp._sock.close()
        with suppress(OSError):
            sock_path(cfg).unlink()
        with suppress(OSError):
            session_path(cfg).unlink()
        if lock_fd is not None:
            with suppress(OSError):
                os.close(lock_fd)
    os._exit(exit_code)


def ensure_reader(cfg: Config, *, port: int = _DEFAULT_PORT) -> None:
    if _reader_alive(cfg):
        try:
            info = json.loads(session_path(cfg).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            info = {}
        if info.get("cet_safe") is True:
            return
        stop_reader(cfg)
    from winbox.kdbg.debugger.client import DaemonClient
    if DaemonClient(cfg).session_alive():
        raise ReaderError(
            "interactive kdbg session owns the gdbstub; detach it before a standalone walk"
        )
    from winbox.kdbg.cet import CetSafetyError, require_safe
    try:
        require_safe(cfg)
    except CetSafetyError as exc:
        raise ReaderError(str(exc)) from exc
    try:
        _fork_reader(cfg, port)
    except ReaderError:
        if not _reader_alive(cfg):
            raise
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if sock_path(cfg).exists():
            return
        time.sleep(0.01)
    raise ReaderError("RSP reader started but its Unix socket did not appear")


def stop_reader(
    cfg: Config,
    *,
    timeout: float = 5.0,
    term_grace: float = 2.0,
    kill_grace: float = 2.0,
) -> bool:
    """Stop the persistent reader if present.

    Graceful-first (unix-socket ``shutdown``), then verify death and escalate
    SIGTERM -> SIGKILL if it did not exit. Returns ``True`` only when a reader
    existed AND is now confirmed dead; raises ``ReaderError`` if a reader
    survives SIGKILL. Returns ``False`` when no reader was alive.
    """
    if not _reader_alive(cfg):
        return False
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(str(sock_path(cfg)))
        _request(sock, "shutdown")
    except (OSError, ReaderError):
        pass
    finally:
        sock.close()

    # Give the graceful shutdown a chance to land.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and _reader_alive(cfg):
        time.sleep(0.02)

    # Still alive -> force it dead, verifying via the flock probe (never waitpid:
    # the reader is setsid-detached and not our child).
    if _reader_alive(cfg):
        pid: int | None = None
        with suppress(OSError, ValueError, KeyError, json.JSONDecodeError):
            info = json.loads(session_path(cfg).read_text(encoding="utf-8"))
            pid = int(info["pid"])
        if not kill_pid_until_dead(
            pid,
            lambda: _reader_alive(cfg),
            term_grace=term_grace,
            kill_grace=kill_grace,
        ):
            raise ReaderError(
                f"reader daemon pid={pid} survived SIGKILL; gdbstub may be stuck"
            )

    # Confirmed dead. Tidy stale runtime files (self-heals anyway; lock untouched).
    with suppress(OSError):
        sock_path(cfg).unlink()
    with suppress(OSError):
        session_path(cfg).unlink()
    return True


@contextmanager
def debug_snapshot(
    cfg: Config,
    *,
    port: int = _DEFAULT_PORT,
    budget: SnapshotBudget | None = None,
    operation: str = "snapshot",
) -> Iterator[DebugSnapshot]:
    existing = current_snapshot(cfg.vm_name)
    if existing is not None:
        yield existing
        return
    snapshot: _RemoteSnapshot | None = None
    for attempt in range(2):
        ensure_reader(cfg, port=port)
        try:
            snapshot = (
                _RemoteSnapshot.connect(cfg)
                if budget is None else _RemoteSnapshot.connect(cfg, budget=budget)
            )
            break
        except (OSError, ReaderError) as exc:
            if getattr(exc, "code", None) == "busy":
                raise
            if attempt:
                raise
            stop_reader(cfg)
    assert snapshot is not None
    token = _active_snapshot.set(snapshot)
    outcome = "ok"
    error_code: str | None = None
    try:
        yield snapshot
    except BaseException as exc:
        outcome = "error"
        raw_code = getattr(exc, "code", None)
        error_code = raw_code if isinstance(raw_code, str) else None
        raise
    finally:
        try:
            snapshot.close()
        finally:
            try:
                from winbox.kdbg.telemetry import record_snapshot_operation
                record_snapshot_operation(
                    cfg, operation=operation, outcome=outcome,
                    snapshot_metadata=snapshot.operation_metadata(), error_code=error_code,
                )
            except Exception:
                pass
            _active_snapshot.reset(token)


@contextmanager
def debug_snapshot_for_vm(vm_name: str) -> Iterator[DebugSnapshot]:
    cfg = Config.load()
    if cfg.vm_name != vm_name:
        cfg.vm_name = vm_name
    with debug_snapshot(cfg) as snapshot:
        yield snapshot


_TRANSIENT_READ_SIGNS = (
    "e14", "m failed", "not present", "pml4e", "pdpte", "pde not", "pte not",
)
_SNAPSHOT_OP_RETRIES = 3


def _is_transient_read_error(exc: BaseException) -> bool:
    """A read that missed a not-present page under this frozen stop.

    PsActiveProcessHead and other kernel globals live on pageable sections; a
    single halt can catch such a page transiently not-present (the gdbstub
    answers ``E14``), which is frozen for the life of that stop. A fresh halt a
    moment later re-samples the vCPU CR3s and usually finds the page faulted
    back in. Budget and busy errors are real limits, not transients.
    """
    if getattr(exc, "code", None) in {"busy", SnapshotBudgetError.code}:
        return False
    message = str(exc).lower()
    return any(sign in message for sign in _TRANSIENT_READ_SIGNS)


def snapshot_operation(func):
    """Wrap a public walker/memory operation in one coherent RSP snapshot.

    A transient not-present read (see ``_is_transient_read_error``) retries in a
    fresh snapshot, so one paged-out kernel page does not fail the whole
    operation. Only standalone calls retry; when a caller already owns the
    active snapshot the read is part of their coherent stop and must surface.
    """
    def wrapped(vm_name: str, *args, **kwargs):
        for attempt in range(_SNAPSHOT_OP_RETRIES):
            caller_owns_snapshot = current_snapshot(vm_name) is not None
            try:
                with debug_snapshot_for_vm(vm_name):
                    return func(vm_name, *args, **kwargs)
            except (ReaderError, HmpError) as exc:
                last = attempt + 1 >= _SNAPSHOT_OP_RETRIES
                if caller_owns_snapshot or last or not _is_transient_read_error(exc):
                    raise
                time.sleep(0.15 * (attempt + 1))
    wrapped.__name__ = func.__name__
    wrapped.__doc__ = func.__doc__
    wrapped.__module__ = func.__module__
    return wrapped


atexit.register(lambda: None)
