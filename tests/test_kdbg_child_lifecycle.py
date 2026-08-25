"""Real-process coverage for bounded debugger child supervision."""

from __future__ import annotations

import os
import signal
import time

import pytest

from winbox.kdbg.debugger.child_lifecycle import (
    ChildStartupError,
    supervise_startup,
)

pytestmark = pytest.mark.filterwarnings(
    "ignore:This process .* is multi-threaded, use of fork.*:DeprecationWarning"
)


def _spawn_writer(payload: bytes | None, *, linger: float = 0.0):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        if payload is not None:
            os.write(write_fd, payload)
        if linger:
            time.sleep(linger)
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    return pid, read_fd


def _assert_reaped(pid: int, *, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    pytest.fail(f"child {pid} was not reaped")


def test_successful_child_is_reaped_after_later_exit():
    pid, fd = _spawn_writer(b"OK\n", linger=0.05)
    assert supervise_startup(
        pid, fd, timeout=1, max_bytes=1024, label="test child",
    ) == b"OK"
    _assert_reaped(pid)


def test_error_status_child_is_synchronously_reaped():
    pid, fd = _spawn_writer(b"ERR: bootstrap failed\n")
    assert supervise_startup(
        pid, fd, timeout=1, max_bytes=1024, label="test child",
    ) == b"ERR: bootstrap failed"
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_hung_startup_is_terminated_and_reaped():
    pid, fd = _spawn_writer(None, linger=10)
    started = time.monotonic()
    with pytest.raises(ChildStartupError, match="timed out"):
        supervise_startup(
            pid, fd, timeout=0.05, max_bytes=1024, label="hung child",
        )
    assert time.monotonic() - started < 2
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_oversized_startup_status_is_terminated_and_reaped():
    pid, fd = _spawn_writer(b"x" * 4096, linger=10)
    with pytest.raises(ChildStartupError, match="exceeds 64 bytes"):
        supervise_startup(
            pid, fd, timeout=1, max_bytes=64, label="noisy child",
        )
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_parent_cancellation_terminates_exact_child(monkeypatch):
    import winbox.kdbg.debugger.child_lifecycle as lifecycle

    pid, fd = _spawn_writer(None, linger=10)

    def cancel(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(lifecycle, "_read_startup_line", cancel)
    with pytest.raises(KeyboardInterrupt):
        supervise_startup(
            pid, fd, timeout=1, max_bytes=64, label="cancelled child",
        )
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_already_reaped_child_is_never_signalled(monkeypatch):
    import winbox.kdbg.debugger.child_lifecycle as lifecycle

    killed = []
    monkeypatch.setattr(
        lifecycle.os, "waitpid",
        lambda *args: (_ for _ in ()).throw(ChildProcessError()),
    )
    monkeypatch.setattr(lifecycle.os, "kill", lambda *args: killed.append(args))

    lifecycle.terminate_and_reap(999999999)

    assert killed == []


def test_repeated_successful_children_leave_no_zombies():
    pids = []
    for _ in range(16):
        pid, fd = _spawn_writer(b"OK\n")
        pids.append(pid)
        supervise_startup(
            pid, fd, timeout=1, max_bytes=64, label="repeat child",
        )
    for pid in pids:
        _assert_reaped(pid)
