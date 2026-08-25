"""Bounded startup handshakes and deterministic child reaping."""

from __future__ import annotations

import os
import select
import signal
import threading
import time


class ChildStartupError(RuntimeError):
    """A debugger child failed to publish bounded startup status."""


def _waitpid_nonblocking(pid: int) -> bool:
    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return waited == pid


def terminate_and_reap(pid: int, *, grace: float = 0.25) -> None:
    """Terminate exactly one still-owned child and synchronously reap it."""
    deadline = time.monotonic() + max(0.0, grace)
    while time.monotonic() < deadline:
        if _waitpid_nonblocking(pid):
            return
        time.sleep(0.01)
    if _waitpid_nonblocking(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + max(0.1, grace)
    while time.monotonic() < deadline:
        if _waitpid_nonblocking(pid):
            return
        time.sleep(0.01)
    if _waitpid_nonblocking(pid):
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def reap_in_background(pid: int, *, label: str) -> None:
    """Ensure a successful long-lived child never becomes a zombie."""
    def reap() -> None:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    threading.Thread(
        target=reap,
        name=f"winbox-{label}-reaper-{pid}",
        daemon=True,
    ).start()


def _read_startup_line(
    fd: int, *, timeout: float, max_bytes: int, label: str,
) -> bytes:
    deadline = time.monotonic() + max(0.01, float(timeout))
    value = bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise ChildStartupError(
                f"{label} startup timed out after {timeout:g}s"
            )
        try:
            ready, _, _ = select.select([fd], [], [], min(left, 0.1))
        except InterruptedError:
            continue
        if not ready:
            continue
        chunk = os.read(fd, min(4096, max_bytes + 1 - len(value)))
        if not chunk:
            if value:
                raise ChildStartupError(
                    f"{label} startup status ended before newline"
                )
            raise ChildStartupError(f"{label} exited before publishing status")
        value.extend(chunk)
        newline = value.find(b"\n")
        if newline >= 0:
            return bytes(value[:newline])
        if len(value) > max_bytes:
            raise ChildStartupError(
                f"{label} startup status exceeds {max_bytes} bytes"
            )


def supervise_startup(
    pid: int,
    pipe_fd: int,
    *,
    timeout: float,
    max_bytes: int,
    label: str,
    success: bytes = b"OK",
) -> bytes:
    """Read one bounded status line, then arrange exactly-once reaping."""
    try:
        line = _read_startup_line(
            pipe_fd, timeout=timeout, max_bytes=max_bytes, label=label,
        )
    except BaseException:
        terminate_and_reap(pid)
        raise
    finally:
        os.close(pipe_fd)

    if line == success:
        reap_in_background(pid, label=label)
    else:
        terminate_and_reap(pid)
    return line
