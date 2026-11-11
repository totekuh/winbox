"""Bounded subprocess execution with timeout, output caps, and cancellation."""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Callable

from winbox.kdbg.decomp.client import DecompError


def _terminate_and_reap(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        process.wait()
        return
    process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _bounded_command(
    command: list[str], *, timeout: float, max_stdout: int,
    max_stderr: int = 2048,
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[bytes, bytes, int]:
    """Run one exact child without ever buffering beyond declared caps."""
    if timeout <= 0 or max_stdout < 0 or max_stderr < 0:
        raise ValueError("invalid bounded-command limits")
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True,
        )
    except FileNotFoundError:
        raise
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()

    def drain(stream, target: bytearray, cap: int, *, enforce: bool) -> None:
        total = 0
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                total += len(chunk)
                remaining = max(0, cap + (1 if enforce else 0) - len(target))
                if remaining:
                    target.extend(chunk[:remaining])
                if enforce and total > cap:
                    overflow.set()
        finally:
            stream.close()

    stdout_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout, max_stdout),
        kwargs={"enforce": True}, daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr, max_stderr),
        kwargs={"enforce": False}, daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    cancelled = False
    try:
        while process.poll() is None:
            if cancel_requested is not None and cancel_requested():
                cancelled = True
                _terminate_and_reap(process)
                break
            if overflow.is_set():
                _terminate_and_reap(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_and_reap(process)
                break
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
    except BaseException:
        _terminate_and_reap(process)
        raise
    finally:
        stdout_thread.join(timeout=2.0)
        stderr_thread.join(timeout=2.0)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _terminate_and_reap(process)
            raise DecompError(
                "PDB extraction pipe did not close after child exit",
                code="pdb_enrichment_failed", retryable=True,
            )
    if cancelled:
        raise DecompError(
            "PDB enrichment was cancelled", code="cancelled", retryable=True,
        )
    if timed_out:
        raise DecompError(
            f"PDB enrichment timed out after {timeout:g}s",
            code="analysis_timeout", retryable=True,
        )
    if overflow.is_set() or len(stdout) > max_stdout:
        raise DecompError(
            f"PDB symbol output exceeds {max_stdout} bytes",
            code="pdb_enrichment_too_large",
        )
    return bytes(stdout), bytes(stderr), int(process.returncode)
