"""Serve loop and shutdown for the kdbg session daemon."""

from __future__ import annotations

import select
import socket
import sys
import time
from contextlib import suppress
from typing import Any

from winbox.kdbg.debugger.protocol import (
    ProtocolError,
    decode,
    encode,
    read_line,
    reply_err,
)
from winbox.kdbg.debugger.rsp import RspError


class _ServeMixin:
    """Unix-socket serve loop and graceful shutdown."""

    def _rsp_fd(self) -> int | None:
        """fileno of the gdbstub socket, or None if unavailable.

        Returns None for RspClient stand-ins that hold no socket (unit
        tests), which is the signal to fall back to a plain blocking wait.
        """
        sock = getattr(self.rsp, "_sock", None)
        if sock is None:
            return None
        try:
            fd = sock.fileno()
        except (OSError, AttributeError):
            return None
        return fd if fd >= 0 else None

    def _wait_for_stop_serving(self, timeout: float):
        """``rsp.wait_for_stop`` that keeps answering daemon clients.

        WHY this exists: ``serve`` accepts one connection, runs the op to
        completion, and only then loops back to ``select``/``accept``. So
        for the whole of a ``cont`` — up to the caller's full timeout —
        nothing accepts. A concurrently-launched ``winbox kdbg interrupt``
        never gets read off the backlog, hits its own 60s socket timeout
        and tells the operator the daemon "went away" on a session that is
        perfectly healthy. The ``is_lightweight`` bypass in ``_serve_one``
        was written for a concurrency that did not exist at the transport
        layer; this is what supplies it.

        We deliberately do NOT slice the RSP read into short timeouts:
        ``_read_packet`` consumes the frame byte by byte and drops what it
        has collected when a read times out, so a stop reply straddling a
        slice boundary would desync the stream. Instead we select on both
        fds and only enter ``wait_for_stop`` once the gdbstub actually has
        bytes for us; the rest of the budget is spent serving clients.
        """
        fd = self._rsp_fd()
        listen = self._listen_sock
        if fd is None or listen is None:
            return self.rsp.wait_for_stop(timeout=timeout)

        deadline = time.monotonic() + timeout
        while not getattr(self.rsp, "_inbuf", None):
            left = deadline - time.monotonic()
            if left <= 0:
                raise RspError("read timed out")
            try:
                ready, _, _ = select.select([fd, listen], [], [], min(left, 0.5))
            except (OSError, InterruptedError):
                continue
            if fd in ready:
                break
            if listen in ready:
                self._pump_client()
        return self.rsp.wait_for_stop(
            timeout=max(0.5, deadline - time.monotonic())
        )

    def _pump_client(self) -> None:
        """Accept and service one client from inside a long-running op."""
        listen = self._listen_sock
        if listen is None:
            return
        try:
            conn, _ = listen.accept()
        except OSError:
            return
        was_busy = self._busy
        self._busy = True
        try:
            self._serve_one(conn, read_timeout=5.0)
        finally:
            self._busy = was_busy
            with suppress(OSError):
                conn.close()

    def serve(self, listen_sock: socket.socket) -> None:
        """Single-threaded select loop. Returns when detach is requested
        or a signal asks for shutdown."""
        self._listen_sock = listen_sock
        self._serving = True
        self._shutdown_requested = False
        listen_sock.setblocking(False)

        while self._serving and not self._shutdown_requested:
            try:
                ready, _, _ = select.select([listen_sock], [], [], 0.5)
            except (OSError, InterruptedError):
                continue
            if not ready:
                continue
            try:
                conn, _ = listen_sock.accept()
            except OSError:
                continue
            try:
                self._serve_one(conn)
            finally:
                with suppress(OSError):
                    conn.close()

    def _serve_one(self, conn: socket.socket, *, read_timeout: float = 60.0) -> None:
        conn.settimeout(read_timeout)
        try:
            line = read_line(conn)
        except (ProtocolError, OSError) as e:
            with suppress(OSError):
                conn.sendall(encode(reply_err(
                    f"protocol: {e}", code="invalid_request",
                )))
            return
        try:
            req = decode(line)
        except ProtocolError as e:
            with suppress(OSError):
                conn.sendall(encode(reply_err(str(e), code="invalid_request")))
            return

        op = req.get("op")
        args = req.get("args") or {}
        if not isinstance(op, str) or not isinstance(args, dict):
            with suppress(OSError):
                conn.sendall(encode(reply_err(
                    "malformed request", code="invalid_request",
                )))
            return

        is_lightweight = op in ("status", "interrupt", "bp_list", "bp_trace")
        if self._busy and not is_lightweight:
            with suppress(OSError):
                conn.sendall(encode(self.BUSY_REPLY))
            return

        if not is_lightweight:
            self._busy = True
        try:
            reply = self.handle_op(op, args)
        finally:
            if not is_lightweight:
                self._busy = False

        with suppress(OSError):
            conn.sendall(encode(reply))

    def shutdown(self) -> None:
        """Best-effort cleanup. Removes bps, resumes VM, detaches gdb,
        closes sock."""
        deadline = time.monotonic() + 2.0
        while self._busy and time.monotonic() < deadline:
            time.sleep(0.02)

        self._cleanup_breakpoints_for_shutdown()
        safe_to_resume = (
            not self._cr3_corrupted
            and self.run_state == "halted"
            and self.stop is not None
        )
        self.bps.clear()
        self._bp_by_va.clear()

        try:
            if safe_to_resume:
                with suppress(Exception):
                    self.rsp.cont()
                time.sleep(0.1)
            elif self._cr3_corrupted:
                print(
                    "[kdbg-daemon] CR3 corrupted; skipping cont on shutdown — "
                    "VM will remain paused. Recover CR3 via HMP or restore snapshot.",
                    file=sys.stderr, flush=True,
                )
            else:
                print(
                    f"[kdbg-daemon] target state is {self.run_state}; skipping "
                    "cont on shutdown because resume safety is not established.",
                    file=sys.stderr, flush=True,
                )
        finally:
            with suppress(OSError):
                self.rsp._sock.close()

        if self._listen_sock is not None:
            with suppress(OSError):
                self._listen_sock.close()
