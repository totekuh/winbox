"""Thin client for the kdbg daemon — connect, send op, parse reply.

Each call opens a fresh Unix-socket connection, writes one request,
reads one reply, closes. No persistent connections, no multiplexing.
The daemon is single-op-at-a-time so a persistent connection wouldn't
buy us anything anyway.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.errors import bounded_details, parse_error_info
from winbox.kdbg.debugger.daemon import (
    lock_path,
    session_path,
    sock_path,
)
from winbox.kdbg.debugger.protocol import (
    ProtocolError,
    decode,
    encode,
    read_line,
    request,
)


class ClientError(RuntimeError):
    """Raised when no daemon is reachable, or the daemon returns an error."""

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


class DaemonClient:
    """Stateless wrapper around the daemon's Unix socket protocol."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._sock_path = sock_path(cfg)

    # ── session presence ────────────────────────────────────────────────

    def session_alive(self) -> bool:
        """Lock-based check: if we *can* acquire LOCK_EX_NB on the lock
        file, no daemon is alive. Otherwise it's running.

        This is the source of truth — kernel auto-releases the lock on
        daemon death, so stale lock files don't fool us.
        """
        import fcntl
        path = lock_path(self.cfg)
        if not path.exists():
            return False
        try:
            fd = os.open(str(path), os.O_RDWR)
        except OSError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True  # someone holds it
            # We grabbed it — meaning no daemon. Release immediately.
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    def session_info(self) -> dict[str, Any] | None:
        path = session_path(self.cfg)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # ── single-op call ──────────────────────────────────────────────────

    def call(self, op: str, *, sock_timeout: float = 60.0, **args: Any) -> dict[str, Any]:
        """Send one op. Returns the daemon's ``result`` payload on
        success, raises ``ClientError`` on connection or daemon errors.

        ``sock_timeout`` is the *socket* timeout for this call; op-level
        timeouts (e.g. ``cont``'s wall-clock budget) go in ``**args``.
        """
        # Authoritative liveness check via the lock file. Catches both
        # the missing-sock case AND stale-sock-without-daemon cases (the
        # daemon was killed but didn't get to unlink the socket). Without
        # this, a dead daemon's stale .sock surfaced raw
        # ``[Errno 111] Connection refused`` in the CLI/MCP tool output —
        # operators saw cryptic socket errors and didn't know they
        # needed to re-run ``kdbg attach``.
        if not self.session_alive():
            raise ClientError(
                "no kdbg session is attached (run `winbox kdbg attach <pid>`)",
                code="no_session",
            )

        # A negative socket timeout is reachable from callers that derive
        # sock_timeout from a user-supplied op timeout (e.g. cont --timeout).
        # socket.settimeout() would raise a bare ValueError that escapes the
        # ClientError contract, so reject it here as a clean ClientError.
        if sock_timeout < 0:
            raise ClientError(
                f"socket timeout must be non-negative, got {sock_timeout}",
                code="invalid_argument",
            )

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(sock_timeout)
            try:
                s.connect(str(self._sock_path))
            except OSError as e:
                # Lock said alive but socket refused → daemon died between
                # the check and the connect, OR the sock isn't where we
                # expect (corrupted state). Still actionable to retry
                # the attach, so spell that out.
                raise ClientError(
                    f"kdbg daemon unreachable ({e}); "
                    "the daemon may have died — re-run `winbox kdbg attach <pid>`",
                    code="daemon_unreachable", retryable=True,
                ) from e
            try:
                s.sendall(encode(request(op, **args)))
                line = read_line(s)
            except ProtocolError as e:
                raise ClientError(
                    f"reply parse: {e}", code="invalid_response", retryable=True,
                ) from e
            except OSError as e:
                # The daemon can die *after* we connect — tearing down a
                # session is exactly when that happens. Without this the
                # caller got a raw ConnectionResetError traceback instead of
                # something it could act on.
                raise ClientError(
                    f"kdbg daemon went away mid-request ({e}); "
                    "re-run `winbox kdbg attach <pid>` if you still need a session",
                    code="daemon_unreachable", retryable=True,
                ) from e
        finally:
            try:
                s.close()
            except OSError:
                pass

        try:
            reply = decode(line)
        except ProtocolError as e:
            raise ClientError(
                f"reply parse: {e}", code="invalid_response", retryable=True,
            ) from e

        if not reply.get("ok"):
            info = parse_error_info(reply.get("error_info"))
            if info is not None:
                raise ClientError(
                    info["message"], code=info["code"],
                    retryable=info["retryable"], details=info["details"],
                )
            raise ClientError(reply.get("error") or "daemon returned error")
        return reply.get("result") or {}
