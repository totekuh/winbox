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
        if not self._sock_path.exists():
            raise ClientError("no kdbg session is attached (run `winbox kdbg attach <pid>`)")

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(sock_timeout)
        try:
            try:
                s.connect(str(self._sock_path))
            except OSError as e:
                raise ClientError(f"daemon unreachable: {e}") from e
            s.sendall(encode(request(op, **args)))
            try:
                line = read_line(s)
            except ProtocolError as e:
                raise ClientError(f"reply parse: {e}") from e
        finally:
            try:
                s.close()
            except OSError:
                pass

        try:
            reply = decode(line)
        except ProtocolError as e:
            raise ClientError(f"reply parse: {e}") from e

        if not reply.get("ok"):
            raise ClientError(reply.get("error") or "daemon returned error")
        return reply.get("result") or {}
