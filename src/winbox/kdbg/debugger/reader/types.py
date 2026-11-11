"""Persistent RSP reader types, exceptions, budget, and wire helpers."""

from __future__ import annotations

import json
import os
import socket
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.debugger.protocol import ProtocolError, decode, encode, read_line
from winbox.kdbg.hmp import HmpError


class ReaderError(HmpError):
    """A persistent debugger-reader transport or safety failure."""


_MAX_READ = 1 << 20
_DEFAULT_PORT = 1234
_READER_STARTUP_TIMEOUT = 30.0
_STARTUP_STATUS_MAX_BYTES = 64 * 1024
_DEFAULT_SNAPSHOT_DURATION_MS = 15_000
_DEFAULT_SNAPSHOT_MAX_READS = 16_384
_DEFAULT_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024
_SNAPSHOT_CACHE_MAX_BYTES = 2 * 1024 * 1024
_active_snapshot: ContextVar["DebugSnapshot | None"] = ContextVar(
    "winbox_kdbg_snapshot", default=None,
)


@dataclass(frozen=True)
class SnapshotBudget:
    """Hard upper bounds for one coherent stopped-guest transaction.

    The reader broker enforces these limits, so an abandoned or unusually
    expensive client cannot hold Windows at an RSP stop indefinitely.  The
    duration bound is also the socket-idle deadline in the broker: a client
    doing CPU work after its final read cannot strand the guest merely by
    forgetting to close its snapshot.
    """

    max_duration_ms: int = _DEFAULT_SNAPSHOT_DURATION_MS
    max_reads: int = _DEFAULT_SNAPSHOT_MAX_READS
    max_bytes: int = _DEFAULT_SNAPSHOT_MAX_BYTES

    def __post_init__(self) -> None:
        if not 100 <= self.max_duration_ms <= 60_000:
            raise ValueError("snapshot max_duration_ms must be between 100 and 60000")
        if not 1 <= self.max_reads <= 65_536:
            raise ValueError("snapshot max_reads must be between 1 and 65536")
        if not 1 <= self.max_bytes <= 64 * 1024 * 1024:
            raise ValueError("snapshot max_bytes must be between 1 and 67108864")

    def public(self) -> dict[str, int]:
        return {
            "max_duration_ms": self.max_duration_ms,
            "max_reads": self.max_reads,
            "max_bytes": self.max_bytes,
        }

    @classmethod
    def from_wire(cls, raw: object) -> "SnapshotBudget":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ReaderError("snapshot budget must be an object")
        try:
            values = {
                key: int(raw[key])
                for key in ("max_duration_ms", "max_reads", "max_bytes")
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("snapshot budget has invalid fields") from exc
        if any(isinstance(raw[key], bool) for key in values):
            raise ReaderError("snapshot budget fields must be integers")
        try:
            return cls(**values)
        except ValueError as exc:
            raise ReaderError(str(exc)) from exc


class SnapshotBudgetError(ReaderError):
    """A stopped snapshot reached its explicit cooperative safety bound."""

    code = "snapshot_budget_exceeded"
    retryable = True

    def __init__(
        self,
        reason: str,
        *,
        budget: SnapshotBudget,
        read_count: int,
        bytes_read: int,
        elapsed_ms: float,
    ) -> None:
        self.details = {
            "reason": reason,
            "budget": budget.public(),
            "read_count": read_count,
            "bytes_read": bytes_read,
            "elapsed_ms": round(max(0.0, elapsed_ms), 3),
        }
        super().__init__(
            f"snapshot budget exceeded ({reason}); guest was resumed after "
            f"{read_count} reads / {bytes_read} bytes"
        )


def _runtime_dir(cfg: Config) -> Path:
    path = Path(cfg.winbox_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def lock_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.lock"


def sock_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.sock"


def session_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.session.json"


def log_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.log"


def _reply_ok(result: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result or {}}


def _reply_err(exc: BaseException | str) -> dict[str, Any]:
    """Serialize typed broker failures without breaking legacy string peers."""
    if isinstance(exc, BaseException):
        error: dict[str, Any] = {"message": str(exc)}
        code = getattr(exc, "code", None)
        if isinstance(code, str) and code:
            error["code"] = code[:64]
        retryable = getattr(exc, "retryable", None)
        if isinstance(retryable, bool):
            error["retryable"] = retryable
        details = getattr(exc, "details", None)
        if isinstance(details, dict):
            error["details"] = details
        return {"ok": False, "error": error}
    return {"ok": False, "error": str(exc)}


def _bounded_counter(value: object, fallback: int) -> int:
    """Accept broker-owned non-negative counters without trusting wire junk."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return fallback
    return value


def _request(sock: socket.socket, op: str, **args: Any) -> dict[str, Any]:
    try:
        sock.sendall(encode({"op": op, "args": args}))
    except OSError as write_exc:
        try:
            reply = decode(read_line(sock, max_bytes=(_MAX_READ * 2) + 65536))
        except (OSError, ProtocolError) as exc:
            raise ReaderError(f"RSP reader broker communication failed: {exc}") from write_exc
    else:
        try:
            reply = decode(read_line(sock, max_bytes=(_MAX_READ * 2) + 65536))
        except (OSError, ProtocolError) as exc:
            raise ReaderError(f"RSP reader broker communication failed: {exc}") from exc
    if not reply.get("ok"):
        raw_error = reply.get("error")
        if isinstance(raw_error, dict):
            error = ReaderError(str(raw_error.get("message") or "RSP reader broker failed"))
            code = raw_error.get("code")
            if isinstance(code, str):
                error.code = code
            if isinstance(raw_error.get("retryable"), bool):
                error.retryable = raw_error["retryable"]
            if isinstance(raw_error.get("details"), dict):
                error.details = raw_error["details"]
            raise error
        raise ReaderError(raw_error or "RSP reader broker failed")
    result = reply.get("result")
    if not isinstance(result, dict):
        raise ReaderError("RSP reader broker returned a malformed result")
    return result
