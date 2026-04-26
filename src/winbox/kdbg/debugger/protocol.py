"""Wire protocol for the kdbg daemon ↔ CLI.

JSON-line framing over a Unix socket: each request is one JSON object
on a line, each reply is one JSON object on a line, then the connection
closes. Newline framing keeps reads simple — no length prefix, no
chunked parsing — and stays human-readable for debugging.

Request shape::

    {"op": "<name>", "args": {<op-specific>}}

Reply shape on success::

    {"ok": true, "result": {<op-specific>}}

Reply shape on failure::

    {"ok": false, "error": "<short message>"}

Operations are listed in ``OPS``; each one corresponds to a method on
``DaemonSession`` named ``op_<name>`` that takes the args dict.
"""

from __future__ import annotations

import json
from typing import Any


# Single source of truth for valid operations. The daemon validates
# requests against this set before dispatching, and the CLI uses these
# constants directly.
OPS: frozenset[str] = frozenset({
    "status",       # daemon health + target info
    "bp_add",       # install bp at sym/VA
    "bp_list",      # enumerate installed bps
    "bp_remove",    # remove bp by id
    "cont",         # resume; blocks daemon-side until next stop in target
    "step",         # single-step the firing vCPU once
    "interrupt",    # async halt (for breaking out of cont)
    "regs",         # current register state at last halt
    "mem",          # read memory in target's CR3
    "write_mem",    # write hex bytes to memory in target's CR3
    "stack",        # read N qwords from RSP
    "bt",           # basic backtrace
    "detach",       # graceful shutdown
})


# Hard cap on a single line — enough for any single response we
# generate (largest is bp_list with hundreds of bps), small enough to
# reject runaway/malformed payloads cleanly.
MAX_LINE_BYTES = 1 << 20  # 1 MB


class ProtocolError(RuntimeError):
    """Malformed wire data — short read, oversize line, invalid JSON."""


# ── encoding ────────────────────────────────────────────────────────────


def encode(obj: dict[str, Any]) -> bytes:
    """Serialise a request or reply, append the framing newline."""
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def decode(line: bytes) -> dict[str, Any]:
    """Parse a single line. Strict on shape — top-level must be a dict."""
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"bad JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ProtocolError(f"top-level not an object: {type(obj).__name__}")
    return obj


def request(op: str, **args: Any) -> dict[str, Any]:
    """Build a request payload."""
    if op not in OPS:
        raise ValueError(f"unknown op {op!r}")
    return {"op": op, "args": args}


def reply_ok(result: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result if result is not None else {}}


def reply_err(message: str) -> dict[str, Any]:
    return {"ok": False, "error": str(message)}


# ── socket helpers ──────────────────────────────────────────────────────


def read_line(sock, *, max_bytes: int = MAX_LINE_BYTES) -> bytes:
    """Read until ``\\n`` from ``sock`` (a connected socket); return the
    data WITHOUT the terminator. Raise ``ProtocolError`` on short read,
    over-size payload, or socket close before newline.
    """
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProtocolError(
                f"connection closed before newline (read {len(buf)} bytes)"
            )
        buf.extend(chunk)
        nl = buf.find(b"\n")
        if nl >= 0:
            return bytes(buf[:nl])
        if len(buf) > max_bytes:
            raise ProtocolError(
                f"line too long: {len(buf)} bytes without newline"
            )
