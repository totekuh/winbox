"""RSP wire-level types and framing helpers.

Foundation types for the gdb Remote Serial Protocol client — the error
class, parsed stop-reply dataclass, and the three stateless byte-level
helpers that frame every packet exchange.
"""

from __future__ import annotations

from dataclasses import dataclass


class RspError(RuntimeError):
    """Raised on protocol-level failures: timeouts, NAKs, malformed framing.

    ``partial`` carries any bytes successfully harvested before the
    failure on chunked memory reads — callers that can use a short read
    can recover them via ``e.partial`` instead of getting nothing.
    """

    def __init__(self, *args: object, partial: bytes = b"") -> None:
        super().__init__(*args)
        self.partial = partial


@dataclass
class StopReply:
    """Parsed gdbstub stop-reply packet.

    ``signal`` is the POSIX-ish signal number QEMU reports (5 = SIGTRAP
    for breakpoints, 2 = SIGINT for our own ``interrupt``).
    ``thread`` is the firing vCPU as a 1-based id ("1", "2", ...) or
    None if the stub didn't include a ``thread:`` key.
    ``stop_kind`` distinguishes ``swbreak``/``hwbreak``/``watch``/None
    when the stub reports it (we use this to confirm a bp actually
    fired vs. some other interrupt).
    ``raw`` is the full packet body for any caller that wants to peek.
    """

    signal: int
    thread: str | None
    stop_kind: str | None
    raw: str


# ── Packet framing ──────────────────────────────────────────────────────


def _checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def _escape(data: bytes) -> bytes:
    """RSP escapes ``$ # } *`` by XOR-0x20 after a leading ``}``."""
    out = bytearray()
    for b in data:
        if b in (0x23, 0x24, 0x2A, 0x7D):  # # $ * }
            out.append(0x7D)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


def _unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)
