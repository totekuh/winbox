"""Minimal gdb Remote Serial Protocol (RSP) client for QEMU's gdbstub.

We don't depend on ``pygdbmi`` or shell out to ``gdb`` for two reasons:
the only sane way to drive bps + single-step + register writes from
agentic / MCP code is a programmatic socket interface, and gdb adds an
interactive process whose state we'd have to babysit. The RSP wire
format is small enough to implement directly.

Protocol primer (just what we use):

* Packets are framed as ``$<data>#<2-hex-checksum>``. Checksum is
  ``sum(data) mod 256`` over the *raw* data bytes between ``$`` and
  ``#``, lowercase hex.
* The receiver acks every well-formed packet with a single ``+``;
  malformed packets get ``-`` and the sender must retransmit.
* Empty response ``$#00`` from the server = "command not supported".
* The control byte ``\\x03`` (raw, no framing) sent to a running target
  triggers an asynchronous interrupt — the standard "pause the VM" lever.
* Stop replies look like ``T<sig><key>:<val>;...`` (preferred) or
  ``S<sig>`` (minimal). QEMU emits T-replies including the firing
  vCPU (``thread:N``).

We escape only the four bytes RSP requires (``$ # } *``) on send, and
honour the same on receive.
"""

from __future__ import annotations

from winbox.kdbg.debugger.rsp_types import (  # noqa: F401 — re-exported
    RspError,
    StopReply,
    _checksum,
    _escape,
    _unescape,
)
from winbox.kdbg.debugger.rsp_protocol import _RspProtocol


class RspClient(_RspProtocol):
    """Synchronous gdb-RSP client over a single TCP connection.

    QEMU's gdbstub allows exactly one client at a time. We don't try to
    multiplex; if you need parallel queries, hold the lock at a higher
    layer.

    Lifetime:
        c = RspClient.connect("127.0.0.1", 1234)
        c.handshake()              # qSupported, ack mode
        c.read_registers()
        c.insert_breakpoint(0x...)
        c.cont()
        stop = c.wait_for_stop()
        c.close()
    """

    # ── memory I/O ─────────────────────────────────────────────────────

    _MEM_CHUNK = 0xFF0

    def read_memory(self, addr: int, length: int) -> bytes:
        """``m addr,len`` — read ``length`` bytes from ``addr``.

        Reads larger than ``_MEM_CHUNK`` are split into multiple ``m``
        requests and concatenated. Each chunk is clamped to a page
        boundary so a single unmapped page doesn't lose the readable
        bytes before it.
        """
        if length <= 0:
            return b""
        out = bytearray()
        remaining = length
        cur = addr
        while remaining > 0:
            n = min(remaining, self._MEM_CHUNK)
            to_page_end = 0x1000 - (cur & 0xFFF)
            n = min(n, to_page_end)
            try:
                resp = self._exchange(f"m{cur:x},{n:x}".encode("ascii"))
            except RspError as e:
                raise RspError(
                    f"m failed at 0x{cur:x} after {len(out)}/{length} bytes: {e}",
                    partial=bytes(out),
                ) from e
            if resp.startswith(b"E"):
                raise RspError(
                    f"m failed at 0x{cur:x} after {len(out)}/{length} bytes: {resp!r}",
                    partial=bytes(out),
                )
            try:
                chunk = bytes.fromhex(resp.decode("ascii"))
            except ValueError as e:
                raise RspError(
                    f"non-hex m response at 0x{cur:x}: {resp!r}",
                    partial=bytes(out),
                ) from e
            if not chunk:
                raise RspError(
                    f"empty m reply at 0x{cur:x} (asked {n}, got 0)",
                    partial=bytes(out),
                )
            out.extend(chunk)
            cur += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

    def write_memory(self, addr: int, data: bytes) -> None:
        """``M addr,len:hex`` — write ``data`` to memory."""
        if not data:
            return
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + self._MEM_CHUNK]
            cur = addr + offset
            body = (
                f"M{cur:x},{len(chunk):x}:".encode("ascii")
                + chunk.hex().encode("ascii")
            )
            resp = self._exchange(body)
            if resp != b"OK":
                raise RspError(f"M failed at 0x{cur:x}: {resp!r}")
            offset += len(chunk)

    # ── breakpoints / watchpoints ──────────────────────────────────────

    _WP_Z = {"write": b"Z2", "read": b"Z3", "access": b"Z4"}
    _WP_z = {"write": b"z2", "read": b"z3", "access": b"z4"}

    def insert_breakpoint(
        self,
        addr: int,
        *,
        kind: int = 1,
        hardware: bool = False,
        wp_type: str | None = None,
    ) -> None:
        """Insert a breakpoint or watchpoint."""
        if wp_type is not None:
            z = self._WP_Z.get(wp_type)
            if z is None:
                raise RspError(f"unknown watchpoint type: {wp_type!r}")
        else:
            z = b"Z1" if hardware else b"Z0"
        resp = self._exchange(b"%b,%x,%x" % (z, addr, kind))
        if resp != b"OK":
            raise RspError(f"{z.decode()} insert at 0x{addr:x} failed: {resp!r}")

    def remove_breakpoint(
        self,
        addr: int,
        *,
        kind: int = 1,
        hardware: bool = False,
        wp_type: str | None = None,
    ) -> None:
        if wp_type is not None:
            z = self._WP_z.get(wp_type)
            if z is None:
                raise RspError(f"unknown watchpoint type: {wp_type!r}")
        else:
            z = b"z1" if hardware else b"z0"
        resp = self._exchange(b"%b,%x,%x" % (z, addr, kind))
        if resp != b"OK":
            raise RspError(f"{z.decode()} remove at 0x{addr:x} failed: {resp!r}")

    # ── run control ────────────────────────────────────────────────────

    def cont(self) -> None:
        """``vCont;c`` — resume all vCPUs. Does NOT wait for a stop."""
        self._send_packet(b"vCont;c")

    def step(self, thread: str | None = None) -> None:
        """``vCont;s`` — single-step the selected vCPU once."""
        if thread:
            packet = f"vCont;s:{thread}".encode("ascii")
        else:
            packet = b"vCont;s"
        self._send_packet(packet)

    def interrupt(self) -> None:
        """Send a raw Ctrl-C (0x03) to halt a running target."""
        self._send_raw(b"\x03")

    def wait_for_stop(self, *, timeout: float | None = None) -> StopReply:
        """Block until the next stop reply, return parsed StopReply."""
        while True:
            resp = self._read_packet(timeout=timeout)
            if resp[:1] == b"O" and resp != b"OK":
                continue
            return self._parse_stop_reply(resp)

    @staticmethod
    def _parse_stop_reply(body: bytes) -> StopReply:
        text = body.decode("ascii", errors="replace")
        if not text:
            raise RspError("empty stop reply")
        kind = text[0]

        def _signal(s: str) -> int:
            try:
                return int(s[1:3], 16)
            except ValueError as e:
                raise RspError(f"malformed stop reply {s!r}: {e}") from e

        if kind == "S":
            return StopReply(signal=_signal(text), thread=None, stop_kind=None, raw=text)
        if kind != "T":
            raise RspError(f"unexpected stop reply prefix {kind!r}: {text!r}")

        sig = _signal(text)
        thread: str | None = None
        stop_kind: str | None = None
        for pair in text[3:].split(";"):
            if not pair:
                continue
            if ":" not in pair:
                continue
            k, _, v = pair.partition(":")
            if k == "thread":
                thread = v
            elif k in ("swbreak", "hwbreak", "watch", "rwatch", "awatch"):
                stop_kind = k
        return StopReply(signal=sig, thread=thread, stop_kind=stop_kind, raw=text)
