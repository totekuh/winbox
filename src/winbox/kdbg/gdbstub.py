"""GDB Remote Serial Protocol client for QEMU's built-in gdbstub.

Today the kdbg subsystem is HMP-only past kdbg_start/stop/status; the
gdbstub is just exposed and left for an external gdb client to attach.
The roadmap (`memory/project_mcp_kdbg_cleanup.md`) adds register reads,
single-step, and breakpoint primitives -- all of which require RSP, the
gdb Remote Serial Protocol. Those operations cannot be done over HMP.

This module is the seam. It's intentionally minimal today -- a thin
client class that knows how to connect, send a packet, and read a reply
-- so the next batch of kdbg tools (`kdbg_regs`, `kdbg_step`,
`kdbg_break`, `kdbg_continue`) can land without having to re-architect
the package's HMP-vs-gdbstub boundary by convention.

Note: QEMU's gdbstub accepts only ONE client at a time. If a developer
already has gdb attached interactively, calls through this client will
fail with a connection refused. Tools that use this should advise the
user to detach gdb first, or wrap their work in a context manager that
disconnects cleanly so the human's gdb session survives.
"""

from __future__ import annotations

import socket
from typing import Optional


class GdbStubError(RuntimeError):
    """Raised on protocol errors, connection failures, or unexpected replies."""


class GdbStubClient:
    """Minimal RSP client. Future-friendly stub.

    Usage::

        with GdbStubClient.connect("127.0.0.1", 1234) as gdb:
            regs = gdb.read_registers()
            gdb.single_step()
            gdb.set_hw_breakpoint(0xfffff80012345678)
            gdb.cont()

    Today only ``connect`` / ``disconnect`` / ``send_packet`` are
    implemented -- the higher-level methods are placeholders that raise
    ``NotImplementedError``. The shape is locked in so the roadmap items
    drop into prepared call-sites.
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 1234

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""

    @classmethod
    def connect(
        cls,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        *,
        timeout: float = 5.0,
    ) -> "GdbStubClient":
        """Open a TCP connection to the QEMU gdbstub.

        Raises :class:`GdbStubError` if nothing is listening (caller has
        not run ``winbox kdbg start``) or if another gdb is already
        attached (QEMU rejects the second client).
        """
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            raise GdbStubError(
                f"could not connect to gdbstub at {host}:{port}: {e}"
            ) from e
        return cls(sock)

    def __enter__(self) -> "GdbStubClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.disconnect()

    def disconnect(self) -> None:
        """Close the socket. Idempotent."""
        try:
            self._sock.close()
        except OSError:
            pass

    # ── RSP framing primitives ───────────────────────────────────────
    #
    # RSP packets are framed as ``$<payload>#<checksum>`` where checksum
    # is the modulo-256 sum of payload bytes printed as 2 hex digits.
    # The receiver replies with ``+`` (ack) or ``-`` (retransmit) before
    # the actual response packet. This pair (send_packet / recv_packet)
    # is the only thing the higher-level methods will need.

    @staticmethod
    def _checksum(payload: bytes) -> str:
        return f"{sum(payload) & 0xff:02x}"

    def send_packet(self, payload: str | bytes) -> None:
        """Send one RSP packet. Caller is responsible for reading any reply."""
        if isinstance(payload, str):
            payload = payload.encode("ascii")
        frame = b"$" + payload + b"#" + self._checksum(payload).encode("ascii")
        try:
            self._sock.sendall(frame)
        except OSError as e:
            raise GdbStubError(f"send_packet: {e}") from e

    def recv_packet(self, *, timeout: float = 5.0) -> bytes:
        """Read one RSP packet payload. Drops leading ``+``/``-`` acks."""
        raise NotImplementedError(
            "recv_packet: implement when first user lands "
            "(needed by read_registers / single_step / etc.)"
        )

    # ── Higher-level operations (roadmap stubs) ──────────────────────

    def read_registers(self) -> dict[str, int]:
        """Send 'g'; parse the register dump per QEMU's x86_64 ordering."""
        raise NotImplementedError(
            "read_registers: see project_mcp_kdbg_cleanup.md for the plan"
        )

    def single_step(self) -> dict[str, int]:
        """Send 's'; wait for the stop reply; return regs at the new RIP."""
        raise NotImplementedError("single_step: roadmap")

    def cont(self) -> Optional[dict[str, int]]:
        """Send 'c'; resume the VM. Returns stop info if a breakpoint hit."""
        raise NotImplementedError("cont: roadmap")

    def set_hw_breakpoint(self, addr: int) -> None:
        """Set a hardware breakpoint via 'Z1,addr,1' (DR0..DR3 limit: 4)."""
        raise NotImplementedError("set_hw_breakpoint: roadmap")

    def remove_hw_breakpoint(self, addr: int) -> None:
        """Remove a hardware breakpoint via 'z1,addr,1'."""
        raise NotImplementedError("remove_hw_breakpoint: roadmap")
