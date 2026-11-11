"""RSP socket transport — packet send/receive over a TCP connection."""

from __future__ import annotations

import socket

from winbox.kdbg.debugger.rsp_types import RspError, _checksum, _escape, _unescape


class _RspTransport:
    """Synchronous gdb-RSP transport over a single TCP connection.

    Handles raw byte I/O, packet framing, ack negotiation, and the
    ``connect``/``close`` lifecycle.  Subclasses add protocol semantics.
    """

    _CHUNK = 4096
    _DEFAULT_TIMEOUT = 10.0
    _MAX_PACKET = 1 << 20
    _MIN_G_PACKET = 212

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._inbuf = bytearray()
        self._noack = False

    # ── lifecycle ──────────────────────────────────────────────────────

    @classmethod
    def connect(
        cls,
        host: str,
        port: int,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> "_RspTransport":
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return cls(sock)

    def close(self) -> None:
        """Detach cleanly: halt -> D -> socket close. VM ends up running.

        The protocol-correct sequence is non-obvious. QEMU's ``D`` handler
        calls ``gdb_continue()`` internally to resume the VM, so the
        client's job is to make sure the VM is *halted* when ``D`` arrives.
        Sending ``D`` to a running VM races with the socket close: QEMU
        often detects the disconnect first and halts the VM as a
        precaution, leaving it paused after we're gone — the exact bug
        this method exists to avoid.

        Failure paths are swallowed: if anything goes wrong we still
        close the socket. The worst case is a paused VM the user can
        recover with ``virsh resume``.
        """
        try:
            try:
                self.interrupt()
                try:
                    self.wait_for_stop(timeout=1.0)
                except RspError:
                    pass
                self._send_packet(b"D")
                try:
                    self._read_packet(timeout=1.0)
                except RspError:
                    pass
            except (RspError, OSError):
                pass
        finally:
            try:
                self._sock.close()
            except OSError:
                pass

    # ── packet I/O ─────────────────────────────────────────────────────

    def _send_raw(self, frame: bytes) -> None:
        try:
            self._sock.sendall(frame)
        except OSError as e:
            raise RspError(f"send failed: {e}") from e

    def _send_packet(self, body: bytes) -> None:
        escaped = _escape(body)
        frame = b"$" + escaped + b"#" + f"{_checksum(escaped):02x}".encode("ascii")
        self._send_raw(frame)
        if not self._noack:
            self._read_ack(strict=True)

    def _read_byte(self, timeout: float | None = None) -> int:
        self._sock.settimeout(timeout)
        if not self._inbuf:
            try:
                chunk = self._sock.recv(self._CHUNK)
            except socket.timeout as e:
                raise RspError("read timed out") from e
            except OSError as e:
                raise RspError(f"recv failed: {e}") from e
            if not chunk:
                raise RspError("connection closed by peer")
            self._inbuf.extend(chunk)
        b = self._inbuf[0]
        del self._inbuf[0]
        return b

    def _read_ack(self, *, strict: bool) -> None:
        b = self._read_byte(timeout=self._DEFAULT_TIMEOUT)
        if b == 0x2B:  # '+'
            return
        if b == 0x2D:  # '-'
            if strict:
                raise RspError("server NAK'd packet — checksum mismatch?")
            return
        if b == 0x24:  # '$'
            self._inbuf.insert(0, b)
            return
        if strict:
            raise RspError(f"expected ack, got unexpected byte {b:#04x}")
        self._inbuf.insert(0, b)

    def _read_packet(self, *, timeout: float | None = _DEFAULT_TIMEOUT) -> bytes:
        """Block until a full ``$...#cs`` frame arrives, return body."""
        while True:
            b = self._read_byte(timeout=timeout)
            if b == 0x24:  # '$'
                break
            if b in (0x2B, 0x2D):
                continue
            continue

        body = bytearray()
        while True:
            b = self._read_byte(timeout=timeout)
            if b == 0x23:  # '#'
                break
            body.append(b)
            if len(body) > self._MAX_PACKET:
                raise RspError(
                    f"packet body exceeded {self._MAX_PACKET} bytes with no "
                    "'#' terminator — malformed/oversized stub reply"
                )

        cs_hex = bytes([self._read_byte(timeout=timeout), self._read_byte(timeout=timeout)])
        try:
            cs_expected = int(cs_hex.decode("ascii"), 16)
        except ValueError as e:
            raise RspError(f"bad checksum hex: {cs_hex!r}") from e

        cs_actual = _checksum(bytes(body))
        if cs_expected != cs_actual:
            if not self._noack:
                self._send_raw(b"-")
            raise RspError(
                f"checksum mismatch: got 0x{cs_expected:02x}, "
                f"computed 0x{cs_actual:02x}"
            )

        if not self._noack:
            self._send_raw(b"+")

        return _unescape(bytes(body))

    def _exchange(self, body: bytes, *, timeout: float | None = _DEFAULT_TIMEOUT) -> bytes:
        """Send a packet, return the next response body."""
        self._send_packet(body)
        return self._read_packet(timeout=timeout)

    # Stubs for methods that close() calls — defined in subclasses.
    def interrupt(self) -> None:
        raise NotImplementedError

    def wait_for_stop(self, *, timeout: float | None = None) -> object:
        raise NotImplementedError
