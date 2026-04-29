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

import socket
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


# ── Client ──────────────────────────────────────────────────────────────


class RspClient:
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

    # Packet-level recv buffer size. Stop replies and m-responses can be
    # several KB; we loop until we have a full ``$...#cs`` frame.
    _CHUNK = 4096
    # Default I/O timeout. Stop replies block until the VM stops, so
    # ``wait_for_stop`` overrides this with its own (or None for forever).
    _DEFAULT_TIMEOUT = 10.0

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._inbuf = bytearray()
        self._noack = False  # set True after qSupported negotiates NoAckMode

    # ── lifecycle ──────────────────────────────────────────────────────

    @classmethod
    def connect(
        cls,
        host: str,
        port: int,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> "RspClient":
        sock = socket.create_connection((host, port), timeout=timeout)
        # Disable Nagle: every RSP exchange is a small request + small
        # response, latency dominates throughput.
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return cls(sock)

    def close(self) -> None:
        """Detach cleanly: halt → D → socket close. VM ends up running.

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
                # Force the VM into a halted state if it isn't already.
                # interrupt() is a no-op if VM is paused (the queued
                # ctrl-C just sits in the buffer); wait_for_stop with a
                # short timeout consumes a real stop reply if one comes.
                self.interrupt()
                try:
                    self.wait_for_stop(timeout=1.0)
                except RspError:
                    # Already halted (no new stop reply) — fine.
                    pass

                # Now send detach. QEMU resumes the VM internally.
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
        # Always set the socket timeout to the requested value — including
        # ``None`` for blocking. Without the explicit ``settimeout(None)``
        # branch, the socket inherits whatever timeout a previous call
        # set, which silently broke ``wait_for_stop(timeout=None)`` (the
        # caller asks to block forever; the socket still has a 10s
        # timeout from a prior _DEFAULT_TIMEOUT read).
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
        # Acks are post-send round-trip — they MUST be bounded. Before
        # the C1 fix this called `_read_byte()` (no timeout), which used
        # to silently inherit the socket's last-set timeout (typically
        # _DEFAULT_TIMEOUT from a prior read). After C1, ``timeout=None``
        # means "block forever" — and ``_read_byte()`` defaults to
        # ``timeout=None``. Without the explicit bound here, a server
        # crash between our send and its ack hung the daemon forever.
        b = self._read_byte(timeout=self._DEFAULT_TIMEOUT)
        if b == 0x2B:  # '+'
            return
        if b == 0x2D:  # '-'
            if strict:
                raise RspError("server NAK'd packet — checksum mismatch?")
            return
        # No ack (NoAckMode) — push the byte back; it's the start of a
        # genuine packet (likely '$').
        self._inbuf.insert(0, b)

    def _read_packet(self, *, timeout: float | None = _DEFAULT_TIMEOUT) -> bytes:
        """Block until a full ``$...#cs`` frame arrives, return body."""
        # Skip leading acks if any leak in (defensive — QEMU shouldn't,
        # but real-gdb-driven flows can).
        while True:
            b = self._read_byte(timeout=timeout)
            if b == 0x24:  # '$'
                break
            if b in (0x2B, 0x2D):
                continue
            # Unexpected leading byte — reframe by dropping until '$'.
            continue

        body = bytearray()
        while True:
            b = self._read_byte(timeout=timeout)
            if b == 0x23:  # '#'
                break
            body.append(b)

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

    # ── high-level operations ──────────────────────────────────────────

    def handshake(self) -> dict[str, str]:
        """Negotiate capabilities. Returns server's qSupported features.

        Tries to enable NoAckMode after the response — strictly faster
        and QEMU supports it. If the server rejects, we just keep the
        ack-every-packet flow.
        """
        # We advertise modest gdb features — we don't implement multiprocess
        # extensions, etc. PacketSize=0x10000 (65536) covers the daemon's
        # 64 KiB op_mem cap in a single ``m`` reply; smaller values silently
        # truncate. We still chunk on our side in ``read_memory`` /
        # ``write_memory`` defensively in case a stub honours a smaller cap.
        body = (
            b"qSupported:"
            b"swbreak+;hwbreak+;multiprocess-;xmlRegisters=i386;"
            b"PacketSize=10000"
        )
        resp = self._exchange(body)
        features = self._parse_features(resp.decode("ascii", errors="replace"))

        # Try to switch off acks. ServerOk -> we can flip our flag.
        try:
            qstart = self._exchange(b"QStartNoAckMode")
            if qstart == b"OK":
                # The exchange we just did still consumed an ack; from
                # now on no acks come from the server, and we don't send
                # them either.
                self._noack = True
        except RspError:
            # Older stubs may not support it — ignore.
            pass

        return features

    @staticmethod
    def _parse_features(text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for token in text.split(";"):
            if not token:
                continue
            if "=" in token:
                k, _, v = token.partition("=")
                out[k] = v
            elif token.endswith("+"):
                out[token[:-1]] = "1"
            elif token.endswith("-"):
                out[token[:-1]] = "0"
            else:
                out[token] = ""
        return out

    def query_halt_reason(self) -> StopReply:
        """``?`` — return the current stop reason without resuming."""
        resp = self._exchange(b"?")
        return self._parse_stop_reply(resp)

    def list_threads(self) -> list[str]:
        """``qfThreadInfo`` / ``qsThreadInfo`` — enumerate vCPUs.

        Each returned id is a hex string identifying a thread (vCPU on
        QEMU). Pass these to ``select_thread`` (Hg).
        """
        ids: list[str] = []
        first = self._exchange(b"qfThreadInfo")
        while first and first != b"l":
            if not first.startswith(b"m"):
                # Unexpected reply shape — bail rather than spin.
                break
            for tok in first[1:].split(b","):
                tok_s = tok.decode("ascii", errors="replace").strip()
                if tok_s:
                    ids.append(tok_s)
            first = self._exchange(b"qsThreadInfo")
        return ids

    def select_thread(self, thread: str, *, op: str = "g") -> None:
        """``H<op><thread>`` — set the thread for subsequent ``op`` packets.

        ``op='g'`` is the standard one (read regs, mem read/write, bp
        install all use it on QEMU). ``op='c'`` would set the thread for
        continue/step but that's better expressed via ``vCont``.

        CRITICAL for multi-vCPU: ``Z0,va,kind`` translates ``va`` using
        the *currently selected vCPU's* CR3. Calling this with the
        target-CR3-loaded vCPU is how we get bps installed against the
        right address space.
        """
        if op not in ("g", "c"):
            raise ValueError(f"unsupported H op: {op!r}")
        resp = self._exchange(f"H{op}{thread}".encode("ascii"))
        if resp != b"OK":
            raise RspError(f"H{op}{thread} rejected: {resp!r}")

    def read_registers(self) -> bytes:
        """``g`` — read all GPRs + control regs as a flat byte blob.

        QEMU's x86-64 register layout in the g-packet (verified
        against ``i386-64bit.xml`` from qXfer):

        ===== =====================================================
        offset  field
        ===== =====================================================
        0     rax..r15 (16 * 8B)
        128   rip (8B)
        136   eflags (4B)
        140   cs, ss, ds, es, fs, gs (each 4B; 24B total)
        164   fs_base, gs_base (each 8B)... layout varies
        188   cr0 (8B)
        196   cr2 (8B)
        204   cr3 (8B)             ← used by ``read_cr3`` shortcut
        212   cr4 (8B)
        220   cr8 (8B)
        228   efer (8B)
        236+  FPU + SSE state
        ===== =====================================================

        Treat as raw bytes; use ``struct.unpack_from`` on the offsets
        you care about. CR3 has a dedicated shortcut.
        """
        resp = self._exchange(b"g")
        if resp.startswith(b"E"):
            raise RspError(f"g failed: {resp!r}")
        try:
            return bytes.fromhex(resp.decode("ascii"))
        except ValueError as e:
            raise RspError(f"non-hex g response: {resp!r}") from e

    # Cache the CR3 offset to avoid repeating the struct.unpack overhead
    # on the hot path; verified against QEMU 8.x/9.x x86-64 stub.
    _CR3_OFFSET = 204

    def read_cr3(self) -> int:
        """``g``-packet shortcut: return CR3 of the currently selected vCPU.

        Faster than HMP-based CR3 read by ~40x (gdbstub round-trip
        beats virsh-qemu-monitor-command). Used by the bp-install
        dance which polls CR3 across many steps.
        """
        import struct
        resp = self._exchange(b"g")
        if resp.startswith(b"E"):
            raise RspError(f"g failed: {resp!r}")
        # We only need 8 bytes at the CR3 offset; decode just that
        # window of the hex response to avoid hex-decoding the whole
        # 608-byte payload on every call.
        hex_off = self._CR3_OFFSET * 2
        hex_window = resp[hex_off:hex_off + 16]
        try:
            cr3_bytes = bytes.fromhex(hex_window.decode("ascii"))
        except ValueError as e:
            raise RspError(f"non-hex CR3 window: {hex_window!r}") from e
        return struct.unpack("<Q", cr3_bytes)[0]

    # Chunk size for memory I/O — kept comfortably under the smallest
    # PacketSize any historical QEMU build advertises (typically 0x1000
    # bytes data, leaving ~4 KB for hex-encoded reply framing). Big
    # reads/writes get split across multiple ``m`` / ``M`` exchanges
    # rather than risking silent truncation or an E22 reject.
    _MEM_CHUNK = 0xFF0  # 4080 bytes per request

    def read_memory(self, addr: int, length: int) -> bytes:
        """``m addr,len`` — read ``length`` bytes from ``addr``.

        VA is translated through the currently selected vCPU's CR3. To
        read another process's memory, ``select_thread`` to a vCPU
        running in that process first — or use the HMP-based
        ``read_virt_cr3`` which lets us pass CR3 explicitly without the
        vCPU dance.

        Reads larger than ``_MEM_CHUNK`` are split into multiple ``m``
        requests and concatenated. QEMU's gdbstub honours per-request
        sizes well below its advertised PacketSize, so chunking is
        the only reliable way to read large windows.
        """
        if length <= 0:
            return b""
        out = bytearray()
        remaining = length
        cur = addr
        while remaining > 0:
            n = min(remaining, self._MEM_CHUNK)
            try:
                resp = self._exchange(f"m{cur:x},{n:x}".encode("ascii"))
            except RspError as e:
                # Surface bytes already collected so callers walking a
                # struct boundary can decide whether to use the partial
                # read or retry.
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
                # gdbstub returned an empty (but non-error) reply.
                # Treat as short read — surface so caller doesn't
                # believe it got ``length`` bytes back.
                raise RspError(
                    f"empty m reply at 0x{cur:x} (asked {n}, got 0)",
                    partial=bytes(out),
                )
            out.extend(chunk)
            cur += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

    def write_memory(self, addr: int, data: bytes) -> None:
        """``M addr,len:hex`` — write ``data`` to memory.

        Same CR3 caveat as ``read_memory``. Writes larger than
        ``_MEM_CHUNK`` bytes are split across multiple ``M`` packets to
        avoid the gdbstub's E22 reject on oversized requests.
        """
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

    def insert_breakpoint(self, addr: int, *, kind: int = 1, hardware: bool = False) -> None:
        """``Z0,addr,kind`` (sw) or ``Z1,addr,kind`` (hw exec).

        ``kind`` is the bp size (1 byte for x86 software int3). For hw
        exec bps, kind is the size of the matched instruction; on x86 we
        pass 1 to mean "first byte" — QEMU honours it.

        SOFTWARE bps patch a 0xCC into the instruction stream at the
        physical page backing ``addr`` in the currently-selected vCPU's
        CR3. The 0xCC is visible to in-process self-hashing; for that
        case use ``hardware=True``, but DR0..3 are per-vCPU and Windows
        save/restores them across context switches.

        HARDWARE bps go via ``Z1`` — limited to 4 active across the
        whole CPU.
        """
        z = b"Z1" if hardware else b"Z0"
        resp = self._exchange(b"%b,%x,%x" % (z, addr, kind))
        if resp != b"OK":
            raise RspError(f"{z.decode()} insert at 0x{addr:x} failed: {resp!r}")

    def remove_breakpoint(self, addr: int, *, kind: int = 1, hardware: bool = False) -> None:
        z = b"z1" if hardware else b"z0"
        resp = self._exchange(b"%b,%x,%x" % (z, addr, kind))
        if resp != b"OK":
            raise RspError(f"{z.decode()} remove at 0x{addr:x} failed: {resp!r}")

    def cont(self) -> None:
        """``vCont;c`` — resume all vCPUs. Does NOT wait for a stop.

        Pair with ``wait_for_stop`` to block until something fires.
        Splitting the two lets callers do other work (HMP probes,
        timeouts) while the VM runs.
        """
        # vCont is more explicit than bare 'c' for multi-CPU guests; QEMU
        # emits the same continuation semantics either way but vCont is
        # the gdb-current standard.
        self._send_packet(b"vCont;c")

    def step(self, thread: str | None = None) -> None:
        """``vCont;s`` — single-step the selected vCPU once.

        On x86-64 a single step advances exactly one instruction at the
        firing vCPU's RIP. Other vCPUs may run during the step depending
        on QEMU's all-stop semantics — in practice all-stop pauses them.
        """
        if thread:
            packet = f"vCont;s:{thread}".encode("ascii")
        else:
            packet = b"vCont;s"
        self._send_packet(packet)

    def interrupt(self) -> None:
        """Send a raw Ctrl-C (0x03) to halt a running target.

        The next ``wait_for_stop`` will return a ``StopReply`` with
        signal 2 (SIGINT). No reply is expected to the byte itself.
        """
        self._send_raw(b"\x03")

    def wait_for_stop(self, *, timeout: float | None = None) -> StopReply:
        """Block until the next stop reply, return parsed StopReply.

        ``timeout=None`` blocks forever (used while waiting for a bp
        hit on an idle target). Pass a numeric timeout to bound the wait.
        """
        resp = self._read_packet(timeout=timeout)
        return self._parse_stop_reply(resp)

    @staticmethod
    def _parse_stop_reply(body: bytes) -> StopReply:
        text = body.decode("ascii", errors="replace")
        if not text:
            raise RspError("empty stop reply")
        kind = text[0]
        if kind == "S":
            sig = int(text[1:3], 16)
            return StopReply(signal=sig, thread=None, stop_kind=None, raw=text)
        if kind != "T":
            # 'W' (process exit), 'X' (signalled), 'O' (output) — we don't
            # expect them from QEMU's gdbstub against a Windows guest, so
            # surface them rather than silently treat as no-op.
            raise RspError(f"unexpected stop reply prefix {kind!r}: {text!r}")

        sig = int(text[1:3], 16)
        thread: str | None = None
        stop_kind: str | None = None
        # Body is 'T<ss><k1>:<v1>;<k2>:<v2>;...'
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
