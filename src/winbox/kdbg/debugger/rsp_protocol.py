"""RSP high-level queries — handshake, threads, registers, memory mode."""

from __future__ import annotations

from winbox.kdbg.debugger.rsp_types import RspError, StopReply
from winbox.kdbg.debugger.rsp_transport import _RspTransport


class _RspProtocol(_RspTransport):
    """Adds register/thread/memory-mode queries on top of the transport."""

    def handshake(self) -> dict[str, str]:
        """Negotiate capabilities. Returns server's qSupported features.

        Tries to enable NoAckMode after the response — strictly faster
        and QEMU supports it. If the server rejects, we just keep the
        ack-every-packet flow.
        """
        body = (
            b"qSupported:"
            b"swbreak+;hwbreak+;multiprocess-;xmlRegisters=i386;"
            b"PacketSize=10000"
        )
        resp = self._exchange(body)
        features = self._parse_features(resp.decode("ascii", errors="replace"))

        try:
            qstart = self._exchange(b"QStartNoAckMode")
            if qstart == b"OK":
                self._noack = True
        except RspError:
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
        if not resp:
            self.interrupt()
            return self.wait_for_stop(timeout=5.0)
        return self._parse_stop_reply(resp)

    def list_threads(self) -> list[str]:
        """``qfThreadInfo`` / ``qsThreadInfo`` — enumerate vCPUs."""
        ids: list[str] = []
        first = self._exchange(b"qfThreadInfo")
        for _ in range(256):
            if not first or first == b"l":
                break
            if not first.startswith(b"m"):
                break
            for tok in first[1:].split(b","):
                tok_s = tok.decode("ascii", errors="replace").strip()
                if tok_s:
                    ids.append(tok_s)
            first = self._exchange(b"qsThreadInfo")
        return ids

    def current_thread(self) -> str:
        """Return the gdbstub's current vCPU via ``qC``."""
        response = self._exchange(b"qC")
        if not response.startswith(b"QC") or len(response) <= 2:
            raise RspError(f"malformed qC response: {response!r}")
        thread = response[2:].decode("ascii", errors="strict")
        try:
            int(thread, 16)
        except ValueError as exc:
            raise RspError(f"malformed qC thread id: {thread!r}") from exc
        return thread

    def select_thread(self, thread: str, *, op: str = "g") -> None:
        """``H<op><thread>`` — set the thread for subsequent ``op`` packets."""
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
        164   segment bases (fs_base, gs_base, k_gs_base, ...) — width and
              count vary by QEMU build; do NOT unpack these by fixed offset
        188   cr0 (8B)
        196   cr2 (8B)
        204   cr3 (8B)             <- used by ``read_cr3`` shortcut (empirically
                                     pinned + plausibility-checked there)
        212   cr4 (8B)
        220   cr8 (8B)
        228   efer (8B)
        236+  FPU + SSE state
        ===== =====================================================

        The only offset this codebase relies on is CR3 (204); the segment-base
        block above it is build-dependent, so treat everything else as opaque.
        """
        resp = self._exchange(b"g")
        if resp.startswith(b"E"):
            raise RspError(f"g failed: {resp!r}")
        try:
            regs = bytes.fromhex(resp.decode("ascii"))
        except ValueError as e:
            raise RspError(f"non-hex g response: {resp!r}") from e
        if len(regs) < self._MIN_G_PACKET:
            raise RspError(
                f"g-packet too short: {len(regs)} bytes "
                f"(need >= {self._MIN_G_PACKET} for the register block)"
            )
        return regs

    _CR3_OFFSET = 204

    def read_cr3(self) -> int:
        """``g``-packet shortcut: return CR3 of the currently selected vCPU."""
        import struct
        resp = self._exchange(b"g")
        if resp.startswith(b"E"):
            raise RspError(f"g failed: {resp!r}")
        hex_off = self._CR3_OFFSET * 2
        hex_window = resp[hex_off:hex_off + 16]
        if len(hex_window) < 16:
            raise RspError(
                f"g-reply too short for CR3 at offset {self._CR3_OFFSET} "
                f"({len(resp)} hex chars) — wrong register layout for this stub?"
            )
        try:
            cr3_bytes = bytes.fromhex(hex_window.decode("ascii"))
            cr3 = struct.unpack("<Q", cr3_bytes)[0]
        except (ValueError, struct.error) as e:
            raise RspError(f"bad CR3 window {hex_window!r}: {e}") from e
        if cr3 == 0 or (cr3 >> 12) == 0 or cr3 >= (1 << 52):
            raise RspError(
                f"implausible CR3 0x{cr3:x} from g-packet offset "
                f"{self._CR3_OFFSET} — register layout may be wrong for this "
                "QEMU build"
            )
        return cr3

    def write_registers(self, registers: bytes) -> bytes:
        """``G`` — replace the selected vCPU's complete register block."""
        return self._exchange(b"G" + registers.hex().encode("ascii"))

    def set_physical_memory_mode(self, enabled: bool) -> None:
        """Select QEMU gdbstub physical-memory mode for subsequent ``m`` ops."""
        value = b"1" if enabled else b"0"
        response = self._exchange(b"Qqemu.PhyMemMode:" + value)
        if response != b"OK":
            raise RspError(
                f"Qqemu.PhyMemMode:{value.decode()} rejected: {response!r}"
            )
