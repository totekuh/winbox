"""Memory operation mixin — mem, write_mem, stack."""

from __future__ import annotations

import struct
from typing import Any

from winbox.kdbg.debugger.rsp import RspError


class _MemoryMixin:

    def op_mem(
        self,
        va: int | str,
        length: int = 64,
        session_id: str | None = None,
        stop_id: int | None = None,
    ) -> dict[str, Any]:
        """Read `length` bytes at `va` in target's CR3."""
        self._require_stop_epoch(session_id, stop_id)
        if isinstance(va, str):
            va = int(va, 0)
        length = max(0, min(int(length), 64 * 1024))
        if length == 0:
            return {"va": f"0x{va:x}", "bytes": ""}

        vcpu = self._pick_vcpu()
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()

        if self.stop is not None and self.stop.cr3 in self.target.cr3_set:
            data = self.rsp.read_memory(va, length)
        else:
            data = self._cr3_masqueraded_call(
                vcpu, regs, lambda: self.rsp.read_memory(va, length)
            )

        return {"va": f"0x{va:x}", "bytes": data.hex()}

    def op_write_mem(self, va: int | str, data: str) -> dict[str, Any]:
        """Write hex-encoded ``data`` at ``va`` in target's address space."""
        self._require_stop_epoch()
        if isinstance(va, str):
            va = int(va, 0)
        try:
            payload = bytes.fromhex(data)
        except ValueError as e:
            raise RuntimeError(f"data must be hex-encoded: {e}") from e
        if not payload:
            return {"va": f"0x{va:x}", "length": 0}
        if len(payload) > 64 * 1024:
            raise RuntimeError(f"write capped at 64 KiB; got {len(payload)} bytes")

        vcpu = self._pick_vcpu()
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()

        if self.stop is not None and self.stop.cr3 in self.target.cr3_set:
            self.rsp.write_memory(va, payload)
        else:
            self._cr3_masqueraded_call(
                vcpu, regs, lambda: self.rsp.write_memory(va, payload)
            )

        return {"va": f"0x{va:x}", "length": len(payload)}

    def op_stack(self, n: int = 16) -> dict[str, Any]:
        """N architecture-sized stack words with RSP-relative labels."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        n = max(1, min(int(n), 256))
        rsp_va = struct.unpack_from("<Q", self.stop.raw_regs, 7 * 8)[0]
        width = 4 if self._is_x86_stop() else 8
        result = self.op_mem(rsp_va, n * width)
        raw = bytes.fromhex(result["bytes"])
        stack_register = "esp" if width == 4 else "rsp"
        entries = [
            {
                "offset": f"{stack_register}+0x{i:02x}",
                "va": f"0x{rsp_va + i:x}",
                "value": f"0x{int.from_bytes(raw[i:i + width], 'little'):0{width * 2}x}",
            }
            for i in range(0, n * width, width)
        ]
        output = {
            "rsp": f"0x{rsp_va:x}",
            "sp": f"0x{rsp_va:x}",
            "stack_register": stack_register,
            "architecture": "x86" if width == 4 else "x64",
            "word_size": width,
            "entries": entries,
        }
        output["dwords" if width == 4 else "qwords"] = entries
        return output
