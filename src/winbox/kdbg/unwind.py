"""Bounded Windows x64 exception-directory unwinding.

The parser reads PE headers, ``.pdata`` RUNTIME_FUNCTION entries, and xdata
directly from the live mapped image.  That makes ASLR irrelevant and avoids a
dangerous dependency on a same-named host PE being the exact loaded build.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass
from typing import Callable


class UnwindError(RuntimeError):
    """Malformed metadata, unsupported architecture, or unreadable stack."""


@dataclass(frozen=True)
class RuntimeFunction:
    begin: int
    end: int
    unwind: int


@dataclass(frozen=True)
class UnwindStep:
    rip: int
    rsp: int
    registers: dict[str, int]
    operations: tuple[str, ...]
    leaf: bool = False


# UNWIND_CODE register numbering is the architectural order, not QEMU's
# g-packet order.
_REGISTERS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)


class PeX64Unwinder:
    """Parse and apply one loaded PE32+ image's x64 unwind metadata."""

    MAX_PDATA = 16 * 1024 * 1024
    MAX_ENTRIES = 1_000_000
    MAX_CHAIN = 8

    def __init__(
        self, base: int, size: int, read: Callable[[int, int], bytes],
    ) -> None:
        if base < 0 or size <= 0 or size > (1 << 32):
            raise UnwindError("invalid module bounds")
        self.base = base
        self.size = size
        self._read = read
        self._functions = self._load_exception_directory()
        self._begins = [entry.begin for entry in self._functions]

    def _exact(self, va: int, length: int) -> bytes:
        if length < 0 or length > self.MAX_PDATA:
            raise UnwindError(f"unwind read length out of bounds: {length}")
        data = self._read(va, length)
        if len(data) != length:
            raise UnwindError(f"short unwind read at 0x{va:x}: {len(data)}/{length}")
        return data

    def _image(self, rva: int, length: int) -> bytes:
        if rva < 0 or length < 0 or rva + length > self.size:
            raise UnwindError(
                f"unwind metadata outside image: rva=0x{rva:x} length=0x{length:x}"
            )
        return self._exact(self.base + rva, length)

    def _load_exception_directory(self) -> list[RuntimeFunction]:
        dos = self._image(0, 0x40)
        if dos[:2] != b"MZ":
            raise UnwindError("loaded module has no MZ header")
        pe_off = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_off > min(self.size - 0x108, 0x100000):
            raise UnwindError(f"invalid PE header offset 0x{pe_off:x}")
        headers = self._image(pe_off, 0x108)
        if headers[:4] != b"PE\0\0":
            raise UnwindError("loaded module has no PE signature")
        machine = struct.unpack_from("<H", headers, 4)[0]
        optional_size = struct.unpack_from("<H", headers, 20)[0]
        if machine != 0x8664:
            raise UnwindError(f"module machine 0x{machine:04x} is not x64")
        if optional_size < 0x88:
            raise UnwindError("PE32+ optional header is truncated")
        optional = headers[24:]
        if struct.unpack_from("<H", optional, 0)[0] != 0x20B:
            raise UnwindError("module is not PE32+")
        directory_count = struct.unpack_from("<I", optional, 108)[0]
        if directory_count <= 3:
            return []
        pdata_rva, pdata_size = struct.unpack_from("<II", optional, 112 + 3 * 8)
        if pdata_size == 0:
            return []
        if pdata_size > self.MAX_PDATA or pdata_size // 12 > self.MAX_ENTRIES:
            raise UnwindError(f"exception directory too large: 0x{pdata_size:x}")
        if pdata_size % 12:
            raise UnwindError("exception directory size is not entry-aligned")
        raw = self._image(pdata_rva, pdata_size)
        functions: list[RuntimeFunction] = []
        previous = -1
        for offset in range(0, len(raw), 12):
            begin, end, unwind = struct.unpack_from("<III", raw, offset)
            if not (begin < end <= self.size) or unwind >= self.size:
                raise UnwindError(f"invalid RUNTIME_FUNCTION at index {offset // 12}")
            if begin < previous:
                raise UnwindError("exception directory is not sorted")
            previous = begin
            functions.append(RuntimeFunction(begin, end, unwind))
        return functions

    def find(self, control_pc: int) -> RuntimeFunction | None:
        rva = control_pc - self.base
        index = bisect.bisect_right(self._begins, rva) - 1
        if index < 0:
            return None
        entry = self._functions[index]
        return entry if entry.begin <= rva < entry.end else None

    @staticmethod
    def _qword(read: Callable[[int, int], bytes], va: int) -> int:
        raw = read(va, 8)
        if len(raw) != 8:
            raise UnwindError(f"short stack read at 0x{va:x}: {len(raw)}/8")
        return int.from_bytes(raw, "little")

    def unwind(
        self,
        control_pc: int,
        rsp: int,
        registers: dict[str, int],
        stack_read: Callable[[int, int], bytes],
    ) -> UnwindStep:
        entry = self.find(control_pc)
        state = dict(registers)
        state["rsp"] = rsp
        if entry is None:
            caller = self._qword(stack_read, rsp)
            return UnwindStep(caller, rsp + 8, state, ("leaf",), leaf=True)
        control_rva = control_pc - self.base
        if any(start <= control_rva < end for start, end in self._epilog_ranges(entry)):
            return self._simulate_epilog(control_pc, entry, state, stack_read)
        operations: list[str] = []
        new_rsp = self._apply_info(
            entry, control_rva, state, stack_read, operations, 0,
        )
        if "__machine_rip" in state:
            caller = state.pop("__machine_rip")
            new_rsp = state.pop("__machine_rsp")
            state["rsp"] = new_rsp
            return UnwindStep(caller, new_rsp, state, tuple(operations))
        caller = self._qword(stack_read, new_rsp)
        new_rsp += 8
        state["rsp"] = new_rsp
        return UnwindStep(caller, new_rsp, state, tuple(operations))

    def _epilog_ranges(self, entry: RuntimeFunction) -> tuple[tuple[int, int], ...]:
        """Decode the v2 epilog descriptors that prefix prolog unwind codes."""
        header = self._image(entry.unwind, 4)
        if header[0] & 0x7 != 2:
            return ()
        count = header[2]
        slots = self._image(entry.unwind + 4, count * 2)
        index = 0
        size: int | None = None
        ranges: list[tuple[int, int]] = []
        while index < count:
            code_offset = slots[index * 2]
            op_byte = slots[index * 2 + 1]
            opcode, info = op_byte & 0x0F, op_byte >> 4
            if opcode != 6:
                break
            index += 1
            if size is None:
                size = code_offset
                if info & 1:
                    offset = code_offset
                else:
                    if index >= count:
                        raise UnwindError("truncated UWOP_EPILOG offset")
                    low = slots[index * 2]
                    high = slots[index * 2 + 1] >> 4
                    index += 1
                    offset = low | high << 8
            else:
                offset = code_offset | info << 8
            if offset:
                start = entry.end - offset
                end = start + size
                if start < entry.begin or end > entry.end:
                    raise UnwindError("UWOP_EPILOG range lies outside function")
                ranges.append((start, end))
        return tuple(ranges)

    def _simulate_epilog(
        self,
        control_pc: int,
        entry: RuntimeFunction,
        state: dict[str, int],
        stack_read: Callable[[int, int], bytes],
    ) -> UnwindStep:
        """Execute the small instruction subset legal in a Windows epilog."""
        try:
            import capstone
            from capstone import x86
        except ImportError as exc:  # pragma: no cover - required dependency
            raise UnwindError("capstone is required for epilog unwinding") from exc

        remaining = min(entry.end - (control_pc - self.base), 128)
        if remaining <= 0:
            raise UnwindError("empty epilog range")
        code = self._image(control_pc - self.base, remaining)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        rsp = state["rsp"]
        operations: list[str] = []
        decoded = 0
        for instruction in decoder.disasm(code, control_pc):
            decoded += 1
            if decoded > 32:
                raise UnwindError("epilog instruction cap exceeded")
            operands = instruction.operands
            if instruction.mnemonic in ("nop", "endbr64"):
                continue
            if instruction.mnemonic == "add" and len(operands) == 2:
                if (
                    operands[0].type == x86.X86_OP_REG
                    and instruction.reg_name(operands[0].reg) == "rsp"
                    and operands[1].type == x86.X86_OP_IMM
                    and operands[1].imm >= 0
                ):
                    rsp += operands[1].imm
                    state["rsp"] = rsp
                    operations.append(f"epilog add rsp,0x{operands[1].imm:x}")
                    continue
            if instruction.mnemonic == "lea" and len(operands) == 2:
                if (
                    operands[0].type == x86.X86_OP_REG
                    and instruction.reg_name(operands[0].reg) == "rsp"
                    and operands[1].type == x86.X86_OP_MEM
                    and operands[1].mem.index == 0
                ):
                    base_name = instruction.reg_name(operands[1].mem.base)
                    if base_name not in state:
                        raise UnwindError(f"missing epilog frame register {base_name}")
                    rsp = state[base_name] + operands[1].mem.disp
                    state["rsp"] = rsp
                    operations.append(f"epilog lea rsp,[{base_name}]")
                    continue
            if instruction.mnemonic == "pop" and len(operands) == 1:
                if operands[0].type == x86.X86_OP_REG:
                    name = instruction.reg_name(operands[0].reg)
                    if name not in _REGISTERS:
                        raise UnwindError(f"invalid epilog pop register {name}")
                    state[name] = self._qword(stack_read, rsp)
                    rsp += 8
                    state["rsp"] = rsp
                    operations.append(f"epilog pop {name}")
                    continue
            if instruction.mnemonic in ("ret", "retf"):
                caller = self._qword(stack_read, rsp)
                rsp += 8
                if operands and operands[0].type == x86.X86_OP_IMM:
                    rsp += operands[0].imm
                state["rsp"] = rsp
                operations.append("epilog ret")
                return UnwindStep(caller, rsp, state, tuple(operations))
            raise UnwindError(
                f"unsupported epilog instruction at 0x{instruction.address:x}: "
                f"{instruction.mnemonic} {instruction.op_str}".rstrip()
            )
        raise UnwindError("epilog ended without ret")

    def _apply_info(
        self,
        entry: RuntimeFunction,
        control_rva: int,
        state: dict[str, int],
        stack_read: Callable[[int, int], bytes],
        operations: list[str],
        chain_depth: int,
    ) -> int:
        if chain_depth >= self.MAX_CHAIN:
            raise UnwindError("chained unwind metadata exceeds depth cap")
        header = self._image(entry.unwind, 4)
        version = header[0] & 0x7
        flags = header[0] >> 3
        prolog_size = header[1]
        count = header[2]
        frame_reg = header[3] & 0x0F
        frame_off = header[3] >> 4
        if version not in (1, 2):
            raise UnwindError(f"unsupported UNWIND_INFO version {version}")
        slots = self._image(entry.unwind + 4, count * 2)
        in_prolog = control_rva - entry.begin < prolog_size
        prolog_offset = max(0, control_rva - entry.begin)
        rsp = state["rsp"]
        index = 0
        epilog_size: int | None = None
        while index < count:
            code_offset = slots[index * 2]
            op_byte = slots[index * 2 + 1]
            opcode, info = op_byte & 0x0F, op_byte >> 4
            index += 1
            apply = not in_prolog or code_offset <= prolog_offset

            def slot16() -> int:
                nonlocal index
                if index >= count:
                    raise UnwindError("truncated UNWIND_CODE operand")
                value = struct.unpack_from("<H", slots, index * 2)[0]
                index += 1
                return value

            def slot32() -> int:
                low = slot16()
                high = slot16()
                return low | high << 16

            if opcode == 0:  # UWOP_PUSH_NONVOL
                if apply:
                    name = _REGISTERS[info]
                    state[name] = self._qword(stack_read, rsp)
                    rsp += 8
                    operations.append(f"restore {name}")
            elif opcode == 1:  # UWOP_ALLOC_LARGE
                if info == 0:
                    amount = slot16() * 8
                elif info == 1:
                    amount = slot32()
                else:
                    raise UnwindError(f"invalid UWOP_ALLOC_LARGE info {info}")
                if apply:
                    rsp += amount
                    operations.append(f"dealloc 0x{amount:x}")
            elif opcode == 2:  # UWOP_ALLOC_SMALL
                amount = info * 8 + 8
                if apply:
                    rsp += amount
                    operations.append(f"dealloc 0x{amount:x}")
            elif opcode == 3:  # UWOP_SET_FPREG
                if frame_reg == 0:
                    raise UnwindError("UWOP_SET_FPREG has no frame register")
                if apply:
                    name = _REGISTERS[frame_reg]
                    if name not in state:
                        raise UnwindError(f"missing frame register {name}")
                    rsp = state[name] - frame_off * 16
                    operations.append(f"frame {name}-0x{frame_off * 16:x}")
            elif opcode in (4, 5):  # SAVE_NONVOL / FAR
                offset = slot16() * 8 if opcode == 4 else slot32()
                if apply:
                    name = _REGISTERS[info]
                    state[name] = self._qword(stack_read, rsp + offset)
                    operations.append(f"restore {name}@+0x{offset:x}")
            elif opcode == 6 and version == 2:  # UWOP_EPILOG descriptor
                # Unwind v2 prefixes the ordinary prolog codes with one or
                # more epilog descriptors.  The first stores epilog size in
                # CodeOffset; bit 0 selects compact (same offset) vs. a second
                # raw slot containing the 12-bit offset from function end.
                if epilog_size is None:
                    epilog_size = code_offset
                    if info & 1:
                        epilog_offset = code_offset
                    else:
                        if index >= count:
                            raise UnwindError("truncated UWOP_EPILOG offset")
                        low = slots[index * 2]
                        high = slots[index * 2 + 1] >> 4
                        index += 1
                        epilog_offset = low | high << 8
                else:
                    epilog_offset = code_offset | info << 8
                # Metadata only. If the control PC was inside this range,
                # ``unwind`` already routed it through instruction simulation.
            elif opcode in (8, 9):  # SAVE_XMM128 / FAR (no GPR effect)
                _ = slot16() * 16 if opcode == 8 else slot32()
            elif opcode == 10:  # UWOP_PUSH_MACHFRAME
                if apply:
                    if info not in (0, 1):
                        raise UnwindError(f"invalid UWOP_PUSH_MACHFRAME info {info}")
                    # Hardware frame layout is specified by the Windows x64
                    # ABI. With an error code, every saved field moves by 8.
                    state["__machine_rip"] = self._qword(
                        stack_read, rsp + (8 if info else 0),
                    )
                    state["__machine_rsp"] = self._qword(
                        stack_read, rsp + (32 if info else 24),
                    )
                    operations.append(
                        "machine-frame-error" if info else "machine-frame"
                    )
            else:
                raise UnwindError(f"unsupported unwind opcode {opcode}")
        state["rsp"] = rsp
        if flags & 0x4:  # UNW_FLAG_CHAININFO
            aligned = (count + 1) & ~1
            raw = self._image(entry.unwind + 4 + aligned * 2, 12)
            chained = RuntimeFunction(*struct.unpack("<III", raw))
            if not (chained.begin < chained.end <= self.size):
                raise UnwindError("invalid chained RUNTIME_FUNCTION")
            rsp = self._apply_info(
                chained, chained.end, state, stack_read, operations,
                chain_depth + 1,
            )
        return rsp
