"""Exact-build derivation and validation of the x64↔x86 WoW64 bridge.

Windows does not publish a stable stack-stitching ABI for wow64cpu.dll.  The
layout below is therefore derived from named public functions in the exact PE
and accepted only when the surrounding instruction relationships agree.  A
new Windows build with different code fails closed instead of reusing offsets
learned from another image.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import capstone
from capstone import x86
import pefile


class Wow64TransitionError(RuntimeError):
    """The exact bridge or its live saved context could not be validated."""


@dataclass(frozen=True)
class Wow64TransitionLayout:
    run_rva: int
    return_rva: int
    cpu_area_teb_offset: int
    context_bias: int
    eip_offset: int
    esp_offset: int
    ebp_offset: int
    ebx_offset: int
    derivation: str = "exact-wow64cpu-instructions"


@dataclass(frozen=True)
class Wow64X86Context:
    eip: int
    esp: int
    ebp: int
    ebx: int
    context_va: int
    source: str


@dataclass(frozen=True)
class NativeTrapLayout:
    kpcr_size: int
    kpcr_self: int
    kpcr_current_prcb: int
    kprcb_size: int
    kprcb_current_thread: int
    kthread_size: int
    kthread_stack_limit: int
    kthread_stack_base: int
    kthread_trap_frame: int
    kthread_teb: int
    kthread_process: int
    trap_size: int
    trap_rip: int
    trap_rsp: int
    trap_seg_cs: int
    trap_registers: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class Wow64NativeContext:
    rip: int
    rsp: int
    registers: dict[str, int]
    kpcr: int
    thread: int
    trap_frame: int
    teb: int
    stack_limit: int
    stack_base: int
    source: str = "current-kthread-trap-frame"


def derive_native_trap_layout(
    struct: Callable[[str], dict[str, Any]],
) -> NativeTrapLayout:
    """Derive every kernel offset from the exact running nt PDB."""
    records = {
        name: struct(name)
        for name in ("_KPCR", "_KPRCB", "_KTHREAD", "_KTRAP_FRAME")
    }

    def field(type_name: str, field_name: str, width: int) -> int:
        record = records[type_name]
        try:
            size = int(record["size"])
            offset = int(record["fields"][field_name]["off"])
        except (KeyError, TypeError, ValueError) as exc:
            raise Wow64TransitionError(
                f"exact nt PDB lacks {type_name}.{field_name}"
            ) from exc
        if not 0 < size <= 1 << 20 or offset < 0 or offset + width > size:
            raise Wow64TransitionError(
                f"invalid exact-PDB layout for {type_name}.{field_name}"
            )
        return offset

    register_fields = (
        ("rax", "Rax"), ("rcx", "Rcx"), ("rdx", "Rdx"),
        ("r8", "R8"), ("r9", "R9"), ("r10", "R10"), ("r11", "R11"),
        ("rbx", "Rbx"), ("rdi", "Rdi"), ("rsi", "Rsi"), ("rbp", "Rbp"),
    )
    return NativeTrapLayout(
        kpcr_size=int(records["_KPCR"]["size"]),
        kpcr_self=field("_KPCR", "Self", 8),
        kpcr_current_prcb=field("_KPCR", "CurrentPrcb", 8),
        kprcb_size=int(records["_KPRCB"]["size"]),
        kprcb_current_thread=field("_KPRCB", "CurrentThread", 8),
        kthread_size=int(records["_KTHREAD"]["size"]),
        kthread_stack_limit=field("_KTHREAD", "StackLimit", 8),
        kthread_stack_base=field("_KTHREAD", "StackBase", 8),
        kthread_trap_frame=field("_KTHREAD", "TrapFrame", 8),
        kthread_teb=field("_KTHREAD", "Teb", 8),
        kthread_process=field("_KTHREAD", "Process", 8),
        trap_size=int(records["_KTRAP_FRAME"]["size"]),
        trap_rip=field("_KTRAP_FRAME", "Rip", 8),
        trap_rsp=field("_KTRAP_FRAME", "Rsp", 8),
        trap_seg_cs=field("_KTRAP_FRAME", "SegCs", 2),
        trap_registers=tuple(
            (name, field("_KTRAP_FRAME", pdb_name, 8))
            for name, pdb_name in register_fields
        ),
    )


def recover_native_trap_context(
    layout: NativeTrapLayout,
    raw_registers: bytes,
    read: Callable[[int, int], bytes],
    *,
    expected_process: int,
    is_x64_code: Callable[[int], bool],
    is_bridge_code: Callable[[int], bool],
) -> Wow64NativeContext:
    """Recover the current thread's last full-width WoW64 user trap.

    QEMU hides r8-r15/RSP while CS selects compatibility mode. Windows still
    retains the x64 syscall-return context in the current KTHREAD trap frame.
    The chain is accepted only when KPCR self identity, current process,
    kernel-stack containment, TEB self identity, native-stack containment,
    x64 CS, and exact bridge image all agree.
    """
    if expected_process <= 0:
        raise Wow64TransitionError("target EPROCESS is unavailable")

    def qword(address: int) -> int:
        raw = read(address, 8)
        if len(raw) != 8:
            raise Wow64TransitionError(f"short pointer read at 0x{address:x}")
        return int.from_bytes(raw, "little")

    def canonical_kernel(address: int) -> bool:
        return address >> 47 == 0x1FFFF

    candidates: list[int] = []
    # This QEMU x86-64 target layout is already pinned by the daemon and the
    # snapshot reader. Both slots are candidates because SWAPGS exchanges them.
    for offset in (172, 180):
        if len(raw_registers) >= offset + 8:
            value = int.from_bytes(raw_registers[offset:offset + 8], "little")
            if canonical_kernel(value) and value not in candidates:
                candidates.append(value)

    errors: list[str] = []
    for kpcr in candidates:
        try:
            if qword(kpcr + layout.kpcr_self) != kpcr:
                raise Wow64TransitionError("KPCR self pointer mismatch")
            prcb = qword(kpcr + layout.kpcr_current_prcb)
            if not canonical_kernel(prcb):
                raise Wow64TransitionError("invalid current PRCB")
            thread = qword(prcb + layout.kprcb_current_thread)
            if not canonical_kernel(thread):
                raise Wow64TransitionError("invalid current KTHREAD")
            if qword(thread + layout.kthread_process) != expected_process:
                raise Wow64TransitionError("current KTHREAD belongs to another process")

            kernel_limit = qword(thread + layout.kthread_stack_limit)
            kernel_base = qword(thread + layout.kthread_stack_base)
            trap = qword(thread + layout.kthread_trap_frame)
            if not (
                canonical_kernel(kernel_limit)
                and canonical_kernel(kernel_base)
                and kernel_limit < trap
                and trap + layout.trap_size <= kernel_base
                and kernel_base - kernel_limit <= 16 * 1024 * 1024
            ):
                raise Wow64TransitionError("trap frame is outside KTHREAD stack")

            teb = qword(thread + layout.kthread_teb)
            if not 0x10000 <= teb < (1 << 47) or qword(teb + 0x30) != teb:
                raise Wow64TransitionError("invalid native TEB self pointer")
            stack_base = qword(teb + 0x08)
            stack_limit = qword(teb + 0x10)
            if not (
                0x10000 <= stack_limit < stack_base < (1 << 47)
                and stack_base - stack_limit <= 16 * 1024 * 1024
            ):
                raise Wow64TransitionError("invalid native TEB stack bounds")

            rip = qword(trap + layout.trap_rip)
            rsp = qword(trap + layout.trap_rsp)
            cs_raw = read(trap + layout.trap_seg_cs, 2)
            if len(cs_raw) != 2 or int.from_bytes(cs_raw, "little") != 0x33:
                raise Wow64TransitionError("persisted trap is not x64 user mode")
            if not is_x64_code(rip) or not is_bridge_code(rip):
                raise Wow64TransitionError(
                    f"persisted RIP 0x{rip:x} is not in exact wow64cpu.dll"
                )
            if not stack_limit <= rsp < stack_base or rsp & 7:
                raise Wow64TransitionError(
                    f"persisted RSP 0x{rsp:x} is outside native TEB stack"
                )

            registers = {name: 0 for name in (
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            )}
            registers["rsp"] = rsp
            for name, offset in layout.trap_registers:
                registers[name] = qword(trap + offset)
            return Wow64NativeContext(
                rip=rip, rsp=rsp, registers=registers, kpcr=kpcr,
                thread=thread, trap_frame=trap, teb=teb,
                stack_limit=stack_limit, stack_base=stack_base,
            )
        except Exception as exc:
            errors.append(f"0x{kpcr:x}: {exc}")

    detail = "; ".join(errors[:4]) if errors else "no canonical KPCR register"
    raise Wow64TransitionError(f"cannot recover native trap context: {detail}")


def _symbol_rva(symbols: dict[str, int], wanted: str) -> int:
    matches = [
        int(value) for name, value in symbols.items()
        if name.lstrip("_").casefold() == wanted.casefold()
    ]
    if len(matches) != 1 or matches[0] <= 0:
        raise Wow64TransitionError(
            f"exact PDB must expose one {wanted} public symbol"
        )
    return matches[0]


def _decode(pe: pefile.PE, rva: int, size: int) -> list:
    raw = pe.get_data(rva, size)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(raw, rva))
    if not instructions or instructions[0].address != rva:
        raise Wow64TransitionError(f"cannot decode wow64cpu RVA 0x{rva:x}")
    return instructions


def derive_transition_layout(
    pe_path: Path,
    symbols: dict[str, int],
) -> Wow64TransitionLayout:
    """Extract bridge offsets from one exact, symbol-identified PE."""
    run_rva = _symbol_rva(symbols, "RunSimulatedCode")
    return_rva = _symbol_rva(symbols, "CpupReturnFromSimulatedCode")
    parsed = None
    try:
        parsed = pefile.PE(str(pe_path), fast_load=True)
        if int(parsed.FILE_HEADER.Machine) != 0x8664:
            raise Wow64TransitionError("wow64cpu transition PE is not x64")
        image_size = int(parsed.OPTIONAL_HEADER.SizeOfImage)
        if not (0 < run_rva < image_size and 0 < return_rva < image_size):
            raise Wow64TransitionError("transition symbol lies outside image")
        run = _decode(parsed, run_rva, min(0x300, image_size - run_rva))
        returned = _decode(
            parsed, return_rva, min(0x100, image_size - return_rva),
        )
    except (OSError, pefile.PEFormatError) as exc:
        raise Wow64TransitionError(f"cannot parse exact wow64cpu PE: {exc}") from exc
    finally:
        if parsed is not None:
            parsed.close()

    teb_offset = None
    context_bias = None
    teb_self_index = None
    for index, instruction in enumerate(run):
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
            dst, src = instruction.operands
            if (
                dst.type == x86.X86_OP_REG and dst.reg == x86.X86_REG_R12
                and src.type == x86.X86_OP_MEM
                and src.mem.segment == x86.X86_REG_GS
                and src.mem.base == x86.X86_REG_INVALID
                and src.mem.index == x86.X86_REG_INVALID
                and int(src.mem.disp) == 0x30
            ):
                teb_self_index = index
            if (
                teb_self_index is not None
                and index - teb_self_index <= 12
                and dst.type == x86.X86_OP_REG and dst.reg == x86.X86_REG_R13
                and src.type == x86.X86_OP_MEM
                and src.mem.base == x86.X86_REG_R12
                and src.mem.index == x86.X86_REG_INVALID
            ):
                teb_offset = int(src.mem.disp)
                for following in run[index + 1:index + 5]:
                    if following.mnemonic != "add" or len(following.operands) != 2:
                        continue
                    left, right = following.operands
                    if (
                        left.type == x86.X86_OP_REG
                        and left.reg == x86.X86_REG_R13
                        and right.type == x86.X86_OP_IMM
                    ):
                        context_bias = int(right.imm)
                        break
                break
    if teb_self_index is None or teb_offset is None or context_bias is None:
        raise Wow64TransitionError("RunSimulatedCode CPU-area pattern changed")

    fields: dict[str, int] = {}
    saw_stack_exchange = False
    saw_x86_return_pop = False
    for instruction in returned:
        if instruction.mnemonic == "xchg" and len(instruction.operands) == 2:
            regs = {
                operand.reg for operand in instruction.operands
                if operand.type == x86.X86_OP_REG
            }
            if regs == {x86.X86_REG_R14, x86.X86_REG_RSP}:
                saw_stack_exchange = True
        if (
            saw_stack_exchange and instruction.mnemonic == "add"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == x86.X86_OP_REG
            and instruction.operands[0].reg == x86.X86_REG_R14
            and instruction.operands[1].type == x86.X86_OP_IMM
            and int(instruction.operands[1].imm) == 4
        ):
            saw_x86_return_pop = True
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        dst, src = instruction.operands
        if (
            dst.type != x86.X86_OP_MEM
            or dst.mem.base != x86.X86_REG_R13
            or dst.mem.index != x86.X86_REG_INVALID
            or src.type != x86.X86_OP_REG
        ):
            continue
        displacement = int(dst.mem.disp)
        if not saw_x86_return_pop:
            continue
        if src.reg == x86.X86_REG_R8D:
            fields.setdefault("eip", displacement)
        elif src.reg == x86.X86_REG_R14D:
            fields.setdefault("esp", displacement)
        elif src.reg == x86.X86_REG_EBP:
            fields.setdefault("ebp", displacement)
        elif src.reg == x86.X86_REG_EBX:
            fields.setdefault("ebx", displacement)

    if not saw_stack_exchange or not saw_x86_return_pop:
        raise Wow64TransitionError("return bridge no longer swaps native/x86 stacks")
    if set(fields) != {"eip", "esp", "ebp", "ebx"}:
        raise Wow64TransitionError(
            "return bridge does not expose the required x86 context fields"
        )
    values = [teb_offset, context_bias, *fields.values()]
    if any(value < 0 or value > 0x10000 for value in values):
        raise Wow64TransitionError("derived transition offset exceeds safety cap")
    if len(set(fields.values())) != len(fields):
        raise Wow64TransitionError("derived x86 context fields overlap")

    return Wow64TransitionLayout(
        run_rva=run_rva,
        return_rva=return_rva,
        cpu_area_teb_offset=teb_offset,
        context_bias=context_bias,
        eip_offset=fields["eip"],
        esp_offset=fields["esp"],
        ebp_offset=fields["ebp"],
        ebx_offset=fields["ebx"],
    )


def recover_x86_context(
    layout: Wow64TransitionLayout,
    raw_registers: bytes,
    read: Callable[[int, int], bytes],
    is_x86_code: Callable[[int], bool],
) -> Wow64X86Context:
    """Recover and validate the saved x86 context at a native bridge stop."""
    candidates: list[tuple[int, str]] = []
    if len(raw_registers) >= 14 * 8:
        r13 = int.from_bytes(raw_registers[13 * 8:14 * 8], "little")
        if 0x10000 <= r13 < (1 << 47):
            candidates.append((r13, "r13"))

    # QEMU's current x86-64 target XML places gs_base at offset 172.  Prove it
    # is a TEB through the documented NT_TIB.Self pointer before using the
    # build-derived CPU-area field.  If a future XML moves it, the r13 path
    # remains available and this path merely fails closed.
    if len(raw_registers) >= 180:
        gs_base = int.from_bytes(raw_registers[172:180], "little")
        if 0x10000 <= gs_base < (1 << 47):
            try:
                self_pointer = int.from_bytes(read(gs_base + 0x30, 8), "little")
                cpu_area = int.from_bytes(
                    read(gs_base + layout.cpu_area_teb_offset, 8), "little",
                )
            except Exception:
                pass
            else:
                context = cpu_area + layout.context_bias
                if self_pointer == gs_base and 0x10000 <= context < (1 << 47):
                    candidates.append((context, "teb64-cpu-area"))

    errors: list[str] = []
    seen: set[int] = set()
    for context_va, source in candidates:
        if context_va in seen:
            continue
        seen.add(context_va)
        try:
            fields = {}
            for name, offset in (
                ("eip", layout.eip_offset), ("esp", layout.esp_offset),
                ("ebp", layout.ebp_offset), ("ebx", layout.ebx_offset),
            ):
                raw = read(context_va + offset, 4)
                if len(raw) != 4:
                    raise Wow64TransitionError(f"short saved {name} read")
                fields[name] = int.from_bytes(raw, "little")
            if not is_x86_code(fields["eip"]):
                raise Wow64TransitionError(
                    f"saved EIP 0x{fields['eip']:x} is outside exact x86 modules"
                )
            if not 0x10000 <= fields["esp"] <= 0xFFFFFFFC:
                raise Wow64TransitionError(f"invalid saved ESP 0x{fields['esp']:x}")
            if fields["esp"] & 3:
                raise Wow64TransitionError("saved ESP is not dword aligned")
            if fields["ebp"] and fields["ebp"] & 3:
                raise Wow64TransitionError("saved EBP is not dword aligned")
            return Wow64X86Context(
                eip=fields["eip"], esp=fields["esp"], ebp=fields["ebp"],
                ebx=fields["ebx"], context_va=context_va, source=source,
            )
        except Exception as exc:
            errors.append(f"{source}: {exc}")
    detail = "; ".join(errors[:4]) if errors else "no validated context pointer"
    raise Wow64TransitionError(f"cannot recover saved x86 context: {detail}")
