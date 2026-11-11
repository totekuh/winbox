"""Capstone-based x86 prologue simulation for bounded stack unwind."""

from __future__ import annotations

import bisect
from typing import Callable

from winbox.kdbg.x86_unwind_types import X86Module, X86Step, X86UnwindError


def x86_prolog_step(
    *,
    read: Callable[[int, int], bytes],
    u32: Callable[[int], int],
    valid_return: Callable[[int], bool],
    module: X86Module,
    eip: int, esp: int, ebp: int, ebx: int,
    max_prolog_bytes: int,
    max_prolog_insns: int,
    max_frame_distance: int,
) -> X86Step:
    rva = eip - module.base
    starts = module.function_starts
    index = bisect.bisect_right(starts, rva) - 1
    if index < 0:
        raise X86UnwindError("no verified function start before EIP")
    start_rva = starts[index]
    distance = rva - start_rva
    if distance > max_prolog_bytes:
        raise X86UnwindError("EIP is beyond bounded prologue-analysis window")
    raw = read(module.base + start_rva, distance)
    if len(raw) != distance:
        raise X86UnwindError("short function prologue read")
    try:
        import capstone
        from capstone import x86
    except ImportError as exc:  # pragma: no cover - required dependency
        raise X86UnwindError("capstone is required for x86 prologue analysis") from exc
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    delta = 0
    saved_ebp = False
    cursor = module.base + start_rva
    count = 0
    for instruction in decoder.disasm(raw, cursor):
        count += 1
        if count > max_prolog_insns:
            raise X86UnwindError("prologue instruction cap exceeded")
        cursor = instruction.address + instruction.size
        if instruction.mnemonic == "push":
            delta += 4
            if instruction.op_str == "ebp":
                saved_ebp = True
            continue
        if instruction.mnemonic == "pop":
            delta -= 4
            if delta < 0:
                raise X86UnwindError("prologue POP underflow")
            continue
        operands = instruction.operands
        if instruction.mnemonic in {"sub", "add"} and len(operands) == 2:
            if (
                operands[0].type == x86.X86_OP_REG
                and instruction.reg_name(operands[0].reg) == "esp"
                and operands[1].type == x86.X86_OP_IMM
            ):
                amount = int(operands[1].imm)
                delta += amount if instruction.mnemonic == "sub" else -amount
                if delta < 0 or delta > max_frame_distance:
                    raise X86UnwindError("implausible prologue stack delta")
                continue
        if any(group in instruction.groups for group in (
            capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP, capstone.CS_GRP_RET,
        )):
            raise X86UnwindError("control flow precedes EIP in prologue window")
        try:
            _, written = instruction.regs_access()
        except capstone.CsError as exc:
            raise X86UnwindError(
                "cannot determine prologue register effects"
            ) from exc
        if x86.X86_REG_ESP in written:
            raise X86UnwindError(
                f"unsupported stack-pointer write in {instruction.mnemonic}"
            )
        if instruction.mnemonic in {"leave", "enter"}:
            raise X86UnwindError(f"unsupported prologue {instruction.mnemonic}")
    if cursor != eip:
        raise X86UnwindError("EIP is not on a decoded instruction boundary")
    ret_slot = esp + delta
    caller = u32(ret_slot)
    if not valid_return(caller):
        raise X86UnwindError(
            f"prologue return 0x{caller:x} is outside x86 modules"
        )
    next_ebp = u32(ret_slot - 4) if saved_ebp else ebp
    return X86Step(
        caller, ret_slot + 4, next_ebp, ebx,
        "instruction-prolog", "medium",
        (f"simulated {count} straight-line instructions",
         f"stack delta 0x{delta:x}"), module.metadata,
    )
