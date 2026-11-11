"""Kernel trap-frame recovery for WoW64 native context at a compatibility stop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from winbox.kdbg.wow64_transition import Wow64TransitionError


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
    """Recover the current thread's last full-width WoW64 user trap."""
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
