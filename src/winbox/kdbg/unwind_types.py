"""Data types for the x64 PE exception-directory unwinder."""

from __future__ import annotations

from dataclasses import dataclass


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


_REGISTERS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
