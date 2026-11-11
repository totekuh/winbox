"""AST nodes, errors, and register table for the predicate language."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Callable


# ── Errors ──────────────────────────────────────────────────────────────


class PredicateSyntaxError(ValueError):
    """Raised by ``parse`` for malformed predicate text."""


class PredicateRuntimeError(RuntimeError):
    """Raised by ``eval`` when memory deref fails (or any other runtime
    issue we want to surface as a ``predicate_error`` halt)."""


# ── Register table ──────────────────────────────────────────────────────

# Offsets into the gdbstub g-packet blob. Mirrors ``_decode_regs`` in
# daemon.py; kept local so this module has no daemon dep.
_REG_OFFSETS: dict[str, int] = {
    "rax": 0, "rbx": 8, "rcx": 16, "rdx": 24,
    "rsi": 32, "rdi": 40, "rbp": 48, "rsp": 56,
    "r8": 64, "r9": 72, "r10": 80, "r11": 88,
    "r12": 96, "r13": 104, "r14": 112, "r15": 120,
    "rip": 128,
    # eflags is 32-bit in the g-packet; we zero-extend to 64 on read.
    "eflags": 136,
}


def _read_reg(blob: bytes, name: str) -> int:
    off = _REG_OFFSETS[name]
    try:
        if name == "eflags":
            return struct.unpack_from("<I", blob, off)[0]
        return struct.unpack_from("<Q", blob, off)[0]
    except struct.error as e:
        # Short / corrupt g-packet blob — surface as a predicate runtime
        # error so the daemon halts with reason='predicate_error' instead
        # of raising an uncaught struct.error up the call stack.
        raise PredicateRuntimeError(
            f"register {name!r} unreadable: blob length {len(blob)} "
            f"too short for offset {off} ({e})"
        ) from e


# ── AST ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IntLit:
    value: int

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        return self.value & 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class RegRef:
    name: str

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        return _read_reg(regs, self.name)


@dataclass(frozen=True)
class MemRead:
    """Qword little-endian read at base + offset. ``base`` is RegRef or
    IntLit (parser enforces this). ``offset`` is signed int already
    folded at parse time."""
    base: object
    offset: int

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        base_val = self.base.eval(regs, mem)
        addr = (base_val + self.offset) & 0xFFFFFFFFFFFFFFFF
        try:
            value = mem(addr)
        except PredicateRuntimeError:
            # Already shaped correctly — don't wrap-twice and lose the
            # original message.
            raise
        except Exception as e:
            # mem() can raise OSError (gdbstub socket), ValueError
            # (packet parsing), RspError, or anything else from the
            # transport layer. The daemon only catches
            # PredicateRuntimeError, so re-raise as one.
            raise PredicateRuntimeError(
                f"mem read at 0x{addr:x} failed: {type(e).__name__}: {e}"
            ) from e
        return value & 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class Poi:
    """Chained qword deref: evaluate inner, add offset, read qword."""
    inner: object
    offset: int

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        inner_val = self.inner.eval(regs, mem)
        addr = (inner_val + self.offset) & 0xFFFFFFFFFFFFFFFF
        try:
            value = mem(addr)
        except PredicateRuntimeError:
            raise
        except Exception as e:
            raise PredicateRuntimeError(
                f"poi read at 0x{addr:x} failed: {type(e).__name__}: {e}"
            ) from e
        return value & 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class TypedRead:
    """Little-endian scalar read with an explicit 1/2/4/8-byte width."""

    inner: object
    offset: int
    width: int
    name: str

    def eval(self, regs: bytes, mem: Callable[..., Any]) -> int:
        addr = (self.inner.eval(regs, mem) + self.offset) & 0xFFFFFFFFFFFFFFFF
        try:
            value = mem(addr, self.width)
        except PredicateRuntimeError:
            raise
        except Exception as e:
            raise PredicateRuntimeError(
                f"{self.name} read at 0x{addr:x} failed: {type(e).__name__}: {e}"
            ) from e
        return int(value) & ((1 << (self.width * 8)) - 1)


@dataclass(frozen=True)
class CaptureValue:
    kind: str
    address: int
    data: bytes


@dataclass(frozen=True)
class CaptureRead:
    """Bounded action-only buffer capture; never valid in a condition."""

    inner: object
    length: int
    kind: str

    @property
    def capture_length(self) -> int:
        return self.length

    def eval(self, regs: bytes, mem: Callable[..., Any]) -> CaptureValue:
        addr = self.inner.eval(regs, mem) & 0xFFFFFFFFFFFFFFFF
        try:
            data = mem(addr, self.length, raw=True)
        except PredicateRuntimeError:
            raise
        except Exception as e:
            raise PredicateRuntimeError(
                f"{self.kind} capture at 0x{addr:x} failed: "
                f"{type(e).__name__}: {e}"
            ) from e
        if not isinstance(data, bytes) or len(data) != self.length:
            got = len(data) if isinstance(data, bytes) else type(data).__name__
            raise PredicateRuntimeError(
                f"short {self.kind} capture at 0x{addr:x}: got {got}, "
                f"expected {self.length} bytes"
            )
        return CaptureValue(self.kind, addr, data)


@dataclass(frozen=True)
class BitAnd:
    left: object
    right: object

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        return self.left.eval(regs, mem) & self.right.eval(regs, mem)


@dataclass(frozen=True)
class Cmp:
    op: str  # == != < <= > >=
    left: object
    right: object

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        l = self.left.eval(regs, mem)
        r = self.right.eval(regs, mem)
        if self.op == "==": return 1 if l == r else 0
        if self.op == "!=": return 1 if l != r else 0
        if self.op == "<":  return 1 if l < r else 0
        if self.op == "<=": return 1 if l <= r else 0
        if self.op == ">":  return 1 if l > r else 0
        if self.op == ">=": return 1 if l >= r else 0
        raise PredicateRuntimeError(f"bad cmp op: {self.op!r}")


@dataclass(frozen=True)
class And:
    left: object
    right: object

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        if not self.left.eval(regs, mem):
            return 0
        return 1 if self.right.eval(regs, mem) else 0


@dataclass(frozen=True)
class Or:
    left: object
    right: object

    def eval(self, regs: bytes, mem: Callable[[int], int]) -> int:
        if self.left.eval(regs, mem):
            return 1
        return 1 if self.right.eval(regs, mem) else 0
