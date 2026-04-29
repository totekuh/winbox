"""Server-side predicate language for conditional breakpoints.

Hand-rolled tokenizer + recursive-descent parser + tree-walking evaluator.
No ``eval``/``compile`` — the daemon socket is local-only and 0o600, but
the predicate runs with full kernel-memory read access via the daemon's
CR3-masquerade primitive, so we treat the input as untrusted.

Grammar::

    or      := and ('||' and)*
    and     := cmp ('&&' cmp)*
    cmp     := bitand (CMP bitand)?
    bitand  := atom ('&' atom)*
    atom    := INT | REG | MEM | '(' or ')'
    MEM     := '[' (REG | INT) (('+' | '-') INT)? ']'   # qword little-endian
    REG     := rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8..r15|rip|eflags
    INT     := 0x[0-9a-fA-F]+ | [0-9]+
    CMP     := == | != | < | <= | > | >=

All values are 64-bit unsigned. Comparisons return 0/1. ``&&``/``||``
short-circuit. There is no arithmetic outside the ``+`` / ``-`` offset
inside ``[...]``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable


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


# ── Tokenizer ──────────────────────────────────────────────────────────

# Token kinds: ('INT', int), ('REG', str), ('OP', str), ('LB',), ('RB',),
# ('LP',), ('RP',), ('PLUS',), ('MINUS',). End-of-input is None.

def _tokenize(src: str) -> list[tuple]:
    out: list[tuple] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "(":
            out.append(("LP",)); i += 1; continue
        if c == ")":
            out.append(("RP",)); i += 1; continue
        if c == "[":
            out.append(("LB",)); i += 1; continue
        if c == "]":
            out.append(("RB",)); i += 1; continue
        if c == "+":
            out.append(("PLUS",)); i += 1; continue
        if c == "-":
            out.append(("MINUS",)); i += 1; continue
        # Two-char ops first.
        two = src[i:i+2]
        if two in ("==", "!=", "<=", ">=", "&&", "||"):
            out.append(("OP", two)); i += 2; continue
        if c == "<":
            out.append(("OP", "<")); i += 1; continue
        if c == ">":
            out.append(("OP", ">")); i += 1; continue
        if c == "&":
            out.append(("OP", "&")); i += 1; continue
        # Numeric literal. We cap the literal length BEFORE calling
        # ``int(...)`` because Python 3.11+ enforces
        # ``sys.set_int_max_str_digits`` on decimal conversions and
        # raises ValueError, not PredicateSyntaxError, on long inputs.
        # 64-bit values fit in 20 decimal / 16 hex digits, so anything
        # past these caps is junk.
        if c.isdigit():
            j = i
            if c == "0" and i + 1 < n and src[i+1] in "xX":
                j = i + 2
                while j < n and src[j] in "0123456789abcdefABCDEF":
                    j += 1
                if j == i + 2:
                    raise PredicateSyntaxError(f"bad hex literal at offset {i}")
                # 0x + 16 hex digits = 18 chars max (uint64).
                if (j - i) > 18:
                    raise PredicateSyntaxError(
                        f"hex literal too long at offset {i} "
                        f"(max 16 hex digits)"
                    )
                out.append(("INT", int(src[i:j], 16)))
            else:
                while j < n and src[j].isdigit():
                    j += 1
                # Way more than any 64-bit decimal needs (20 digits);
                # 32 keeps us comfortably under PEP 651's 4300 cap and
                # fails fast on adversarial input.
                if (j - i) > 32:
                    raise PredicateSyntaxError(
                        f"integer literal too long at offset {i} "
                        f"(max 32 digits)"
                    )
                out.append(("INT", int(src[i:j], 10)))
            i = j
            continue
        # Identifier (register).
        if c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            ident = src[i:j].lower()
            if ident not in _REG_OFFSETS:
                raise PredicateSyntaxError(
                    f"unknown identifier {ident!r} at offset {i} "
                    f"(allowed: {sorted(_REG_OFFSETS)})"
                )
            out.append(("REG", ident))
            i = j
            continue
        raise PredicateSyntaxError(f"unexpected character {c!r} at offset {i}")
    return out


# ── Parser ─────────────────────────────────────────────────────────────


_MAX_PAREN_DEPTH = 64


class _Parser:
    def __init__(self, toks: list[tuple]) -> None:
        self.toks = toks
        self.pos = 0
        # Tracks currently-open '(' / '[' nesting. Bumped on entry,
        # decremented on exit. Capped to keep recursive-descent off the
        # Python recursion limit (which would raise RecursionError, not
        # PredicateSyntaxError).
        self.depth = 0

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _eat(self):
        t = self._peek()
        self.pos += 1
        return t

    def _expect(self, kind: str, value=None):
        t = self._peek()
        if t is None or t[0] != kind or (value is not None and t[1] != value):
            want = f"{kind}({value})" if value is not None else kind
            raise PredicateSyntaxError(f"expected {want}, got {t!r}")
        return self._eat()

    def parse(self):
        node = self._or()
        if self._peek() is not None:
            raise PredicateSyntaxError(f"trailing tokens: {self.toks[self.pos:]!r}")
        return node

    def _or(self):
        node = self._and()
        while self._peek() is not None and self._peek() == ("OP", "||"):
            self._eat()
            node = Or(node, self._and())
        return node

    def _and(self):
        node = self._cmp()
        while self._peek() is not None and self._peek() == ("OP", "&&"):
            self._eat()
            node = And(node, self._cmp())
        return node

    _CMP_OPS = ("==", "!=", "<", "<=", ">", ">=")

    def _cmp(self):
        node = self._bitand()
        t = self._peek()
        if t is not None and t[0] == "OP" and t[1] in self._CMP_OPS:
            self._eat()
            return Cmp(t[1], node, self._bitand())
        return node

    def _bitand(self):
        node = self._atom()
        while self._peek() is not None and self._peek() == ("OP", "&"):
            self._eat()
            node = BitAnd(node, self._atom())
        return node

    def _atom(self):
        t = self._peek()
        if t is None:
            raise PredicateSyntaxError("unexpected end of input")
        if t[0] == "INT":
            self._eat()
            return IntLit(t[1])
        if t[0] == "REG":
            self._eat()
            return RegRef(t[1])
        if t[0] == "LP":
            self._eat()
            self.depth += 1
            if self.depth > _MAX_PAREN_DEPTH:
                raise PredicateSyntaxError(
                    f"expression too deep (max nesting {_MAX_PAREN_DEPTH})"
                )
            try:
                inner = self._or()
            finally:
                self.depth -= 1
            self._expect("RP")
            return inner
        if t[0] == "LB":
            self.depth += 1
            if self.depth > _MAX_PAREN_DEPTH:
                raise PredicateSyntaxError(
                    f"expression too deep (max nesting {_MAX_PAREN_DEPTH})"
                )
            try:
                return self._mem()
            finally:
                self.depth -= 1
        raise PredicateSyntaxError(f"unexpected token {t!r}")

    def _mem(self):
        self._expect("LB")
        t = self._peek()
        if t is None:
            raise PredicateSyntaxError("unexpected end of input inside [")
        if t[0] == "REG":
            base = RegRef(t[1])
            self._eat()
        elif t[0] == "INT":
            base = IntLit(t[1])
            self._eat()
        else:
            raise PredicateSyntaxError(f"expected REG or INT inside [, got {t!r}")
        offset = 0
        nxt = self._peek()
        if nxt is not None and nxt[0] in ("PLUS", "MINUS"):
            sign = 1 if nxt[0] == "PLUS" else -1
            self._eat()
            it = self._peek()
            if it is None or it[0] != "INT":
                raise PredicateSyntaxError(f"expected INT after +/- inside [, got {it!r}")
            self._eat()
            offset = sign * it[1]
        self._expect("RB")
        return MemRead(base, offset)


# ── Public API ─────────────────────────────────────────────────────────


def parse(src: str):
    """Parse a predicate string into an evaluable AST.

    Raises ``PredicateSyntaxError`` for malformed input. The returned
    object exposes ``eval(regs_blob: bytes, mem_qword_reader)`` and
    returns 0 / 1 (or a non-zero qword value for raw register/mem
    expressions, but predicates at the daemon level are always
    boolean-shaped).
    """
    if not isinstance(src, str):
        raise PredicateSyntaxError(f"predicate must be str, got {type(src).__name__}")
    if not src.strip():
        raise PredicateSyntaxError("empty predicate")
    toks = _tokenize(src)
    return _Parser(toks).parse()
