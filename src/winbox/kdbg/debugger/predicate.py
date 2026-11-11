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
    atom    := INT | REG | MEM | POI | TYPED | '(' or ')'
    MEM     := '[' (REG | INT) (('+' | '-') INT)? ']'   # qword little-endian
    POI     := 'poi' '(' atom (('+' | '-') INT)? ')'    # chained qword deref
    TYPED   := ('byte'|'word'|'dword'|'qword') '(' atom (('+' | '-') INT)? ')'
    CAPTURE := ('bytes'|'ascii'|'utf16') '(' atom ',' INT ')' # actions only
    REG     := rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8..r15|rip|eflags
    INT     := 0x[0-9a-fA-F]+ | [0-9]+
    CMP     := == | != | < | <= | > | >=

All values are 64-bit unsigned. Comparisons return 0/1. ``&&``/``||``
short-circuit. ``poi(expr)`` reads a qword at the address ``expr``
evaluates to, enabling chained pointer chases:
``poi(poi(rcx+0x10)+0x8) == 0x1234``.

Buffer captures are accepted only when ``parse(..., allow_capture=True)`` and
must be the complete action expression. Their length is a literal so bounds
are enforced at breakpoint-install time, never after an untrusted hit.
"""

from __future__ import annotations

from winbox.kdbg.debugger.predicate_ast import (  # noqa: F401 — re-exported
    And,
    BitAnd,
    CaptureRead,
    CaptureValue,
    Cmp,
    IntLit,
    MemRead,
    Or,
    Poi,
    PredicateRuntimeError,
    PredicateSyntaxError,
    RegRef,
    TypedRead,
    _REG_OFFSETS,
    _read_reg,
)


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
        if c == ",":
            out.append(("COMMA",)); i += 1; continue
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
        # Cap literal length before int() — Python 3.11+ sys.set_int_max_str_digits
        # raises ValueError on long decimals. ASCII-only: str.isdigit accepts '²'.
        if c in "0123456789":
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
                while j < n and src[j] in "0123456789":
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
            if ident == "poi":
                out.append(("POI",))
            elif ident in ("byte", "word", "dword", "qword"):
                out.append(("TYPED", ident))
            elif ident in ("bytes", "ascii", "utf16"):
                out.append(("CAPTURE", ident))
            elif ident not in _REG_OFFSETS:
                raise PredicateSyntaxError(
                    f"unknown identifier {ident!r} at offset {i} "
                    f"(allowed: poi, byte, word, dword, qword, "
                    f"bytes, ascii, utf16, {sorted(_REG_OFFSETS)})"
                )
            else:
                out.append(("REG", ident))
            i = j
            continue
        raise PredicateSyntaxError(f"unexpected character {c!r} at offset {i}")
    return out


# ── Parser ─────────────────────────────────────────────────────────────


_MAX_PAREN_DEPTH = 64
# Flat chains bypass _MAX_PAREN_DEPTH but build deep ASTs that
# RecursionError at eval time; cap tokens to fail at parse instead.
_MAX_TOKENS = 500


class _Parser:
    def __init__(self, toks: list[tuple], *, allow_capture: bool = False) -> None:
        self.toks = toks
        self.pos = 0
        self.allow_capture = allow_capture
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
        if self._peek() is not None and self._peek()[0] == "CAPTURE":
            if not self.allow_capture:
                raise PredicateSyntaxError(
                    "buffer captures are action-only; conditions must remain scalar"
                )
            node = self._capture()
        else:
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
        if t[0] == "POI":
            self.depth += 1
            if self.depth > _MAX_PAREN_DEPTH:
                raise PredicateSyntaxError(
                    f"expression too deep (max nesting {_MAX_PAREN_DEPTH})"
                )
            try:
                return self._poi()
            finally:
                self.depth -= 1
        if t[0] == "TYPED":
            self.depth += 1
            if self.depth > _MAX_PAREN_DEPTH:
                raise PredicateSyntaxError(
                    f"expression too deep (max nesting {_MAX_PAREN_DEPTH})"
                )
            try:
                return self._typed()
            finally:
                self.depth -= 1
        if t[0] == "CAPTURE":
            raise PredicateSyntaxError(
                "buffer capture must be the complete action expression"
            )
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

    def _poi(self):
        self._expect("POI")
        self._expect("LP")
        inner = self._atom()
        offset = 0
        nxt = self._peek()
        if nxt is not None and nxt[0] in ("PLUS", "MINUS"):
            sign = 1 if nxt[0] == "PLUS" else -1
            self._eat()
            it = self._peek()
            if it is None or it[0] != "INT":
                raise PredicateSyntaxError(
                    f"expected INT after +/- inside poi(), got {it!r}"
                )
            self._eat()
            offset = sign * it[1]
        self._expect("RP")
        return Poi(inner, offset)

    def _typed(self):
        token = self._expect("TYPED")
        name = token[1]
        self._expect("LP")
        inner = self._atom()
        offset = self._offset("inside typed read")
        self._expect("RP")
        width = {"byte": 1, "word": 2, "dword": 4, "qword": 8}[name]
        return TypedRead(inner, offset, width, name)

    def _capture(self):
        token = self._expect("CAPTURE")
        kind = token[1]
        self._expect("LP")
        inner = self._atom()
        self._expect("COMMA")
        length = self._expect("INT")[1]
        self._expect("RP")
        if not 1 <= length <= 256:
            raise PredicateSyntaxError(
                f"{kind} capture length must be between 1 and 256 bytes"
            )
        if kind == "utf16" and length % 2:
            raise PredicateSyntaxError("utf16 capture length must be even")
        return CaptureRead(inner, length, kind)

    def _offset(self, context: str) -> int:
        offset = 0
        nxt = self._peek()
        if nxt is not None and nxt[0] in ("PLUS", "MINUS"):
            sign = 1 if nxt[0] == "PLUS" else -1
            self._eat()
            it = self._peek()
            if it is None or it[0] != "INT":
                raise PredicateSyntaxError(
                    f"expected INT after +/- {context}, got {it!r}"
                )
            self._eat()
            offset = sign * it[1]
        return offset


# ── Public API ─────────────────────────────────────────────────────────


def parse(src: str, *, allow_capture: bool = False):
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
    if len(toks) > _MAX_TOKENS:
        raise PredicateSyntaxError(
            f"predicate too long: {len(toks)} tokens (max {_MAX_TOKENS})"
        )
    return _Parser(toks, allow_capture=allow_capture).parse()
