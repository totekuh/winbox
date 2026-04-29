"""Unit tests for the conditional-bp predicate language."""

from __future__ import annotations

import struct

import pytest

from winbox.kdbg.debugger.predicate import (
    And,
    BitAnd,
    Cmp,
    IntLit,
    MemRead,
    Or,
    PredicateRuntimeError,
    PredicateSyntaxError,
    RegRef,
    parse,
)


_BLOB_LEN = 608


def _blob(**regs) -> bytes:
    """Build a g-packet blob with named register overrides."""
    b = bytearray(_BLOB_LEN)
    offsets = {
        "rax": 0, "rbx": 8, "rcx": 16, "rdx": 24,
        "rsi": 32, "rdi": 40, "rbp": 48, "rsp": 56,
        "r8": 64, "r9": 72, "r10": 80, "r11": 88,
        "r12": 96, "r13": 104, "r14": 112, "r15": 120,
        "rip": 128,
    }
    for name, val in regs.items():
        if name == "eflags":
            struct.pack_into("<I", b, 136, val)
        else:
            struct.pack_into("<Q", b, offsets[name], val)
    return bytes(b)


def _mem_from(d: dict[int, int]):
    def reader(va: int) -> int:
        if va not in d:
            raise PredicateRuntimeError(f"no fake mem at 0x{va:x}")
        return d[va]
    return reader


# ── Parser ──────────────────────────────────────────────────────────────


def test_parse_register_compare():
    ast = parse("rcx == 0xdeadbeef")
    assert isinstance(ast, Cmp)
    assert ast.op == "=="
    assert isinstance(ast.left, RegRef) and ast.left.name == "rcx"
    assert isinstance(ast.right, IntLit) and ast.right.value == 0xdeadbeef


def test_parse_decimal_literal():
    ast = parse("rax == 42")
    assert ast.right.value == 42


def test_parse_mem_no_offset():
    ast = parse("[rcx] == 0")
    assert isinstance(ast.left, MemRead)
    assert isinstance(ast.left.base, RegRef) and ast.left.base.name == "rcx"
    assert ast.left.offset == 0


def test_parse_mem_plus_offset():
    ast = parse("[rsp+0x18] == 1")
    assert ast.left.offset == 0x18


def test_parse_mem_minus_offset():
    ast = parse("[rbp-0x8] == 1")
    assert ast.left.offset == -0x8


def test_parse_mem_absolute_addr():
    ast = parse("[0xfffff80000001000] == 0")
    assert isinstance(ast.left.base, IntLit)
    assert ast.left.base.value == 0xfffff80000001000


def test_parse_bitand_in_compare():
    ast = parse("(rax & 0x80000000) != 0")
    assert isinstance(ast, Cmp) and ast.op == "!="
    assert isinstance(ast.left, BitAnd)


def test_parse_boolean_combo():
    ast = parse("rcx == 4 && rdx != 0")
    assert isinstance(ast, And)


def test_parse_or_lower_than_and():
    # a == 1 || b == 2 && c == 3  -->  Or(a==1, And(b==2, c==3))
    ast = parse("rax == 1 || rbx == 2 && rcx == 3")
    assert isinstance(ast, Or)
    assert isinstance(ast.right, And)


def test_parse_parens_override_precedence():
    ast = parse("(rax == 1 || rbx == 2) && rcx == 3")
    assert isinstance(ast, And)


def test_parse_unknown_register():
    with pytest.raises(PredicateSyntaxError):
        parse("xax == 1")


def test_parse_unbalanced_paren():
    with pytest.raises(PredicateSyntaxError):
        parse("(rax == 1")


def test_parse_unbalanced_bracket():
    with pytest.raises(PredicateSyntaxError):
        parse("[rcx == 1")


def test_parse_bare_arithmetic_rejected():
    # No '+' outside [...] — bare 1+2 should fail at the trailing-token check.
    with pytest.raises(PredicateSyntaxError):
        parse("1 + 2 == 3")


def test_parse_empty_string_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("")


def test_parse_whitespace_only_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("   \t  ")


def test_parse_double_star_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("rax ** 1")


def test_parse_eval_call_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("eval(rax)")


def test_parse_trailing_junk_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("rax == 1 garbage")


def test_parse_bad_hex_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("rax == 0x")


def test_parse_mem_inside_mem_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse("[[rcx]] == 0")


def test_parse_non_str_rejected():
    with pytest.raises(PredicateSyntaxError):
        parse(123)


# ── Eval ────────────────────────────────────────────────────────────────


def test_eval_register_equal_true():
    ast = parse("rcx == 0xdeadbeef")
    assert ast.eval(_blob(rcx=0xdeadbeef), _mem_from({})) == 1


def test_eval_register_equal_false():
    ast = parse("rcx == 0xdeadbeef")
    assert ast.eval(_blob(rcx=0x1), _mem_from({})) == 0


def test_eval_register_not_equal():
    ast = parse("rax != 0")
    assert ast.eval(_blob(rax=1), _mem_from({})) == 1
    assert ast.eval(_blob(rax=0), _mem_from({})) == 0


def test_eval_register_relational():
    for src, l, r, expect in [
        ("rax < rbx", 1, 2, 1),
        ("rax < rbx", 2, 2, 0),
        ("rax <= rbx", 2, 2, 1),
        ("rax > rbx", 3, 2, 1),
        ("rax >= rbx", 2, 2, 1),
    ]:
        ast = parse(src)
        assert ast.eval(_blob(rax=l, rbx=r), _mem_from({})) == expect, src


def test_eval_mem_with_offset():
    ast = parse("[rsp+0x18] == 0x226048")
    blob = _blob(rsp=0x1000)
    mem = _mem_from({0x1018: 0x226048})
    assert ast.eval(blob, mem) == 1


def test_eval_mem_with_negative_offset():
    ast = parse("[rbp-0x8] == 0x41")
    blob = _blob(rbp=0x2000)
    mem = _mem_from({0x1ff8: 0x41})
    assert ast.eval(blob, mem) == 1


def test_eval_mem_absolute():
    ast = parse("[0xfffff80000001000] == 0xc0de")
    mem = _mem_from({0xfffff80000001000: 0xc0de})
    assert ast.eval(_blob(), mem) == 1


def test_eval_mask_check():
    ast = parse("(rax & 0x80000000) != 0")
    assert ast.eval(_blob(rax=0x80001234), _mem_from({})) == 1
    assert ast.eval(_blob(rax=0x00001234), _mem_from({})) == 0


def test_eval_boolean_combo():
    ast = parse("rcx == 4 && rdx != 0")
    assert ast.eval(_blob(rcx=4, rdx=0xff), _mem_from({})) == 1
    assert ast.eval(_blob(rcx=4, rdx=0), _mem_from({})) == 0
    assert ast.eval(_blob(rcx=5, rdx=0xff), _mem_from({})) == 0


def test_eval_or_short_circuits():
    # Left side true → right side (a bad mem deref) must not run.
    ast = parse("rax == 1 || [rcx] == 0")
    blob = _blob(rax=1, rcx=0xdead)  # rcx isn't in fake mem
    assert ast.eval(blob, _mem_from({})) == 1


def test_eval_and_short_circuits():
    # Left side false → right side (bad mem deref) must not run.
    ast = parse("rax == 1 && [rcx] == 0")
    blob = _blob(rax=0, rcx=0xdead)
    assert ast.eval(blob, _mem_from({})) == 0


def test_eval_runtime_error_on_bad_mem():
    ast = parse("[rcx] == 0")
    blob = _blob(rcx=0xdead)
    with pytest.raises(PredicateRuntimeError):
        ast.eval(blob, _mem_from({}))


def test_eval_eflags_readable():
    ast = parse("(eflags & 0x1) == 0")  # CF clear
    blob = _blob()
    # Default eflags is 0 in our fake.
    assert ast.eval(blob, _mem_from({})) == 1


def test_eval_rip_readable():
    ast = parse("rip == 0xfffff80608628780")
    blob = _blob(rip=0xfffff80608628780)
    assert ast.eval(blob, _mem_from({})) == 1


def test_eval_overflow_wraps_to_64():
    # rcx + 0x10 wrap-around (rcx = -0x10 == 0xfff..fff0) → addr = 0
    ast = parse("[rcx+0x10] == 0xc0de")
    blob = _blob(rcx=(0 - 0x10) & 0xFFFFFFFFFFFFFFFF)
    mem = _mem_from({0: 0xc0de})
    assert ast.eval(blob, mem) == 1


# ── Regressions: leaked-exception shielding ─────────────────────────────


def test_eval_short_blob_raises_predicate_runtime_error():
    """Bug 1: _read_reg used to leak struct.error on short blobs."""
    ast = parse("rax == 0")
    short = b"\x00" * 4  # nowhere near 8 bytes for rax
    with pytest.raises(PredicateRuntimeError):
        ast.eval(short, _mem_from({}))


def test_eval_short_blob_does_not_leak_struct_error():
    """Belt-and-suspenders: confirm the underlying struct.error is NOT
    what bubbles out (would slip past the daemon's PredicateRuntimeError
    catch and crash the cont loop)."""
    ast = parse("rcx == 0")
    short = b""
    try:
        ast.eval(short, _mem_from({}))
    except PredicateRuntimeError:
        pass
    except struct.error:
        pytest.fail("struct.error leaked from _read_reg")


def test_eval_mem_oserror_wrapped():
    """Bug 2: arbitrary mem() exceptions must be re-raised as
    PredicateRuntimeError (gdbstub socket errors are OSError)."""
    ast = parse("[rcx] == 0")
    blob = _blob(rcx=0x1000)

    def bad_read(va: int) -> int:
        raise OSError("connection reset")

    with pytest.raises(PredicateRuntimeError):
        ast.eval(blob, bad_read)


def test_eval_mem_value_error_wrapped():
    """Bug 2: ValueError from packet parsing must surface as
    PredicateRuntimeError."""
    ast = parse("[rcx] == 0")
    blob = _blob(rcx=0x1000)

    def bad_read(va: int) -> int:
        raise ValueError("bad m-packet response")

    with pytest.raises(PredicateRuntimeError):
        ast.eval(blob, bad_read)


def test_eval_mem_rsp_error_wrapped():
    """Bug 2: RspError from the gdbstub layer must be wrapped."""
    from winbox.kdbg.debugger.rsp import RspError

    ast = parse("[rcx] == 0")
    blob = _blob(rcx=0x1000)

    def bad_read(va: int) -> int:
        raise RspError("E14")

    with pytest.raises(PredicateRuntimeError):
        ast.eval(blob, bad_read)


def test_eval_mem_plain_exception_wrapped():
    """Bug 2: any plain Exception must be wrapped, not leaked."""
    ast = parse("[rcx] == 0")
    blob = _blob(rcx=0x1000)

    def bad_read(va: int) -> int:
        raise Exception("anything weird")

    with pytest.raises(PredicateRuntimeError):
        ast.eval(blob, bad_read)


def test_eval_mem_predicate_runtime_error_not_double_wrapped():
    """Bug 2 corollary: if mem() already raises PredicateRuntimeError,
    the original message must reach the caller untouched."""
    ast = parse("[rcx] == 0")
    blob = _blob(rcx=0xdead)
    sentinel = "ORIGINAL_MARKER_42"

    def bad_read(va: int) -> int:
        raise PredicateRuntimeError(sentinel)

    with pytest.raises(PredicateRuntimeError) as exc_info:
        ast.eval(blob, bad_read)
    assert sentinel in str(exc_info.value)
    # And the wrapper text isn't there.
    assert "mem read at" not in str(exc_info.value)


def test_parse_recursion_depth_capped():
    """Bug 3: 65 nested parens used to RecursionError. Must surface as
    PredicateSyntaxError, never a RecursionError."""
    src = "(" * 65 + "rax" + ")" * 65
    with pytest.raises(PredicateSyntaxError):
        parse(src)


def test_parse_recursion_depth_extreme_input():
    """Bug 3: heavy adversarial nesting (600 parens) must also fail with
    PredicateSyntaxError, NOT RecursionError. This is the original
    attack vector."""
    src = "(" * 600 + "rax" + ")" * 600
    try:
        parse(src)
    except PredicateSyntaxError:
        pass
    except RecursionError:
        pytest.fail("RecursionError leaked — depth cap missing")


def test_parse_recursion_depth_at_limit_ok():
    """Sanity check: nesting at the cap should still parse."""
    src = "(" * 64 + "rax" + ")" * 64 + " == 1"
    # Should not raise.
    parse(src)


def test_parse_long_decimal_literal_rejected():
    """Bug 4: 5000-char decimal literal — Python 3.11+ would raise
    ValueError from int(); must be PredicateSyntaxError instead."""
    src = "rax == " + ("9" * 5000)
    with pytest.raises(PredicateSyntaxError):
        parse(src)


def test_parse_long_hex_literal_rejected():
    """Bug 4: 100-char hex literal must be a clean PredicateSyntaxError."""
    src = "rax == 0x" + ("f" * 100)
    with pytest.raises(PredicateSyntaxError):
        parse(src)


def test_parse_64bit_hex_literal_at_limit_ok():
    """Sanity: a max-width uint64 hex literal must still parse."""
    ast = parse("rax == 0xFFFFFFFFFFFFFFFF")
    assert ast.right.value == 0xFFFFFFFFFFFFFFFF


def test_parse_long_decimal_literal_does_not_leak_value_error():
    """Belt-and-suspenders: the wrapper must not leak ValueError."""
    src = "rax == " + ("1" * 6000)
    try:
        parse(src)
    except PredicateSyntaxError:
        pass
    except ValueError as e:
        # PredicateSyntaxError IS-A ValueError (subclass), so a bare
        # ValueError that's NOT the subclass means we leaked.
        if not isinstance(e, PredicateSyntaxError):
            pytest.fail(f"raw ValueError leaked: {e!r}")
