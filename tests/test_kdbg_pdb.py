"""Tests for the llvm-pdbutil text parser.

Uses hand-crafted fixture strings that mirror real llvm-pdbutil ``dump``
output — this keeps the tests hermetic (no real PDB required) while
still catching parser regressions when the output format drifts.
"""

from __future__ import annotations

from winbox.kdbg.pdb import (
    parse_publics,
    parse_section_headers,
    parse_types,
)


# ── Section headers ─────────────────────────────────────────────────────


SECTION_HEADERS_FIXTURE = """

                      Section Headers
============================================================

  SECTION HEADER #1
    .rdata name
     C73D0 virtual size
      1000 virtual address
     C8000 size of raw data
       1000 file pointer to raw data

  SECTION HEADER #2
    .pdata name
     6DEE4 virtual size
     C9000 virtual address
     6E000 size of raw data

  SECTION HEADER #3
    .idata name
      20FE virtual size
    137000 virtual address
      3000 size of raw data
"""


def test_parse_section_headers():
    sections = parse_section_headers(SECTION_HEADERS_FIXTURE)
    assert sections == {
        1: 0x1000,
        2: 0xC9000,
        3: 0x137000,
    }


# ── Publics ─────────────────────────────────────────────────────────────


PUBLICS_FIXTURE = """
                       Public Symbols
============================================================
  Records
       0 | S_PUB32 [size = 32] `ZwCreateTimer2`
           flags = function, addr = 0001:2180304
      32 | S_PUB32 [size = 32] `PsActiveProcessHead`
           flags = none, addr = 0002:156576
      64 | S_PUB32 [size = 32] `KiSystemCall64`
           flags = function, addr = 0001:2262912
"""


def test_parse_publics_uses_section_vas():
    sections = {1: 0x1000, 2: 0x2000}
    syms = parse_publics(PUBLICS_FIXTURE, sections)
    assert syms["ZwCreateTimer2"] == 0x1000 + 2180304
    assert syms["PsActiveProcessHead"] == 0x2000 + 156576
    assert syms["KiSystemCall64"] == 0x1000 + 2262912


def test_parse_publics_ignores_unknown_section():
    sections = {1: 0x1000}  # no section 2
    syms = parse_publics(PUBLICS_FIXTURE, sections)
    assert "ZwCreateTimer2" in syms
    assert "KiSystemCall64" in syms
    # PsActiveProcessHead references section 2 which we don't have — dropped.
    assert "PsActiveProcessHead" not in syms


def test_parse_publics_warns_on_dropped_unknown_section(capsys):
    """When a public references a section index we don't have, we drop
    it AND surface a stderr warning so the caller doesn't silently get
    a partial symbol table (truncated llvm-pdbutil output, corrupt
    PDB, etc.)."""
    sections = {1: 0x1000}  # no section 2 — PsActiveProcessHead drops
    syms = parse_publics(PUBLICS_FIXTURE, sections)
    captured = capsys.readouterr()
    assert "PsActiveProcessHead" not in syms
    assert "parse_publics dropped" in captured.err
    # Must include a count so the user can gauge severity.
    assert "1 symbol" in captured.err


def test_parse_publics_no_warning_when_nothing_dropped(capsys):
    """Healthy parse: every section is known → no spurious warning."""
    sections = {1: 0x1000, 2: 0x2000}
    parse_publics(PUBLICS_FIXTURE, sections)
    captured = capsys.readouterr()
    assert "dropped" not in captured.err


def test_parse_publics_counts_multiple_drops(capsys):
    """Drop counter aggregates across multiple unknown-section symbols."""
    text = """
       0 | S_PUB32 [size = 32] `Sym1`
           flags = none, addr = 0009:100
      32 | S_PUB32 [size = 32] `Sym2`
           flags = none, addr = 0009:200
      64 | S_PUB32 [size = 32] `Sym3`
           flags = none, addr = 0001:300
"""
    syms = parse_publics(text, {1: 0x1000})
    captured = capsys.readouterr()
    assert "Sym3" in syms
    assert "Sym1" not in syms and "Sym2" not in syms
    assert "2 symbol" in captured.err


def test_parse_publics_survives_name_without_addr():
    # llvm-pdbutil section offsets are decimal, so 256 -> RVA = 0x1100.
    text = """
       0 | S_PUB32 [size = 32] `OrphanName`
         flags = none
      32 | S_PUB32 [size = 32] `FollowUp`
           flags = function, addr = 0001:256
"""
    syms = parse_publics(text, {1: 0x1000})
    # OrphanName has no addr line — a second name should displace it so
    # that FollowUp still resolves correctly.
    assert syms["FollowUp"] == 0x1100
    assert "OrphanName" not in syms


# ── Types ───────────────────────────────────────────────────────────────


TYPES_FIXTURE = """
                     Types (TPI Stream)
============================================================
  Showing 6 records
   0x1000 | LF_STRUCTURE [size = 48] `_EPROCESS`
            unique name: `.?AU_EPROCESS@@`
            vtable: <no type>, base list: <no type>, field list: <no type>
            options: forward ref (-> 0x1003) | has unique name, sizeof 0
   0x1001 | LF_POINTER [size = 12]
            referent = 0x1000, mode = pointer, opts = None, kind = ptr64
   0x1002 | LF_FIELDLIST [size = 80]
            - LF_MEMBER [name = `Pcb`, Type = 0x0041, offset = 0, attrs = public]
            - LF_MEMBER [name = `UniqueProcessId`, Type = 0x0603 (void*), offset = 1088, attrs = public]
            - LF_MEMBER [name = `ActiveProcessLinks`, Type = 0x1057, offset = 1096, attrs = public]
            - LF_MEMBER [name = `ImageFileName`, Type = 0x1B4F, offset = 1448, attrs = public]
   0x1003 | LF_STRUCTURE [size = 48] `_EPROCESS`
            unique name: `.?AU_EPROCESS@@`
            vtable: <no type>, base list: <no type>, field list: 0x1002
            options: has unique name, sizeof 2944
   0x1004 | LF_FIELDLIST [size = 24]
            - LF_MEMBER [name = `DirectoryTableBase`, Type = 0x0023 (unsigned __int64), offset = 40, attrs = public]
   0x1005 | LF_STRUCTURE [size = 48] `_KPROCESS`
            unique name: `.?AU_KPROCESS@@`
            vtable: <no type>, base list: <no type>, field list: 0x1004
            options: has unique name, sizeof 1080
"""


def test_parse_types_resolves_real_layout_not_forward_ref():
    types = parse_types(TYPES_FIXTURE, ["_EPROCESS", "_KPROCESS"])
    eproc = types["_EPROCESS"]
    assert eproc.size == 2944
    assert eproc.fields["ActiveProcessLinks"].offset == 1096
    assert eproc.fields["UniqueProcessId"].offset == 1088
    assert eproc.fields["ImageFileName"].offset == 1448
    assert eproc.fields["UniqueProcessId"].type_hint == "void*"

    kproc = types["_KPROCESS"]
    assert kproc.size == 1080
    assert kproc.fields["DirectoryTableBase"].offset == 40
    assert kproc.fields["DirectoryTableBase"].type_hint == "unsigned __int64"


def test_parse_types_only_returns_wanted():
    types = parse_types(TYPES_FIXTURE, ["_EPROCESS"])
    assert "_EPROCESS" in types
    assert "_KPROCESS" not in types


def test_parse_types_skips_forward_refs_with_missing_fields():
    # A forward-ref-only struct (no populated entry) should simply be
    # absent, not raise.
    fixture = """
   0x1000 | LF_STRUCTURE [size = 48] `_ONLY_FWD`
            vtable: <no type>, base list: <no type>, field list: <no type>
            options: forward ref (-> 0x1001) | has unique name, sizeof 0
"""
    types = parse_types(fixture, ["_ONLY_FWD"])
    assert types == {}
