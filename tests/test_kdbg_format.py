"""Tests for winbox.kdbg.format — the shared sym/struct renderers.

Both the CLI and the MCP tool layer render symbol lookups and struct layouts
through these, so a formatting change silently alters two user-facing
surfaces at once. They are pure functions over a SymbolStore, which makes
them cheap to pin down exactly.
"""

from __future__ import annotations

from winbox.kdbg.format import format_struct, format_sym, symbolicate_va


class FakeStore:
    """Minimal SymbolStore stand-in covering only what the formatters call."""

    def __init__(self, *, base=0xFFFFF80084400000, hits=None, struct_info=None):
        self._base = base
        self._hits = hits or []
        self._struct = struct_info or {}
        self.calls: list[tuple] = []

    def parse_symbol(self, name):
        self.calls.append(("parse_symbol", name))
        if "!" in name:
            module, sym = name.split("!", 1)
            return module, sym
        return "nt", name

    def search(self, sym, *, module, limit):
        self.calls.append(("search", sym, module, limit))
        return self._hits[:limit]

    def load(self, module):
        self.calls.append(("load", module))
        return {"base": self._base}

    def resolve(self, name):
        self.calls.append(("resolve", name))
        return self._base + 0x1000

    def rva(self, name):
        self.calls.append(("rva", name))
        return 0x1000

    def struct(self, type_name, *, field=None, module="nt"):
        self.calls.append(("struct", type_name, field, module))
        return self._struct


class TestFormatSymExact:
    def test_resolves_to_an_absolute_va(self):
        store = FakeStore()
        assert format_sym(store, "nt!PsInitialSystemProcess") == [
            "nt!PsInitialSystemProcess 0xfffff80084401000"
        ]

    def test_rva_mode_prints_the_relative_offset(self):
        store = FakeStore()
        assert format_sym(store, "nt!Foo", rva=True) == ["nt!Foo 0x1000"]

    def test_rva_mode_does_not_resolve_an_absolute_address(self):
        """The two paths are distinct store calls; mixing them would report
        an RVA as though it were a VA."""
        store = FakeStore()
        format_sym(store, "nt!Foo", rva=True)
        assert ("rva", "nt!Foo") in store.calls
        assert not any(c[0] == "resolve" for c in store.calls)


class TestFormatSymSearch:
    def test_no_matches_returns_an_empty_list(self):
        """Empty means "no matches" — the caller decides if that's an error."""
        assert format_sym(FakeStore(hits=[]), "nt!Nope", search=True) == []

    def test_matches_are_rebased_onto_the_module_base(self):
        store = FakeStore(base=0x1000000, hits=[("Alpha", 0x10), ("Beta", 0x20)])
        assert format_sym(store, "nt!A", search=True) == [
            "nt!Alpha 0x1000010",
            "nt!Beta 0x1000020",
        ]

    def test_search_with_rva_skips_rebasing(self):
        store = FakeStore(base=0x1000000, hits=[("Alpha", 0x10)])
        assert format_sym(store, "nt!A", search=True, rva=True) == ["nt!Alpha 0x10"]

    def test_limit_is_passed_through_to_the_store(self):
        store = FakeStore(hits=[("A", 1), ("B", 2), ("C", 3)])
        result = format_sym(store, "nt!x", search=True, limit=2)
        assert len(result) == 2
        assert ("search", "x", "nt", 2) in store.calls

    def test_a_missing_base_is_treated_as_zero(self):
        """A module whose base never resolved must not crash the formatter."""
        store = FakeStore(hits=[("Alpha", 0x40)])
        store.load = lambda module: {"base": None}
        assert format_sym(store, "nt!A", search=True) == ["nt!Alpha 0x40"]

    def test_module_prefix_is_honored(self):
        store = FakeStore(base=0, hits=[("Zw", 0x8)])
        assert format_sym(store, "hal!Zw", search=True) == ["hal!Zw 0x8"]


class TestFormatStructField:
    def test_single_field_line(self):
        store = FakeStore(struct_info={"off": 0x440, "type": "void*"})
        assert format_struct(store, "_EPROCESS", "UniqueProcessId") == [
            "nt!_EPROCESS.UniqueProcessId off=0x440 type=void*"
        ]

    def test_missing_type_renders_empty_rather_than_none(self):
        store = FakeStore(struct_info={"off": 0x10})
        assert format_struct(store, "_X", "f") == ["nt!_X.f off=0x10 type="]

    def test_module_is_used_in_the_label_and_the_lookup(self):
        store = FakeStore(struct_info={"off": 0x4, "type": "int"})
        out = format_struct(store, "_Y", "f", module="hal")
        assert out == ["hal!_Y.f off=0x4 type=int"]
        assert ("struct", "_Y", "f", "hal") in store.calls


class TestFormatStructLayout:
    def test_fields_are_sorted_by_offset_not_by_name(self):
        store = FakeStore(struct_info={
            "size": 0x30,
            "fields": {
                "Zeta": {"off": 0x00, "type": "int"},
                "Alpha": {"off": 0x20, "type": "void*"},
                "Mid": {"off": 0x08, "type": "char"},
            },
        })
        out = format_struct(store, "_S")
        assert out[0] == "nt!_S size=0x30 (48)"
        assert out[1:] == [
            "  +0x0000  Zeta  int",
            "  +0x0008  Mid  char",
            "  +0x0020  Alpha  void*",
        ]

    def test_header_shows_size_in_hex_and_decimal(self):
        store = FakeStore(struct_info={"size": 0x100, "fields": {}})
        assert format_struct(store, "_S")[0] == "nt!_S size=0x100 (256)"

    def test_empty_struct_returns_only_the_header(self):
        assert len(format_struct(FakeStore(struct_info={"size": 0, "fields": {}}), "_S")) == 1

    def test_missing_size_defaults_to_zero(self):
        store = FakeStore(struct_info={"fields": {}})
        assert format_struct(store, "_S")[0] == "nt!_S size=0x0 (0)"

    def test_offsets_are_zero_padded_to_four_digits(self):
        """Fixed-width offsets keep the column readable for large structs."""
        store = FakeStore(struct_info={
            "size": 0x2000,
            "fields": {"Big": {"off": 0x1234, "type": "q"},
                       "Small": {"off": 0x2, "type": "b"}},
        })
        out = format_struct(store, "_S")
        assert "  +0x0002  Small  b" in out
        assert "  +0x1234  Big  q" in out


# ── symbolicate_va ─────────────────────────────────────────────────────


class SymStoreForVA:
    """SymbolStore stand-in for symbolicate_va tests."""

    def __init__(self, modules: dict):
        self._modules = modules

    def list_modules(self):
        return list(self._modules.keys())

    def load(self, name):
        return self._modules[name]


class TestSymbolicateVa:
    def test_resolves_kernel_va(self):
        store = SymStoreForVA({
            "nt": {
                "base": 0xfffff80608000000,
                "size_of_image": 0x1000000,
                "symbols": {"NtCreateFile": 0x80000, "NtClose": 0x80100},
            },
        })
        result = symbolicate_va(store, 0xfffff80608080050)
        assert result == "nt!NtCreateFile+0x50"
        result2 = symbolicate_va(store, 0xfffff80608080100)
        assert result2 == "nt!NtClose+0x0"

    def test_resolves_user_mode_va(self):
        store = SymStoreForVA({
            "nt": {
                "base": 0xfffff80608000000,
                "size_of_image": 0x1000000,
                "symbols": {"NtCreateFile": 0x80000},
            },
            "ntdll": {
                "base": 0x7ffa12340000,
                "size_of_image": 0x200000,
                "symbols": {"NtClose": 0x1000, "RtlInitUnicodeString": 0x2000},
            },
        })
        result = symbolicate_va(store, 0x7ffa12341500)
        assert result == "ntdll!NtClose+0x500"

    def test_returns_none_for_unmatched_va(self):
        store = SymStoreForVA({
            "nt": {
                "base": 0xfffff80608000000,
                "size_of_image": 0x1000000,
                "symbols": {"NtCreateFile": 0x80000},
            },
        })
        assert symbolicate_va(store, 0x12345678) is None

    def test_skips_module_with_no_base(self):
        store = SymStoreForVA({
            "nt": {"base": None, "size_of_image": 0x1000, "symbols": {"X": 0x10}},
        })
        assert symbolicate_va(store, 0x10) is None

    def test_empty_store(self):
        store = SymStoreForVA({})
        assert symbolicate_va(store, 0xfffff80608080000) is None

    def test_picks_closest_symbol(self):
        store = SymStoreForVA({
            "mod": {
                "base": 0x1000,
                "size_of_image": 0x5000,
                "symbols": {"A": 0x100, "B": 0x200, "C": 0x300},
            },
        })
        result = symbolicate_va(store, 0x1250)
        assert result == "mod!B+0x50"
