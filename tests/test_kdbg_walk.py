"""Unit tests for the user-mode module walker.

Stubs the kdbg.walk read primitives directly with a tiny address-keyed
backing store. Avoids building a full PML4/PDPT/PD/PT mock for what is
fundamentally a list-traversal test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from winbox.kdbg import walk
from winbox.kdbg.walk import (
    ProcessRecord,
    UserModuleRecord,
    list_user_modules,
)


# ── Fakes ───────────────────────────────────────────────────────────────


class FakeStore:
    """In-memory SymbolStore stand-in with only the layouts the walker needs."""

    def __init__(self, types: dict[str, dict[str, Any]]) -> None:
        self._types = types

    def struct(self, type_name: str, field=None, *, module: str = "nt"):
        return self._types[type_name]


@dataclass
class _Backing:
    qwords: dict[int, int]
    dwords: dict[int, int]
    strings: dict[int, str]


def _stub_reads(monkeypatch, backing: _Backing) -> None:
    """Monkey-patch walk's typed-read shims to read from the backing store."""

    def fake_u64(vm_name, cr3, va, cache):
        if va not in backing.qwords:
            raise AssertionError(f"unexpected u64 read at 0x{va:x}")
        return backing.qwords[va]

    def fake_u32(vm_name, cr3, va, cache):
        if va not in backing.dwords:
            raise AssertionError(f"unexpected u32 read at 0x{va:x}")
        return backing.dwords[va]

    def fake_unicode(vm_name, cr3, va, store, cache):
        # The walker passes the offset of a UNICODE_STRING; we key the
        # backing store by that VA directly so tests don't have to model
        # the Length/Buffer indirection.
        if va not in backing.strings:
            raise AssertionError(f"unexpected unicode read at 0x{va:x}")
        return backing.strings[va]

    monkeypatch.setattr(walk, "_read_u64", fake_u64)
    monkeypatch.setattr(walk, "_read_u32", fake_u32)
    monkeypatch.setattr(walk, "_read_unicode_string", fake_unicode)


# Shared offsets across tests — chosen to look like real Windows layout
# but small enough to read in a stack trace.
_TYPES = {
    "_EPROCESS": {"size": 0x800, "fields": {"Peb": {"off": 0x550, "type": ""}}},
    "_PEB": {"size": 0x800, "fields": {"Ldr": {"off": 0x18, "type": ""}}},
    "_PEB_LDR_DATA": {
        "size": 0x100,
        "fields": {"InLoadOrderModuleList": {"off": 0x10, "type": ""}},
    },
    "_LDR_DATA_TABLE_ENTRY": {
        "size": 0x110,
        "fields": {
            "InLoadOrderLinks": {"off": 0x00, "type": ""},
            "DllBase": {"off": 0x30, "type": ""},
            "SizeOfImage": {"off": 0x40, "type": ""},
            "BaseDllName": {"off": 0x58, "type": ""},
            "FullDllName": {"off": 0x48, "type": ""},
        },
    },
    "_UNICODE_STRING": {
        "size": 0x10,
        "fields": {"Length": {"off": 0, "type": ""}, "Buffer": {"off": 8, "type": ""}},
    },
}


@pytest.fixture
def store() -> FakeStore:
    return FakeStore(_TYPES)


def _proc(eproc: int = 0xFFFFE001_00100000, dtb: int = 0x12345000) -> ProcessRecord:
    return ProcessRecord(pid=4712, name="notepad.exe", eprocess=eproc, directory_table_base=dtb)


# ── Tests ───────────────────────────────────────────────────────────────


def test_list_user_modules_returns_each_loaded_module(monkeypatch, store):
    target = _proc()
    peb_va = 0x7FF7_AAAA_0000
    ldr_va = 0x7FF7_BBBB_0000
    head = ldr_va + 0x10  # InLoadOrderModuleList offset
    e1 = 0x7FF7_CCCC_0000  # first LDR_DATA_TABLE_ENTRY
    e2 = 0x7FF7_DDDD_0000

    qwords = {
        target.eprocess + 0x550: peb_va,            # EPROCESS.Peb
        peb_va + 0x18: ldr_va,                      # PEB.Ldr
        head: e1,                                   # head.Flink -> e1.InLoadOrderLinks
        e1: e2,                                     # e1.InLoadOrderLinks.Flink -> e2
        e2: head,                                   # e2.InLoadOrderLinks.Flink -> head (closes ring)
        e1 + 0x30: 0x7FF7_1000_0000,                # e1.DllBase
        e2 + 0x30: 0x7FF8_2000_0000,                # e2.DllBase
    }
    dwords = {
        e1 + 0x40: 0x10000,                         # e1.SizeOfImage
        e2 + 0x40: 0x200000,                        # e2.SizeOfImage
    }
    strings = {
        e1 + 0x58: "notepad.exe",
        e2 + 0x58: "ntdll.dll",
        e1 + 0x48: "C:\\Windows\\System32\\notepad.exe",
        e2 + 0x48: "C:\\Windows\\System32\\ntdll.dll",
    }
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords=dwords, strings=strings))

    mods = list_user_modules("vm", store, target)
    assert len(mods) == 2
    assert mods[0] == UserModuleRecord(
        name="notepad.exe", base=0x7FF7_1000_0000, size=0x10000,
        full_path="C:\\Windows\\System32\\notepad.exe", entry=e1,
    )
    assert mods[1].name == "ntdll.dll"
    assert mods[1].base == 0x7FF8_2000_0000


def test_list_user_modules_zero_peb_returns_empty(monkeypatch, store):
    """Kernel-only processes (System, Registry) have EPROCESS.Peb == 0."""
    target = _proc()
    qwords = {target.eprocess + 0x550: 0}
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords={}, strings={}))
    assert list_user_modules("vm", store, target) == []


def test_list_user_modules_zero_ldr_returns_empty(monkeypatch, store):
    """Mid-tear-down processes can have PEB.Ldr == 0 transiently."""
    target = _proc()
    peb_va = 0x7FF7_AAAA_0000
    qwords = {
        target.eprocess + 0x550: peb_va,
        peb_va + 0x18: 0,
    }
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords={}, strings={}))
    assert list_user_modules("vm", store, target) == []


def test_list_user_modules_skips_zero_base_entries(monkeypatch, store):
    """Unloaded modules linger in PEB.Ldr with DllBase=0 — skip them."""
    target = _proc()
    peb_va = 0x7FF7_AAAA_0000
    ldr_va = 0x7FF7_BBBB_0000
    head = ldr_va + 0x10
    e1 = 0x7FF7_CCCC_0000
    e2 = 0x7FF7_DDDD_0000

    qwords = {
        target.eprocess + 0x550: peb_va,
        peb_va + 0x18: ldr_va,
        head: e1,
        e1: e2,
        e2: head,
        e1 + 0x30: 0,                               # zero base — should be skipped
        e2 + 0x30: 0x7FF8_2000_0000,
    }
    dwords = {e1 + 0x40: 0, e2 + 0x40: 0x1000}
    strings = {
        e1 + 0x58: "stale.dll", e1 + 0x48: "",
        e2 + 0x58: "real.dll",  e2 + 0x48: "C:\\real.dll",
    }
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords=dwords, strings=strings))

    mods = list_user_modules("vm", store, target)
    assert [m.name for m in mods] == ["real.dll"]


def test_list_user_modules_breaks_on_cycle(monkeypatch, store):
    """Corrupt list with self-link must not infinite-loop."""
    target = _proc()
    peb_va = 0x7FF7_AAAA_0000
    ldr_va = 0x7FF7_BBBB_0000
    head = ldr_va + 0x10
    e1 = 0x7FF7_CCCC_0000

    qwords = {
        target.eprocess + 0x550: peb_va,
        peb_va + 0x18: ldr_va,
        head: e1,
        e1: e1,                                     # cycle: e1.Flink -> e1
        e1 + 0x30: 0x7FF7_1000_0000,
    }
    dwords = {e1 + 0x40: 0x10000}
    strings = {e1 + 0x58: "loop.dll", e1 + 0x48: "C:\\loop.dll"}
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords=dwords, strings=strings))

    mods = list_user_modules("vm", store, target)
    # First entry consumed once, then cycle detected and walk stops.
    assert len(mods) == 1
    assert mods[0].name == "loop.dll"


def test_list_user_modules_missing_struct_in_store_raises(monkeypatch):
    """If the cached symbol store predates the PEB structs and the caller
    forgot to call ensure_types_loaded, we want a clear KeyError-style
    failure, not a silent empty list."""
    target = _proc()
    incomplete = FakeStore({
        # Only EPROCESS — _PEB and friends absent.
        "_EPROCESS": {"size": 0x800, "fields": {"Peb": {"off": 0x550, "type": ""}}},
    })
    # No reads should happen; the failure is at struct lookup time.
    with pytest.raises(KeyError):
        list_user_modules("vm", incomplete, target)
