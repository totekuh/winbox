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


# ── KPTI dual-CR3 validation (H7) ───────────────────────────────────────


_PROC_TYPES = {
    "_EPROCESS": {
        "size": 0x800,
        "fields": {
            "ImageFileName": {"off": 0x5a8, "type": ""},
            "UniqueProcessId": {"off": 0x440, "type": ""},
            "ActiveProcessLinks": {"off": 0x448, "type": ""},
        },
    },
    "_KPROCESS": {
        "size": 0x300,
        "fields": {
            "DirectoryTableBase": {"off": 0x28, "type": ""},
            "UserDirectoryTableBase": {"off": 0x388, "type": ""},
        },
    },
}


def _list_proc_with_user_dtb(monkeypatch, raw_user_dtb_value: int):
    """Run list_processes against a single-process walk where the
    UserDirectoryTableBase field reads as ``raw_user_dtb_value``.
    Returns the resulting ProcessRecord."""
    from winbox.kdbg.walk import list_processes

    HEAD = 0xFFFFF800_00C26340
    EPROC = 0xFFFFE000_00100000
    DTB = 0x12345000

    apl_off = _PROC_TYPES["_EPROCESS"]["fields"]["ActiveProcessLinks"]["off"]
    pid_off = _PROC_TYPES["_EPROCESS"]["fields"]["UniqueProcessId"]["off"]
    img_off = _PROC_TYPES["_EPROCESS"]["fields"]["ImageFileName"]["off"]
    dtb_off = _PROC_TYPES["_KPROCESS"]["fields"]["DirectoryTableBase"]["off"]
    user_off = _PROC_TYPES["_KPROCESS"]["fields"]["UserDirectoryTableBase"]["off"]

    flink = EPROC + apl_off
    qwords = {
        HEAD: flink,            # head -> first entry's flink
        flink: HEAD,            # entry's flink -> head (single entry)
        EPROC + pid_off: 1234,
        EPROC + dtb_off: DTB,
        EPROC + user_off: raw_user_dtb_value,
    }

    monkeypatch.setattr("winbox.kdbg.walk._cpu_cr3", lambda vm: 0x999000)
    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: qwords[va])
    monkeypatch.setattr("winbox.kdbg.walk._read_cstr",
                        lambda vm, cr3, va, n, cache: "test.exe")

    class S:
        def resolve(self, name):
            return HEAD
        def struct(self, t, field=None, *, module="nt"):
            return _PROC_TYPES[t]

    procs = list_processes("vm", S())
    assert len(procs) == 1
    return procs[0]


def test_list_processes_accepts_valid_user_dtb(monkeypatch):
    """KPTI build with a well-formed second PML4 PA: page-aligned,
    non-zero, below 2^52. Walker preserves it."""
    p = _list_proc_with_user_dtb(monkeypatch, 0x6789a000)
    assert p.user_directory_table_base == 0x6789a000


def test_list_processes_rejects_unaligned_user_dtb(monkeypatch):
    """Stale store: the cached _KPROCESS offset points at an adjacent
    field, read returns a non-page-aligned value. Must be filtered to
    0 so the daemon's CR3 filter doesn't accept fires from random
    processes whose dtb happens to match the garbage."""
    p = _list_proc_with_user_dtb(monkeypatch, 0xdeadbeef00112233)
    assert p.user_directory_table_base == 0


def test_list_processes_rejects_user_dtb_above_phys_addr_cap(monkeypatch):
    """A value > 2^52 cannot be a real PA on x86-64 (architectural
    cap). Must be filtered to 0."""
    p = _list_proc_with_user_dtb(monkeypatch, 1 << 60)
    assert p.user_directory_table_base == 0


def test_list_processes_rejects_zero_user_dtb(monkeypatch):
    """Pre-KPTI builds and read failures yield 0 raw — must stay 0
    (sentinel meaning "no second CR3 known")."""
    p = _list_proc_with_user_dtb(monkeypatch, 0)
    assert p.user_directory_table_base == 0
