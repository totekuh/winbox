"""Unit tests for the user-mode module walker.

Stubs the kdbg.walk read primitives directly with a tiny address-keyed
backing store. Avoids building a full PML4/PDPT/PD/PT mock for what is
fundamentally a list-traversal test.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from winbox.kdbg import walk
from winbox.kdbg.store import SymbolStoreError
from winbox.kdbg.walk import (
    ProcessRecord,
    ThreadRecord,
    UserModuleRecord,
    is_wow64,
    list_current_vcpu_threads,
    list_threads,
    list_user_modules,
    resolve_thread_start_addresses,
    select_threads,
)


@pytest.fixture(autouse=True)
def _no_live_snapshot(monkeypatch):
    import winbox.kdbg.debugger.reader as reader
    monkeypatch.setattr(
        reader, "debug_snapshot_for_vm", lambda _vm: nullcontext(),
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


@pytest.fixture(autouse=True)
def clear_kernel_cr3_cache():
    walk._kernel_cr3_by_vm.clear()
    yield
    walk._kernel_cr3_by_vm.clear()


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
            "Pcb": {"off": 0, "type": ""},
            "ImageFileName": {"off": 0x5a8, "type": ""},
            "UniqueProcessId": {"off": 0x440, "type": ""},
            "ActiveProcessLinks": {"off": 0x448, "type": ""},
        },
    },
    "_KPROCESS": {
        "size": 0x400,
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
    flink = EPROC + apl_off
    qwords = {
        HEAD: flink,            # head -> first entry's flink
    }

    monkeypatch.setattr("winbox.kdbg.walk._cpu_cr3_candidates", lambda vm: [0x999000])
    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: qwords[va])

    class S:
        def resolve(self, name):
            return HEAD
        def struct(self, t, field=None, *, module="nt"):
            return _PROC_TYPES[t]

    layout = walk._process_layout(S())

    def read_span(vm, cr3, va, length, *, cache):
        raw = bytearray(length)
        def put(offset, size, value):
            start = EPROC + offset - va
            if 0 <= start and start + size <= length:
                raw[start:start + size] = value.to_bytes(size, "little")
        put(layout.active_links, 8, HEAD)
        put(layout.pid, 8, 1234)
        put(layout.dtb, 8, DTB)
        put(layout.user_dtb, 8, raw_user_dtb_value)
        start = EPROC + layout.image_name - va
        if 0 <= start and start + 8 <= length:
            raw[start:start + 8] = b"test.exe"
        return bytes(raw)

    monkeypatch.setattr(walk, "read_virt_cr3", read_span)

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


def test_process_entry_coalesces_adjacent_fields_without_sparse_overread(monkeypatch):
    """PID/Flink share a read; distant fields remain compact spans."""
    eprocess = 0xFFFFE000_00100000
    next_flink = 0xFFFFE000_00200448

    class S:
        def struct(self, type_name, field=None, *, module="nt"):
            return _PROC_TYPES[type_name]

    layout = walk._process_layout(S())
    calls = []

    def read_span(vm, cr3, va, length, *, cache):
        calls.append((vm, cr3, va, length, cache))
        raw = bytearray(length)

        def put(offset, size, value):
            start = eprocess + offset - va
            if 0 <= start and start + size <= length:
                raw[start:start + size] = value.to_bytes(size, "little")

        put(layout.active_links, 8, next_flink)
        put(layout.pid, 8, 4242)
        put(layout.dtb, 8, 0x12345000)
        put(layout.user_dtb, 8, 0x12344000)
        name_start = eprocess + layout.image_name - va
        if 0 <= name_start and name_start + 15 <= length:
            raw[name_start:name_start + 15] = b"worker.exe\x00\x00\x00\x00\x00"
        return bytes(raw)

    monkeypatch.setattr(walk, "read_virt_cr3", read_span)
    cache = walk.WalkCache()
    record, flink = walk._read_process_entry(
        "vm", 0x999000, eprocess, layout, cache,
    )

    assert calls == [
        ("vm", 0x999000, eprocess + span.start, span.size, cache)
        for span in layout.spans
    ]
    assert len(calls) == 4
    assert sum(span.size for span in layout.spans) == 55
    assert any(
        span.start <= layout.pid
        and layout.active_links + 8 <= span.start + span.size
        for span in layout.spans
    )
    assert record == ProcessRecord(
        pid=4242,
        name="worker.exe",
        eprocess=eprocess,
        directory_table_base=0x12345000,
        user_directory_table_base=0x12344000,
    )
    assert flink == next_flink


def test_process_layout_rejects_out_of_bounds_symbol_offset():
    types = {
        **_PROC_TYPES,
        "_EPROCESS": {
            **_PROC_TYPES["_EPROCESS"],
            "fields": {
                **_PROC_TYPES["_EPROCESS"]["fields"],
                "ImageFileName": {"off": 0x900, "type": ""},
            },
        },
    }

    class S:
        def struct(self, type_name, field=None, *, module="nt"):
            return types[type_name]

    with pytest.raises(SymbolStoreError, match="invalid _EPROCESS.ImageFileName span"):
        walk._process_layout(S())


def test_process_layout_supports_pre_kpti_without_user_dtb():
    types = {
        **_PROC_TYPES,
        "_KPROCESS": {
            **_PROC_TYPES["_KPROCESS"],
            "fields": {
                "DirectoryTableBase": {"off": 0x28, "type": ""},
            },
        },
    }

    class S:
        def struct(self, type_name, field=None, *, module="nt"):
            return types[type_name]

    layout = walk._process_layout(S())
    assert layout.user_dtb is None
    assert len(layout.spans) == 3


def test_process_entry_preserves_create_and_exit_identity_fields(monkeypatch):
    types = {
        **_PROC_TYPES,
        "_EPROCESS": {
            **_PROC_TYPES["_EPROCESS"],
            "fields": {
                **_PROC_TYPES["_EPROCESS"]["fields"],
                "CreateTime": {"off": 0x468, "type": ""},
                "ExitTime": {"off": 0x840 - 0x48, "type": ""},
            },
            "size": 0x900,
        },
    }

    class S:
        def struct(self, type_name, field=None, *, module="nt"):
            return types[type_name]

    layout = walk._process_layout(S())
    eprocess = 0xFFFFE00000100000
    values = {
        layout.active_links: 0xFFFFF80000C26340,
        layout.pid: 4242,
        layout.dtb: 0x12345000,
        layout.user_dtb: 0x12344000,
        layout.create_time: 0x112233445566,
        layout.exit_time: 0x778899,
    }

    def read_span(_vm, _cr3, va, length, *, cache):
        raw = bytearray(length)
        for offset, value in values.items():
            start = eprocess + offset - va
            if 0 <= start and start + 8 <= length:
                raw[start:start + 8] = value.to_bytes(8, "little")
        name_start = eprocess + layout.image_name - va
        if 0 <= name_start and name_start + 8 <= length:
            raw[name_start:name_start + 8] = b"live.exe"
        return bytes(raw)

    monkeypatch.setattr(walk, "read_virt_cr3", read_span)
    record, _ = walk._read_process_entry(
        "vm", 0x999000, eprocess, layout, walk.WalkCache(),
    )
    assert record.create_time == 0x112233445566
    assert record.exit_time == 0x778899


def test_process_entry_rejects_short_coalesced_read(monkeypatch):
    class S:
        def struct(self, type_name, field=None, *, module="nt"):
            return _PROC_TYPES[type_name]

    layout = walk._process_layout(S())
    monkeypatch.setattr(
        walk,
        "read_virt_cr3",
        lambda vm, cr3, va, length, *, cache: b"\x00" * (length - 1),
    )
    with pytest.raises(walk.HmpError, match="short EPROCESS read"):
        walk._read_process_entry(
            "vm", 0x999000, 0xFFFFE000_00100000, layout, walk.WalkCache(),
        )


def test_find_process_stops_reading_immediately_after_match(monkeypatch):
    """The lookup must not touch later EPROCESS records once PID matches."""
    from winbox.kdbg.walk import find_process

    head = 0xFFFFF800_00C26340
    apl_off = _PROC_TYPES["_EPROCESS"]["fields"]["ActiveProcessLinks"]["off"]
    system = 0xFFFFE000_00100000
    target = 0xFFFFE000_00200000
    tail = 0xFFFFE000_00300000
    reads = []

    class S:
        def resolve(self, name):
            return head
        def struct(self, type_name, field=None, *, module="nt"):
            return _PROC_TYPES[type_name]

    monkeypatch.setattr(walk, "_cpu_cr3_candidates", lambda vm: [0x999000])
    monkeypatch.setattr(
        walk, "_read_u64",
        lambda vm, cr3, va, cache: system + apl_off,
    )

    def read_entry(vm, cr3, eprocess, layout, cache):
        reads.append(eprocess)
        if eprocess == system:
            return ProcessRecord(4, "System", system, 0x1AE000, 0), target + apl_off
        if eprocess == target:
            return ProcessRecord(828, "lsass.exe", target, 0x172643000, 0), tail + apl_off
        pytest.fail("early-exit lookup read past the matching process")

    monkeypatch.setattr(walk, "_read_process_entry", read_entry)
    result = find_process("vm", S(), pid=828)

    assert result is not None and result.name == "lsass.exe"
    assert reads == [system, target]
    assert walk._cached_kernel_cr3("vm") == 0x1AE000


def test_cpu_cr3_comes_from_active_rsp_snapshot(monkeypatch):
    from winbox.kdbg.walk import _cpu_cr3
    from types import SimpleNamespace

    snapshot = SimpleNamespace(current_cr3=0x1AA000)
    monkeypatch.setattr(walk, "current_snapshot", lambda vm: snapshot)
    assert _cpu_cr3("winbox") == 0x1AA000


def test_cpu_cr3_requires_active_rsp_snapshot(monkeypatch):
    from winbox.kdbg.hmp import HmpError
    from winbox.kdbg.walk import _cpu_cr3

    monkeypatch.setattr(walk, "current_snapshot", lambda vm: None)
    with pytest.raises(HmpError, match="no active RSP snapshot"):
        _cpu_cr3("winbox")


def test_cpu_cr3_candidates_reads_every_vcpu_and_deduplicates(monkeypatch):
    from types import SimpleNamespace
    snapshot = SimpleNamespace(cr3_candidates=(0x100000, 0x200000))
    monkeypatch.setattr(walk, "current_snapshot", lambda vm: snapshot)
    assert walk._cpu_cr3_candidates("vm") == [0x100000, 0x200000]


def test_cached_kernel_cr3_avoids_volatile_vcpu_sampling(monkeypatch):
    head = 0xFFFFF800_00100000
    stable = 0x1AE000
    walk._remember_kernel_cr3("vm", stable)
    monkeypatch.setattr(
        walk, "_cpu_cr3_candidates",
        lambda vm: pytest.fail("cached fast path must not sample vCPU CR3"),
    )
    monkeypatch.setattr(
        walk, "_read_u64",
        lambda vm, cr3, va, cache: 0xFFFFE000_DEADBEE8 if cr3 == stable else 0,
    )
    cr3, flink, _ = walk._read_kernel_list_head("vm", head, None)
    assert (cr3, flink) == (stable, 0xFFFFE000_DEADBEE8)


def test_stale_cached_cr3_is_invalidated_then_all_vcpus_are_tried(monkeypatch):
    from winbox.kdbg.memory import PageWalkError

    head = 0xFFFFF800_00100000
    stale = 0x1AE000
    working_user_half = 0x880000
    working_kernel_half = working_user_half ^ 0x1000
    walk._remember_kernel_cr3("vm", stale)
    monkeypatch.setattr(
        walk, "_cpu_cr3_candidates", lambda vm: [0x770000, working_user_half]
    )
    attempted = []

    def read(vm, cr3, va, cache):
        attempted.append(cr3)
        if cr3 == working_kernel_half:
            return 0xFFFFE000_00001238
        raise PageWalkError(f"0x{cr3:x} does not map head")

    monkeypatch.setattr(walk, "_read_u64", read)
    cr3, flink, _ = walk._read_kernel_list_head("vm", head, None)
    assert (cr3, flink) == (working_kernel_half, 0xFFFFE000_00001238)
    assert attempted == [
        stale, stale ^ 0x1000,
        0x770000, 0x770000 ^ 0x1000,
        working_user_half, working_kernel_half,
    ]
    assert walk._cached_kernel_cr3("vm") is None


def test_reboot_poison_pointer_is_rejected_as_a_cr3_candidate(monkeypatch):
    head = 0xFFFFF800_00100000
    poisoned = 0x1AE000
    working = 0x2BE000
    walk._remember_kernel_cr3("vm", poisoned)
    monkeypatch.setattr(walk, "_cpu_cr3_candidates", lambda vm: [working])

    def read(vm, cr3, va, cache):
        if cr3 in (poisoned, poisoned ^ 0x1000):
            return 0x000FAFAFAFAFA0B0
        return 0xFFFFE000_00100448

    monkeypatch.setattr(walk, "_read_u64", read)
    cr3, flink, _ = walk._read_kernel_list_head("vm", head, None)
    assert (cr3, flink) == (working, 0xFFFFE000_00100448)
    assert walk._cached_kernel_cr3("vm") is None


def test_impossible_empty_kernel_list_is_rejected(monkeypatch):
    head = 0xFFFFF800_00100000
    stale = 0x1AE000
    working = 0x2BE000
    walk._remember_kernel_cr3("vm", stale)
    monkeypatch.setattr(walk, "_cpu_cr3_candidates", lambda vm: [working])
    monkeypatch.setattr(
        walk, "_read_u64",
        lambda vm, cr3, va, cache: (
            head if cr3 in (stale, stale ^ 0x1000) else 0xFFFFE000_00100448
        ),
    )
    cr3, _, _ = walk._read_kernel_list_head("vm", head, None)
    assert cr3 == working


def test_explicit_cr3_ignores_cache_and_live_vcpus(monkeypatch):
    head = 0xFFFFF800_00100000
    walk._remember_kernel_cr3("vm", 0x1AE000)
    monkeypatch.setattr(
        walk, "_cpu_cr3_candidates",
        lambda vm: pytest.fail("explicit CR3 must not sample vCPUs"),
    )
    seen = []

    def read(vm, cr3, va, cache):
        seen.append(cr3)
        return 0xFFFFE000_00004320

    monkeypatch.setattr(walk, "_read_u64", read)
    cr3, flink, _ = walk._read_kernel_list_head("vm", head, 0x990000)
    assert (cr3, flink) == (0x990000, 0xFFFFE000_00004320)
    assert seen == [0x990000]
    assert walk._cached_kernel_cr3("vm") == 0x1AE000


def test_kernel_cr3_cache_is_scoped_per_vm():
    walk._remember_kernel_cr3("vm-a", 0x100000)
    walk._remember_kernel_cr3("vm-b", 0x200000)
    walk._forget_kernel_cr3("vm-a", 0x100000)
    assert walk._cached_kernel_cr3("vm-a") is None
    assert walk._cached_kernel_cr3("vm-b") == 0x200000


def test_find_process_matches_name_longer_than_15_chars(monkeypatch):
    """EPROCESS.ImageFileName is a 15-byte kernel field, so a real name like
    'SecurityHealthService.exe' arrives truncated to 15 chars. find_process
    must still match it (against the 15-char prefix) instead of never matching."""
    from winbox.kdbg.walk import find_process

    truncated = "SecurityHealth"[:15] + "S"  # 15 chars, as the kernel stores it
    rec = ProcessRecord(
        pid=1234, name=truncated, eprocess=0x1000,
        directory_table_base=0x2000, user_directory_table_base=0,
    )
    monkeypatch.setattr(walk, "_iter_processes", lambda *a, **k: iter([rec]))

    assert find_process("winbox", None, name="SecurityHealthService.exe") is rec
    # A different long name that truncates differently must NOT match.
    assert find_process("winbox", None, name="NotepadPlusPlusReally.exe") is None


# ── KPTI stabilization ────────────────────────────────────────────────


def test_list_processes_switches_to_system_dtb(monkeypatch):
    """After reading System (PID 4), the walker should switch to its DTB
    for subsequent reads — stabilizes the walk against KPTI CR3 races."""
    from winbox.kdbg.walk import list_processes

    HEAD = 0xFFFFF800_00C26340
    SYSTEM = 0xFFFFE000_00100000
    PROC2 = 0xFFFFE000_00200000
    SYS_DTB = 0x1ae000
    CPU_CR3 = 0x999000  # different from SYS_DTB

    apl_off = _PROC_TYPES["_EPROCESS"]["fields"]["ActiveProcessLinks"]["off"]
    sys_flink = SYSTEM + apl_off
    p2_flink = PROC2 + apl_off
    qwords = {
        HEAD: sys_flink,
    }

    cr3s_used = []

    def tracking_read_u64(vm, cr3, va, cache):
        cr3s_used.append(cr3)
        return qwords[va]

    monkeypatch.setattr("winbox.kdbg.walk._cpu_cr3_candidates", lambda vm: [CPU_CR3])
    monkeypatch.setattr("winbox.kdbg.walk._read_u64", tracking_read_u64)

    def read_entry(vm, cr3, eproc, layout, cache):
        cr3s_used.append(cr3)
        if eproc == SYSTEM:
            return ProcessRecord(4, "System", SYSTEM, SYS_DTB, 0), p2_flink
        assert eproc == PROC2
        return ProcessRecord(1234, "proc2.exe", PROC2, 0x5678000, 0), HEAD

    monkeypatch.setattr(walk, "_read_process_entry", read_entry)

    class S:
        def resolve(self, name):
            return HEAD
        def struct(self, t, field=None, *, module="nt"):
            return _PROC_TYPES[t]

    procs = list_processes("vm", S())
    assert len(procs) == 2
    assert procs[0].pid == 4
    assert procs[1].pid == 1234
    assert walk._cached_kernel_cr3("vm") == SYS_DTB

    # First reads use CPU_CR3, reads after System should use SYS_DTB
    first_read_cr3 = cr3s_used[0]
    assert first_read_cr3 == CPU_CR3
    # After System is read, subsequent reads must use SYS_DTB
    last_read_cr3 = cr3s_used[-1]
    assert last_read_cr3 == SYS_DTB


def test_list_processes_no_switch_when_system_dtb_matches(monkeypatch):
    """If System's DTB matches the current CR3, no switch needed."""
    from winbox.kdbg.walk import list_processes

    HEAD = 0xFFFFF800_00C26340
    SYSTEM = 0xFFFFE000_00100000
    DTB = 0x1ae000

    apl_off = _PROC_TYPES["_EPROCESS"]["fields"]["ActiveProcessLinks"]["off"]
    sys_flink = SYSTEM + apl_off
    qwords = {
        HEAD: sys_flink,
    }

    cr3s_used = []

    def tracking_read_u64(vm, cr3, va, cache):
        cr3s_used.append(cr3)
        return qwords[va]

    monkeypatch.setattr("winbox.kdbg.walk._cpu_cr3_candidates", lambda vm: [DTB])
    monkeypatch.setattr("winbox.kdbg.walk._read_u64", tracking_read_u64)
    monkeypatch.setattr(
        walk,
        "_read_process_entry",
        lambda vm, cr3, eproc, layout, cache: (
            ProcessRecord(4, "System", SYSTEM, DTB, 0), HEAD,
        ),
    )

    class S:
        def resolve(self, name):
            return HEAD
        def struct(self, t, field=None, *, module="nt"):
            return _PROC_TYPES[t]

    procs = list_processes("vm", S())
    assert len(procs) == 1
    # All reads should use the same CR3
    assert all(c == DTB for c in cr3s_used)
    assert walk._cached_kernel_cr3("vm") == DTB


# ── Per-process ETHREAD list ───────────────────────────────────────────


_THREAD_TYPES = {
    "_EPROCESS": {
        "size": 0x800,
        "fields": {
            "Pcb": {"off": 0, "type": ""},
            "ThreadListHead": {"off": 0x380, "type": ""},
        },
    },
    "_ETHREAD": {
        "size": 0x700,
        "fields": {
            "Tcb": {"off": 0, "type": ""},
            "ThreadListEntry": {"off": 0x580, "type": ""},
            "Cid": {"off": 0x500, "type": ""},
            "StartAddress": {"off": 0x4E0, "type": ""},
            "Win32StartAddress": {"off": 0x560, "type": ""},
            "CreateTime": {"off": 0x4C0, "type": ""},
            "ExitStatus": {"off": 0x5D8, "type": ""},
        },
    },
    "_KTHREAD": {
        "size": 0x480,
        "fields": {
            "State": {"off": 0x184, "type": ""},
            "WaitReason": {"off": 0x283, "type": ""},
            "Priority": {"off": 0xC3, "type": ""},
            "BasePriority": {"off": 0x233, "type": ""},
            "ContextSwitches": {"off": 0x154, "type": ""},
            "Teb": {"off": 0xF0, "type": ""},
            "KernelStack": {"off": 0x58, "type": ""},
            "StackLimit": {"off": 0x30, "type": ""},
            "StackBase": {"off": 0x38, "type": ""},
            "Process": {"off": 0x220, "type": ""},
        },
    },
}


class _ThreadStore(FakeStore):
    def resolve(self, name):
        assert name == "PsActiveProcessHead"
        return 0xFFFFF800_00C26340


def _thread_store() -> _ThreadStore:
    return _ThreadStore(_THREAD_TYPES)


def _thread_target() -> ProcessRecord:
    return ProcessRecord(
        pid=4712,
        name="target.exe",
        eprocess=0xFFFFE001_00100000,
        directory_table_base=0x12345000,
        create_time=0x1122334455667788,
    )


def _thread_backing(monkeypatch, target: ProcessRecord):
    """Install a byte-addressed ETHREAD fake and return a record builder."""
    layout = walk._thread_layout(_thread_store())
    memory: dict[int, int] = {}
    qwords: dict[int, int] = {}
    calls = []
    head = target.eprocess + layout.thread_list_head
    qwords[head + 8] = head
    last_link = head

    def put(addr: int, size: int, value: int, *, signed: bool = False):
        raw = value.to_bytes(size, "little", signed=signed)
        memory.update(dict(zip(range(addr, addr + size), raw)))

    def read_span(vm, cr3, va, length, *, cache):
        calls.append((vm, cr3, va, length, cache))
        return bytes(memory.get(va + i, 0) for i in range(length))

    monkeypatch.setattr(walk, "read_virt_cr3", read_span)
    monkeypatch.setattr(
        walk, "_read_kernel_list_head",
        lambda *_args: (0x1AE000, 0xFFFFE001_00000000, walk.WalkCache()),
    )
    monkeypatch.setattr(
        walk, "_read_u64",
        lambda _vm, _cr3, va, _cache: qwords[va],
    )

    def add(
        ethread: int,
        next_flink: int,
        tid: int,
        *,
        blink: int | None = None,
        client_pid: int | None = None,
        owner: int | None = None,
        state: int = 5,
        wait_reason: int = 6,
    ) -> None:
        nonlocal last_link
        fields = layout.fields
        put(ethread + fields["thread_list_entry"].offset, 8, next_flink)
        link = ethread + fields["thread_list_entry"].offset
        put(link + 8, 8, last_link if blink is None else blink)
        put(ethread + fields["cid"].offset, 8, target.pid if client_pid is None else client_pid)
        put(ethread + fields["cid"].offset + 8, 8, tid)
        put(ethread + fields["process"].offset, 8, target.eprocess if owner is None else owner)
        put(ethread + fields["state"].offset, 1, state)
        put(ethread + fields["wait_reason"].offset, 1, wait_reason)
        put(ethread + fields["priority"].offset, 1, 13, signed=True)
        put(ethread + fields["base_priority"].offset, 1, 8, signed=True)
        put(ethread + fields["context_switches"].offset, 4, 927)
        put(ethread + fields["teb"].offset, 8, 0x00000000_7FFDE000)
        put(ethread + fields["kernel_stack"].offset, 8, 0xFFFFF800_01234000)
        put(ethread + fields["stack_limit"].offset, 8, 0xFFFFF800_01230000)
        put(ethread + fields["stack_base"].offset, 8, 0xFFFFF800_01238000)
        put(ethread + fields["start_address"].offset, 8, 0xFFFFF800_10001000)
        put(ethread + fields["win32_start_address"].offset, 8, 0x00007FF7_40001000)
        put(ethread + fields["create_time"].offset, 8, 0x0102030405060708)
        put(ethread + fields["exit_status"].offset, 4, 259, signed=True)
        if next_flink == head:
            qwords[head + 8] = link
        last_link = link

    return layout, qwords, add, calls


def test_list_threads_walks_validated_ethread_ring(monkeypatch):
    target = _thread_target()
    layout, qwords, add, calls = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    first = 0xFFFFE001_00200000
    second = 0xFFFFE001_00300000
    qwords[head] = first + layout.thread_list_entry
    add(first, second + layout.thread_list_entry, 4816)
    add(second, head, 4820, state=1, wait_reason=0xFE)

    result = list_threads("vm", _thread_store(), target)

    assert result.complete is True
    assert result.truncated_reason is None
    assert result.threads == [
        ThreadRecord(
            tid=4816, ethread=first, state=5, state_name="Waiting",
            wait_reason=6, wait_reason_name="UserRequest", priority=13,
            base_priority=8, context_switches=927, teb=0x7FFDE000,
            kernel_stack=0xFFFFF80001234000, stack_limit=0xFFFFF80001230000,
            stack_base=0xFFFFF80001238000, start_address=0xFFFFF80010001000,
            win32_start_address=0x7FF740001000, create_time=0x0102030405060708,
            exit_status=259,
        ),
        ThreadRecord(
            tid=4820, ethread=second, state=1, state_name="Ready",
            wait_reason=0xFE, wait_reason_name=None, priority=13,
            base_priority=8, context_switches=927, teb=0x7FFDE000,
            kernel_stack=0xFFFFF80001234000, stack_limit=0xFFFFF80001230000,
            stack_base=0xFFFFF80001238000, start_address=0xFFFFF80010001000,
            win32_start_address=0x7FF740001000, create_time=0x0102030405060708,
            exit_status=259,
        ),
    ]
    # Each ETHREAD is read in bounded, coalesced exact-PDB spans through the
    # separately verified kernel CR3; no target DTB guessing is involved.
    assert {call[1] for call in calls} == {0x1AE000}
    assert len(calls) == len(layout.spans) * 2


def test_list_threads_reports_cycle_without_claiming_complete(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    ethread = 0xFFFFE001_00200000
    node = ethread + layout.thread_list_entry
    qwords[head] = node
    add(ethread, node, 4816)

    result = list_threads("vm", _thread_store(), target)

    assert [thread.tid for thread in result.threads] == [4816]
    assert result.complete is False
    assert result.truncated_reason == f"cycle detected at ETHREAD list entry 0x{node:x}"


def test_list_threads_rejects_foreign_client_pid_before_returning_it(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    ethread = 0xFFFFE001_00200000
    qwords[head] = ethread + layout.thread_list_entry
    add(ethread, head, 4816, client_pid=9001)

    result = list_threads("vm", _thread_store(), target)

    assert result.threads == []
    assert result.complete is False
    assert "belongs to pid 9001, expected 4712" in result.truncated_reason


def test_list_threads_rejects_foreign_kthread_owner_before_returning_it(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    ethread = 0xFFFFE001_00200000
    qwords[head] = ethread + layout.thread_list_entry
    add(ethread, head, 4816, owner=0xFFFFE001_00400000)

    result = list_threads("vm", _thread_store(), target)

    assert result.threads == []
    assert result.complete is False
    assert "KTHREAD.Process=0xffffe00100400000" in result.truncated_reason


def test_list_threads_reports_cap_as_partial_result(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    first = 0xFFFFE001_00200000
    second = 0xFFFFE001_00300000
    qwords[head] = first + layout.thread_list_entry
    add(first, second + layout.thread_list_entry, 4816)
    add(second, head, 4820)
    monkeypatch.setattr(walk, "MAX_THREADS_PER_PROCESS", 1)

    result = list_threads("vm", _thread_store(), target)

    assert [thread.tid for thread in result.threads] == [4816]
    assert result.complete is False
    assert result.truncated_reason == "hit thread cap=1"
    assert result.truncation is not None
    assert result.truncation.public() == {
        "stage": "cap",
        "link": f"0x{second + layout.thread_list_entry:016x}",
        "ethread": None,
        "returned": 1,
        "reason": "hit thread cap=1",
    }


def test_thread_layout_refuses_nonzero_eprocess_pcb():
    types = {
        name: {**value, "fields": dict(value["fields"])}
        for name, value in _THREAD_TYPES.items()
    }
    types["_EPROCESS"]["fields"]["Pcb"] = {"off": 0x10, "type": ""}
    with pytest.raises(SymbolStoreError, match="EPROCESS.Pcb offset"):
        walk._thread_layout(_ThreadStore(types))


def test_thread_layout_rejects_boolean_or_type_width_corruption():
    boolean_types = {
        name: {**value, "fields": dict(value["fields"])}
        for name, value in _THREAD_TYPES.items()
    }
    boolean_types["_ETHREAD"]["fields"]["Cid"] = {"off": True, "type": ""}
    with pytest.raises(SymbolStoreError, match="invalid _ETHREAD.Cid.off"):
        walk._thread_layout(_ThreadStore(boolean_types))

    width_types = {
        name: {**value, "fields": dict(value["fields"])}
        for name, value in _THREAD_TYPES.items()
    }
    width_types["_KTHREAD"]["fields"]["State"] = {
        "off": 0x184, "type": "unsigned long",
    }
    with pytest.raises(SymbolStoreError, match="KTHREAD.State declares 4 bytes"):
        walk._thread_layout(_ThreadStore(width_types))


def test_walk_layout_refuses_non_x64_symbol_store():
    class X86Store(_ThreadStore):
        def load(self, name):
            assert name == "nt"
            return {"architecture": "x86"}

    with pytest.raises(SymbolStoreError, match="unsupported nt symbol-store architecture"):
        walk._thread_layout(X86Store(_THREAD_TYPES))


def _wait_layout_for_test() -> walk._WaitLayout:
    thread = walk._thread_layout(_thread_store())
    return walk._WaitLayout(
        thread=thread,
        wait_block_list=walk._ThreadField("WaitBlockList", 0xD0, 8),
        embedded_wait_block=0x140,
        wait_block_thread=walk._ThreadField("Thread", 0x18, 8),
        wait_block_object=walk._ThreadField("Object", 0x20, 8),
        dispatcher_type=walk._ThreadField("Type", 0, 1),
        mutant_owner_thread=walk._ThreadField("OwnerThread", 0x28, 8),
    )


def _install_wait_reads(monkeypatch, values: dict[int, tuple[int, int]]) -> None:
    """Install exact-width byte reads keyed by address for wait tests."""
    def read(_vm, _cr3, address, length, *, cache):
        value, width = values[address]
        assert width == length
        return value.to_bytes(width, "little")
    monkeypatch.setattr(walk, "read_virt_cr3", read)
    monkeypatch.setattr(
        walk, "_read_kernel_list_head",
        lambda *_args: (0x1AE000, 0xFFFFE001_00000000, walk.WalkCache()),
    )


def test_wait_object_evidence_returns_only_proven_mutant_owner_chain(monkeypatch):
    target = _thread_target()
    thread = ThreadRecord(
        tid=4816, ethread=0xFFFFE001_00200000, state=5, state_name="Waiting",
        wait_reason=29, wait_reason_name="WrMutex", priority=8, base_priority=8,
        context_switches=1, teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
        start_address=0, win32_start_address=0, create_time=1, exit_status=259,
    )
    owner = 0xFFFFE001_00300000
    mutant = 0xFFFFE001_00400000
    layout = _wait_layout_for_test()
    monkeypatch.setattr(walk, "_wait_layout", lambda _store: layout)
    values = {
        thread.ethread + 0xD0: (thread.ethread + 0x140, 8),
        thread.ethread + 0x140 + 0x18: (thread.ethread, 8),
        thread.ethread + 0x140 + 0x20: (mutant, 8),
        mutant: (2, 1),
        mutant + 0x28: (owner, 8),
        owner + layout.thread.fields["cid"].offset: ((7212 << 64) | 4, 16),
        owner + layout.thread.fields["process"].offset: (0xFFFFE001_00500000, 8),
        owner + layout.thread.fields["state"].offset: (1, 1),
    }
    _install_wait_reads(monkeypatch, values)

    result = walk.resolve_thread_wait_objects("vm", _thread_store(), target, [thread])

    assert result["scope"]["waiting_threads"] == 1
    evidence = result["records"][thread.ethread]
    assert evidence["complete"] is True
    assert evidence["object"] == {
        "address": f"0x{mutant:016x}",
        "dispatcher_type": {"raw": 2, "name": "mutant"},
    }
    assert evidence["owner_chain"][0]["pid"] == 4
    assert evidence["owner_chain"][0]["tid"] == 7212
    assert evidence["reason"] == "owner is not waiting"


def test_wait_object_evidence_refuses_external_blocks_and_owner_cycles(monkeypatch):
    target = _thread_target()
    thread = ThreadRecord(
        tid=4816, ethread=0xFFFFE001_00200000, state=5, state_name="Waiting",
        wait_reason=29, wait_reason_name="WrMutex", priority=8, base_priority=8,
        context_switches=1, teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
        start_address=0, win32_start_address=0, create_time=1, exit_status=259,
    )
    layout = _wait_layout_for_test()
    monkeypatch.setattr(walk, "_wait_layout", lambda _store: layout)
    _install_wait_reads(monkeypatch, {
        thread.ethread + 0xD0: (0xFFFFE001_00BAD000, 8),
    })
    external = walk.resolve_thread_wait_objects("vm", _thread_store(), target, [thread])
    assert external["records"][thread.ethread]["complete"] is False
    assert "external/multi-object" in external["records"][thread.ethread]["reason"]

    mutant = 0xFFFFE001_00400000
    _install_wait_reads(monkeypatch, {
        thread.ethread + 0xD0: (thread.ethread + 0x140, 8),
        thread.ethread + 0x140 + 0x18: (thread.ethread, 8),
        thread.ethread + 0x140 + 0x20: (mutant, 8),
        mutant: (2, 1),
        mutant + 0x28: (thread.ethread, 8),
    })
    cycle = walk.resolve_thread_wait_objects("vm", _thread_store(), target, [thread])
    assert cycle["records"][thread.ethread]["complete"] is False
    assert cycle["records"][thread.ethread]["reason"] == "owner chain cycle detected"


def test_list_threads_rejects_bad_blink_with_exact_failed_entry(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    ethread = 0xFFFFE001_00200000
    link = ethread + layout.thread_list_entry
    qwords[head] = link
    add(ethread, head, 4816, blink=0xFFFFE001_00BAD000)

    result = list_threads("vm", _thread_store(), target)

    assert result.threads == []
    assert result.complete is False
    assert result.truncation is not None
    assert result.truncation.stage == "entry"
    assert result.truncation.link == link
    assert result.truncation.ethread == ethread
    assert "Blink" in result.truncated_reason


def test_list_threads_rejects_bad_head_blink(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    ethread = 0xFFFFE001_00200000
    qwords[head] = ethread + layout.thread_list_entry
    add(ethread, head, 4816)
    qwords[head + 8] = 0xFFFFE001_00BAD000

    result = list_threads("vm", _thread_store(), target)

    assert [thread.tid for thread in result.threads] == [4816]
    assert result.complete is False
    assert result.truncation is not None
    assert result.truncation.stage == "head"
    assert result.truncation.link == head
    assert "ThreadListHead Blink" in result.truncated_reason


def test_list_threads_rejects_duplicate_live_tids(monkeypatch):
    target = _thread_target()
    layout, qwords, add, _ = _thread_backing(monkeypatch, target)
    head = target.eprocess + layout.thread_list_head
    first = 0xFFFFE001_00200000
    second = 0xFFFFE001_00300000
    qwords[head] = first + layout.thread_list_entry
    add(first, second + layout.thread_list_entry, 4816)
    add(second, head, 4816)

    result = list_threads("vm", _thread_store(), target)

    assert [thread.tid for thread in result.threads] == [4816]
    assert result.complete is False
    assert result.truncation is not None
    assert result.truncation.stage == "identity"
    assert result.truncation.ethread == second
    assert "duplicate live ETHREAD client thread id 4816" == result.truncated_reason


def test_list_threads_accepts_empty_ring(monkeypatch):
    target = _thread_target()
    layout, qwords, _, _ = _thread_backing(monkeypatch, target)
    qwords[target.eprocess + layout.thread_list_head] = target.eprocess + layout.thread_list_head

    result = list_threads("vm", _thread_store(), target)

    assert result == walk.ThreadWalkResult([], True)


def test_select_threads_separates_complete_walk_from_output_limit():
    threads = [
        ThreadRecord(
            tid=1, ethread=0xFFFFE001_00100000, state=5, state_name="Waiting",
            wait_reason=6, wait_reason_name="UserRequest", priority=8,
            base_priority=8, context_switches=5, teb=0, kernel_stack=0,
            stack_limit=0, stack_base=0, start_address=0x1000,
            win32_start_address=0, create_time=1, exit_status=259,
        ),
        ThreadRecord(
            tid=2, ethread=0xFFFFE001_00200000, state=1, state_name="Ready",
            wait_reason=6, wait_reason_name=None, priority=12,
            base_priority=8, context_switches=20, teb=0, kernel_stack=0,
            stack_limit=0, stack_base=0, start_address=0x2000,
            win32_start_address=0, create_time=2, exit_status=259,
        ),
        ThreadRecord(
            tid=3, ethread=0xFFFFE001_00300000, state=5, state_name="Waiting",
            wait_reason=6, wait_reason_name="UserRequest", priority=9,
            base_priority=8, context_switches=30, teb=0, kernel_stack=0,
            stack_limit=0, stack_base=0, start_address=0x3000,
            win32_start_address=0, create_time=3, exit_status=259,
        ),
    ]

    selected = select_threads(
        threads, state="Waiting", wait_reason="UserRequest",
        sort="context-switches", limit=1,
    )

    assert [thread.tid for thread in selected.threads] == [3]
    assert selected.total_count == 3
    assert selected.matched_count == 2
    assert selected.filtered_out == 1
    assert selected.output_truncated is True
    assert selected.state_counts == {"Waiting": 2, "Ready": 1}
    assert selected.wait_reason_counts == {"UserRequest": 2}


def test_select_threads_rejects_invalid_filter_and_limit():
    with pytest.raises(walk.ThreadFilterError, match="invalid state"):
        select_threads([], state="hallucinating")
    with pytest.raises(walk.ThreadFilterError, match="between 1 and 1024"):
        select_threads([], limit=0)


def test_resolve_thread_start_addresses_uses_live_module_bases_and_local_symbols(monkeypatch):
    target = _thread_target()
    thread = ThreadRecord(
        tid=4816, ethread=0xFFFFE001_00200000, state=5, state_name="Waiting",
        wait_reason=6, wait_reason_name="UserRequest", priority=13,
        base_priority=8, context_switches=927, teb=0, kernel_stack=0,
        stack_limit=0, stack_base=0, start_address=0xFFFFF800_10001234,
        win32_start_address=0x00007FF7_40002222, create_time=1, exit_status=259,
    )
    kernel = walk.ModuleRecord(
        name="ntoskrnl.exe", base=0xFFFFF800_10000000, size=0x4000,
        entry=0xFFFFE001_01000000,
    )
    user = UserModuleRecord(
        name="target.exe", base=0x00007FF7_40000000, size=0x4000,
        full_path="C:\\target.exe", entry=0x7FF70000,
    )

    class SymbolFake:
        def list_modules(self):
            return ["nt", "target"]

        def load(self, name):
            return {
                "symbols": (
                    {"PspSystemThreadStartup": 0x1000}
                    if name == "nt" else {"ThreadMain": 0x2000}
                ),
            }

    monkeypatch.setattr(walk, "list_modules", lambda *_a, **_k: [kernel])
    monkeypatch.setattr(walk, "list_user_modules", lambda *_a, **_k: [user])

    resolved, warnings = resolve_thread_start_addresses(
        "vm", SymbolFake(), target, [thread], cache=walk.WalkCache(),
    )

    assert warnings == ()
    start = resolved[thread.ethread].start_address
    assert (start.mapping, start.module, start.rva, start.symbol, start.symbol_offset) == (
        "kernel_module", "ntoskrnl.exe", 0x1234, "PspSystemThreadStartup", 0x234,
    )
    win32 = resolved[thread.ethread].win32_start_address
    assert (win32.mapping, win32.module, win32.rva, win32.symbol) == (
        "user_module", "target.exe", 0x2222, "ThreadMain",
    )


def test_resolve_thread_start_addresses_does_not_guess_private_or_jit(monkeypatch):
    target = _thread_target()
    thread = ThreadRecord(
        tid=4816, ethread=0xFFFFE001_00200000, state=1, state_name="Ready",
        wait_reason=0, wait_reason_name=None, priority=8, base_priority=8,
        context_switches=0, teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
        start_address=0x00007FF7_50000000, win32_start_address=0, create_time=1,
        exit_status=259,
    )
    monkeypatch.setattr(walk, "list_modules", lambda *_a, **_k: [])
    monkeypatch.setattr(walk, "list_user_modules", lambda *_a, **_k: [])

    resolved, warnings = resolve_thread_start_addresses(
        "vm", FakeStore(_THREAD_TYPES), target, [thread], cache=walk.WalkCache(),
    )

    assert any("VAD enrichment unavailable" in warning for warning in warnings)
    assert resolved[thread.ethread].start_address.mapping == "user_not_in_loader_module"
    assert resolved[thread.ethread].start_address.vad == {"status": "not_checked"}
    assert resolved[thread.ethread].win32_start_address.mapping == "null"


def test_resolve_thread_start_addresses_adds_validated_vad_without_rewriting_loader_lead(monkeypatch):
    target = _thread_target()
    thread = ThreadRecord(
        tid=4816, ethread=0xFFFFE001_00200000, state=1, state_name="Ready",
        wait_reason=0, wait_reason_name=None, priority=8, base_priority=8,
        context_switches=0, teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
        start_address=0x00007FF7_50000000, win32_start_address=0, create_time=1,
        exit_status=259,
    )
    monkeypatch.setattr(walk, "list_modules", lambda *_a, **_k: [])
    monkeypatch.setattr(walk, "list_user_modules", lambda *_a, **_k: [])
    import winbox.kdbg.vad as vad

    record = SimpleNamespace(public=lambda: {
        "start": "0x00007ff750000000", "end": "0x00007ff75000ffff",
        "kind": "private", "provenance": {"layout": "exact_nt_pdb"},
    })
    monkeypatch.setattr(
        vad, "lookup_addresses",
        lambda _vm, _store, _target, addresses, **_kw: {address: record for address in addresses},
    )

    resolved, warnings = resolve_thread_start_addresses(
        "vm", FakeStore(_THREAD_TYPES), target, [thread], cache=walk.WalkCache(),
    )

    value = resolved[thread.ethread].start_address
    assert warnings == ()
    assert value.mapping == "user_not_in_loader_module"
    assert value.vad == {"status": "mapped", "record": record.public()}


def test_list_current_vcpu_threads_validates_kpcr_prcb_and_ethread(monkeypatch):
    target = _thread_target()
    ethread = 0xFFFFE001_00200000
    kpcr = 0xFFFFF780_00000000
    prcb = 0xFFFFF780_00000100
    owner = target.eprocess
    idle_kpcr = 0xFFFFF780_00001000
    idle_prcb = 0xFFFFF780_00001100
    idle_ethread = 0xFFFFE001_00400000
    idle_owner = 0xFFFFE001_00000000
    listed = ThreadRecord(
        tid=4816, ethread=ethread, state=2, state_name="Running",
        wait_reason=0, wait_reason_name=None, priority=13, base_priority=8,
        context_switches=927, teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
        start_address=0, win32_start_address=0, create_time=1, exit_status=259,
    )
    thread_layout = SimpleNamespace(fields={
        "process": walk._ThreadField("Process", 0x220, 8),
        "cid": walk._ThreadField("Cid", 0x500, 16),
    })
    current_layout = walk._CurrentVcpuLayout(
        kpcr_self=walk._ThreadField("Self", 0x18, 8),
        kpcr_current_prcb=walk._ThreadField("CurrentPrcb", 0x20, 8),
        kprcb_current_thread=walk._ThreadField("CurrentThread", 0x8, 8),
    )
    values = {
        kpcr + 0x18: kpcr,
        kpcr + 0x20: prcb,
        prcb + 0x8: ethread,
        ethread + 0x220: owner,
        idle_kpcr + 0x18: idle_kpcr,
        idle_kpcr + 0x20: idle_prcb,
        idle_prcb + 0x8: idle_ethread,
        idle_ethread + 0x220: idle_owner,
    }
    monkeypatch.setattr(
        walk, "current_snapshot",
        lambda _vm: SimpleNamespace(
            vcpu_kernel_gs_bases=((0, (0xDEAD, kpcr)), (1, (0xBEEF,)), (2, (idle_kpcr,))),
        ),
    )
    monkeypatch.setattr(walk, "_current_vcpu_layout", lambda _store: current_layout)
    monkeypatch.setattr(walk, "_thread_layout", lambda _store: thread_layout)
    monkeypatch.setattr(walk, "_process_layout", lambda _store: object())
    monkeypatch.setattr(walk, "_read_kernel_list_head", lambda *_args: (0x1AE000, 0, walk.WalkCache()))
    monkeypatch.setattr(walk, "_read_u64", lambda _vm, _cr3, va, _cache: values[va])
    monkeypatch.setattr(
        walk, "_read_process_entry",
        lambda _vm, _cr3, eprocess, _layout, _cache: (
            ProcessRecord(
                pid=0 if eprocess == idle_owner else target.pid,
                name="Idle" if eprocess == idle_owner else target.name,
                eprocess=eprocess, directory_table_base=0x1AE000,
            ),
            0,
        ),
    )
    def fake_cid(_vm, _cr3, va, length, *, cache):
        assert length == 16
        if va == ethread + 0x500:
            return target.pid.to_bytes(8, "little") + listed.tid.to_bytes(8, "little")
        if va == idle_ethread + 0x500:
            return b"\x00" * 16
        return b""
    monkeypatch.setattr(
        walk, "read_virt_cr3",
        fake_cid,
    )

    current = list_current_vcpu_threads(
        "vm", _thread_store(), target, threads=[listed], cache=walk.WalkCache(),
    )

    assert current[0].status == "current"
    assert (current[0].vcpu, current[0].ethread, current[0].tid, current[0].in_target_process) == (
        0, ethread, 4816, True,
    )
    assert current[1].status == "unavailable"
    assert "invalid KPCR candidate" in current[1].reason
    assert (current[2].status, current[2].pid, current[2].tid, current[2].process_name) == (
        "idle", 0, 0, "Idle",
    )


# ── WoW64 detection ───────────────────────────────────────────────────


_WOW64_TYPES = {
    **_PROC_TYPES,
    "_EWOW64PROCESS": {
        "size": 0x10,
        "fields": {"Peb": {"off": 0, "type": ""}},
    },
}


def test_is_wow64_true(monkeypatch):
    """EPROCESS.WoW64Process -> EWOW64PROCESS.Peb means WoW64."""
    target = ProcessRecord(
        pid=1234, name="wow32.exe", eprocess=0xFFFFE000_00100000,
        directory_table_base=0x12345000, user_directory_table_base=0,
    )
    WOW64_OFF = 0x580
    WOW64_PROCESS = 0xFFFFE000_00200000
    PEB32 = 0x7FFE0000

    qwords = {
        target.eprocess + WOW64_OFF: WOW64_PROCESS,
        WOW64_PROCESS: PEB32,
    }

    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: qwords.get(va, 0))

    class S:
        def struct(self, t, field=None, *, module="nt"):
            types = {**_WOW64_TYPES}
            types["_EPROCESS"] = {
                "size": 0xB80,
                "fields": {**_PROC_TYPES["_EPROCESS"]["fields"], "WoW64Process": {"off": WOW64_OFF, "type": ""}},
            }
            return types[t]

    assert is_wow64("vm", S(), target) is True


def test_is_wow64_false(monkeypatch):
    """Zero EPROCESS.WoW64Process means native 64-bit."""
    target = ProcessRecord(
        pid=1234, name="native64.exe", eprocess=0xFFFFE000_00100000,
        directory_table_base=0x12345000, user_directory_table_base=0,
    )
    WOW64_OFF = 0x580

    qwords = {
        target.eprocess + WOW64_OFF: 0,
    }

    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: qwords.get(va, 0))

    class S:
        def struct(self, t, field=None, *, module="nt"):
            types = {**_WOW64_TYPES}
            types["_EPROCESS"] = {
                "size": 0xB80,
                "fields": {**_PROC_TYPES["_EPROCESS"]["fields"], "WoW64Process": {"off": WOW64_OFF, "type": ""}},
            }
            return types[t]

    assert is_wow64("vm", S(), target) is False


def test_is_wow64_no_field(monkeypatch):
    """If EPROCESS has no WoW64Process field, detection is safely false."""
    target = ProcessRecord(
        pid=1234, name="old.exe", eprocess=0xFFFFE000_00100000,
        directory_table_base=0x12345000, user_directory_table_base=0,
    )

    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: 0x7FFE_0000_0000)

    class S:
        def struct(self, t, field=None, *, module="nt"):
            types = {**_PROC_TYPES}
            types["_EPROCESS"] = {
                "size": 0xB80,
                "fields": {**_PROC_TYPES["_EPROCESS"]["fields"], "Peb": {"off": 0x550, "type": ""}},
            }
            types["_PEB"] = {"size": 0x100, "fields": {"Ldr": {"off": 0x18, "type": ""}}}
            return types[t]

    assert is_wow64("vm", S(), target) is False


def test_wow64_module_walk_returns_x86_loader_view(monkeypatch):
    target = _proc()
    native_peb = 0x7FF700000000
    native_ldr = 0x7FF700001000
    native_head = native_ldr + 0x10
    wow_process = 0xFFFFE00100200000
    peb32 = 0x7FFDF000
    ldr32 = 0x77001000
    head32 = ldr32 + 0x0C
    entry32 = 0x77002000
    types = {
        **_TYPES,
        "_EPROCESS": {"size": 0x800, "fields": {
            "Peb": {"off": 0x550, "type": ""},
            "WoW64Process": {"off": 0x580, "type": ""},
        }},
        "_EWOW64PROCESS": {"size": 8, "fields": {"Peb": {"off": 0, "type": ""}}},
    }
    store = FakeStore(types)
    qwords = {
        target.eprocess + 0x550: native_peb,
        native_peb + 0x18: native_ldr,
        native_head: native_head,
        target.eprocess + 0x580: wow_process,
        wow_process: peb32,
    }
    dwords = {
        peb32 + 0x0C: ldr32,
        head32: entry32,
        entry32: head32,
        entry32 + 0x18: 0x400000,
        entry32 + 0x20: 0x12000,
    }
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords=dwords, strings={}))
    monkeypatch.setattr(
        walk, "_read_unicode_string32",
        lambda vm, cr3, va, cache: {
            entry32 + 0x24: "C:\\Windows\\SysWOW64\\legacy.exe",
            entry32 + 0x2C: "legacy.exe",
        }[va],
    )

    mods = list_user_modules("vm", store, target)
    assert mods == [UserModuleRecord(
        "legacy.exe", 0x400000, 0x12000,
        "C:\\Windows\\SysWOW64\\legacy.exe", entry32, "x86",
    )]


def test_wow64_duplicate_main_exe_prefers_x86_record(monkeypatch):
    """Native PEB compatibility entry must not masquerade as an x64 EXE."""
    target = _proc()
    peb = 0x7FF700000000
    ldr = 0x7FF700001000
    head = ldr + 0x10
    entry = 0x7FF700002000
    qwords = {
        target.eprocess + 0x550: peb,
        peb + 0x18: ldr,
        head: entry,
        entry: head,
        entry + 0x30: 0x7C0000,
    }
    dwords = {entry + 0x40: 0x5D000}
    strings = {
        entry + 0x58: "cmd.exe",
        entry + 0x48: r"C:\Windows\SysWOW64\cmd.exe",
    }
    _stub_reads(monkeypatch, _Backing(qwords=qwords, dwords=dwords, strings=strings))
    x86 = UserModuleRecord(
        "cmd.exe", 0x7C0000, 0x5D000, r"C:\Windows\SysWOW64\cmd.exe",
        0x77002000, "x86",
    )
    monkeypatch.setattr(walk, "_list_wow64_modules", lambda *a, **k: [x86])
    mods = list_user_modules("vm", store=FakeStore(_TYPES), target=target)
    assert mods == [x86]


def test_wow64_rejects_peb_above_32bit(monkeypatch):
    target = _proc()
    store = FakeStore({
        "_EPROCESS": {"fields": {"WoW64Process": {"off": 0x580}}},
        "_EWOW64PROCESS": {"fields": {"Peb": {"off": 0}}},
    })
    values = {
        target.eprocess + 0x580: 0xFFFFE00100200000,
        0xFFFFE00100200000: 0x1_00000000,
    }
    monkeypatch.setattr(walk, "_read_u64", lambda vm, cr3, va, cache: values[va])
    assert is_wow64("vm", store, target) is False
