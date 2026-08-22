"""Unit tests for the user-mode module walker.

Stubs the kdbg.walk read primitives directly with a tiny address-keyed
backing store. Avoids building a full PML4/PDPT/PD/PT mock for what is
fundamentally a list-traversal test.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

import pytest

from winbox.kdbg import walk
from winbox.kdbg.walk import (
    ProcessRecord,
    UserModuleRecord,
    is_wow64,
    list_user_modules,
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
    assert sum(span.size for span in layout.spans) == 47
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

    with pytest.raises(walk.HmpError, match="exceeds struct size"):
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


# ── WoW64 detection ───────────────────────────────────────────────────


_WOW64_TYPES = {
    **_PROC_TYPES,
    "_PEB": {
        "size": 0x7C8,
        "fields": {
            "Ldr": {"off": 0x18, "type": ""},
            "Wow64Process": {"off": 0x2C0, "type": ""},
        },
    },
}


def test_is_wow64_true(monkeypatch):
    """Non-zero PEB.Wow64Process means WoW64."""
    target = ProcessRecord(
        pid=1234, name="wow32.exe", eprocess=0xFFFFE000_00100000,
        directory_table_base=0x12345000, user_directory_table_base=0,
    )
    PEB_OFF = 0x550
    PEB_VA = 0x7FFE_0000_0000
    WOW64_OFF = 0x2C0

    qwords = {
        target.eprocess + PEB_OFF: PEB_VA,
        PEB_VA + WOW64_OFF: 0x7FFE_0001_0000,  # non-zero = WoW64
    }

    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: qwords.get(va, 0))

    class S:
        def struct(self, t, field=None, *, module="nt"):
            types = {**_WOW64_TYPES}
            types["_EPROCESS"] = {
                "size": 0xB80,
                "fields": {**_PROC_TYPES["_EPROCESS"]["fields"], "Peb": {"off": PEB_OFF, "type": ""}},
            }
            return types[t]

    assert is_wow64("vm", S(), target) is True


def test_is_wow64_false(monkeypatch):
    """Zero PEB.Wow64Process means native 64-bit."""
    target = ProcessRecord(
        pid=1234, name="native64.exe", eprocess=0xFFFFE000_00100000,
        directory_table_base=0x12345000, user_directory_table_base=0,
    )
    PEB_OFF = 0x550
    PEB_VA = 0x7FFE_0000_0000

    qwords = {
        target.eprocess + PEB_OFF: PEB_VA,
    }

    monkeypatch.setattr("winbox.kdbg.walk._read_u64",
                        lambda vm, cr3, va, cache: qwords.get(va, 0))

    class S:
        def struct(self, t, field=None, *, module="nt"):
            types = {**_WOW64_TYPES}
            types["_EPROCESS"] = {
                "size": 0xB80,
                "fields": {**_PROC_TYPES["_EPROCESS"]["fields"], "Peb": {"off": PEB_OFF, "type": ""}},
            }
            return types[t]

    assert is_wow64("vm", S(), target) is False


def test_is_wow64_no_field(monkeypatch):
    """If _PEB has no Wow64Process field, return False (old Windows build)."""
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
