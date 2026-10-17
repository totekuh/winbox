"""Tests for the memory helpers and retained x86 page translator.

We never touch a real VM — an in-memory DebugSnapshot stands in for the
persistent RSP reader.
"""

from __future__ import annotations

from contextlib import nullcontext

import pytest

from winbox.kdbg import memory
from winbox.kdbg.hmp import parse_idt, parse_registers
from winbox.kdbg.memory import (
    WalkCache,
    parse_hex_dump,
    read_phys,
    read_virt_cr3,
    virt_to_phys,
)


# ── parse_hex_dump ──────────────────────────────────────────────────────


def test_parse_hex_dump_one_line():
    text = "0000000000123000: 0x48 0x89 0x5c 0x24\n"
    assert parse_hex_dump(text) == b"\x48\x89\x5c\x24"


def test_parse_hex_dump_multiple_lines():
    text = (
        "0000000000123000: 0x01 0x02 0x03 0x04\n"
        "0000000000123004: 0x05 0x06 0x07 0x08\n"
    )
    assert parse_hex_dump(text) == b"\x01\x02\x03\x04\x05\x06\x07\x08"


def test_parse_hex_dump_skips_unrecognized_lines():
    text = (
        "-- prompt noise --\n"
        "0000000000123000: 0xff 0xee\n"
        "ERROR: something\n"
    )
    assert parse_hex_dump(text) == b"\xff\xee"


# ── Registers / IDT parsing ─────────────────────────────────────────────


INFO_REG_FIXTURE = """\
CPU#0
RAX=0000000000000000 RBX=0000000000000001 RCX=0000000000000002
RIP=fffff80559c1251f RFL=00040282 [--S----] CPL=0
CS =0010 0000000000000000 ffffffff 00a09b00
GS =002b fffff80558e2e000 ffffffff 00c0f300
IDT=     fffff80558f1a000 00000fff
CR0=80050033 CR2=0000000000ff1000 CR3=00000000001ae000 CR4=00350ef8
EFER=0000000000004d01
"""


def test_parse_registers_picks_standard_ones():
    regs = parse_registers(INFO_REG_FIXTURE)
    assert regs["RAX"] == 0
    assert regs["RIP"] == 0xFFFFF80559C1251F
    assert regs["CR3"] == 0x1AE000


def test_parse_idt_returns_base_and_limit():
    base, limit = parse_idt(INFO_REG_FIXTURE)
    assert base == 0xFFFFF80558F1A000
    assert limit == 0xFFF


# ── Fake HMP backing for page-walker tests ──────────────────────────────


class FakeMemory:
    """Minimal physical RAM plus RSP-snapshot adapter."""

    def __init__(self) -> None:
        self.ram: dict[int, int] = {}
        self.vm_name = "vm"
        self.current_cr3 = 0x200000
        self.cr3_candidates = (self.current_cr3,)
        self.kernel_gs_bases = ()
        self.virtual_reads: list[tuple[int, int, int]] = []

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.ram[addr + i] = b

    def write_qword(self, addr: int, value: int) -> None:
        self.write_bytes(addr, value.to_bytes(8, "little"))

    def read_physical(self, addr: int, length: int) -> bytes:
        return bytes(self.ram.get(addr + offset, 0) for offset in range(length))

    def read_virtual(self, cr3: int, addr: int, length: int) -> bytes:
        self.virtual_reads.append((cr3, addr, length))
        out = bytearray()
        cursor = addr
        remaining = length
        cache = WalkCache()
        while remaining:
            take = min(remaining, 0x1000 - (cursor & 0xFFF))
            pa = virt_to_phys("vm", cr3, cursor, cache=cache)
            out += self.read_physical(pa, take)
            cursor += take
            remaining -= take
        return bytes(out)


@pytest.fixture
def fake_mem(monkeypatch):
    mem = FakeMemory()
    import winbox.kdbg.debugger.reader as reader
    monkeypatch.setattr(memory, "current_snapshot", lambda _vm=None: mem)
    monkeypatch.setattr(
        reader, "debug_snapshot_for_vm", lambda _vm: nullcontext(mem),
    )
    return mem


def test_read_phys_returns_expected_bytes(fake_mem):
    fake_mem.write_bytes(0x1000, b"\xde\xad\xbe\xef")
    assert read_phys("vm", 0x1000, 4) == b"\xde\xad\xbe\xef"


def test_read_phys_chunks_larger_than_chunk_size(fake_mem):
    payload = bytes(range(256)) * 8  # 2 KiB
    fake_mem.write_bytes(0x5000, payload)
    assert read_phys("vm", 0x5000, len(payload), chunk=512) == payload


# ── Page walker happy path ──────────────────────────────────────────────


def _populate_4k_mapping(mem: FakeMemory, cr3: int, va: int, page_phys: int) -> None:
    """Build PML4/PDPT/PD/PT entries mapping ``va`` -> ``page_phys``.

    Uses disjoint pages for each table so we don't accidentally overlap.
    """
    pml4_pa = cr3 & ~0xFFF
    pdpt_pa = 0x100000
    pd_pa   = 0x101000
    pt_pa   = 0x102000

    def pte_index(va, level):
        return (va >> (12 + 9 * (level - 1))) & 0x1FF

    present = 1 << 0
    mem.write_qword(pml4_pa + pte_index(va, 4) * 8, pdpt_pa | present)
    mem.write_qword(pdpt_pa + pte_index(va, 3) * 8, pd_pa | present)
    mem.write_qword(pd_pa   + pte_index(va, 2) * 8, pt_pa | present)
    mem.write_qword(pt_pa   + pte_index(va, 1) * 8, page_phys | present)


def test_virt_to_phys_4k_mapping(fake_mem):
    _populate_4k_mapping(fake_mem, cr3=0x200000, va=0x7FF600001234, page_phys=0x3A0000)
    pa = virt_to_phys("vm", cr3=0x200000, va=0x7FF600001234)
    assert pa == 0x3A0000 + 0x234  # offset within the page preserved


def test_read_virt_cr3_reads_bytes_across_cr3(fake_mem):
    _populate_4k_mapping(fake_mem, cr3=0x200000, va=0x7FF600000000, page_phys=0x3A0000)
    fake_mem.write_bytes(0x3A0100, b"hello world")
    out = read_virt_cr3("vm", 0x200000, 0x7FF600000100, 11)
    assert out == b"hello world"
    assert fake_mem.virtual_reads[-1] == (0x200000, 0x7FF600000100, 11)


def test_read_virt_cr3_spans_page_boundary(fake_mem):
    # Map two contiguous virtual pages to two disjoint physical pages.
    _populate_4k_mapping(fake_mem, cr3=0x200000, va=0x7FF600000000, page_phys=0x3A0000)
    _populate_4k_mapping(fake_mem, cr3=0x200000, va=0x7FF600001000, page_phys=0x3B0000)
    fake_mem.write_bytes(0x3A0FFE, b"\xaa\xbb")
    fake_mem.write_bytes(0x3B0000, b"\xcc\xdd")
    out = read_virt_cr3("vm", 0x200000, 0x7FF600000FFE, 4)
    assert out == b"\xaa\xbb\xcc\xdd"


def test_walk_cache_collapses_repeated_pte_reads(fake_mem):
    _populate_4k_mapping(fake_mem, cr3=0x200000, va=0x7FF600001000, page_phys=0x3A0000)

    cache = WalkCache()
    # Two calls back-to-back with the same cache should only populate
    # four levels once — not eight.
    virt_to_phys("vm", 0x200000, 0x7FF600001000, cache=cache)
    before = len(cache.entries)
    virt_to_phys("vm", 0x200000, 0x7FF600001000, cache=cache)
    assert len(cache.entries) == before  # no new entries
    assert before == 4  # PML4E + PDPTE + PDE + PTE


def test_page_walk_error_on_missing_pml4e(fake_mem):
    # No mappings at all under this CR3.
    from winbox.kdbg.memory import PageWalkError
    with pytest.raises(PageWalkError):
        virt_to_phys("vm", cr3=0x200000, va=0x7FF600000000)


@pytest.mark.parametrize("va", [0x0001_0000_0000_0000, 0x00FF_8000_0000_0000, -1])
def test_page_walker_refuses_noncanonical_or_la57_addresses(fake_mem, va):
    from winbox.kdbg.memory import PageWalkError
    with pytest.raises(PageWalkError, match="four-level paging only"):
        virt_to_phys("vm", cr3=0x200000, va=va)


# ── _LocalRspSnapshot pagewalk mode tests ──────────────────────────────


import struct


_CR3_OFFSET = 204
_PRESENT = 1


def _build_regs_blob(cr3: int = 0x200000) -> bytes:
    blob = bytearray(608)
    struct.pack_into("<Q", blob, _CR3_OFFSET, cr3)
    # GS_BASE / KERNEL_GS_BASE at 172/180 — set to canonical-high for
    # snapshot init to pick up as KPCR candidates.
    struct.pack_into("<Q", blob, 172, 0xFFFFF80000000000)
    struct.pack_into("<Q", blob, 180, 0xFFFFF80000001000)
    return bytes(blob)


class PagewalkFakeRsp:
    """FakeRsp with physical memory backing for pagewalk tests."""

    def __init__(self, cr3: int = 0x200000) -> None:
        self.ram: dict[int, int] = {}
        self._cr3 = cr3
        self._regs = _build_regs_blob(cr3)
        self._physical_mode = False

    def list_threads(self):
        return ["01"]

    def current_thread(self):
        return "01"

    def select_thread(self, t, *, op="g"):
        pass

    def read_registers(self):
        return self._regs

    def write_registers(self, regs):
        self._regs = regs
        return b"OK"

    def set_physical_memory_mode(self, enabled):
        self._physical_mode = enabled

    def read_memory(self, addr, length):
        if not self._physical_mode:
            raise RuntimeError(f"VA read attempted at 0x{addr:x} — pagewalk should use physical mode")
        return bytes(self.ram.get(addr + i, 0) for i in range(length))

    def interrupt(self):
        pass

    def wait_for_stop(self, *, timeout=None):
        from winbox.kdbg.debugger.rsp import StopReply
        return StopReply(signal=5, thread="01", stop_kind="swbreak", raw="T05")

    def close(self):
        pass

    def write_qword(self, addr, value):
        for i, b in enumerate(value.to_bytes(8, "little")):
            self.ram[addr + i] = b

    def write_bytes(self, addr, data):
        for i, b in enumerate(data):
            self.ram[addr + i] = b


def _populate_pagewalk_mapping(rsp: PagewalkFakeRsp, cr3: int, va: int, page_phys: int):
    pml4_pa = cr3 & ~0xFFF
    pdpt_pa = 0x100000
    pd_pa   = 0x101000
    pt_pa   = 0x102000

    def idx(va, level):
        return (va >> (12 + 9 * (level - 1))) & 0x1FF

    rsp.write_qword(pml4_pa + idx(va, 4) * 8, pdpt_pa | _PRESENT)
    rsp.write_qword(pdpt_pa + idx(va, 3) * 8, pd_pa | _PRESENT)
    rsp.write_qword(pd_pa   + idx(va, 2) * 8, pt_pa | _PRESENT)
    rsp.write_qword(pt_pa   + idx(va, 1) * 8, page_phys | _PRESENT)


def _make_pagewalk_snapshot(rsp: PagewalkFakeRsp):
    from winbox.kdbg.debugger.reader import _LocalRspSnapshot
    stop = rsp.wait_for_stop()
    return _LocalRspSnapshot("vm", rsp, stop, pagewalk=True)


def test_pagewalk_snapshot_reads_4k_page():
    rsp = PagewalkFakeRsp(cr3=0x200000)
    _populate_pagewalk_mapping(rsp, 0x200000, 0x7FF600001000, 0x3A0000)
    rsp.write_bytes(0x3A0100, b"\xde\xad\xbe\xef")
    snap = _make_pagewalk_snapshot(rsp)
    data = snap.read_virtual(0x200000, 0x7FF600001100, 4)
    assert data == b"\xde\xad\xbe\xef"


def test_pagewalk_snapshot_spans_page_boundary():
    rsp = PagewalkFakeRsp(cr3=0x200000)
    _populate_pagewalk_mapping(rsp, 0x200000, 0x7FF600000000, 0x3A0000)
    _populate_pagewalk_mapping(rsp, 0x200000, 0x7FF600001000, 0x3B0000)
    rsp.write_bytes(0x3A0FFE, b"\xaa\xbb")
    rsp.write_bytes(0x3B0000, b"\xcc\xdd")
    snap = _make_pagewalk_snapshot(rsp)
    data = snap.read_virtual(0x200000, 0x7FF600000FFE, 4)
    assert data == b"\xaa\xbb\xcc\xdd"


def test_pagewalk_snapshot_uses_physical_reads_only():
    """Pagewalk mode never issues VA reads through gdbstub."""
    rsp = PagewalkFakeRsp(cr3=0x200000)
    _populate_pagewalk_mapping(rsp, 0x200000, 0x7FF600001000, 0x3A0000)
    rsp.write_bytes(0x3A0000, b"\x42" * 16)
    snap = _make_pagewalk_snapshot(rsp)
    # read_memory raises RuntimeError if called without physical mode
    data = snap.read_virtual(0x200000, 0x7FF600001000, 16)
    assert data == b"\x42" * 16


def test_pagewalk_snapshot_different_cr3():
    """read_virtual with a non-current CR3 still works via page walk."""
    rsp = PagewalkFakeRsp(cr3=0x200000)
    other_cr3 = 0x300000
    _populate_pagewalk_mapping(rsp, other_cr3, 0x7FF600001000, 0x4A0000)
    rsp.write_bytes(0x4A0000, b"\xff\xee\xdd")
    snap = _make_pagewalk_snapshot(rsp)
    data = snap.read_virtual(other_cr3, 0x7FF600001000, 3)
    assert data == b"\xff\xee\xdd"


def test_pagewalk_snapshot_error_on_unmapped_va():
    from winbox.kdbg.memory import PageWalkError
    rsp = PagewalkFakeRsp(cr3=0x200000)
    snap = _make_pagewalk_snapshot(rsp)
    with pytest.raises(PageWalkError):
        snap.read_virtual(0x200000, 0x7FF600001000, 4)


def test_pagewalk_snapshot_caches_reads():
    """Second read of same (cr3, addr, len) should hit cache."""
    rsp = PagewalkFakeRsp(cr3=0x200000)
    _populate_pagewalk_mapping(rsp, 0x200000, 0x7FF600001000, 0x3A0000)
    rsp.write_bytes(0x3A0000, b"\x01\x02\x03\x04")
    snap = _make_pagewalk_snapshot(rsp)
    d1 = snap.read_virtual(0x200000, 0x7FF600001000, 4)
    # Wipe physical RAM — if cache is working, second read still returns same data.
    rsp.ram.clear()
    d2 = snap.read_virtual(0x200000, 0x7FF600001000, 4)
    assert d1 == d2 == b"\x01\x02\x03\x04"


def test_pagewalk_off_uses_va_read():
    """With pagewalk=False, snapshot uses CR3 masquerade + VA read."""
    from winbox.kdbg.debugger.reader import _LocalRspSnapshot

    class VaReadRsp(PagewalkFakeRsp):
        def __init__(self):
            super().__init__()
            self.va_reads = []

        def read_memory(self, addr, length):
            if self._physical_mode:
                return super().read_memory(addr, length)
            self.va_reads.append((addr, length))
            return b"\x90" * length

    rsp = VaReadRsp()
    stop = rsp.wait_for_stop()
    snap = _LocalRspSnapshot("vm", rsp, stop, pagewalk=False)
    snap.read_virtual(0x200000, 0x7FF600001000, 4)
    assert len(rsp.va_reads) == 1
    assert rsp.va_reads[0] == (0x7FF600001000, 4)


def test_pagewalk_noncanonical_va_raises():
    from winbox.kdbg.memory import PageWalkError
    rsp = PagewalkFakeRsp(cr3=0x200000)
    snap = _make_pagewalk_snapshot(rsp)
    with pytest.raises(PageWalkError, match="non-canonical"):
        snap.read_virtual(0x200000, 0x0001_0000_0000_0000, 4)


def test_pagewalk_2mb_large_page():
    """Walk through a 2 MiB large page (PS bit set in PDE)."""
    rsp = PagewalkFakeRsp(cr3=0x200000)
    cr3 = 0x200000
    va = 0x7FF600200000  # offset 0 into a 2 MiB region
    pml4_pa = cr3 & ~0xFFF
    pdpt_pa = 0x100000
    pd_pa   = 0x101000
    large_page_pa = 0x800000  # 2 MiB aligned

    def idx(va, level):
        return (va >> (12 + 9 * (level - 1))) & 0x1FF

    rsp.write_qword(pml4_pa + idx(va, 4) * 8, pdpt_pa | _PRESENT)
    rsp.write_qword(pdpt_pa + idx(va, 3) * 8, pd_pa | _PRESENT)
    rsp.write_qword(pd_pa   + idx(va, 2) * 8, large_page_pa | _PRESENT | (1 << 7))  # PS bit

    offset = 0x1234
    rsp.write_bytes(large_page_pa + offset, b"\xab\xcd")
    snap = _make_pagewalk_snapshot(rsp)
    data = snap.read_virtual(cr3, va + offset, 2)
    assert data == b"\xab\xcd"


# ── Config pagewalk tests ──────────────────────────────────────────────


def test_config_kdbg_pagewalk_default_false():
    from winbox.config import Config
    cfg = Config()
    assert cfg.kdbg_pagewalk is False


def test_config_kdbg_pagewalk_from_file(tmp_path):
    from winbox.config import Config
    config_file = tmp_path / ".winbox" / "config"
    config_file.parent.mkdir(parents=True)
    config_file.write_text("KDBG_PAGEWALK=1\n")
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    cfg = Config._apply_overrides(cfg, config_file)
    assert cfg.kdbg_pagewalk is True


def test_config_kdbg_pagewalk_off_values(tmp_path):
    from winbox.config import Config
    for val in ("0", "false", "no", "off", "garbage"):
        config_file = tmp_path / ".winbox" / "config"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(f"KDBG_PAGEWALK={val}\n")
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg = Config._apply_overrides(cfg, config_file)
        assert cfg.kdbg_pagewalk is False, f"expected False for value {val!r}"


def test_config_kdbg_pagewalk_persist_roundtrip(tmp_path):
    from winbox.config import Config
    config_file = tmp_path / ".winbox" / "config"
    config_file.parent.mkdir(parents=True)
    config_file.write_text("")
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    cfg.config_source = config_file
    cfg.persist("KDBG_PAGEWALK", "1")
    cfg2 = Config._apply_overrides(Config(), config_file)
    assert cfg2.kdbg_pagewalk is True
