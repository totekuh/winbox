"""Tests for the memory parsing helpers and CR3 page walker.

We never touch a real VM — the page walker is driven through a fake
``hmp`` that serves pre-canned ``xp`` output from an in-memory physical
backing store.
"""

from __future__ import annotations

import re

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
    """Minimal physical-RAM simulator driven through an ``xp`` shim.

    Tests patch ``winbox.kdbg.memory.hmp`` with ``FakeMemory().hmp`` to
    avoid touching virsh/QEMU. We only support the ``xp /<N>bx 0x<addr>``
    form the walker issues — not a general HMP simulator.
    """

    def __init__(self) -> None:
        self.ram: dict[int, int] = {}

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.ram[addr + i] = b

    def write_qword(self, addr: int, value: int) -> None:
        self.write_bytes(addr, value.to_bytes(8, "little"))

    def hmp(self, vm_name, command, *, timeout=15):  # signature matches kdbg.hmp.hmp
        match = re.match(
            r"xp /(\d+)bx 0x([0-9A-Fa-f]+)\s*$",
            command,
        )
        if not match:
            raise AssertionError(f"unexpected HMP command in test: {command}")
        count = int(match.group(1))
        base = int(match.group(2), 16)
        out_lines = []
        for off in range(0, count, 16):
            chunk = [self.ram.get(base + off + i, 0) for i in range(min(16, count - off))]
            hex_bytes = " ".join(f"0x{b:02x}" for b in chunk)
            out_lines.append(f"{base + off:016x}: {hex_bytes}")
        return "\n".join(out_lines) + "\n"


@pytest.fixture
def fake_mem(monkeypatch):
    mem = FakeMemory()
    monkeypatch.setattr(memory, "hmp", mem.hmp)
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
