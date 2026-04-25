"""Physical/virtual memory reads via HMP + CR3 page walker.

Three layers, from raw to convenient:

1. ``read_phys(vm, pa, length)`` — dumb ``xp`` passthrough. CR3-agnostic,
   only physical addresses. The foundation everything else builds on.
2. ``read_virt_current(vm, va, length)`` — HMP ``x`` passthrough. Uses the
   CPU's current CR3, so only sees whichever process was scheduled when
   the VM halted.
3. ``read_virt_cr3(vm, cr3, va, length)`` — manual 4-level page walk using
   ``read_phys``. The "CR3 switching" primitive — lets us read any
   process's user address space from any halt.

Why not use the gdbstub socket directly? The user may already have a gdb
client attached through pygdbmi-mcp; QEMU only allows a single gdb
client, so fighting for the socket would break interactive sessions.
HMP is always available and plays nicely alongside an attached gdb.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from winbox.kdbg.hmp import HmpError, hmp


# ── Text parsing for `xp`/`x` output ────────────────────────────────────

# `xp /<N>bx 0xADDR` prints lines like:
#   0000000000123000: 0x48 0x89 0x5c 0x24 0x10 0x57 0x48 0x83 ...
# We parse any line of that shape into (address, [bytes]).
_HEX_LINE_RE = re.compile(
    r"^\s*([0-9A-Fa-f]{1,16})\s*:\s*((?:0x[0-9A-Fa-f]{2}\s*)+)",
)


def parse_hex_dump(text: str) -> bytes:
    """Parse HMP ``xp``/``x`` byte-format output into a flat bytes blob.

    Tolerant: skips any line that doesn't match, so interleaved warnings
    or prompt echoes don't derail us. Addresses are assumed to be in
    natural order — HMP always emits them that way.
    """
    out = bytearray()
    for line in text.splitlines():
        match = _HEX_LINE_RE.match(line)
        if not match:
            continue
        for token in match.group(2).split():
            if token.startswith("0x") or token.startswith("0X"):
                out.append(int(token, 16))
    return bytes(out)


# ── Physical reads via `xp` ─────────────────────────────────────────────

# QEMU `xp` happily takes large counts, but a single HMP call has to round-
# trip through virsh, so we batch at a reasonable page-sized chunk.
_PHYS_CHUNK_DEFAULT = 4096


def read_phys(
    vm_name: str,
    addr: int,
    length: int,
    *,
    chunk: int = _PHYS_CHUNK_DEFAULT,
) -> bytes:
    """Read ``length`` bytes of physical memory starting at ``addr``."""
    if length <= 0:
        return b""
    out = bytearray()
    remaining = length
    cursor = addr
    while remaining > 0:
        take = min(remaining, chunk)
        text = hmp(vm_name, f"xp /{take}bx 0x{cursor:x}")
        data = parse_hex_dump(text)
        if len(data) < take:
            raise HmpError(
                f"xp truncated: asked {take} bytes at 0x{cursor:x}, got {len(data)}"
            )
        out += data[:take]
        remaining -= take
        cursor += take
    return bytes(out)


def read_virt_current(
    vm_name: str,
    addr: int,
    length: int,
    *,
    chunk: int = _PHYS_CHUNK_DEFAULT,
) -> bytes:
    """Read virtual memory using the *current* CPU context's CR3.

    Useful when the VA is already mapped in whatever process was
    scheduled at halt time (e.g. kernel addresses, which are in every
    process's address space on x86-64 Windows).
    """
    if length <= 0:
        return b""
    out = bytearray()
    remaining = length
    cursor = addr
    while remaining > 0:
        take = min(remaining, chunk)
        text = hmp(vm_name, f"x /{take}bx 0x{cursor:x}")
        data = parse_hex_dump(text)
        if len(data) < take:
            raise HmpError(
                f"x truncated: asked {take} bytes at 0x{cursor:x}, got {len(data)}"
            )
        out += data[:take]
        remaining -= take
        cursor += take
    return bytes(out)


# ── CR3 page walker (x86-64, 4-level paging) ────────────────────────────

PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
PAGE_MASK = PAGE_SIZE - 1
PHYS_ADDR_MASK = (1 << 52) - 1
PTE_PRESENT = 1 << 0
PTE_LARGE = 1 << 7  # 2 MiB (PD) or 1 GiB (PDPT)


def _pte_index(va: int, level: int) -> int:
    """Extract the 9-bit index at paging level ``level`` (PML4=4..PT=1)."""
    shift = PAGE_SHIFT + 9 * (level - 1)
    return (va >> shift) & 0x1FF


@dataclass
class WalkCache:
    """Per-CR3 cache of page-table reads.

    Page walks share a lot of work for sequentially close virtual addresses —
    same PML4E/PDPTE/PDE for everything in the same 2 MiB / 1 GiB region.
    Caching the entries by table-physical-address lets a multi-page read
    avoid re-issuing the same ``xp`` calls.
    """

    entries: dict[tuple[int, int], int] = field(default_factory=dict)

    def get(self, table_pa: int, index: int) -> int | None:
        return self.entries.get((table_pa, index))

    def put(self, table_pa: int, index: int, pte: int) -> None:
        self.entries[(table_pa, index)] = pte


def _read_pte(vm_name: str, table_pa: int, index: int, cache: WalkCache) -> int:
    cached = cache.get(table_pa, index)
    if cached is not None:
        return cached
    entry_pa = table_pa + index * 8
    data = read_phys(vm_name, entry_pa, 8)
    pte = int.from_bytes(data, "little")
    cache.put(table_pa, index, pte)
    return pte


class PageWalkError(HmpError):
    pass


def virt_to_phys(
    vm_name: str,
    cr3: int,
    va: int,
    *,
    cache: WalkCache | None = None,
) -> int:
    """Translate ``va`` to a physical address under the given CR3.

    Returns the physical address of the byte at ``va``. Raises
    ``PageWalkError`` if any intermediate entry is not present.

    Handles 4 KiB, 2 MiB (PS bit in PDE) and 1 GiB (PS bit in PDPTE)
    pages — all three are common in Windows kernel VA space.
    """
    if cache is None:
        cache = WalkCache()

    # Strip CR3's low flags (PCID bits, etc.) to get the PML4 physical base.
    pml4_pa = cr3 & ~PAGE_MASK & PHYS_ADDR_MASK

    pml4e = _read_pte(vm_name, pml4_pa, _pte_index(va, 4), cache)
    if not (pml4e & PTE_PRESENT):
        raise PageWalkError(f"PML4E not present for va 0x{va:x}")
    pdpt_pa = pml4e & 0x000FFFFFFFFFF000

    pdpte = _read_pte(vm_name, pdpt_pa, _pte_index(va, 3), cache)
    if not (pdpte & PTE_PRESENT):
        raise PageWalkError(f"PDPTE not present for va 0x{va:x}")
    if pdpte & PTE_LARGE:
        base = pdpte & 0x000FFFFFC0000000  # 1 GiB page
        return base | (va & 0x3FFFFFFF)
    pd_pa = pdpte & 0x000FFFFFFFFFF000

    pde = _read_pte(vm_name, pd_pa, _pte_index(va, 2), cache)
    if not (pde & PTE_PRESENT):
        raise PageWalkError(f"PDE not present for va 0x{va:x}")
    if pde & PTE_LARGE:
        base = pde & 0x000FFFFFFFE00000  # 2 MiB page
        return base | (va & 0x1FFFFF)
    pt_pa = pde & 0x000FFFFFFFFFF000

    pte = _read_pte(vm_name, pt_pa, _pte_index(va, 1), cache)
    if not (pte & PTE_PRESENT):
        raise PageWalkError(f"PTE not present for va 0x{va:x}")
    page_pa = pte & 0x000FFFFFFFFFF000
    return page_pa | (va & PAGE_MASK)


def read_virt_cr3(
    vm_name: str,
    cr3: int,
    va: int,
    length: int,
    *,
    cache: WalkCache | None = None,
) -> bytes:
    """Read ``length`` bytes from ``va`` under an arbitrary CR3.

    The core CR3-switching primitive: given the ``DirectoryTableBase`` of
    any process, read its virtual memory from any halt — no matter which
    process was actually running on the CPU.

    Reads cross page boundaries by splitting at 4 KiB, 2 MiB, 1 GiB walks
    are cached per-CR3 so sequential reads only pay for the final PT
    lookup. Caller may supply a ``WalkCache`` to extend caching across
    calls in the same debug session.
    """
    if length <= 0:
        return b""
    if cache is None:
        cache = WalkCache()

    out = bytearray()
    cursor = va
    remaining = length
    while remaining > 0:
        # Only translate the page base — bytes in one page share a PTE.
        page_base = cursor & ~PAGE_MASK
        offset_in_page = cursor - page_base
        bytes_in_page = PAGE_SIZE - offset_in_page
        take = min(bytes_in_page, remaining)

        page_phys = virt_to_phys(vm_name, cr3, page_base, cache=cache)
        data = read_phys(vm_name, page_phys + offset_in_page, take)
        out += data
        cursor += take
        remaining -= take
    return bytes(out)


# ── Typed read shortcuts (used by walkers) ──────────────────────────────

# Live in memory.py instead of walk.py so any future walker (handle table,
# DPC queue, etc.) doesn't have to reinvent them.

def read_u64(vm_name: str, cr3: int, va: int, cache: WalkCache | None = None) -> int:
    """Read 8 little-endian bytes from VA in CR3 and return the unsigned int."""
    return int.from_bytes(read_virt_cr3(vm_name, cr3, va, 8, cache=cache), "little")


def read_u32(vm_name: str, cr3: int, va: int, cache: WalkCache | None = None) -> int:
    """Read 4 little-endian bytes from VA in CR3 and return the unsigned int."""
    return int.from_bytes(read_virt_cr3(vm_name, cr3, va, 4, cache=cache), "little")


def read_cstr(
    vm_name: str,
    cr3: int,
    va: int,
    length: int,
    cache: WalkCache | None = None,
) -> str:
    """Read up to ``length`` bytes and decode as Latin-1 up to the first NUL.

    Used for fixed-size kernel name fields like EPROCESS.ImageFileName
    (15 bytes + NUL). Latin-1 because the field can contain arbitrary bytes
    on corrupted/truncated entries; 'replace' would mask them.
    """
    raw = read_virt_cr3(vm_name, cr3, va, length, cache=cache)
    return raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace")


def read_unicode_string(
    vm_name: str,
    cr3: int,
    va: int,
    length_off: int,
    buffer_off: int,
    cache: WalkCache | None = None,
    *,
    max_length: int = 1024,
) -> str:
    """Read a Windows ``_UNICODE_STRING`` and return its text.

    Layout: ``USHORT Length; USHORT MaximumLength; PWSTR Buffer;`` -- where
    Length is in bytes and Buffer points at UTF-16LE chars.

    Pass the field offsets explicitly (callers already have a SymbolStore
    in scope and can look them up once per walk) so this primitive doesn't
    depend on the symbol-store layer.
    """
    length = int.from_bytes(
        read_virt_cr3(vm_name, cr3, va + length_off, 2, cache=cache), "little"
    )
    if length == 0:
        return ""
    # Cap absurd values so a bogus read can't hang the walker.
    length = min(length, max_length)
    buffer_va = read_u64(vm_name, cr3, va + buffer_off, cache)
    if buffer_va == 0:
        return ""
    raw = read_virt_cr3(vm_name, cr3, buffer_va, length, cache=cache)
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
