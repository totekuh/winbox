"""Local RSP snapshot adapter and context managers."""

from __future__ import annotations

import struct
import time
from contextlib import contextmanager
from typing import Any, Iterator

from winbox.kdbg.debugger.install import _CR3_OFFSET_IN_G
from winbox.kdbg.debugger.rsp import RspClient, StopReply
from winbox.kdbg.debugger.reader.types import (
    ReaderError,
    _SNAPSHOT_CACHE_MAX_BYTES,
    _active_snapshot,
)
from winbox.kdbg.debugger.reader.snapshot import DebugSnapshot


class _LocalRspSnapshot(DebugSnapshot):
    """Snapshot adapter for code already owning a halted RSP connection."""

    def __init__(self, vm_name: str, rsp: RspClient, stop: StopReply, *, pagewalk: bool = False):
        self.vm_name = vm_name
        self.rsp = rsp
        self._pagewalk = pagewalk
        threads = rsp.list_threads()
        if not threads:
            raise ReaderError("gdbstub returned no vCPUs")
        self._vcpu = stop.thread or rsp.current_thread()
        if self._vcpu not in threads:
            try:
                wanted = int(self._vcpu, 16)
                self._vcpu = next(t for t in threads if int(t, 16) == wanted)
            except (ValueError, StopIteration) as exc:
                raise ReaderError(
                    f"stop vCPU {self._vcpu!r} is absent from gdbstub thread list"
                ) from exc
        cr3s: list[int] = []
        kernel_gs_bases: list[int] = []
        vcpu_kernel_gs_bases: list[tuple[int, tuple[int, ...]]] = []
        regs_by_thread: dict[str, bytes] = {}
        for thread in threads:
            rsp.select_thread(thread)
            regs = rsp.read_registers()
            regs_by_thread[thread] = regs
            value = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
            if value not in cr3s:
                cr3s.append(value)
            vcpu_bases: list[int] = []
            for offset in (172, 180):
                base = struct.unpack_from("<Q", regs, offset)[0]
                if base >> 47 == 0x1FFFF:
                    if base not in vcpu_bases:
                        vcpu_bases.append(base)
                    if base not in kernel_gs_bases:
                        kernel_gs_bases.append(base)
            try:
                vcpu = int(thread, 16)
            except ValueError as exc:
                raise ReaderError(f"gdbstub returned invalid vCPU id {thread!r}") from exc
            if vcpu_bases:
                vcpu_kernel_gs_bases.append((vcpu, tuple(vcpu_bases)))
        rsp.select_thread(self._vcpu)
        self._original_regs = regs_by_thread.get(self._vcpu) or rsp.read_registers()
        self.current_cr3 = struct.unpack_from(
            "<Q", self._original_regs, _CR3_OFFSET_IN_G,
        )[0]
        self.cr3_candidates = tuple(cr3s)
        self.kernel_gs_bases = tuple(kernel_gs_bases)
        self.vcpu_kernel_gs_bases = tuple(vcpu_kernel_gs_bases)
        self._active_cr3 = self.current_cr3
        self._physical = False
        self._poisoned = False
        self._registers_dirty = False
        self._virtual_cache: dict[tuple[int, int, int], bytes] = {}
        self._virtual_cache_bytes = 0
        self._transport_read_count = 0
        self._transport_bytes_read = 0
        self._logical_read_count = 0
        self._logical_bytes_read = 0
        self._cache_hits = 0
        self._phases_ms: dict[str, float] = {}

    def _set_cr3(self, cr3: int) -> None:
        if self._physical:
            self._set_physical(False)
        if cr3 == self._active_cr3:
            return
        regs = bytearray(self._original_regs)
        struct.pack_into("<Q", regs, _CR3_OFFSET_IN_G, cr3)
        reply = self.rsp.write_registers(bytes(regs))
        if reply != b"OK":
            raise ReaderError(f"gdbstub rejected CR3 0x{cr3:x}: {reply!r}")
        self._active_cr3 = cr3
        self._registers_dirty = True

    def _set_physical(self, enabled: bool) -> None:
        if self._physical == enabled:
            return
        self.rsp.set_physical_memory_mode(enabled)
        self._physical = enabled

    def virtual_cache_hit(self, cr3: int, addr: int, length: int) -> bool:
        return (cr3, addr, length) in self._virtual_cache

    def transport_counters(self) -> dict[str, int]:
        return {
            "transport_read_count": self._transport_read_count,
            "transport_bytes_read": self._transport_bytes_read,
            "logical_read_count": self._logical_read_count,
            "logical_bytes_read": self._logical_bytes_read,
            "cache_hits": self._cache_hits,
        }

    def read_virtual(self, cr3: int, addr: int, length: int) -> bytes:
        self._logical_read_count += 1
        self._logical_bytes_read += max(0, length)
        key = (cr3, addr, length)
        cached = self._virtual_cache.get(key)
        if cached is not None:
            self._cache_hits += 1
            return cached
        if self._pagewalk:
            data = self._read_virtual_pagewalk(cr3, addr, length)
        else:
            self._set_cr3(cr3)
            data = self.rsp.read_memory(addr, length)
        self._transport_read_count += 1
        self._transport_bytes_read += len(data)
        if 0 < len(data) <= 4096 and self._virtual_cache_bytes + len(data) <= _SNAPSHOT_CACHE_MAX_BYTES:
            self._virtual_cache[key] = data
            self._virtual_cache_bytes += len(data)
        return data

    def _read_virtual_pagewalk(self, cr3: int, addr: int, length: int) -> bytes:
        from winbox.kdbg.memory import (
            PAGE_SIZE, PAGE_MASK, PHYS_ADDR_MASK,
            PTE_PRESENT, PTE_LARGE, _pte_index, _is_canonical_x64_4level,
            PageWalkError,
        )
        out = bytearray()
        remaining = length
        cursor = addr
        pte_cache: dict[int, int] = {}
        while remaining > 0:
            pa = self._walk_va(
                cr3, cursor, pte_cache,
                PAGE_MASK, PHYS_ADDR_MASK, PTE_PRESENT, PTE_LARGE,
                _pte_index, _is_canonical_x64_4level, PageWalkError,
            )
            to_page_end = PAGE_SIZE - (pa & (PAGE_SIZE - 1))
            take = min(remaining, to_page_end)
            chunk = self.read_physical(pa, take)
            out.extend(chunk)
            cursor += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

    def _walk_va(
        self, cr3: int, va: int, cache: dict[int, int],
        PAGE_MASK, PHYS_ADDR_MASK, PTE_PRESENT, PTE_LARGE,
        _pte_index, _is_canonical, PageWalkError,
    ) -> int:
        if not _is_canonical(va):
            raise PageWalkError(f"non-canonical VA 0x{va:x}")
        def pte_at(table_pa: int, index: int) -> int:
            entry_pa = table_pa + index * 8
            cached = cache.get(entry_pa)
            if cached is not None:
                return cached
            raw = self.read_physical(entry_pa, 8)
            val = int.from_bytes(raw, "little")
            cache[entry_pa] = val
            return val

        pml4_pa = cr3 & ~PAGE_MASK & PHYS_ADDR_MASK
        pml4e = pte_at(pml4_pa, _pte_index(va, 4))
        if not (pml4e & PTE_PRESENT):
            raise PageWalkError(f"PML4E not present for VA 0x{va:x}")

        pdpt_pa = pml4e & 0x000FFFFFFFFFF000
        pdpte = pte_at(pdpt_pa, _pte_index(va, 3))
        if not (pdpte & PTE_PRESENT):
            raise PageWalkError(f"PDPTE not present for VA 0x{va:x}")
        if pdpte & PTE_LARGE:
            return (pdpte & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF)

        pd_pa = pdpte & 0x000FFFFFFFFFF000
        pde = pte_at(pd_pa, _pte_index(va, 2))
        if not (pde & PTE_PRESENT):
            raise PageWalkError(f"PDE not present for VA 0x{va:x}")
        if pde & PTE_LARGE:
            return (pde & 0x000FFFFFFFE00000) | (va & 0x1FFFFF)

        pt_pa = pde & 0x000FFFFFFFFFF000
        pte = pte_at(pt_pa, _pte_index(va, 1))
        if not (pte & PTE_PRESENT):
            raise PageWalkError(f"PTE not present for VA 0x{va:x}")
        return (pte & 0x000FFFFFFFFFF000) | (va & PAGE_MASK)

    def read_physical(self, addr: int, length: int) -> bytes:
        self._set_physical(True)
        try:
            data = self.rsp.read_memory(addr, length)
            self._transport_read_count += 1
            self._transport_bytes_read += len(data)
            self._logical_read_count += 1
            self._logical_bytes_read += max(0, length)
            return data
        finally:
            self._set_physical(False)

    def phase_started(self, name: str) -> None:
        return None

    def phase_finished(self, name: str, elapsed_ms: float) -> None:
        safe = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in name)[:64]
        if not safe or elapsed_ms < 0:
            return
        self._phases_ms[safe] = round(self._phases_ms.get(safe, 0.0) + elapsed_ms, 3)

    def operation_metadata(self) -> dict[str, Any]:
        return {
            "snapshot_id": None,
            "reader_owner": "interactive_daemon",
            "admission": "embedded",
            "queue_delay_ms": 0.0,
            "stop_duration_ms": None,
            "read_count": self._transport_read_count,
            "bytes_read": self._transport_bytes_read,
            "logical_read_count": self._logical_read_count,
            "logical_bytes_read": self._logical_bytes_read,
            "cache_hits": self._cache_hits,
            "budget": None,
            "budget_exhausted": False,
            "phases_ms": dict(self._phases_ms),
        }

    def restore(self) -> None:
        try:
            if self._physical:
                self._set_physical(False)
            if self._registers_dirty:
                reply = self.rsp.write_registers(self._original_regs)
                if reply != b"OK":
                    raise ReaderError(
                        f"gdbstub rejected register restore: {reply!r}"
                    )
            self._active_cr3 = self.current_cr3
            self._registers_dirty = False
        except BaseException:
            self._poisoned = True
            raise


def current_snapshot(vm_name: str | None = None) -> DebugSnapshot | None:
    snapshot = _active_snapshot.get()
    if snapshot is not None and vm_name is not None and snapshot.vm_name != vm_name:
        return None
    return snapshot


@contextmanager
def snapshot_phase(name: str) -> Iterator[None]:
    snapshot = current_snapshot()
    started = time.monotonic()
    if snapshot is not None:
        snapshot.phase_started(name)
    try:
        yield
    finally:
        if snapshot is not None:
            snapshot.phase_finished(name, (time.monotonic() - started) * 1000)


@contextmanager
def use_local_rsp(
    vm_name: str, rsp: RspClient, stop: StopReply, *, pagewalk: bool = False,
) -> Iterator[DebugSnapshot]:
    """Expose an already halted RSP connection to walkers in this process."""
    existing = current_snapshot(vm_name)
    if existing is not None:
        yield existing
        return
    snapshot = _LocalRspSnapshot(vm_name, rsp, stop, pagewalk=pagewalk)
    token = _active_snapshot.set(snapshot)
    try:
        yield snapshot
    finally:
        try:
            snapshot.restore()
        finally:
            _active_snapshot.reset(token)
