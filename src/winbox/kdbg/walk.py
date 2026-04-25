"""Windows-aware kernel walkers built on the memory + symbol primitives.

Two walks for now, both standard kernel list traversals:

* ``list_processes`` — starts at ``PsActiveProcessHead``, walks the
  ``_EPROCESS.ActiveProcessLinks`` circular list, returns
  ``ProcessRecord`` entries.
* ``list_modules`` — starts at ``PsLoadedModuleList``, walks the
  ``_KLDR_DATA_TABLE_ENTRY`` list via ``InLoadOrderLinks``, returns
  ``ModuleRecord`` entries.

Both use ``read_virt_cr3`` with whatever CR3 the kernel happens to be in,
so they work against a live (non-halted) VM as well. The linked lists
live in the kernel half of the address space, which is the same mapping
regardless of which process was scheduled at halt time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import logging

from winbox.kdbg.hmp import HmpError, read_cpu_state
from winbox.kdbg.memory import PageWalkError, WalkCache, read_virt_cr3

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore


MAX_PROCESSES = 4096
MAX_MODULES = 1024


@dataclass
class ProcessRecord:
    pid: int
    name: str
    eprocess: int           # VA of the EPROCESS struct
    directory_table_base: int


@dataclass
class ModuleRecord:
    name: str
    base: int               # DllBase
    size: int               # SizeOfImage
    entry: int              # VA of the KLDR_DATA_TABLE_ENTRY


# ── Shared helpers ──────────────────────────────────────────────────────


def _cpu_cr3(vm_name: str) -> int:
    return read_cpu_state(vm_name)["CR3"]


def _read_u64(vm_name: str, cr3: int, va: int, cache: WalkCache) -> int:
    return int.from_bytes(read_virt_cr3(vm_name, cr3, va, 8, cache=cache), "little")


def _read_u32(vm_name: str, cr3: int, va: int, cache: WalkCache) -> int:
    return int.from_bytes(read_virt_cr3(vm_name, cr3, va, 4, cache=cache), "little")


def _read_cstr(
    vm_name: str,
    cr3: int,
    va: int,
    length: int,
    cache: WalkCache,
) -> str:
    raw = read_virt_cr3(vm_name, cr3, va, length, cache=cache)
    return raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace")


def _read_unicode_string(
    vm_name: str,
    cr3: int,
    va: int,
    store: SymbolStore,
    cache: WalkCache,
) -> str:
    """Read a Windows ``_UNICODE_STRING`` and return its text.

    Layout: ``USHORT Length; USHORT MaximumLength; PWSTR Buffer;`` —
    Length is in bytes, Buffer is a pointer to UTF-16LE chars.
    """
    us = store.struct("_UNICODE_STRING")
    fields = us["fields"]
    length_off = fields["Length"]["off"]
    buffer_off = fields["Buffer"]["off"]

    length = int.from_bytes(
        read_virt_cr3(vm_name, cr3, va + length_off, 2, cache=cache), "little"
    )
    if length == 0:
        return ""
    # Cap absurd values so a bogus read can't hang the walker.
    length = min(length, 1024)
    buffer_va = _read_u64(vm_name, cr3, va + buffer_off, cache)
    if buffer_va == 0:
        return ""
    raw = read_virt_cr3(vm_name, cr3, buffer_va, length, cache=cache)
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


# ── Process list ────────────────────────────────────────────────────────


def list_processes(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ProcessRecord]:
    """Walk ``PsActiveProcessHead`` and return every live process."""
    if cr3 is None:
        cr3 = _cpu_cr3(vm_name)
    if cache is None:
        cache = WalkCache()

    head = store.resolve("PsActiveProcessHead")
    eproc_fields = store.struct("_EPROCESS")["fields"]
    apl_off = eproc_fields["ActiveProcessLinks"]["off"]
    img_off = eproc_fields["ImageFileName"]["off"]
    pid_off = eproc_fields["UniqueProcessId"]["off"]
    kproc_fields = store.struct("_KPROCESS")["fields"]
    dtb_off = kproc_fields["DirectoryTableBase"]["off"]

    # Flink of PsActiveProcessHead points at the first EPROCESS.ActiveProcessLinks.
    flink = _read_u64(vm_name, cr3, head, cache)
    results: list[ProcessRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_PROCESSES:
        if flink in seen:
            break
        seen.add(flink)
        eproc = flink - apl_off
        try:
            pid = _read_u64(vm_name, cr3, eproc + pid_off, cache)
            dtb = _read_u64(vm_name, cr3, eproc + dtb_off, cache)
            name = _read_cstr(vm_name, cr3, eproc + img_off, 15, cache)
        except (HmpError, PageWalkError) as e:
            # Bare `except Exception` here used to silently truncate the walk
            # mid-list — callers thought they had the full process table.
            # Surface the partial-truncation reason in logs (still partial
            # data is returned so the UI shows what we did get).
            logger.warning(
                "list_processes: walk truncated at EPROCESS 0x%x (%d returned): %s",
                eproc, len(results), e,
            )
            break
        results.append(ProcessRecord(
            pid=pid, name=name, eprocess=eproc, directory_table_base=dtb,
        ))
        flink = _read_u64(vm_name, cr3, flink, cache)
    return results


def find_process(
    vm_name: str,
    store: SymbolStore,
    *,
    pid: int | None = None,
    name: str | None = None,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> ProcessRecord | None:
    """Return the first matching process, or None."""
    for proc in list_processes(vm_name, store, cr3=cr3, cache=cache):
        if pid is not None and proc.pid == pid:
            return proc
        if name is not None and proc.name.lower() == name.lower():
            return proc
    return None


# ── Module list ─────────────────────────────────────────────────────────


def list_modules(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ModuleRecord]:
    """Walk ``PsLoadedModuleList`` and return every loaded kernel module."""
    if cr3 is None:
        cr3 = _cpu_cr3(vm_name)
    if cache is None:
        cache = WalkCache()

    head = store.resolve("PsLoadedModuleList")
    ldr_fields = store.struct("_KLDR_DATA_TABLE_ENTRY")["fields"]
    # _KLDR_DATA_TABLE_ENTRY starts with InLoadOrderLinks at offset 0.
    inload_off = ldr_fields.get("InLoadOrderLinks", {}).get("off", 0)
    dll_base_off = ldr_fields["DllBase"]["off"]
    size_off = ldr_fields["SizeOfImage"]["off"]
    base_name_off = ldr_fields["BaseDllName"]["off"]

    flink = _read_u64(vm_name, cr3, head, cache)
    results: list[ModuleRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_MODULES:
        if flink in seen:
            break
        seen.add(flink)
        entry = flink - inload_off
        try:
            base = _read_u64(vm_name, cr3, entry + dll_base_off, cache)
            size = _read_u32(vm_name, cr3, entry + size_off, cache)
            name = _read_unicode_string(vm_name, cr3, entry + base_name_off, store, cache)
        except (HmpError, PageWalkError) as e:
            logger.warning(
                "list_modules: walk truncated at LDR_DATA_TABLE_ENTRY 0x%x (%d returned): %s",
                entry, len(results), e,
            )
            break
        results.append(ModuleRecord(name=name, base=base, size=size, entry=entry))
        flink = _read_u64(vm_name, cr3, flink, cache)
    return results
