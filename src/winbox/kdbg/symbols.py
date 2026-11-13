"""End-to-end symbol-load orchestrator.

The high-level entry point is ``load_module``: copy a Windows PE out of
the running guest via VirtIO-FS, fetch its CodeView-referenced PDB from
msdl, parse with llvm-pdbutil, and persist into ``SymbolStore``. The
``load_nt`` wrapper layers on the kernel-specific base resolution (via
the live IDT[0] handler).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

import pefile

_log = logging.getLogger(__name__)

from winbox.kdbg.debugger.reader import debug_snapshot
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import read_virt_cr3
from winbox.kdbg.pdb import (
    NT_DEFAULT_TYPES,
    build_type_map,
    load_fpo,
    load_publics_metadata,
    load_section_headers,
)
from winbox.kdbg.pe import fetch_pdb, read_pdb_ref
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.symbols_copy import (  # noqa: F401 — re-exported
    SymbolLoadError, _copy_via_share, _sha256, copy_ntoskrnl, copy_user_module,
)

if TYPE_CHECKING:
    from winbox.config import Config
    from winbox.vm import GuestAgent

logger = logging.getLogger(__name__)


@dataclass
class LoadedModule:
    """Thin result object returned by the orchestrator."""

    module: str
    build: str
    base: int | None
    path: Path
    symbol_count: int
    type_count: int


def _pagewalk_read(snapshot, cr3: int, va: int, length: int) -> bytes:
    """4-level x86-64 page table walk via physical reads."""
    def _pte(table_pa: int, index: int) -> int:
        raw = snapshot.read_physical(table_pa + index * 8, 8)
        return int.from_bytes(raw, "little")

    pml4_pa = cr3 & 0x000FFFFFFFFFF000
    pml4e = _pte(pml4_pa, (va >> 39) & 0x1FF)
    if not (pml4e & 1):
        raise SymbolLoadError(f"PML4E not present for VA 0x{va:x}")
    pdpt_pa = pml4e & 0x000FFFFFFFFFF000
    pdpte = _pte(pdpt_pa, (va >> 30) & 0x1FF)
    if not (pdpte & 1):
        raise SymbolLoadError(f"PDPTE not present for VA 0x{va:x}")
    if pdpte & 0x80:
        pa = (pdpte & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF)
        return snapshot.read_physical(pa, length)
    pd_pa = pdpte & 0x000FFFFFFFFFF000
    pde = _pte(pd_pa, (va >> 21) & 0x1FF)
    if not (pde & 1):
        raise SymbolLoadError(f"PDE not present for VA 0x{va:x}")
    if pde & 0x80:
        pa = (pde & 0x000FFFFFFFE00000) | (va & 0x1FFFFF)
        return snapshot.read_physical(pa, length)
    pt_pa = pde & 0x000FFFFFFFFFF000
    pte = _pte(pt_pa, (va >> 12) & 0x1FF)
    if not (pte & 1):
        raise SymbolLoadError(f"PTE not present for VA 0x{va:x}")
    pa = (pte & 0x000FFFFFFFFFF000) | (va & 0xFFF)
    return snapshot.read_physical(pa, length)


def _discover_kernel_cr3_via_eprocess(cfg, store: SymbolStore) -> int | None:
    """Walk PsActiveProcessHead to find System (PID 4) and its kernel CR3.

    The EPROCESS walk succeeds even with user-mode CR3s because
    PsActiveProcessHead is at a VA the user PML4 maps correctly.
    The System process's DirectoryTableBase is the kernel CR3.
    """
    try:
        from winbox.kdbg.walk import list_processes
        walked = list_processes(cfg.vm_name, store, pid=4)
        for proc in walked.processes:
            if proc.pid == 4 and proc.directory_table_base:
                return proc.directory_table_base
    except Exception:
        pass
    return None


def _find_kernel_cr3(snapshot, store: SymbolStore, cr3s, kpcrs) -> int | None:
    """Walk KPCR → KPRCB → KTHREAD → KPROCESS → DirectoryTableBase.

    Uses the first reachable KPCR to extract the kernel CR3, which maps
    the full kernel address space (unlike the user CR3 on KVAS builds).
    """
    try:
        prcb_off = int(store.struct("_KPCR", "CurrentPrcb")["off"])
        thread_off = int(store.struct("_KPRCB", "CurrentThread")["off"])
        proc_off = int(store.struct("_KTHREAD", "Process")["off"])
        dtb_off = int(store.struct("_KPROCESS", "DirectoryTableBase")["off"])
    except (KeyError, TypeError, SymbolStoreError):
        return None

    def _u64(cr3: int, va: int) -> int:
        return int.from_bytes(_pagewalk_read(snapshot, cr3, va, 8), "little")

    for kpcr in kpcrs:
        for cr3 in cr3s:
            try:
                prcb = _u64(cr3, kpcr + prcb_off)
                thread = _u64(cr3, prcb + thread_off)
                process = _u64(cr3, thread + proc_off)
                dtb = _u64(cr3, process + dtb_off)
                if dtb and (dtb & 0xFFF) == 0:
                    return dtb
            except (HmpError, SymbolLoadError):
                continue
    return None


def resolve_nt_base(cfg: Config, nt_syms: dict[str, int], *, kernel_cr3: int | None = None) -> int:
    """Derive ntoskrnl's load base using RSP registers and memory only."""
    rvas: list[int] = []
    for name in ("KiDivideErrorFaultShadow", "KiDivideErrorFault"):
        v = nt_syms.get(name)
        if v is not None and v not in rvas:
            rvas.append(v)
    if not rvas:
        raise SymbolLoadError(
            "KiDivideErrorFault[Shadow] missing from PDB publics — "
            "this PDB may not be ntkrnlmp"
        )

    store = SymbolStore(cfg.symbols_dir)
    try:
        idt_off = int(store.struct("_KPCR", "IdtBase")["off"])
    except (KeyError, TypeError, SymbolStoreError) as exc:
        raise SymbolLoadError(
            "_KPCR.IdtBase is missing from the nt symbol store; reload nt symbols"
        ) from exc

    failures: list[str] = []
    with debug_snapshot(cfg) as snapshot:
        cr3s: list[int] = []
        if kernel_cr3 is not None and kernel_cr3 not in cr3s:
            cr3s.append(kernel_cr3)
        from winbox.kdbg.walk._layout import _cached_kernel_cr3
        cached = _cached_kernel_cr3(cfg.vm_name)
        if cached is not None and cached not in cr3s:
            cr3s.append(cached)
        for sampled in snapshot.cr3_candidates:
            for candidate in (sampled, sampled ^ 0x1000):
                if candidate not in cr3s:
                    cr3s.append(candidate)
        kpcrs = snapshot.kernel_gs_bases

        kernel_cr3 = _find_kernel_cr3(snapshot, store, cr3s, kpcrs)
        if kernel_cr3 is None:
            kernel_cr3 = _discover_kernel_cr3_via_eprocess(cfg, store)
        if kernel_cr3 is not None and kernel_cr3 not in cr3s:
            cr3s.insert(0, kernel_cr3)

        for kpcr in kpcrs:
            for cr3 in cr3s:
                try:
                    idt_raw = _pagewalk_read(snapshot, cr3, kpcr + idt_off, 8)
                    idt_base = int.from_bytes(idt_raw, "little")
                    if idt_base >> 47 != 0x1FFFF or idt_base & 0xF:
                        raise SymbolLoadError(f"invalid IDT base 0x{idt_base:x}")
                    entry = _pagewalk_read(snapshot, cr3, idt_base, 16)
                    if len(entry) != 16:
                        raise SymbolLoadError(
                            f"short IDT read at 0x{idt_base:x}: {len(entry)}"
                        )
                    handler = (
                        int.from_bytes(entry[0:2], "little")
                        | (int.from_bytes(entry[6:8], "little") << 16)
                        | (int.from_bytes(entry[8:12], "little") << 32)
                    )
                    for rva in rvas:
                        base = handler - rva
                        if base & 0xFFF or base >> 47 != 0x1FFFF:
                            continue
                        head = _pagewalk_read(snapshot, cr3, base, 2)
                        if head == b"MZ":
                            return base
                    raise SymbolLoadError(
                        f"handler 0x{handler:x} did not resolve to a "
                        f"valid nt base with any known RVA"
                    )
                except (HmpError, SymbolLoadError) as exc:
                    failures.append(
                        f"KPCR=0x{kpcr:x}/CR3=0x{cr3:x}: {exc}"
                    )
    if not failures:
        raise SymbolLoadError("could not resolve nt base: no KPCR candidates from RSP")
    summary = "; ".join(failures[:4])
    if len(failures) > 4:
        summary += f" (+{len(failures) - 4} more)"
    raise SymbolLoadError(f"could not resolve nt base through KPCR/IDT: {summary}")


def load_module(
    cfg: Config,
    store: SymbolStore,
    *,
    pe_path: Path,
    module_name: str,
    base: int | None = None,
    wanted_types: Iterable[str] = (),
) -> LoadedModule:
    """PE -> PDB ref -> fetch -> parse -> persist for an arbitrary binary."""
    ref = read_pdb_ref(pe_path)
    pdb_path = fetch_pdb(ref, cfg.symbols_dir)

    parsed_pe = None
    try:
        parsed_pe = pefile.PE(str(pe_path), fast_load=True)
        machine = int(parsed_pe.FILE_HEADER.Machine)
    except (OSError, pefile.PEFormatError, AttributeError) as exc:
        raise SymbolLoadError(f"cannot identify PE architecture: {exc}") from exc
    finally:
        if parsed_pe is not None:
            parsed_pe.close()

    sections = load_section_headers(pdb_path)
    publics = load_publics_metadata(pdb_path, sections)
    symbols = publics.symbols
    types = build_type_map(pdb_path, wanted=wanted_types) if wanted_types else {}
    frame_data = (
        [record.to_json() for record in load_fpo(pdb_path)]
        if machine == 0x014C else []
    )

    store.save(
        module=module_name,
        build=ref.build_key,
        image=ref.pdb_name,
        symbols=symbols,
        types=types,
        base=base,
        size_of_image=ref.size_of_image,
        architecture="x86" if machine == 0x014C else "x64",
        function_symbols=sorted(publics.functions),
        frame_data=frame_data,
        pe_path=str(pe_path),
        pe_sha256=_sha256(pe_path),
    )
    info = store.info(module_name)
    return LoadedModule(
        module=module_name,
        build=ref.build_key,
        base=base,
        path=info.path,
        symbol_count=info.symbol_count,
        type_count=info.type_count,
    )


def load_nt(
    cfg: Config,
    ga: GuestAgent,
    store: SymbolStore,
    *,
    reuse_cached_pe: bool = False,
) -> LoadedModule:
    """Copy ntoskrnl out of the VM, fetch PDB, extract, compute base, save."""
    cached_pe = None
    try:
        stored = store.load("nt").get("pe_path")
        candidate = Path(str(stored)) if stored else None
        if candidate and candidate.is_file():
            cached_pe = candidate
    except Exception:
        pass
    if reuse_cached_pe and cached_pe is not None:
        pe_path = cached_pe
    else:
        pe_path = copy_ntoskrnl(cfg, ga)

    info = load_module(
        cfg, store,
        pe_path=pe_path,
        module_name="nt",
        base=None,
        wanted_types=NT_DEFAULT_TYPES,
    )

    try:
        base = resolve_nt_base(cfg, store.load("nt").get("symbols", {}))
        store.set_base("nt", base)
        info = LoadedModule(
            module=info.module,
            build=info.build,
            base=base,
            path=info.path,
            symbol_count=info.symbol_count,
            type_count=info.type_count,
        )
    except (HmpError, SymbolLoadError) as e:
        _log.warning(
            "load_nt: symbols cached but nt base unresolved (%s: %s); "
            "re-run `winbox kdbg base` once the VM is in kernel context",
            type(e).__name__, e,
        )

    return info


# ── Re-exports from extracted modules ──────────────────────────────────

from winbox.kdbg.symbols_lazy import (  # noqa: E402, F401
    cached_pdb_path, ensure_nt_base_current, ensure_types_loaded,
)
