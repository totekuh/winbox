"""End-to-end symbol-load orchestrator.

``load_nt`` ties PE parsing, PDB fetch, llvm-pdbutil extraction, and base
resolution together. The caller is the only place that talks to the VM
(to copy ntoskrnl.exe out) and to the store (to persist the result).
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from winbox.kdbg.hmp import HmpError, read_cpu_state
from winbox.kdbg.memory import read_virt_current
from winbox.kdbg.pdb import build_type_map, load_publics, load_section_headers
from winbox.kdbg.pe import fetch_pdb, read_pdb_ref
from winbox.kdbg.store import SymbolStore

if TYPE_CHECKING:
    from winbox.config import Config
    from winbox.vm import GuestAgent


class SymbolLoadError(RuntimeError):
    pass


@dataclass
class LoadedModule:
    """Thin result object returned by the orchestrator."""

    module: str
    build: str
    base: int | None
    path: Path
    symbol_count: int
    type_count: int


# ── nt loader ───────────────────────────────────────────────────────────


def copy_ntoskrnl(cfg: Config, ga: GuestAgent) -> Path:
    """Copy ``C:\\Windows\\System32\\ntoskrnl.exe`` out via VirtIO-FS.

    The file lands on the shared Z: drive briefly, is copied into the
    cache next to the PDB, and the staging copy on the share is removed.
    """
    cfg.symbols_dir.mkdir(parents=True, exist_ok=True)
    cached = cfg.symbols_dir / "ntoskrnl.exe"

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    staging = cfg.shared_dir / "ntoskrnl.exe"

    try:
        result = ga.exec_powershell(
            r"Copy-Item -Force C:\Windows\System32\ntoskrnl.exe Z:\ntoskrnl.exe",
            timeout=60,
        )
        if result.exitcode != 0:
            raise SymbolLoadError(
                f"Copy-Item ntoskrnl.exe failed: {result.stderr or result.stdout}"
            )
        if not staging.exists():
            raise SymbolLoadError(
                "ntoskrnl.exe did not appear on the share after Copy-Item"
            )
        shutil.copy2(staging, cached)
    finally:
        staging.unlink(missing_ok=True)

    return cached


def resolve_nt_base(cfg: Config, nt_syms: dict[str, int]) -> int:
    """Derive ntoskrnl's load base from the live guest via the IDT.

    ``info registers`` on x86-64 shows ``IDT= <base> <limit>``. We read
    the first IDT entry (INT 0 = ``KiDivideErrorFault``), reconstruct the
    64-bit handler VA from its three offset halves, and subtract the
    symbol's RVA to get the load base. One virtual read beats walking
    backwards from RIP looking for ``MZ``.
    """
    state = read_cpu_state(cfg.vm_name)
    idt_base = state.get("IDT_BASE")
    if idt_base is None:
        raise SymbolLoadError("IDT base not available from info registers")

    entry = read_virt_current(cfg.vm_name, idt_base, 16)
    if len(entry) != 16:
        raise SymbolLoadError(
            f"short IDT read: expected 16 bytes at 0x{idt_base:x}, got {len(entry)}"
        )
    off_low = int.from_bytes(entry[0:2], "little")
    off_mid = int.from_bytes(entry[6:8], "little")
    off_high = int.from_bytes(entry[8:12], "little")
    handler = off_low | (off_mid << 16) | (off_high << 32)

    rva = nt_syms.get("KiDivideErrorFault")
    if rva is None:
        raise SymbolLoadError(
            "KiDivideErrorFault missing from PDB publics — "
            "this PDB may not be ntkrnlmp"
        )

    base = handler - rva
    # Sanity: kernel base is canonical-high, page-aligned.
    if base & 0xFFF:
        raise SymbolLoadError(
            f"computed nt base 0x{base:x} is not page-aligned — "
            "IDT[0] handler probably doesn't belong to nt"
        )
    if (base >> 47) != 0x1FFFF:
        raise SymbolLoadError(
            f"computed nt base 0x{base:x} is not canonical-high — "
            "something is wrong with the IDT read"
        )
    return base


def load_nt(
    cfg: Config,
    ga: GuestAgent,
    store: SymbolStore,
    *,
    reuse_cached_pe: bool = True,
) -> LoadedModule:
    """Copy ntoskrnl out of the VM, fetch PDB, extract, compute base, save.

    Passing ``reuse_cached_pe=True`` skips the in-VM Copy-Item if the
    cached PE still exists — useful for re-runs after provisioning where
    the kernel binary hasn't changed.
    """
    cached_pe = cfg.symbols_dir / "ntoskrnl.exe"
    if reuse_cached_pe and cached_pe.exists():
        pe_path = cached_pe
    else:
        pe_path = copy_ntoskrnl(cfg, ga)

    ref = read_pdb_ref(pe_path)
    pdb_path = fetch_pdb(ref, cfg.symbols_dir)

    sections = load_section_headers(pdb_path)
    symbols = load_publics(pdb_path, sections)
    types = build_type_map(pdb_path)

    try:
        base: int | None = resolve_nt_base(cfg, symbols)
    except (HmpError, SymbolLoadError):
        # VM may not be in kernel context at the time of the load call,
        # or some other transient HMP issue — save symbols without base
        # and let the caller re-resolve later via `kdbg symbols base`.
        base = None

    store.save(
        module="nt",
        build=ref.build_key,
        image=ref.pdb_name,
        symbols=symbols,
        types=types,
        base=base,
    )
    info = store.info("nt")
    return LoadedModule(
        module="nt",
        build=ref.build_key,
        base=base,
        path=info.path,
        symbol_count=info.symbol_count,
        type_count=info.type_count,
    )


# ── Ghidra-sourced module loader ────────────────────────────────────────


def load_from_ghidra(
    store: SymbolStore,
    module: str,
    ghidra_json: Path,
    *,
    base: int | None = None,
) -> LoadedModule:
    """Ingest a Ghidra-exported symbol JSON.

    Expected format (whatever the user's Ghidra export script produces,
    loosely)::

        {
          "symbols": { "name": 0xrva, ... },
          "types":   { "_STRUCT": { "size": N, "fields": { ... } } }
        }

    Both keys are optional — a symbol-only export is fine. The ``base``
    argument overrides any file-supplied base.
    """
    if not ghidra_json.exists():
        raise SymbolLoadError(f"file not found: {ghidra_json}")
    data = json.loads(ghidra_json.read_text(encoding="utf-8"))

    symbols_in = data.get("symbols") or {}
    types_in = data.get("types") or {}
    # Normalize symbol values: accept hex strings or ints.
    symbols: dict[str, int] = {}
    for name, value in symbols_in.items():
        if isinstance(value, str):
            symbols[name] = int(value, 16) if value.lower().startswith("0x") else int(value)
        else:
            symbols[name] = int(value)

    file_base = data.get("base")
    if base is None and file_base is not None:
        if isinstance(file_base, str):
            base = int(file_base, 16) if file_base.lower().startswith("0x") else int(file_base)
        else:
            base = int(file_base)

    store.save(
        module=module,
        build=f"ghidra_{ghidra_json.stem}",
        image=ghidra_json.name,
        symbols=symbols,
        types=types_in,
        base=base,
    )
    info = store.info(module)
    return LoadedModule(
        module=module,
        build=info.build,
        base=base,
        path=info.path,
        symbol_count=info.symbol_count,
        type_count=info.type_count,
    )
