"""End-to-end symbol-load orchestrator.

The high-level entry point is ``load_module``: copy a Windows PE out of
the running guest via VirtIO-FS, fetch its CodeView-referenced PDB from
msdl, parse with llvm-pdbutil, and persist into ``SymbolStore``. The
``load_nt`` wrapper layers on the kernel-specific base resolution (via
the live IDT[0] handler).

For per-process user-mode loads, ``copy_user_module`` extracts a binary
out of an arbitrary process's address space — the binary on disk is
authoritative for symbol lookup, the in-VM module base is recorded
separately by the caller (``walk_user_modules``).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from winbox.kdbg.hmp import HmpError, read_cpu_state
from winbox.kdbg.memory import read_virt_current
from winbox.kdbg.pdb import (
    NT_DEFAULT_TYPES,
    build_type_map,
    load_publics,
    load_section_headers,
    load_types,
)
from winbox.kdbg.pe import fetch_pdb, pdb_cache_path, read_pdb_ref
from winbox.kdbg.store import SymbolStore, SymbolStoreError

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


# ── Binary copy helpers ─────────────────────────────────────────────────


def _copy_via_share(
    cfg: Config,
    ga: GuestAgent,
    src_in_vm: str,
    cached_name: str,
) -> Path:
    """Copy a file out of the VM via the VirtIO-FS share.

    Stages at ``Z:\\<basename>``, copies into ``cfg.symbols_dir``, removes
    the staging copy. Raises ``SymbolLoadError`` if the in-VM Copy-Item
    fails or the staged file never appears.
    """
    cfg.symbols_dir.mkdir(parents=True, exist_ok=True)
    cached = cfg.symbols_dir / cached_name

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    # Use a unique staging name — concurrent module loads (e.g. parallel
    # MCP calls) on the same VM share would otherwise race on the basename.
    staging = cfg.shared_dir / cached_name
    src_basename = src_in_vm.rsplit("\\", 1)[-1]
    staging_in_vm = f"Z:\\{cached_name}"

    try:
        result = ga.exec_powershell(
            f"Copy-Item -Force '{src_in_vm}' '{staging_in_vm}'",
            timeout=60,
        )
        if result.exitcode != 0:
            raise SymbolLoadError(
                f"Copy-Item {src_basename} failed: {result.stderr or result.stdout}"
            )
        if not staging.exists():
            raise SymbolLoadError(
                f"{src_basename} did not appear on the share after Copy-Item"
            )
        shutil.copy2(staging, cached)
    finally:
        staging.unlink(missing_ok=True)

    return cached


def copy_ntoskrnl(cfg: Config, ga: GuestAgent) -> Path:
    """Copy ``C:\\Windows\\System32\\ntoskrnl.exe`` into the symbol cache."""
    return _copy_via_share(cfg, ga, r"C:\Windows\System32\ntoskrnl.exe", "ntoskrnl.exe")


def copy_user_module(
    cfg: Config,
    ga: GuestAgent,
    vm_path: str,
    cached_name: str,
) -> Path:
    """Copy any user-mode binary out of the VM into the symbol cache.

    ``vm_path`` is the absolute Windows path (e.g.
    ``C:\\Windows\\System32\\notepad.exe``). ``cached_name`` is the
    filename to store under (e.g. ``notepad.exe``).
    """
    return _copy_via_share(cfg, ga, vm_path, cached_name)


# ── nt-specific base resolver ───────────────────────────────────────────


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


# ── Generic module loader ───────────────────────────────────────────────


def load_module(
    cfg: Config,
    store: SymbolStore,
    *,
    pe_path: Path,
    module_name: str,
    base: int | None = None,
    wanted_types: Iterable[str] = (),
) -> LoadedModule:
    """PE → PDB ref → fetch → parse → persist for an arbitrary binary.

    Caller is responsible for getting the PE file onto disk (use
    ``copy_ntoskrnl`` / ``copy_user_module`` for live VM extraction). The
    base, when known, is recorded so ``store.resolve(name)`` can return
    absolute VAs; pass None if the caller will fill it in later via
    ``store.set_base``.

    ``wanted_types`` is the subset of structs to extract. Empty means
    "no types" — useful for user-mode binaries where only symbols matter.
    For the kernel pass ``NT_DEFAULT_TYPES``.
    """
    ref = read_pdb_ref(pe_path)
    pdb_path = fetch_pdb(ref, cfg.symbols_dir)

    sections = load_section_headers(pdb_path)
    symbols = load_publics(pdb_path, sections)
    types = build_type_map(pdb_path, wanted=wanted_types) if wanted_types else {}

    store.save(
        module=module_name,
        build=ref.build_key,
        image=ref.pdb_name,
        symbols=symbols,
        types=types,
        base=base,
        size_of_image=ref.size_of_image,
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
    """Copy ntoskrnl out of the VM, fetch PDB, extract, compute base, save.

    ``reuse_cached_pe=True`` skips the in-VM Copy-Item if the cached PE
    still exists — fast, but UNSAFE if the kernel changed (e.g., after a
    Windows Update). Default is False; the extra ~1s Copy-Item is the
    right trade-off vs surprising the user with bad symbols.
    """
    cached_pe = cfg.symbols_dir / "ntoskrnl.exe"
    if reuse_cached_pe and cached_pe.exists():
        pe_path = cached_pe
    else:
        pe_path = copy_ntoskrnl(cfg, ga)

    # Load symbols + nt's default type set first, then resolve base.
    # We do it in two passes because base resolution needs the symbol
    # table to look up KiDivideErrorFault.
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
    except (HmpError, SymbolLoadError):
        # VM may not be in kernel context at the time of the load call,
        # or some other transient HMP issue — leave base unset and let
        # the caller re-resolve later via `kdbg symbols base`.
        pass

    return info


# ── Lazy type extraction ────────────────────────────────────────────────


def cached_pdb_path(cfg: Config, store: SymbolStore, module: str) -> Path:
    """Return the on-disk PDB path for a loaded module, or raise.

    Mirrors ``pe.pdb_cache_path`` using the metadata persisted in the
    store. Useful for re-extraction on demand without the round-trip to
    the VM.
    """
    data = store.load(module)
    image = data.get("image", "")
    build = data.get("build", "")
    if not image or not build:
        raise SymbolLoadError(
            f"module {module!r} has no image/build metadata — "
            f"re-run `winbox kdbg symbols`"
        )
    path = cfg.symbols_dir / f"{Path(image).stem}_{build}.pdb"
    if not path.exists():
        raise SymbolLoadError(
            f"cached PDB missing for {module!r} at {path} — "
            f"re-run `winbox kdbg symbols`"
        )
    return path


def ensure_types_loaded(
    cfg: Config,
    store: SymbolStore,
    type_names: Iterable[str],
    *,
    module: str = "nt",
) -> None:
    """Make sure ``type_names`` are present in the store; extract if missing.

    Reads the cached PDB once and parses the requested types; persists
    the result back to the store so subsequent calls hit the JSON path.

    No-op if every type is already present. Cheap enough to call from
    walkers as a precondition without worrying about cost — the JSON
    check is in-memory.
    """
    data = store.load(module)
    have = data.get("types", {})
    missing = [t for t in type_names if t not in have]
    if not missing:
        return

    pdb_path = cached_pdb_path(cfg, store, module)
    layouts = load_types(pdb_path, wanted=missing)
    if not layouts:
        # Nothing to add — every requested type was either already present
        # or absent from the PDB. The walker that needed them will surface
        # a more specific "field not found" message downstream.
        return

    have.update({name: layout.to_json() for name, layout in layouts.items()})
    # Re-save preserves base, image, symbols, size, etc.
    store.save(
        module=data["module"],
        build=data["build"],
        image=data["image"],
        symbols=data["symbols"],
        types=have,
        base=data.get("base"),
        size_of_image=data.get("size_of_image"),
    )
