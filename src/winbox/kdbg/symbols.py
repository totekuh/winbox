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

import base64
import logging
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

_log = logging.getLogger(__name__)

from winbox.kdbg.debugger.reader import debug_snapshot
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import read_virt_cr3
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



logger = logging.getLogger(__name__)

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
    if not src_in_vm or "\0" in src_in_vm:
        raise SymbolLoadError("invalid source module path")
    cfg.symbols_dir.mkdir(parents=True, exist_ok=True)
    # Both values originate in a target-controlled PEB. BaseDllName must be a
    # single filename: rejecting both host and Windows separators keeps it from
    # becoming either a host traversal or a guest-side Z:\ subpath.
    if (
        not cached_name
        or cached_name in {".", ".."}
        or any(character in cached_name for character in ("/", "\\", "\0"))
    ):
        raise SymbolLoadError(f"invalid module filename: {cached_name!r}")
    cached = cfg.symbols_dir / cached_name
    # cached_name can originate from a PEB BaseDllName read out of a live
    # process on the analyzed VM — a hostile sample can spoof that to a
    # traversal payload, so we must not let it walk either copy outside
    # its intended directory.
    if not cached.resolve().is_relative_to(cfg.symbols_dir.resolve()):
        raise SymbolLoadError(f"invalid module filename: {cached_name!r}")

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    # Never interpolate target-controlled loader strings into PowerShell
    # source. UTF-16LE base64 is both lossless for Windows paths and restricted
    # to an inert alphabet; the generated destination name is host-owned.
    token = secrets.token_hex(16)
    suffix = Path(cached_name).suffix
    if len(suffix) > 16 or any(not (c.isalnum() or c == ".") for c in suffix):
        suffix = ".bin"
    staging_name = f"winbox-kdbg-{token}{suffix}"
    staging = cfg.shared_dir / staging_name
    src_basename = src_in_vm.rsplit("\\", 1)[-1]
    staging_in_vm = f"Z:\\{staging_name}"

    def encoded_path(value: str) -> str:
        return base64.b64encode(value.encode("utf-16-le")).decode("ascii")

    src_encoded = encoded_path(src_in_vm)
    dst_encoded = encoded_path(staging_in_vm)
    script = (
        "$src=[Text.Encoding]::Unicode.GetString("
        f"[Convert]::FromBase64String('{src_encoded}'))\n"
        "$dst=[Text.Encoding]::Unicode.GetString("
        f"[Convert]::FromBase64String('{dst_encoded}'))\n"
        "Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop"
    )
    temporary = cfg.symbols_dir / f".{cached_name}.{token}.part"

    try:
        result = ga.exec_powershell(script, timeout=60)
        if result.exitcode != 0:
            raise SymbolLoadError(
                f"Copy-Item {src_basename} failed: {result.stderr or result.stdout}"
            )
        if not staging.exists():
            raise SymbolLoadError(
                f"{src_basename} did not appear on the share after Copy-Item"
            )
        shutil.copyfile(staging, temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, cached)
    finally:
        staging.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)

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
    """Derive ntoskrnl's load base using RSP registers and memory only.

    QEMU's gdb register block exposes GS_BASE/KERNEL_GS_BASE but not IDTR.
    One of those bases is Windows' KPCR on each halted vCPU; ``_KPCR.IdtBase``
    gives the IDT anchor without issuing HMP ``info registers``.  Candidate
    KPCRs and CR3s are validated by the IDT handler and final MZ header.
    """
    rva = nt_syms.get("KiDivideErrorFault")
    if rva is None:
        raise SymbolLoadError(
            "KiDivideErrorFault missing from PDB publics — "
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
        for sampled in snapshot.cr3_candidates:
            for candidate in (sampled, sampled ^ 0x1000):
                if candidate not in cr3s:
                    cr3s.append(candidate)
        for kpcr in snapshot.kernel_gs_bases:
            for cr3 in cr3s:
                try:
                    idt_raw = read_virt_cr3(
                        cfg.vm_name, cr3, kpcr + idt_off, 8,
                    )
                    idt_base = int.from_bytes(idt_raw, "little")
                    if idt_base >> 47 != 0x1FFFF or idt_base & 0xF:
                        raise SymbolLoadError(f"invalid IDT base 0x{idt_base:x}")
                    entry = read_virt_cr3(cfg.vm_name, cr3, idt_base, 16)
                    if len(entry) != 16:
                        raise SymbolLoadError(
                            f"short IDT read at 0x{idt_base:x}: {len(entry)}"
                        )
                    handler = (
                        int.from_bytes(entry[0:2], "little")
                        | (int.from_bytes(entry[6:8], "little") << 16)
                        | (int.from_bytes(entry[8:12], "little") << 32)
                    )
                    base = handler - rva
                    if base & 0xFFF or base >> 47 != 0x1FFFF:
                        raise SymbolLoadError(
                            f"invalid nt base candidate 0x{base:x}"
                        )
                    head = read_virt_cr3(cfg.vm_name, cr3, base, 2)
                    if head != b"MZ":
                        raise SymbolLoadError(
                            f"nt base candidate 0x{base:x} has header {head!r}"
                        )
                    return base
                except (HmpError, SymbolLoadError) as exc:
                    failures.append(
                        f"KPCR=0x{kpcr:x}/CR3=0x{cr3:x}: {exc}"
                    )
    detail = failures[-1] if failures else "no canonical KPCR candidates from RSP"
    raise SymbolLoadError(f"could not resolve nt base through KPCR/IDT: {detail}")


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
    except (HmpError, SymbolLoadError) as e:
        # VM may not be in kernel context at the time of the load call,
        # or some other transient HMP issue — leave base unset and let
        # the caller re-resolve later via `kdbg symbols base`. Logged
        # so an operator can tell the symbol load partially succeeded
        # (symbols cached, base unresolved) rather than seeing a silent
        # ``base=null`` and wondering why every later resolve fails.
        _log.warning(
            "load_nt: symbols cached but nt base unresolved (%s: %s); "
            "re-run `winbox kdbg base` once the VM is in kernel context",
            type(e).__name__, e,
        )

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


def ensure_nt_base_current(cfg: Config, store: SymbolStore) -> bool:
    """Re-point the store's nt base at the running kernel if ASLR moved it.

    The symbol store outlives the boot that produced it, but ASLR
    re-randomizes the kernel base on every restart. Every RVA in the store is
    still correct — only the number they are added to changed — so this is
    the entire repair, and it is cheap enough to do before a walk rather than
    making the user run ``kdbg base`` by hand after every reboot.

    Must run *before* anything resolves a kernel symbol: a walk against a
    stale base fails deep inside the page-table walk as
    ``PageWalkError: PDPTE not present``, which says nothing about the actual
    cause.

    Returns True if the base was changed. Never raises — a probe that cannot
    run leaves the store alone, and the walk fails as it did before.
    """
    try:
        data = store.load("nt")
    except Exception:
        return False  # nt not loaded yet; nothing to correct

    cached = data.get("base")
    syms = data.get("symbols") or {}
    if not cached or not syms:
        # resolve_nt_base works backwards from the IDT using
        # KiDivideErrorFault's RVA, so with no symbols there is nothing to
        # compare against.
        return False

    # Stores created before the RSP-only resolver did not extract KPCR.
    # Upgrade them lazily from the already-cached PDB. Failure here is not
    # itself fatal: resolve_nt_base below reports the precise missing-field
    # error, and test/custom stores may provide their own resolver.
    try:
        ensure_types_loaded(cfg, store, ["_KPCR"], module="nt")
    except Exception:
        pass
    try:
        live = resolve_nt_base(cfg, syms)
    except Exception:
        return False

    if not live or live == cached:
        return False

    store.set_base("nt", live)
    logger.info(
        "nt base moved 0x%x -> 0x%x (ASLR, typically a VM reboot); refreshed",
        cached, live,
    )
    return True
