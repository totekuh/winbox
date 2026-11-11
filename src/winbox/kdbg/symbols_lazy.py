"""Post-load symbol helpers: cached PDB lookup, lazy type extraction, base refresh."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from winbox.kdbg.hmp import HmpError
from winbox.kdbg.pdb import load_types
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.symbols_copy import SymbolLoadError

if TYPE_CHECKING:
    from winbox.config import Config

logger = logging.getLogger(__name__)


def cached_pdb_path(cfg: Config, store: SymbolStore, module: str) -> Path:
    """Return the on-disk PDB path for a loaded module, or raise."""
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
    """Make sure ``type_names`` are present in the store; extract if missing."""
    data = store.load(module)
    have = data.get("types", {})
    missing = [t for t in type_names if t not in have]
    if not missing:
        return

    pdb_path = cached_pdb_path(cfg, store, module)
    layouts = load_types(pdb_path, wanted=missing)
    if not layouts:
        return

    have.update({name: layout.to_json() for name, layout in layouts.items()})
    store.save(
        module=data["module"],
        build=data["build"],
        image=data["image"],
        symbols=data["symbols"],
        types=have,
        base=data.get("base"),
        size_of_image=data.get("size_of_image"),
        architecture=data.get("architecture"),
        function_symbols=data.get("function_symbols"),
        frame_data=data.get("frame_data"),
        pe_path=data.get("pe_path"),
        pe_sha256=data.get("pe_sha256"),
    )


def ensure_nt_base_current(cfg: Config, store: SymbolStore) -> bool:
    """Re-point the store's nt base at the running kernel if ASLR moved it."""
    from winbox.kdbg.symbols import resolve_nt_base

    try:
        data = store.load("nt")
    except Exception:
        return False

    cached = data.get("base")
    syms = data.get("symbols") or {}
    if not cached or not syms:
        return False

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
