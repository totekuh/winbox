"""Tests for the symbols.py orchestrator refactor.

Focused on the bits we just added: cached_pdb_path lookup,
ensure_types_loaded lazy extraction, and the shape of LoadedModule.

The PE+PDB pipeline itself is exercised by the existing test_kdbg_pdb
suite — no need to re-mock llvm-pdbutil here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winbox.kdbg import symbols
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.symbols import (
    SymbolLoadError,
    cached_pdb_path,
    ensure_types_loaded,
)


def _save_nt(store: SymbolStore, build: str = "ABCD1234", types: dict | None = None) -> None:
    store.save(
        module="nt",
        build=build,
        image="ntkrnlmp.pdb",
        symbols={"NtCreateFile": 0x100},
        types=types or {},
        base=None,
    )


# ── cached_pdb_path ─────────────────────────────────────────────────────


def test_cached_pdb_path_returns_existing_file(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store, build="DEAF")
    pdb_file = tmp_path / "ntkrnlmp_DEAF.pdb"
    pdb_file.write_bytes(b"fake pdb bytes")
    assert cached_pdb_path(_FakeCfg(tmp_path), store, "nt") == pdb_file


def test_cached_pdb_path_raises_when_pdb_missing(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store, build="DEAF")
    with pytest.raises(SymbolLoadError, match="cached PDB missing"):
        cached_pdb_path(_FakeCfg(tmp_path), store, "nt")


def test_cached_pdb_path_raises_when_module_metadata_blank(tmp_path):
    store = SymbolStore(tmp_path)
    # Save a record with empty image/build to simulate a corrupted store.
    store.save(
        module="nt", build="", image="",
        symbols={}, types={}, base=None,
    )
    with pytest.raises(SymbolLoadError, match="no image/build metadata"):
        cached_pdb_path(_FakeCfg(tmp_path), store, "nt")


# ── ensure_types_loaded ─────────────────────────────────────────────────


def test_ensure_types_loaded_noop_when_all_present(tmp_path, monkeypatch):
    """If every requested type is already in the store, do not even open
    the PDB — important because callers (walkers) invoke this on every
    request and the no-op path must be cheap."""
    store = SymbolStore(tmp_path)
    _save_nt(store, types={"_PEB": {"size": 0x100, "fields": {}}})

    called = {"n": 0}

    def fake_load_types(*args, **kwargs):
        called["n"] += 1
        return {}

    monkeypatch.setattr(symbols, "load_types", fake_load_types)
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_PEB"])
    assert called["n"] == 0


def test_ensure_types_loaded_extracts_missing_and_persists(tmp_path, monkeypatch):
    store = SymbolStore(tmp_path)
    _save_nt(store, build="BEEF", types={})
    (tmp_path / "ntkrnlmp_BEEF.pdb").write_bytes(b"fake pdb")

    captured: dict = {}

    class FakeLayout:
        def to_json(self):
            return {"size": 0x60, "fields": {"Ldr": {"off": 0x18, "type": ""}}}

    def fake_load_types(pdb_path, wanted):
        captured["pdb_path"] = pdb_path
        captured["wanted"] = list(wanted)
        return {"_PEB": FakeLayout()}

    monkeypatch.setattr(symbols, "load_types", fake_load_types)
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_PEB", "_PEB_LDR_DATA"])

    # Only the missing types were requested.
    assert captured["wanted"] == ["_PEB", "_PEB_LDR_DATA"]
    assert captured["pdb_path"] == tmp_path / "ntkrnlmp_BEEF.pdb"

    # The extracted layout was persisted.
    data = store.load("nt")
    assert "_PEB" in data["types"]
    assert data["types"]["_PEB"]["fields"]["Ldr"]["off"] == 0x18


def test_ensure_types_loaded_partial_extraction_keeps_others(tmp_path, monkeypatch):
    """If the PDB only has some of the requested types, persist what
    came back and don't error — the walker that needed the missing one
    will surface a more specific failure."""
    store = SymbolStore(tmp_path)
    _save_nt(store, build="CAFE", types={})
    (tmp_path / "ntkrnlmp_CAFE.pdb").write_bytes(b"fake pdb")

    class FakeLayout:
        def to_json(self):
            return {"size": 0x40, "fields": {}}

    def fake_load_types(pdb_path, wanted):
        return {"_PEB": FakeLayout()}  # _PEB_LDR_DATA not returned

    monkeypatch.setattr(symbols, "load_types", fake_load_types)
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_PEB", "_PEB_LDR_DATA"])

    data = store.load("nt")
    assert "_PEB" in data["types"]
    assert "_PEB_LDR_DATA" not in data["types"]


def test_ensure_types_loaded_empty_pdb_response_is_silent(tmp_path, monkeypatch):
    """If the PDB doesn't have any of the requested types, no
    persistence happens but no exception either."""
    store = SymbolStore(tmp_path)
    _save_nt(store, build="DEAD", types={})
    (tmp_path / "ntkrnlmp_DEAD.pdb").write_bytes(b"fake pdb")

    monkeypatch.setattr(symbols, "load_types", lambda pdb_path, wanted: {})
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_NEVER_HEARD_OF_IT"])

    # Store untouched.
    data = store.load("nt")
    assert data["types"] == {}


# ── Helpers ─────────────────────────────────────────────────────────────


class _FakeCfg:
    """Minimal Config stand-in — symbols.py only reads symbols_dir."""

    def __init__(self, root: Path) -> None:
        self.symbols_dir = root
