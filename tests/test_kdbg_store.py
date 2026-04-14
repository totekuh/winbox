"""Tests for the SymbolStore file-backed symbol cache."""

from __future__ import annotations

import json

import pytest

from winbox.kdbg.store import SymbolStore, SymbolStoreError


def _sample_types() -> dict:
    return {
        "_EPROCESS": {
            "size": 2944,
            "fields": {
                "Pcb": {"off": 0, "type": "_KPROCESS"},
                "UniqueProcessId": {"off": 1088, "type": "void*"},
                "ActiveProcessLinks": {"off": 1096, "type": ""},
                "ImageFileName": {"off": 1448, "type": ""},
            },
        },
        "_KPROCESS": {
            "size": 1080,
            "fields": {
                "DirectoryTableBase": {"off": 40, "type": "unsigned __int64"},
            },
        },
    }


def _save_nt(store: SymbolStore, *, base: int | None = 0xFFFFF80559800000) -> None:
    store.save(
        module="nt",
        build="ABCD1234",
        image="ntkrnlmp.pdb",
        symbols={
            "NtCreateFile": 0x7BDDE0,
            "PsActiveProcessHead": 0xC263A0,
            "KiSystemCall64": 0x428780,
        },
        types=_sample_types(),
        base=base,
    )


def test_save_and_info(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    info = store.info("nt")
    assert info.name == "nt"
    assert info.build == "ABCD1234"
    assert info.base == 0xFFFFF80559800000
    assert info.symbol_count == 3
    assert info.type_count == 2
    assert info.path.exists()


def test_index_records_latest_file(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    # Overwrite with a new build; index should point at the new file.
    store.save(
        module="nt", build="FEEDFACE", image="ntkrnlmp.pdb",
        symbols={"Foo": 1}, types={}, base=None,
    )
    index = json.loads((tmp_path / "index.json").read_text())
    assert index["nt"] == "nt_FEEDFACE.json"


def test_resolve_absolute_va(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    va = store.resolve("NtCreateFile")
    assert va == 0xFFFFF80559800000 + 0x7BDDE0


def test_resolve_with_module_prefix(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    assert store.resolve("nt!KiSystemCall64") == 0xFFFFF80559800000 + 0x428780


def test_rva_without_base(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store, base=None)
    assert store.rva("NtCreateFile") == 0x7BDDE0
    with pytest.raises(SymbolStoreError, match="has no base"):
        store.resolve("NtCreateFile")


def test_resolve_unknown_symbol(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    with pytest.raises(SymbolStoreError, match="symbol not found"):
        store.resolve("ZwTotallyFake")


def test_search_substring(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    hits = store.search("Ps")
    assert ("PsActiveProcessHead", 0xC263A0) in hits


def test_search_limit(tmp_path):
    store = SymbolStore(tmp_path)
    store.save(
        module="nt", build="T", image="x.pdb",
        symbols={f"Ki_{i}": i for i in range(10)}, types={},
    )
    hits = store.search("Ki_", limit=3)
    assert len(hits) == 3


def test_struct_full_layout(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    layout = store.struct("_EPROCESS")
    assert layout["size"] == 2944
    assert "ActiveProcessLinks" in layout["fields"]
    assert layout["fields"]["ActiveProcessLinks"]["off"] == 1096


def test_struct_single_field(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    field = store.struct("_KPROCESS", "DirectoryTableBase")
    assert field["off"] == 40
    assert field["type"] == "unsigned __int64"


def test_struct_missing_field_raises(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    with pytest.raises(SymbolStoreError, match="field not found"):
        store.struct("_EPROCESS", "NotAField")


def test_struct_missing_type_raises(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    with pytest.raises(SymbolStoreError, match="type not found"):
        store.struct("_NOT_A_TYPE")


def test_set_base_updates_json(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store, base=None)
    store.set_base("nt", 0xFFFFF80500000000)
    info = store.info("nt")
    assert info.base == 0xFFFFF80500000000


def test_parse_symbol_default_module():
    assert SymbolStore.parse_symbol("NtCreateFile") == ("nt", "NtCreateFile")


def test_parse_symbol_with_bang():
    assert SymbolStore.parse_symbol("cyverak!g_DeviceObject") == ("cyverak", "g_DeviceObject")


def test_load_missing_module(tmp_path):
    store = SymbolStore(tmp_path)
    with pytest.raises(SymbolStoreError, match="not loaded"):
        store.load("nt")


def test_list_modules(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store)
    store.save(
        module="cyverak", build="ghidra_local", image="cyverak.json",
        symbols={"g_Ptr": 0x1000}, types={},
    )
    assert store.list_modules() == ["cyverak", "nt"]
