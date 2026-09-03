"""Local exact-PE integration coverage for offline kdbg discovery."""

from __future__ import annotations

import hashlib
import struct

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.identity import parse_static_pe
from winbox.kdbg.static_search import (
    StaticSearchError,
    direct_call_xrefs,
    search_cached_module,
)
from winbox.kdbg.store import SymbolStore


def _write_sample_pe(tmp_path):
    """Build a tiny but structurally real PE with xrefs, pdata, and MSVC RTTI."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "mpengine.dll"
    data = bytearray(0xA00)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHI", data, coff, 0x8664, 3, 0x12345678)
    struct.pack_into("<H", data, coff + 16, 0xF0)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 32, 0x1000)  # section alignment
    struct.pack_into("<I", data, optional + 36, 0x200)   # file alignment
    struct.pack_into("<I", data, optional + 56, 0x4000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<I", data, optional + 108, 16)
    # IMAGE_DIRECTORY_ENTRY_EXCEPTION (3): two IMAGE_RUNTIME_FUNCTION_ENTRYs.
    struct.pack_into("<II", data, optional + 112 + 3 * 8, 0x3000, 24)

    sections = optional + 0xF0

    def section(offset, name, vsize, rva, raw_size, raw_offset, flags):
        data[offset:offset + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIIIIIHHI", data, offset + 8,
                         vsize, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)

    section(sections, b".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020)
    section(sections + 40, b".rdata", 0x200, 0x2000, 0x200, 0x600, 0x40000040)
    section(sections + 80, b".pdata", 0x200, 0x3000, 0x200, 0x800, 0x40000040)

    # lea rcx,[rip+0x1009] -> rva 0x2010; call rva 0x1050; both functions ret.
    data[0x400:0x407] = b"\x48\x8d\x0d\x09\x10\x00\x00"
    data[0x407:0x40C] = b"\xe8\x44\x00\x00\x00"
    data[0x40C] = 0xC3
    data[0x450] = 0xC3

    data[0x610:0x620] = b"HandleUnpacker\0"
    data[0x630:0x63D] = b"ResolveE8E9\0"
    # MSVC x64 TypeDescriptor starts 16 bytes before decorated class name.
    data[0x650:0x666] = b".?AVAspackUnpacker@@\0"
    # Complete Object Locator at rva 0x2080: type descriptor rva 0x2040.
    struct.pack_into("<IIIIII", data, 0x680,
                     1, 0, 0, 0x2040, 0x20C0, 0x2080)
    # vftable[-1] points at the COL; the first two entries are code pointers.
    struct.pack_into("<QQQ", data, 0x700,
                     0x140002080, 0x140001000, 0x140001050)
    struct.pack_into("<III", data, 0x800, 0x1000, 0x1040, 0)
    struct.pack_into("<III", data, 0x80C, 0x1050, 0x1080, 0)
    path.write_bytes(data)
    return path


def _register(cfg: Config, path, *, name: str = "mpengine", image: str = "mpengine.dll"):
    SymbolStore(cfg.symbols_dir).save(
        name,
        "TEST",
        image=image,
        symbols={},
        types={},
        pe_path=str(path),
        pe_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def _cache_binary(cfg: Config, path, *, name: str = "mpengine.dll") -> str:
    """Populate only persistent decomp cache state — no symbol-store record."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    root = cfg.winbox_dir / "decomp" / "cache"
    binaries = root / "verified-binaries"
    metadata = root / "metadata"
    binaries.mkdir(parents=True, exist_ok=True)
    metadata.mkdir(parents=True, exist_ok=True)
    cached = binaries / f"{digest}.dll"
    cached.write_bytes(path.read_bytes())
    (metadata / f"{digest}.json").write_text(
        '{"schema":"winbox.decomp-cache/1","sha256":"'
        + digest + '","binary_name":"' + name
        + '","project_name":"warm_' + digest + '"}',
        encoding="utf-8",
    )
    return digest


def test_static_search_cached_pe_local_integration(tmp_path):
    """Exercise PE parsing, string-xref disassembly, RTTI, and call xrefs locally."""
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    path = _write_sample_pe(tmp_path)
    _register(cfg, path)

    strings = search_cached_module(
        cfg, module="MPENGINE.DLL", query="handleunpacker", limit=16,
    )
    assert strings["schema"] == "winbox.kdbg-static-search/1"
    assert strings["module"]["store_name"] == "mpengine"
    assert any(row["value"] == "HandleUnpacker" for row in strings["string_matches"])
    xref = next(row for row in strings["results"] if row["context"]["kind"] == "direct_string_xref")
    assert xref["rva"] == "0x1000"
    assert xref["context"]["xref_rva"] == "0x1000"

    rtti = search_cached_module(cfg, module="mpengine", query="AspackUnpacker")
    vtable = next(row for row in rtti["results"] if row["context"]["kind"] == "msvc_rtti_vtable")
    assert vtable["rva"] == "0x2108"
    assert vtable["context"]["vfunc_rvas"] == ["0x1000", "0x1050"]

    calls = direct_call_xrefs(
        path, parse_static_pe(path), rva=0x1050, callers=True, callees=False,
    )
    assert calls["source_function"] == {"rva": "0x1050", "end": "0x1080"}
    assert calls["callers"][0]["rva"] == "0x1000"
    assert calls["callers"][0]["context"]["call_rva"] == "0x1007"


def test_static_search_rejects_tampered_or_ambiguous_cached_artifacts(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    path = _write_sample_pe(tmp_path)
    _register(cfg, path)
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(StaticSearchError, match="digest"):
        search_cached_module(cfg, module="mpengine", query="HandleUnpacker")

    clean = _write_sample_pe(tmp_path / "clean")
    _register(cfg, clean, name="mpengine_x86", image="mpengine.dll")
    # Restore the first artifact so ambiguity is reached rather than digest rejection.
    original = _write_sample_pe(tmp_path / "restored")
    _register(cfg, original)
    with pytest.raises(StaticSearchError, match="ambiguous"):
        search_cached_module(cfg, module="mpengine", query="HandleUnpacker")


def test_static_search_falls_back_to_named_persistent_decomp_cache(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    path = _write_sample_pe(tmp_path)
    digest = _cache_binary(cfg, path)

    result = search_cached_module(
        cfg, module="MPENGINE", query="ResolveE8E9", limit=8,
    )
    assert result["module"]["artifact_source"] == "decomp-cache"
    assert result["module"]["sha256"] == digest
    assert result["query"] == "ResolveE8E9"
    assert any(row["value"] == "ResolveE8E9" for row in result["string_matches"])


def test_static_search_decomp_cache_ambiguity_requires_exact_sha256(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    first = _write_sample_pe(tmp_path / "first")
    second = _write_sample_pe(tmp_path / "second")
    first_digest = _cache_binary(cfg, first)
    second_data = bytearray(second.read_bytes())
    second_data[0x40C] = 0x90
    second.write_bytes(second_data)
    _cache_binary(cfg, second)

    with pytest.raises(StaticSearchError, match="ambiguous.*sha256"):
        search_cached_module(cfg, module="mpengine", query="HandleUnpacker")

    selected = search_cached_module(
        cfg, module="mpengine", query="HandleUnpacker", sha256=first_digest,
    )
    assert selected["module"]["sha256"] == first_digest


@pytest.mark.parametrize("query", ["", "x", "x" * 257])
def test_static_search_bounds_untrusted_query_before_disk_access(tmp_path, query):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    with pytest.raises(StaticSearchError, match="query"):
        search_cached_module(cfg, module="mpengine", query=query)
