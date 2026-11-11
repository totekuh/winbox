"""Bounded offline discovery over an exact cached PE artifact.

This deliberately stays outside the debugger daemon.  It answers the common
"where is the interesting code?" question from the immutable PE staged at
attach time, so discovery never consumes a new RSP stop or relies on a warm
Ghidra project.  Results are leads with explicit static provenance: direct
RIP-relative data references and direct relative calls only.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

import pefile

from winbox.config import Config
from winbox.kdbg.decomp.identity import PeIdentity
from winbox.kdbg.store import SymbolStore

from winbox.kdbg.static_search_types import (  # noqa: F401 — re-exported
    SCHEMA,
    XREF_SCHEMA,
    MAX_RESULTS,
    MAX_VFUNCS,
    StaticSearchError,
    _FunctionIndex,
    _hex,
    _validate_limit,
    _validate_module,
    _validate_query,
    _validate_sha256,
)
from winbox.kdbg.static_search_resolve import (
    _load_exact_artifact,
    _read_bounded_regular_file,
)
from winbox.kdbg.static_search_disasm import (
    _bytes_at_rva,
    _code_sections,
    _data_sections,
    _direct_call_target,
    _find_strings,
    _function_public,
    _instruction_iter,
    _instruction_rva,
    _runtime_functions,
    _scan_string_xrefs,
    _section_data,
    _bounded_text,
)


def _exports(path: Path, query: str, functions: _FunctionIndex) -> list[dict[str, Any]]:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]],
        )
        symbols = list(getattr(pe, "DIRECTORY_ENTRY_EXPORT", object()).symbols)
    except AttributeError:
        return []
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        raise StaticSearchError(f"PE export directory is malformed: {exc}") from exc
    finally:
        try:
            pe.close()
        except (AttributeError, UnboundLocalError):
            pass
    needle = query.lower()
    results: list[dict[str, Any]] = []
    for symbol in symbols:
        raw_name = getattr(symbol, "name", None)
        if not isinstance(raw_name, (bytes, bytearray)):
            continue
        name = raw_name.decode("ascii", errors="replace")
        if needle not in name.lower():
            continue
        rva = int(getattr(symbol, "address", 0))
        if rva <= 0:
            continue
        function = functions.find(rva)
        results.append({
            "rva": _hex(function.begin if function is not None else rva),
            "context": {
                "kind": "export_name",
                "export": name,
                "export_rva": _hex(rva),
                "function": _function_public(function),
            },
        })
    return results


def _rtti_results(
    data: bytes,
    identity: PeIdentity,
    strings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve validated MSVC x64 TypeDescriptor -> COL -> vftable chains."""
    if identity.machine != 0x8664:
        return []
    wanted = [
        item for item in strings
        if str(item.get("value", "")).startswith(".?A")
    ]
    if not wanted:
        return []
    data_sects = _data_sections(identity)
    results: list[dict[str, Any]] = []
    seen_vtables: set[int] = set()
    for string in wanted:
        name_rva = int(str(string["rva"]), 0)
        type_rva = name_rva - 16
        if type_rva < 0:
            continue
        locators: set[int] = set()
        for section in data_sects:
            raw = _section_data(data, identity, section)
            needle = struct.pack("<I", type_rva)
            offset = 0
            while True:
                found = raw.find(needle, offset)
                if found < 0:
                    break
                offset = found + 1
                if found < 12:
                    continue
                col_rva = section.virtual_address + found - 12
                col = _bytes_at_rva(data, identity, col_rva, 24)
                if col is None:
                    continue
                signature, _offset, _cd, type_ref, class_ref, self_ref = struct.unpack("<IIIIII", col)
                if signature not in (0, 1) or type_ref != type_rva:
                    continue
                if not 0 < class_ref < identity.image_size:
                    continue
                if self_ref not in (0, col_rva):
                    continue
                locators.add(col_rva)
        for col_rva in sorted(locators):
            pointer = struct.pack("<Q", identity.preferred_base + col_rva)
            for section in data_sects:
                raw = _section_data(data, identity, section)
                offset = 0
                while True:
                    found = raw.find(pointer, offset)
                    if found < 0:
                        break
                    offset = found + 1
                    vtable_rva = section.virtual_address + found + 8
                    if vtable_rva in seen_vtables:
                        continue
                    vfuncs: list[str] = []
                    for index in range(MAX_VFUNCS):
                        value = _bytes_at_rva(data, identity, vtable_rva + index * 8, 8)
                        if value is None:
                            break
                        target = struct.unpack("<Q", value)[0] - identity.preferred_base
                        if not 0 <= target < identity.image_size:
                            break
                        if not any(
                            section.virtual_address <= target < section.virtual_address + section.raw_size
                            for section in _code_sections(identity)
                        ):
                            break
                        vfuncs.append(_hex(target))
                    if not vfuncs:
                        continue
                    seen_vtables.add(vtable_rva)
                    results.append({
                        "rva": _hex(vtable_rva),
                        "context": {
                            "kind": "msvc_rtti_vtable",
                            "type_name": string["value"],
                            "type_descriptor_rva": _hex(type_rva),
                            "complete_object_locator_rva": _hex(col_rva),
                            "vfunc_rvas": vfuncs,
                        },
                    })
    return results


def _module_public(store_name: str, record: dict[str, Any], identity: PeIdentity) -> dict[str, Any]:
    return {
        "store_name": store_name,
        "image": str(record.get("image") or store_name)[:260],
        "architecture": "x64" if identity.machine == 0x8664 else "x86" if identity.machine == 0x14C else f"0x{identity.machine:04x}",
        "sha256": identity.sha256,
        "image_size": identity.image_size,
        "artifact_source": str(record.get("artifact_source") or "symbols-store"),
    }


def search_cached_module(
    cfg: Config,
    *,
    module: object,
    query: object,
    limit: object = 32,
    sha256: object = "",
) -> dict[str, Any]:
    """Find static string/RTTI/export leads in one exact staged PE artifact."""
    requested_sha256 = _validate_sha256(sha256)
    requested_module = _validate_module(module, required=not requested_sha256)
    requested_query = _validate_query(query)
    requested_limit = _validate_limit(limit)
    store = SymbolStore(cfg.symbols_dir)
    store_name, record, path, identity, data = _load_exact_artifact(
        cfg, store, requested_module, sha256=requested_sha256,
    )
    functions = _runtime_functions(path, identity, data)
    strings = _find_strings(data, identity, requested_query)
    xrefs, truncated = _scan_string_xrefs(
        data, identity, functions, strings, limit=requested_limit,
    )
    rtti = _rtti_results(data, identity, strings)
    exports = _exports(path, requested_query, functions)
    results = (rtti + exports + xrefs)[:requested_limit]
    if len(rtti) + len(exports) + len(xrefs) > requested_limit:
        truncated = True
    return {
        "schema": SCHEMA,
        "module": _module_public(store_name, record, identity),
        "query": requested_query,
        "string_matches": strings,
        "results": results,
        "returned": len(results),
        "truncated": truncated,
        "provenance": {
            "binary": "exact_cached_pe_sha256",
            "execution": "offline_no_vm_stop",
            "string_xrefs": "direct_x64_rip_relative_only",
            "calls": "not_collected",
        },
        "limitations": [
            "string results include only direct RIP-relative xrefs in .text",
            "RTTI results require a validated MSVC x64 TypeDescriptor/COL/vftable chain",
            "mangled-name leads require an exported name; .pdata supplies boundaries, not names",
        ],
    }


def direct_call_xrefs(
    path: Path,
    identity: PeIdentity,
    *,
    rva: int,
    callers: bool = False,
    callees: bool = False,
    limit: int = MAX_RESULTS,
) -> dict[str, Any]:
    """Return bounded static direct-call evidence for a selected function RVA."""
    if not isinstance(callers, bool) or not isinstance(callees, bool):
        raise StaticSearchError("callers and callees must be booleans")
    if not callers and not callees:
        return {"schema": XREF_SCHEMA, "available": True, "callers": [], "callees": []}
    if not isinstance(rva, int) or not 0 <= rva < identity.image_size:
        raise StaticSearchError("function RVA lies outside the exact cached PE")
    if not 1 <= limit <= MAX_RESULTS:
        raise StaticSearchError(f"limit must be between 1 and {MAX_RESULTS}")
    data = _read_bounded_regular_file(path, label="exact cached PE")
    if hashlib.sha256(data).hexdigest() != identity.sha256:
        raise StaticSearchError("exact cached PE changed before direct-call scan")
    functions = _runtime_functions(path, identity, data)
    selected = functions.find(rva)
    if selected is None:
        raise StaticSearchError("selected RVA has no validated x64 .pdata function boundary")
    caller_rows: list[dict[str, Any]] = []
    callee_rows: list[dict[str, Any]] = []
    caller_seen: set[int] = set()
    callee_seen: set[int] = set()
    caller_truncated = callee_truncated = False
    for instruction in _instruction_iter(data, identity):
        target = _direct_call_target(identity, instruction)
        if target is None:
            continue
        instruction_rva_val = _instruction_rva(identity, instruction)
        source = functions.find(instruction_rva_val)
        rendered = _bounded_text(f"{instruction.mnemonic} {instruction.op_str}".strip(), 260)
        if callers and target == rva and source is not None and source.begin not in caller_seen:
            caller_seen.add(source.begin)
            caller_rows.append({
                "rva": _hex(source.begin),
                "context": {
                    "kind": "direct_caller", "function_end": _hex(source.end),
                    "call_rva": _hex(instruction_rva_val), "instruction": rendered,
                    "target_rva": _hex(rva),
                },
            })
            if len(caller_rows) >= limit:
                caller_truncated = True
        if callees and selected.begin <= instruction_rva_val < selected.end and target not in callee_seen:
            callee_seen.add(target)
            target_function = functions.find(target)
            callee_rows.append({
                "rva": _hex(target_function.begin if target_function is not None else target),
                "context": {
                    "kind": "direct_callee", "call_rva": _hex(instruction_rva_val),
                    "instruction": rendered, "target_rva": _hex(target),
                    "function": _function_public(target_function),
                },
            })
            if len(callee_rows) >= limit:
                callee_truncated = True
        if (not callers or caller_truncated) and (not callees or callee_truncated):
            break
    return {
        "schema": XREF_SCHEMA,
        "available": True,
        "source_function": _function_public(selected),
        "callers": caller_rows[:limit] if callers else [],
        "callees": callee_rows[:limit] if callees else [],
        "callers_truncated": caller_truncated,
        "callees_truncated": callee_truncated,
        "provenance": "exact_cached_pe_direct_relative_calls_only",
        "limitations": [
            "indirect calls, tail jumps, dynamic dispatch, and unresolved import thunks are not inferred",
        ],
    }
