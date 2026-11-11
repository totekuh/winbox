"""Result envelope and instruction formatting for decompilation queries."""

from __future__ import annotations

from typing import Any

from winbox.kdbg.decomp.service.resolve import _hex_int


def _format_result(
    result: dict[str, Any],
    detail: str,
    *,
    instruction_bytes: bool = True,
    runtime_vas: bool = True,
) -> dict[str, Any]:
    """Apply the public response envelope without weakening verification.

    The diagnostic form is the internal evidence record. Compact/standard
    forms retain the operational answer and truthful source mapping while
    avoiding repeated PE/PDB/cache provenance on every agent query.
    """
    if detail == "diagnostic":
        return result

    module = result.get("module") or {}
    identity = result.get("identity") or {}
    function = result.get("function") or {}
    mapping = result.get("mapping") or {}
    ghidra_base = _hex_int(result.get("ghidra_image_base"))
    module_base = _hex_int(module.get("base"))
    requested_rva = _hex_int(module.get("rva"))
    requested_static = (
        ghidra_base + requested_rva
        if ghidra_base is not None and requested_rva is not None
        else None
    )

    nearby_assembly: list[dict[str, Any]] = []
    for instruction in result.get("instructions") or []:
        nearby_assembly.append(
            _format_instruction(
                instruction, ghidra_base, module_base,
                instruction_bytes=instruction_bytes,
                runtime_vas=runtime_vas,
            )
        )

    kind, direction, distance = _mapping_relation(mapping, requested_static)
    selected_line = mapping.get("line")
    candidate_lines = list(mapping.get("candidate_lines") or [])
    if not candidate_lines and selected_line is not None:
        candidate_lines = [selected_line]

    pseudocode: list[dict[str, Any]] = []
    for source_line in mapping.get("excerpt") or []:
        item = {
            "line": source_line.get("line"),
            "text": source_line.get("text"),
        }
        ranges = source_line.get("address_ranges") or []
        if not ranges and source_line.get("line") == selected_line:
            addresses = [
                value for value in (
                    _hex_int(address) for address in mapping.get("addresses") or []
                ) if value is not None
            ]
            if addresses:
                ranges = [{"start": min(addresses), "end": max(addresses)}]
        rva_ranges: list[dict[str, str]] = []
        for address_range in ranges:
            start = _hex_int(address_range.get("start"))
            end = _hex_int(address_range.get("end"))
            if start is None or end is None or ghidra_base is None:
                continue
            rva_ranges.append({
                "start": f"0x{start - ghidra_base:x}",
                "end": f"0x{end - ghidra_base:x}",
            })
        if rva_ranges:
            item["rva_ranges"] = rva_ranges
        relation = source_line.get("relation")
        if relation is None and source_line.get("line") in candidate_lines:
            relation = kind
        if relation:
            item["relation"] = relation
        mapped = source_line.get("assembly") or []
        if mapped:
            item["assembly"] = [
                _format_instruction(
                    instruction, ghidra_base, module_base,
                    instruction_bytes=instruction_bytes,
                    runtime_vas=runtime_vas,
                )
                for instruction in mapped
            ]
        if "assembly_complete" in source_line:
            item["assembly_complete"] = bool(source_line["assembly_complete"])
        pseudocode.append(item)

    compact: dict[str, Any] = {
        "schema": "winbox.kdbg-decomp/5",
        "detail": detail,
        "target": result.get("target"),
        "stop_epoch": result.get("stop_epoch"),
        "location": {
            "symbol": result.get("runtime_symbol"),
            "va": module.get("runtime_va"),
            "rva": module.get("rva"),
        },
        "function": {
            "name": function.get("verified_name") or function.get("name"),
            "ghidra_name": function.get("name"),
            "name_source": function.get("name_source") or "ghidra",
            "signature": function.get("signature"),
            "entry_rva": function.get("rva"),
            "offset": function.get("offset"),
            "source": function.get("source"),
        },
        "assembly_mode": result.get("assembly_mode") or "nearby",
        "assembly_fields": {
            "instruction_bytes": instruction_bytes,
            "runtime_vas": runtime_vas,
        },
        "assembly": nearby_assembly,
        "pseudocode": pseudocode,
        "line_selection": mapping.get("selection"),
        "next_cursor": result.get("next_cursor"),
        "instruction_location": result.get("instruction_location"),
        "rip_mapping": {
            "kind": kind,
            "pseudocode_line": selected_line,
            "candidate_lines": candidate_lines,
            "distance_bytes": distance,
            "direction": direction,
            "reason": _mapping_reason(kind),
        },
        "verified": {
            "build_identity_match": True,
            "identity_method": identity.get("confidence"),
            "analyzed_file_sha256": (identity.get("static") or {}).get("sha256"),
            "current_instruction_match": identity.get("current_instruction_match"),
        },
        "cache_hit": result.get("cache_hit"),
        "decompile_cache_hit": result.get("decompile_cache_hit"),
        "analysis_admission": result.get("analysis_admission"),
        "operation_metadata": result.get("operation_metadata"),
        "warnings": result.get("warnings") or [],
    }
    if "code" in result:
        compact["code"] = result["code"]
    if result.get("direct_calls") is not None:
        compact["direct_calls"] = result["direct_calls"]
    if "code" in result and (result.get("analysis") or {}).get("code_truncated"):
        compact["code_truncated"] = True
    if detail == "standard":
        compact.update({
            "module": module,
            "identity": identity,
            "symbol_hint": result.get("symbol_hint"),
            "ghidra": {
                "version": result.get("ghidra_version"),
                "image_base": result.get("ghidra_image_base"),
                "address": result.get("ghidra_address"),
            },
            "analysis": result.get("analysis") or {},
        })
    return compact


def _format_instruction(
    instruction: dict[str, Any],
    ghidra_base: int | None,
    module_base: int | None,
    *,
    instruction_bytes: bool = True,
    runtime_vas: bool = True,
) -> dict[str, Any]:
    address = _hex_int(instruction.get("address"))
    item: dict[str, Any] = {"text": instruction.get("text")}
    if instruction_bytes:
        item["bytes"] = instruction.get("bytes")
    if address is not None and ghidra_base is not None:
        instruction_rva = address - ghidra_base
        item["rva"] = f"0x{instruction_rva:x}"
        if runtime_vas and module_base is not None:
            item["va"] = f"0x{module_base + instruction_rva:x}"
    if instruction.get("current"):
        item["current"] = True
    targets = []
    for target in instruction.get("flow_targets") or []:
        static_target = _hex_int(target)
        if static_target is None or ghidra_base is None:
            continue
        target_rva = static_target - ghidra_base
        if target_rva < 0:
            continue
        target_item = {"rva": f"0x{target_rva:x}"}
        if runtime_vas:
            target_item["static_va"] = f"0x{static_target:x}"
        if runtime_vas and module_base is not None:
            target_item["runtime_va"] = f"0x{module_base + target_rva:x}"
        symbol = (instruction.get("flow_target_symbols") or {}).get(str(target))
        if symbol:
            target_item["symbol"] = symbol
        targets.append(target_item)
    if targets:
        item["flow_targets"] = targets
    return item


def _mapping_relation(
    mapping: dict[str, Any], requested_static: int | None
) -> tuple[str, str | None, int | None]:
    kind = str(mapping.get("kind") or "")
    direction = mapping.get("direction")
    distance = mapping.get("distance_bytes")
    if kind:
        return kind, direction, distance

    confidence = mapping.get("confidence")
    if confidence == "exact":
        return "exact", "overlap", 0
    if confidence == "function-only":
        return "unmapped", None, None
    addresses = [
        value for value in (
            _hex_int(address) for address in mapping.get("addresses") or []
        ) if value is not None
    ]
    if confidence == "nearest" and addresses and requested_static is not None:
        low, high = min(addresses), max(addresses)
        if requested_static < low:
            return "nearest-forward", "forward", low - requested_static
        if requested_static > high:
            return "nearest-backward", "backward", requested_static - high
        return "range", "overlap", 0
    return "unmapped", None, None


def _mapping_reason(kind: str) -> str:
    return {
        "exact": "RIP has direct single-address decompiler token provenance",
        "range": "RIP lies inside an address range contributing to this statement",
        "nearest-forward": "RIP has no direct pseudocode token; this is the next mapped statement",
        "nearest-backward": "RIP has no direct pseudocode token; this is the previous mapped statement",
        "ambiguous": "multiple pseudocode lines have equally valid address provenance",
        "unmapped": "Ghidra returned no defensible instruction-to-pseudocode mapping",
    }.get(kind, "mapping relationship reported by the decompiler")
