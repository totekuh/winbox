"""Composition layer joining a live kdbg stop to focused Ghidra output."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.identity import (
    IdentityError,
    parse_live_pe,
    parse_static_pe,
    static_bytes_at_rva,
    validate_identity,
)
from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.format import symbolicate_va
from winbox.kdbg.store import SymbolStore, SymbolStoreError


MAX_CONTEXT_LINES = 20
MAX_LIVE_READ = 64 * 1024
MAX_LINE_BATCH = 100
DETAIL_LEVELS = {"compact", "standard", "diagnostic"}
ASSEMBLY_MODES = {"nearby", "mapped"}


def worker_status(cfg: Config) -> dict[str, Any]:
    return DecompClient(cfg).status()


def install_service(cfg: Config, *, pull: bool = True) -> dict[str, Any]:
    """Build the pinned, self-contained PyGhidra image."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).install(pull=pull)
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def start_service(cfg: Config) -> dict[str, Any]:
    """Start the private Unix-socket API without loading the JVM yet."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    manager = DockerManager(cfg)
    try:
        # Do not stop a legacy host worker unless the replacement image is
        # definitely available.
        if manager.image_info() is None:
            raise DockerError(
                "PyGhidra image is not installed; run `winbox kdbg ghidra install`"
            )
        DecompClient(cfg).ensure_selected_backend()
        result = manager.start()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc
    # Prove the API, not merely Docker's process state.
    status = DecompClient(cfg).call("status", start=False, timeout=10.0)
    return {**result, "api": status}


def stop_service(cfg: Config) -> dict[str, Any]:
    """Stop and remove only the precisely labelled winbox container."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).stop()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def query_decomp(
    cfg: Config,
    *,
    addr: str = "",
    symbol: str = "",
    module: str = "",
    rva: str = "",
    cursor: str = "",
    before: int = 3,
    after: int = 5,
    full: bool = False,
    binary: str = "",
    timeout: int = 60,
    detail: str = "compact",
    lines: str = "",
    assembly: str = "nearby",
    instruction_bytes: bool = False,
    runtime_vas: bool = False,
    daemon_client: DaemonClient | None = None,
    decomp_client: DecompClient | None = None,
) -> dict[str, Any]:
    """Return focused pseudocode for ``addr`` (current RIP by default).

    The order is intentionally fail-closed: fresh live module resolution,
    exact PE identity validation, RVA mapping, and only then Ghidra. A stale
    same-named file never reaches the decompiler cache.
    """
    before = _bounded_int("before", before, 0, MAX_CONTEXT_LINES)
    after = _bounded_int("after", after, 0, MAX_CONTEXT_LINES)
    timeout = _bounded_int("timeout", timeout, 5, 300)
    detail = _detail_level(detail)
    cursor_data = _decode_cursor(cursor) if cursor else None
    coordinates = sum(bool(value and str(value).strip()) for value in (addr, symbol))
    coordinates += bool(module or rva)
    if cursor_data and (coordinates or lines):
        raise DecompError("cursor is mutually exclusive with address/symbol/module/lines")
    if coordinates > 1:
        raise DecompError("addr, symbol, and module+rva are mutually exclusive")
    if bool(module) != bool(rva):
        raise DecompError("module and rva must be supplied together")
    if module and not str(module).strip():
        raise DecompError("module must not be blank")
    line_range = _line_range(lines)
    if cursor_data:
        module = str(cursor_data["module"])
        rva = str(cursor_data["function_rva"])
        start = int(cursor_data["next_start"])
        page_size = int(cursor_data["page_size"])
        line_range = (start, start + page_size - 1)
    assembly = _assembly_mode(assembly)
    daemon = daemon_client or DaemonClient(cfg)
    worker = decomp_client or DecompClient(cfg)

    store = SymbolStore(cfg.symbols_dir)
    if symbol:
        try:
            module, _ = store.parse_symbol(symbol)
            rva = f"0x{store.rva(symbol):x}"
        except SymbolStoreError as exc:
            raise DecompError(f"could not resolve symbol: {exc}") from exc

    try:
        snapshot_args: dict[str, Any] = {}
        if module:
            snapshot_args.update(module=module, rva=rva)
        elif addr and addr.strip():
            snapshot_args["va"] = addr.strip()
        snapshot = daemon.call(
            "decomp_snapshot", **snapshot_args
        )
        target = snapshot.get("target") or {}
        runtime_va = int(str(snapshot.get("runtime_va", "0")), 0)
        epoch_session = str(snapshot["session_id"])
        epoch_stop = int(snapshot["stop_id"])
        if cursor_data and (
            cursor_data["session_id"] != epoch_session
            or int(cursor_data["stop_id"]) != epoch_stop
        ):
            raise DecompError(
                "continuation no longer matches this debugger stop"
            )
        if runtime_va < 0 or runtime_va >= (1 << 64):
            raise ValueError("address outside uint64 range")
    except DecompError:
        raise
    except (ClientError, KeyError, TypeError, ValueError) as exc:
        raise DecompError(f"could not resolve live address: {exc}") from exc

    try:
        module = snapshot["module"]
        module_base = int(str(module["base"]), 0)
        module_size = int(module["size"])
        rva = runtime_va - module_base
    except (ClientError, KeyError, TypeError, ValueError) as exc:
        raise DecompError(f"could not resolve live module: {exc}") from exc
    if rva < 0 or rva >= module_size:
        raise DecompError(
            f"resolved RVA 0x{rva:x} lies outside {module.get('name')} "
            f"(size 0x{module_size:x})"
        )

    binary_path = _resolve_binary(cfg, str(module.get("name", "")), binary)

    def live_read(address: int, length: int) -> bytes:
        if length < 0 or length > (1 << 20):
            raise IdentityError(f"invalid live read length: {length}")
        chunks: list[bytes] = []
        offset = 0
        while offset < length:
            size = min(MAX_LIVE_READ, length - offset)
            try:
                reply = daemon.call(
                    "mem", va=f"0x{address + offset:x}", length=size,
                    session_id=epoch_session, stop_id=epoch_stop,
                )
                chunk = bytes.fromhex(str(reply["bytes"]))
            except (ClientError, KeyError, ValueError) as exc:
                raise IdentityError(str(exc)) from exc
            if len(chunk) != size:
                raise IdentityError(f"short daemon memory read: {len(chunk)}/{size}")
            chunks.append(chunk)
            offset += size
        return b"".join(chunks)

    try:
        static_identity = parse_static_pe(binary_path)
        live_identity = parse_live_pe(live_read, module_base)
        identity_confidence = validate_identity(
            live_identity,
            static_identity,
            module_name=str(module.get("name") or binary_path.name),
            live_module_size=module_size,
        )
    except IdentityError as exc:
        raise DecompError(str(exc)) from exc

    runtime_symbol = symbolicate_va(store, runtime_va)
    symbol_hint = _nearest_symbol_hint(store, str(module.get("name", "")), rva)

    result = worker.call(
        "decompile",
        timeout=float(timeout) + 840.0,
        binary=str(binary_path),
        sha256=static_identity.sha256,
        rva=rva,
        before=before,
        after=after,
        full=bool(full),
        decompile_timeout=timeout,
        symbol_hint=symbol_hint,
        line_start=line_range[0] if line_range else None,
        line_end=line_range[1] if line_range else None,
        assembly=assembly,
    )
    _annotate_flow_symbols(
        result, store, str(module.get("name", "")), module_size
    )

    if cursor_data:
        if (
            cursor_data["binary_sha256"] != static_identity.sha256
            or cursor_data["ghidra_version"] != result.get("ghidra_version")
            or cursor_data["analysis_profile"] != result.get("analysis_profile")
        ):
            raise DecompError(
                "continuation no longer matches this debugger stop or analysis"
            )

    selection = (result.get("mapping") or {}).get("selection") or {}
    next_cursor = None
    if selection.get("has_more") and selection.get("next_start"):
        function_rva = int(str((result.get("function") or {})["rva"]), 0)
        page_size = max(1, int(selection["end"]) - int(selection["start"]) + 1)
        next_cursor = _encode_cursor({
            "module": str(snapshot["module"]["name"]),
            "function_rva": function_rva,
            "next_start": int(selection["next_start"]),
            "page_size": page_size,
            "session_id": epoch_session,
            "stop_id": epoch_stop,
            "binary_sha256": static_identity.sha256,
            "ghidra_version": result.get("ghidra_version"),
            "analysis_profile": result.get("analysis_profile"),
        })

    warnings: list[str] = []
    if full and (result.get("analysis") or {}).get("code_truncated"):
        warnings.append(
            "full pseudocode was truncated; mapping and selected lines use the complete function"
        )
    if (result.get("mapping") or {}).get("assembly_truncated"):
        warnings.append(
            "mapped assembly was truncated at the bounded response limit"
        )
    live_bytes_match: bool | None = None
    current = next(
        (item for item in result.get("instructions", []) if item.get("current")),
        None,
    )
    if current is not None:
        try:
            static_instruction = bytes.fromhex(str(current.get("bytes", "")))
            instruction_address = int(str(current["address"]), 0)
            ghidra_base = int(str(result["ghidra_image_base"]), 0)
            instruction_rva = instruction_address - ghidra_base
            raw_file = static_bytes_at_rva(
                binary_path, static_identity, instruction_rva, len(static_instruction)
            )
            if raw_file and raw_file != static_instruction:
                warnings.append(
                    "Ghidra instruction bytes differ from the cached PE; "
                    "rebuild the analysis cache"
                )
            live_instruction = live_read(
                module_base + instruction_rva, len(static_instruction)
            )
            live_bytes_match = live_instruction == static_instruction
            if not live_bytes_match:
                warnings.append(
                    "live instruction bytes differ from the exact cached PE "
                    "(software breakpoint, hotpatch, runtime patch, or relocation)"
                )
        except (IdentityError, KeyError, TypeError, ValueError):
            warnings.append("could not compare live and static instruction bytes")

    try:
        final_status = daemon.call("status")
    except ClientError as exc:
        raise DecompError(f"could not revalidate debugger stop: {exc}") from exc
    if (
        final_status.get("state") != "halted"
        or final_status.get("session_id") != epoch_session
        or final_status.get("stop_id") != epoch_stop
    ):
        raise DecompError(
            "debugger stop changed during decompilation; retry at the new stop"
        )

    composed = {
        "target": {"pid": target.get("pid"), "name": target.get("name")},
        "stop_epoch": {"session_id": epoch_session, "stop_id": epoch_stop},
        "module": {
            **module,
            "runtime_va": f"0x{runtime_va:x}",
            "rva": f"0x{rva:x}",
            "binary": str(binary_path),
        },
        "identity": {
            "confidence": identity_confidence,
            "live": live_identity.public(),
            "static": static_identity.public(),
            "live_bytes_match": live_bytes_match,
        },
        "runtime_symbol": runtime_symbol,
        "symbol_hint": symbol_hint,
        "next_cursor": next_cursor,
        **result,
        "warnings": warnings,
    }
    return _format_result(
        composed, detail,
        instruction_bytes=bool(instruction_bytes),
        runtime_vas=bool(runtime_vas),
    )


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
            # Compatibility with worker API 1 diagnostic responses. API 2+
            # supplies per-line ranges directly.
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
            "name": function.get("name"),
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
            "exact_binary": True,
            "identity": identity.get("confidence"),
            "live_bytes_match": identity.get("live_bytes_match"),
        },
        "cache_hit": result.get("cache_hit"),
        "decompile_cache_hit": result.get("decompile_cache_hit"),
        "warnings": result.get("warnings") or [],
    }
    if "code" in result:
        compact["code"] = result["code"]
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


def _hex_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str) -> dict[str, Any]:
    raw = str(value).strip()
    if not raw or len(raw) > 4096:
        raise DecompError("invalid or oversized continuation cursor")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.b64decode(
            padded, altchars=b"-_", validate=True
        ).decode("utf-8"))
        required = {
            "module", "function_rva", "next_start", "page_size",
            "session_id", "stop_id", "binary_sha256", "ghidra_version",
            "analysis_profile",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise ValueError("unexpected cursor fields")
        if (
            not isinstance(payload["module"], str)
            or not payload["module"].strip()
            or len(payload["module"]) > 260
            or "\0" in payload["module"]
        ):
            raise ValueError("empty module")
        for key in ("function_rva", "next_start", "page_size", "stop_id"):
            if isinstance(payload[key], bool) or not isinstance(payload[key], int):
                raise ValueError(f"{key} is not an integer")
        if not 0 <= payload["function_rva"] < (1 << 32):
            raise ValueError("function RVA out of range")
        if not 1 <= payload["next_start"] <= 1_000_000:
            raise ValueError("next line out of range")
        if not 1 <= payload["page_size"] <= MAX_LINE_BATCH:
            raise ValueError("line window out of range")
        if payload["stop_id"] < 1:
            raise ValueError("stop id out of range")
        if (
            not isinstance(payload["session_id"], str)
            or not 1 <= len(payload["session_id"]) <= 128
            or not isinstance(payload["binary_sha256"], str)
            or len(payload["binary_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in payload["binary_sha256"])
            or not isinstance(payload["ghidra_version"], str)
            or not 1 <= len(payload["ghidra_version"]) <= 64
            or not isinstance(payload["analysis_profile"], str)
            or not 1 <= len(payload["analysis_profile"]) <= 128
        ):
            raise ValueError("invalid cursor identity")
        return payload
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DecompError(f"invalid continuation cursor: {exc}") from exc


def _annotate_flow_symbols(
    result: dict[str, Any], store: SymbolStore, module_name: str, module_size: int
) -> None:
    """Attach reusable module-relative symbol labels to branch/call targets."""
    ghidra_base = _hex_int(result.get("ghidra_image_base"))
    if ghidra_base is None:
        return
    instructions = list(result.get("instructions") or [])
    for source_line in (result.get("mapping") or {}).get("excerpt") or []:
        instructions.extend(source_line.get("assembly") or [])
    for instruction in instructions:
        symbols = {}
        for target in instruction.get("flow_targets") or []:
            static_target = _hex_int(target)
            if static_target is None:
                continue
            target_rva = static_target - ghidra_base
            if not 0 <= target_rva < module_size:
                continue
            hint = _nearest_symbol_hint(store, module_name, target_rva)
            if hint is None:
                continue
            suffix = f"+0x{hint['offset']:x}" if hint["offset"] else ""
            symbols[str(target)] = f"{hint['module']}!{hint['name']}{suffix}"
        if symbols:
            instruction["flow_target_symbols"] = symbols


def _resolve_binary(cfg: Config, module_name: str, explicit: str) -> Path:
    if explicit and explicit.strip():
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise DecompError(f"binary does not exist or is not a regular file: {path}")
        return path

    root = Path(cfg.symbols_dir)
    resolved_root = root.resolve()
    normalized = module_name.lower()
    candidates: list[Path] = []
    if normalized in {"ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "nt"}:
        candidates.append(root / "ntoskrnl.exe")
    candidates.extend((root / module_name, root / Path(module_name).name))
    try:
        candidates.extend(
            item for item in root.iterdir()
            if item.is_file() and item.name.lower() == normalized
        )
    except OSError:
        pass
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_relative_to(resolved_root) and resolved.is_file():
            return resolved
    raise DecompError(
        f"no cached PE for live module {module_name!r}. Before attaching, run "
        "`kdbg_user_symbols_load` for that module, or pass `binary` as the "
        "exact host-side PE path."
    )


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DecompError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise DecompError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _detail_level(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in DETAIL_LEVELS:
        choices = ", ".join(sorted(DETAIL_LEVELS))
        raise DecompError(f"detail must be one of: {choices}")
    return normalized


def _line_range(value: str) -> tuple[int, int] | None:
    raw = str(value).strip()
    if not raw:
        return None
    parts = [part.strip() for part in raw.split("-")]
    if len(parts) not in {1, 2} or any(not part.isdigit() for part in parts):
        raise DecompError("lines must be N or N-M (for example, 1-22)")
    start = int(parts[0])
    end = int(parts[-1])
    if start < 1 or end < start:
        raise DecompError("lines must be a positive ascending range")
    if end - start + 1 > MAX_LINE_BATCH:
        raise DecompError(f"lines may select at most {MAX_LINE_BATCH} lines")
    return start, end


def _assembly_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in ASSEMBLY_MODES:
        choices = ", ".join(sorted(ASSEMBLY_MODES))
        raise DecompError(f"assembly must be one of: {choices}")
    return normalized


def _nearest_symbol_hint(
    store: SymbolStore, module_name: str, rva: int
) -> dict[str, object] | None:
    """Return a bounded PDB-public hint for Ghidra's missed-function case."""
    normalized = module_name.lower()
    if normalized.startswith("ntoskrnl") or normalized.startswith("ntkrnl"):
        keys = ["nt"]
    else:
        keys = [Path(normalized).stem, normalized]
    for key in keys:
        try:
            symbols = store.load(key).get("symbols", {})
        except Exception:
            continue
        best_name = None
        best_rva = -1
        for name, value in symbols.items():
            if isinstance(value, int) and best_rva < value <= rva:
                best_name, best_rva = name, value
        if best_name is None:
            continue
        offset = rva - best_rva
        # A far-away public is more likely the previous unrelated symbol than
        # a useful function boundary. Never let it create a giant function.
        if offset > 64 * 1024:
            return None
        return {
            "module": key,
            "name": best_name,
            "rva": best_rva,
            "offset": offset,
        }
    return None
