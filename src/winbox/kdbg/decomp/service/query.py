"""Main decompilation query: live module resolution, identity verification, Ghidra."""

from __future__ import annotations

from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.identity import IdentityError, parse_live_pe, static_bytes_at_rva
from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.format import symbolicate_va
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.decomp.service.lifecycle import _wrapped_decomp_error
from winbox.kdbg.decomp.service.resolve import (
    MAX_LIVE_READ,
    MAX_LINE_BATCH,
    _annotate_flow_symbols,
    _assembly_mode,
    _bounded_int,
    _decode_cursor,
    _detail_level,
    _encode_cursor,
    _line_range,
    _nearest_symbol_hint,
    _resolve_verified_binary,
)
from winbox.kdbg.decomp.service.format import _format_result


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
    analysis_timeout: int = 900,
    detail: str = "compact",
    lines: str = "",
    assembly: str = "nearby",
    instruction_bytes: bool = False,
    runtime_vas: bool = False,
    callers: bool = False,
    callees: bool = False,
    allow_cold: bool = False,
    daemon_client: DaemonClient | None = None,
    decomp_client: DecompClient | None = None,
) -> dict[str, Any]:
    """Return focused pseudocode for ``addr`` (current RIP by default).

    The order is intentionally fail-closed: fresh live module resolution,
    exact PE identity validation, RVA mapping, and only then Ghidra. A stale
    same-named file never reaches the decompiler cache.
    """
    from winbox.kdbg.decomp.service.resolve import MAX_CONTEXT_LINES

    before = _bounded_int("before", before, 0, MAX_CONTEXT_LINES)
    after = _bounded_int("after", after, 0, MAX_CONTEXT_LINES)
    timeout = _bounded_int("timeout", timeout, 5, 300)
    analysis_timeout = _bounded_int("analysis_timeout", analysis_timeout, 5, 1800)
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
    if not isinstance(callers, bool) or not isinstance(callees, bool):
        raise DecompError("callers and callees must be booleans", code="invalid_argument")
    if not isinstance(allow_cold, bool):
        raise DecompError("allow_cold must be a boolean", code="invalid_argument")
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
    except ClientError as exc:
        raise _wrapped_decomp_error("could not resolve live address", exc) from exc
    except (KeyError, TypeError, ValueError) as exc:
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
            except ClientError as exc:
                error = IdentityError(str(getattr(exc, "message", exc)))
                error.code = exc.code
                error.retryable = exc.retryable
                error.details = exc.details
                raise error from exc
            except (KeyError, ValueError) as exc:
                raise IdentityError(str(exc)) from exc
            if len(chunk) != size:
                raise IdentityError(f"short daemon memory read: {len(chunk)}/{size}")
            chunks.append(chunk)
            offset += size
        return b"".join(chunks)

    try:
        live_identity = parse_live_pe(live_read, module_base)
        binary_path, static_identity, identity_confidence = _resolve_verified_binary(
            cfg, str(module.get("name", "")), binary, live_identity, module_size,
        )
    except IdentityError as exc:
        raise _wrapped_decomp_error("could not verify live module", exc) from exc

    runtime_symbol = symbolicate_va(store, runtime_va)
    symbol_hint = _nearest_symbol_hint(
        store, str(module.get("name", "")), rva, build=live_identity.pdb_key,
    )

    from winbox.kdbg.decomp.cache import analysis_readiness
    readiness = analysis_readiness(cfg, static_identity.sha256)
    module_name = str(module.get("name") or "")[:260]
    if not readiness["ready"] and not allow_cold:
        raise DecompError(
            "exact Ghidra analysis is cold; refusing to hold the target stopped. "
            "Detach or continue the debugger, run kdbg_decomp_prepare for the "
            "verified module, then retry (or set allow_cold=true explicitly).",
            code="analysis_required", retryable=True,
            details={
                "module": module_name,
                "sha256": static_identity.sha256,
                "readiness": readiness,
                "next_action": "kdbg_decomp_prepare",
            },
        )

    from winbox.kdbg.decomp.enrichment import enrichment_path
    sidecar = enrichment_path(cfg, static_identity.sha256)
    result = worker.call(
        "decompile",
        timeout=float(timeout + analysis_timeout) + 90.0,
        binary=str(binary_path),
        binary_name=str(module.get("name") or binary_path.name),
        sha256=static_identity.sha256,
        rva=rva,
        before=before,
        after=after,
        full=bool(full),
        decompile_timeout=timeout,
        analysis_timeout=analysis_timeout,
        enrichment=str(sidecar) if sidecar.is_file() and not sidecar.is_symlink() else "",
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
    direct_calls: dict[str, Any] | None = None
    if callers or callees:
        from winbox.kdbg.static_search import StaticSearchError, direct_call_xrefs

        try:
            function_rva = int(str((result.get("function") or {})["rva"]), 0)
            direct_calls = direct_call_xrefs(
                binary_path,
                static_identity,
                rva=function_rva,
                callers=callers,
                callees=callees,
            )
        except (StaticSearchError, KeyError, TypeError, ValueError) as exc:
            direct_calls = {
                "schema": "winbox.kdbg-direct-call-xrefs/1",
                "available": False,
                "callers": [],
                "callees": [],
                "reason": str(exc)[:512],
            }
            warnings.append("static direct-call xrefs were unavailable for this function")
    if full and (result.get("analysis") or {}).get("code_truncated"):
        warnings.append(
            "full pseudocode was truncated; mapping and selected lines use the complete function"
        )
    if (result.get("mapping") or {}).get("assembly_truncated"):
        warnings.append(
            "mapped assembly was truncated at the bounded response limit"
        )
    instruction_match = "not_checked"
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
            instruction_match = "match" if live_instruction == static_instruction else "mismatch"
            if instruction_match == "mismatch":
                warnings.append(
                    "live instruction bytes differ from the exact cached PE "
                    "(software breakpoint, hotpatch, runtime patch, or relocation)"
                )
        except (IdentityError, KeyError, TypeError, ValueError):
            warnings.append("could not compare live and static instruction bytes")

    try:
        final_status = daemon.call("status")
    except ClientError as exc:
        raise _wrapped_decomp_error(
            "could not revalidate debugger stop", exc,
        ) from exc
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
            "current_instruction_match": instruction_match,
        },
        "runtime_symbol": runtime_symbol,
        "symbol_hint": symbol_hint,
        "next_cursor": next_cursor,
        "analysis_admission": {
            "policy": "allow_cold" if allow_cold else "warm_required",
            "cache": readiness,
            "cold_analysis": not readiness["ready"],
        },
        **result,
        "direct_calls": direct_calls,
        "warnings": warnings,
    }
    return _format_result(
        composed, detail,
        instruction_bytes=bool(instruction_bytes),
        runtime_vas=bool(runtime_vas),
    )
