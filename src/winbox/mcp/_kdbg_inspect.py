"""kdbg inspection tools — decomp, ghidra, mem, write_mem, context, stack, bt."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp._common import _research_ok, _research_error
from winbox.mcp._kdbg_session import _kdbg_client, _kdbg_cfg_only

from winbox.kdbg.debugger.client import ClientError as _ClientError


@mcp.tool()
def kdbg_decomp(
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
) -> dict[str, Any]:
    """Return focused Ghidra pseudocode for ADDR or the current RIP.

    Combines live debugger state with static analysis safely: resolves ADDR
    through a fresh target/kernel loader walk, computes an ASLR-independent
    RVA, verifies the host PE against the live module's CodeView GUID+age and
    PE headers, then asks an isolated persistent PyGhidra worker to decompile
    only the containing function.

    Args:
        addr: Runtime VA as hex/decimal. Empty (default) means current RIP.
        symbol: Loaded symbol such as ``services!RQueryServiceStatus``.
        module: Live module name; use together with ``rva``.
        rva: Module-relative address as hex/decimal; requires ``module``.
        cursor: Opaque ``next_cursor`` from a previous page.
        before: Source context lines before the mapped line (0..20).
        after: Source context lines after the mapped line (0..20).
        full: Include the whole containing function (bounded to 256 KiB).
        binary: Exact host-side PE path. Empty uses the winbox symbols cache.
        timeout: Per-function Ghidra decompilation timeout (5..300 seconds).
        analysis_timeout: Cold import/auto-analysis budget (5..1800 seconds).
        detail: Response detail: compact (default), standard, or diagnostic.
        lines: Absolute pseudocode line or range (for example ``1-22``).
        assembly: ``nearby`` (default) or ``mapped``.
        instruction_bytes: Include raw instruction bytes (off by default).
        runtime_vas: Include repeated static/runtime VAs.
        callers: Include static direct callers.
        callees: Include static direct callees.
        allow_cold: Permit cold import/analysis while the target is halted.
    """
    from winbox.kdbg.decomp import DecompError, query_decomp

    cfg = _kdbg_cfg_only()
    try:
        result = query_decomp(
            cfg,
            addr=addr,
            symbol=symbol,
            module=module,
            rva=rva,
            cursor=cursor,
            before=before,
            after=after,
            full=full,
            binary=binary,
            timeout=timeout,
            analysis_timeout=analysis_timeout,
            detail=detail,
            lines=lines,
            assembly=assembly,
            instruction_bytes=instruction_bytes,
            runtime_vas=runtime_vas,
            callers=callers,
            callees=callees,
            allow_cold=allow_cold,
        )
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_decomp")
    return _research_ok(result)


@mcp.tool()
def kdbg_decomp_status() -> dict[str, Any]:
    """Show Docker/PyGhidra API, worker/JVM state, and analysis-cache status."""
    from winbox.kdbg.decomp import worker_status

    return _research_ok(worker_status(_kdbg_cfg_only()))


@mcp.tool()
def kdbg_decomp_cache() -> dict[str, Any]:
    """List Ghidra content-cache entries, sizes, profiles, and LRU timestamps."""
    from winbox.kdbg.decomp import cache_inventory
    return _research_ok(cache_inventory(_kdbg_cfg_only()))


@mcp.tool()
def kdbg_decomp_cache_prune(
    max_bytes: int = 0, older_than_days: float = 0.0,
    sha256: list[str] | None = None, project: list[str] | None = None,
    module: list[str] | None = None, dry_run: bool = True,
) -> dict[str, Any]:
    """Preview or prune cold Ghidra caches; dry-run is the safe default.

    Args:
        max_bytes: Reduce aggregate cache usage to this many bytes; zero disables.
        older_than_days: Select entries unused for this many days; zero disables.
        sha256: Select exact immutable binary digests.
        project: Select exact Ghidra project names.
        module: Select exact module basenames (case-insensitive).
        dry_run: Preview only. Set false explicitly to delete while worker is stopped.
    """
    from winbox.kdbg.decomp import DecompError, prune_cache
    try:
        return _research_ok(prune_cache(
            _kdbg_cfg_only(), max_bytes=int(max_bytes),
            older_than_days=float(older_than_days), sha256=sha256,
            project=project, module=module, dry_run=bool(dry_run),
        ))
    except (DecompError, TypeError, ValueError) as exc:
        return _research_error(exc, operation="kdbg_decomp_cache_prune")


@mcp.tool()
def kdbg_decomp_cache_repair(sha256: str) -> dict[str, Any]:
    """Delete and rebuild one exact digest-keyed Ghidra project cache."""
    from winbox.kdbg.decomp import DecompError, repair_cache
    try:
        return _research_ok(repair_cache(_kdbg_cfg_only(), sha256=sha256))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_decomp_cache_repair")


@mcp.tool()
def kdbg_decomp_prepare(
    module: str = "all", analysis_timeout: int = 900,
    background: bool = False, force_enrichment: bool = False,
) -> dict[str, Any]:
    """Analyze exact cached modules while the VM runs.

    This performs PDB enrichment plus import/auto-analysis without requiring
    a debugger session or stop. Background mode returns a durable token.
    """
    from winbox.kdbg.decomp import (
        DecompError, prepare_decomp, start_prepare_background,
    )
    from winbox.kdbg.decomp.service import _prepare_modules
    cfg = _kdbg_cfg_only()
    try:
        if background:
            selected = _prepare_modules(cfg, module)
            return _research_ok(start_prepare_background(
                cfg, modules=selected, analysis_timeout=analysis_timeout,
                force_enrichment=force_enrichment,
            ))
        return _research_ok(prepare_decomp(
            cfg, module=module, analysis_timeout=analysis_timeout,
            force_enrichment=force_enrichment,
        ))
    except (DecompError, TypeError, ValueError) as exc:
        return _research_error(exc, operation="kdbg_decomp_prepare")


@mcp.tool()
def kdbg_decomp_prepare_status(token: str = "") -> dict[str, Any]:
    """Read the latest or token-selected background preparation result."""
    from winbox.kdbg.decomp import DecompError, prepare_status
    try:
        return _research_ok(prepare_status(_kdbg_cfg_only(), token=token))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_decomp_prepare_status")


@mcp.tool()
def kdbg_decomp_cancel(request_id: str = "", token: str = "") -> dict[str, Any]:
    """Cancel an active request or one exact background preparation token."""
    from winbox.kdbg.decomp import DecompError, cancel_decomp
    try:
        return _research_ok(cancel_decomp(
            _kdbg_cfg_only(), request_id=request_id, token=token,
        ))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_decomp_cancel")


@mcp.tool()
def kdbg_ghidra_install(pull: bool = True) -> dict[str, Any]:
    """Build the pinned, self-contained headless Ghidra Docker image.

    Args:
        pull: Refresh the pinned JDK base image before building.
    """
    from winbox.kdbg.decomp import DecompError, install_service

    try:
        return _research_ok(install_service(_kdbg_cfg_only(), pull=bool(pull)))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_ghidra_install")


@mcp.tool()
def kdbg_ghidra_run() -> dict[str, Any]:
    """Start and verify the private persistent headless Ghidra API."""
    from winbox.kdbg.decomp import DecompError, start_service

    try:
        return _research_ok(start_service(_kdbg_cfg_only()))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_ghidra_run")


@mcp.tool()
def kdbg_ghidra_stop() -> dict[str, Any]:
    """Stop and remove only the labelled winbox headless Ghidra container."""
    from winbox.kdbg.decomp import DecompError, stop_service

    try:
        return _research_ok(stop_service(_kdbg_cfg_only()))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_ghidra_stop")


@mcp.tool()
def kdbg_mem(
    va: str, length: int = 64, decode: str = "hex",
) -> dict[str, Any]:
    """Read LENGTH bytes at VA in the attached target's address space.

    Args:
        va: Virtual address as hex string or decimal.
        length: Bytes to read (capped at 64 KiB by the daemon).
        decode: ``hex``, ``utf-16le``/``utf16``, ``utf-8``/``utf8``,
            ``ascii``, ``cstr``, or ``qwords``.
    """
    cfg = _kdbg_cfg_only()
    try:
        result = _kdbg_client(cfg).call("mem", va=va, length=int(length))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_mem")

    if decode != "hex":
        try:
            raw = bytes.fromhex(result["bytes"])
        except (KeyError, ValueError):
            raw = b""
        d = decode.lower()
        if d in ("utf-16le", "utf16", "utf-16"):
            text = raw.decode("utf-16-le", errors="replace")
            text = text.rstrip("\x00")
            result["decoded"] = text
        elif d in ("utf-8", "utf8"):
            result["decoded"] = raw.decode("utf-8", errors="replace").rstrip("\x00")
        elif d == "ascii":
            result["decoded"] = "".join(
                chr(b) if 32 <= b < 127 else "." for b in raw
            )
        elif d == "cstr":
            cut = raw.split(b"\x00", 1)[0]
            result["decoded"] = cut.decode("latin-1", errors="replace")
        elif d == "qwords":
            result["decoded"] = [
                "0x{:016x}".format(int.from_bytes(raw[i:i+8], "little"))
                for i in range(0, len(raw) - len(raw) % 8, 8)
            ]
        else:
            result["decoded"] = f"unknown decode mode: {decode!r}"
    return _research_ok(result)


@mcp.tool()
def kdbg_write_mem(va: str, data: str) -> dict[str, Any]:
    """Write hex-encoded DATA at VA in the attached target's address space.

    Args:
        va: Virtual address (hex string ``0x...`` or decimal).
        data: Hex-encoded bytes (no ``0x`` prefix needed).
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("write_mem", va=va, data=data))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_write_mem")


@mcp.tool()
def kdbg_context(
    disasm_count: int = 8,
    stack_qwords: int = 16,
    bt_depth: int = 8,
    memory: list[dict[str, object]] | None = None,
) -> dict[str, Any]:
    """Return one bounded triage bundle for the current halted stop.

    Args:
        disasm_count: Instructions at RIP (0..32).
        stack_qwords: Native stack words to return (0..32).
        bt_depth: Backtrace frames to return (0..16).
        memory: Optional list of up to four ``{va, length}`` reads.
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call(
            "context",
            disasm_count=disasm_count,
            stack_qwords=stack_qwords,
            bt_depth=bt_depth,
            memory=memory or [],
        ))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_context")


@mcp.tool()
def kdbg_stack(n: int = 16) -> dict[str, Any]:
    """Read N native words starting at RSP/ESP at the current halt.

    Args:
        n: Number of words to read (1..256).
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("stack", n=int(n)))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_stack")


@mcp.tool()
def kdbg_bt(depth: int = 8) -> dict[str, Any]:
    """Unwind the live Windows x64 or WoW64 x86 stack.

    Args:
        depth: Max frames to return (1..64).
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("bt", depth=int(depth)))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_bt")
