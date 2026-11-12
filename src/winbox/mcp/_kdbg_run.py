"""kdbg execution control tools — cont, step, disasm, search, interrupt, regs."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp._common import _research_ok, _research_error
from winbox.mcp._kdbg_session import _kdbg_client, _kdbg_cfg_only
from winbox.mcp._kdbg_infra import _kdbg_get_store

from winbox.kdbg.debugger.client import ClientError as _ClientError


@mcp.tool()
def kdbg_cont(timeout: float = 30.0) -> dict[str, Any]:
    """Resume the VM; block until next bp hit in target's CR3.

    The daemon silent-continues fires that aren't in the target process.
    Returns when a bp fires *in the target* OR when the timeout
    expires OR when ``kdbg_interrupt`` is called from another flow.

    Args:
        timeout: Wall-clock budget in seconds (default 30).
    """
    cfg = _kdbg_cfg_only()
    try:
        result = _kdbg_client(cfg).call(
            "cont",
            sock_timeout=float(timeout) + 10.0,
            timeout=float(timeout),
        )
    except _ClientError as e:
        return _research_error(e, operation="kdbg_cont")
    return _research_ok(result)


@mcp.tool()
def kdbg_cont_start(timeout: float = 300.0) -> dict[str, Any]:
    """Start a durable continue operation and return immediately.

    The host worker survives MCP transport reloads. Use the returned token
    with ``kdbg_cont_poll``; call ``kdbg_cont_cancel`` to halt early.

    Args:
        timeout: Continue budget in seconds (0.5..86400).
    """
    from winbox.kdbg.debugger.continue_job import ContinueJobError, start_continue

    try:
        return _research_ok(start_continue(_kdbg_cfg_only(), timeout=timeout))
    except ContinueJobError as exc:
        return _research_error(exc, operation="kdbg_cont_start")


@mcp.tool()
def kdbg_cont_poll(token: str = "") -> dict[str, Any]:
    """Poll the durable continue operation without blocking.

    Args:
        token: Token returned by ``kdbg_cont_start``. Empty selects the current
            job, which is useful after an MCP reload.
    """
    from winbox.kdbg.debugger.continue_job import ContinueJobError, poll_continue

    try:
        return _research_ok(poll_continue(_kdbg_cfg_only(), token=token))
    except ContinueJobError as exc:
        return _research_error(exc, operation="kdbg_cont_poll")


@mcp.tool()
def kdbg_cont_cancel(token: str = "") -> dict[str, Any]:
    """Interrupt and cancel the current durable continue operation."""
    from winbox.kdbg.debugger.continue_job import ContinueJobError, cancel_continue

    try:
        return _research_ok(cancel_continue(_kdbg_cfg_only(), token=token))
    except ContinueJobError as exc:
        return _research_error(exc, operation="kdbg_cont_cancel")


@mcp.tool()
def kdbg_step(over: bool = False, out: bool = False) -> dict[str, Any]:
    """Single-step the firing vCPU.

    Args:
        over: Step OVER call/syscall — temp hw bp at next instruction.
        out: Step OUT of current function — temp hw bp at return address.
    """
    cfg = _kdbg_cfg_only()
    if out:
        op = "step_out"
    elif over:
        op = "step_over"
    else:
        op = "step"
    try:
        return _research_ok(_kdbg_client(cfg).call(op))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_step")


@mcp.tool()
def kdbg_disasm(
    addr: str = "", count: int = 8, instruction_bytes: bool = False,
) -> dict[str, Any]:
    """Disassemble x86-64 instructions at ADDR (or current RIP if empty).

    Reads up to ~16*count bytes from the target's address space via
    CR3-masquerade ``mem``, then runs Capstone over them.

    Args:
        addr: Hex VA, decimal, or empty for RIP.
        count: How many instructions to decode (1..64).
        instruction_bytes: Include raw instruction bytes.
    """
    try:
        import capstone as _cs
    except ImportError:
        return _research_error(
            "capstone not installed (apt install python3-capstone)",
            operation="kdbg_disasm",
        )

    cfg = _kdbg_cfg_only()
    client = _kdbg_client(cfg)

    if not addr or not addr.strip():
        try:
            regs = client.call("regs")
            addr_int = int(regs.get("rip", "0x0"), 16)
        except _ClientError as e:
            return _research_error(e, operation="kdbg_disasm")
    else:
        try:
            addr_int = int(addr.strip(), 0)
        except ValueError:
            return _research_error(
                f"not a valid VA: {addr!r}", operation="kdbg_disasm"
            )

    n = max(1, min(int(count), 64))
    bytes_to_read = min(n * 15, 1024)

    try:
        result = client.call("mem", va=hex(addr_int), length=bytes_to_read)
    except _ClientError as e:
        return _research_error(e, operation="kdbg_disasm")

    try:
        raw = bytes.fromhex(result["bytes"])
    except (KeyError, ValueError):
        return _research_error("malformed mem result", operation="kdbg_disasm")

    md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
    md.detail = True

    store = _kdbg_get_store()
    from winbox.kdbg.format import symbolicate_va
    _CALL = _cs.CS_GRP_CALL
    _JUMP = _cs.CS_GRP_JUMP
    _IMM = _cs.x86.X86_OP_IMM

    insns = []
    for ins in md.disasm(raw, addr_int):
        entry = {
            "addr": f"0x{ins.address:x}",
            "mnemonic": ins.mnemonic,
            "op_str": ins.op_str,
        }
        if instruction_bytes:
            entry["bytes"] = ins.bytes.hex()
        if any(g in (_CALL, _JUMP) for g in ins.groups):
            for op in ins.operands:
                if op.type == _IMM:
                    sym = symbolicate_va(store, op.imm)
                    if sym:
                        entry["sym"] = sym
                    break
        insns.append(entry)
        if len(insns) >= n:
            break

    return _research_ok({
        "base": f"0x{addr_int:x}",
        "instruction_bytes": bool(instruction_bytes),
        "instructions": insns,
    })


@mcp.tool()
def kdbg_search(
    module: str, query: str, limit: int = 32, sha256: str = "",
) -> dict[str, Any]:
    """Find static research leads in one exact cached/staged PE artifact.

    The search is strictly offline and never opens the debugger socket or
    alters VM state.

    Args:
        module: Cached/staged module name, case-insensitive.
        query: Case-insensitive text to search (2..256 characters).
        limit: Maximum result leads (1..64).
        sha256: Optional full exact cache digest.
    """
    from winbox.kdbg.static_search import StaticSearchError, search_cached_module

    try:
        result = search_cached_module(
            _kdbg_cfg_only(), module=module, query=query, limit=limit,
            sha256=sha256,
        )
    except StaticSearchError as exc:
        return _research_error(exc, operation="kdbg_search")
    return _research_ok(result)


@mcp.tool()
def kdbg_interrupt() -> dict[str, Any]:
    """Async halt request — breaks out of an in-flight ``kdbg_cont``.

    Useful when ``kdbg_cont`` is sitting in a long wait and you want
    to inspect immediately. The interrupt is queued; the cont loop
    will pick it up at its next iteration and return with
    ``reason=interrupt``.
    """
    cfg = _kdbg_cfg_only()
    from winbox.kdbg.debugger.continue_job import (
        ACTIVE_STATES, ContinueJobError, cancel_continue, poll_continue,
    )
    try:
        job = poll_continue(cfg)
        if job.get("state") in ACTIVE_STATES:
            return _research_ok(cancel_continue(cfg, token=str(job["token"])))
    except ContinueJobError:
        pass
    try:
        return _research_ok(_kdbg_client(cfg).call("interrupt"))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_interrupt")


@mcp.tool()
def kdbg_regs() -> dict[str, Any]:
    """Dump full register state at the most recent halt.

    Returns:
        JSON dict with ``rip, rsp, rbp, rax..r15, eflags, cs, cr0..cr4``
        as hex strings.
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("regs"))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_regs")
