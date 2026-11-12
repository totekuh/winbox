"""kdbg daemon session tools — attach, bp, bps, bp-trace, rm, intents."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import _get_state, _research_ok, _research_error

from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStoreError as _KdbgStoreError,
)
from winbox.kdbg.debugger.client import DaemonClient as _DaemonClient
from winbox.kdbg.debugger.client import ClientError as _ClientError
from winbox.kdbg.debugger.daemon import DaemonError as _DaemonError
from winbox.kdbg.debugger.daemon import fork_daemon as _fork_daemon
from winbox.kdbg.debugger.reader import stop_reader as _kdbg_stop_reader
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.vm import VMState

from winbox.mcp._kdbg_infra import _kdbg_get_store


def _kdbg_client(cfg) -> "_DaemonClient":
    return _DaemonClient(cfg)


def _kdbg_cfg_only():
    """Get cfg without _ensure_vm_ready's resume-on-paused logic.

    Daemon-driven tools (bp, cont, regs, mem, etc.) require the VM to
    be paused via gdbstub. Calling _ensure_vm_ready here would
    forcibly resume the VM out from under the gdbstub, breaking the
    debug session. Use this lighter helper instead — it just returns
    cfg without messing with VM state.
    """
    cfg, _, _ = _get_state()
    return cfg


@mcp.tool()
def kdbg_attach(
    pid: int, port: int = 1234, staging_policy: str = "full",
    preflight: bool = False, prewarm: bool = False,
    apply_intents: bool = False,
) -> dict[str, Any]:
    """Attach a kdbg debugging session to a Windows process via the gdbstub.

    Before taking QEMU's single RSP connection, freezes the target's native
    and WoW64 loader entries into a bounded, content-addressed exact-binary
    manifest and enriches matching PDB metadata when available. Then forks a
    long-running daemon that holds the gdb connection alive
    across subsequent MCP tool calls. Only one session can be active at
    a time (fcntl-locked); call ``kdbg_detach`` before re-attaching.

    Requires the gdbstub to be running (``kdbg_start``) and nt symbols
    to be loaded (``kdbg_symbols_load``).

    Args:
        pid: Target Windows process PID (find via ``kdbg_ps``).
        port: gdbstub TCP port the daemon should connect to.
        staging_policy: ``full`` (copy + enrich), ``binaries`` (copy/reuse
            only), or ``cached-only`` (no guest copies or downloads).
        preflight: Return the bounded loader/staging plan without copying
            artifacts, taking the gdbstub, or attaching a daemon.
        prewarm: After attach, start background Ghidra preparation for every
            exact symbol-enriched module; the VM is not held for this work.
        apply_intents: Explicitly snapshot saved module-relative breakpoint
            intents and install only those resolved by this fresh attach.

    Returns:
        The common envelope with daemon PID, target, gdbstub metadata, and
        bounded ``auto_stage`` counts/failures.
    """
    if not isinstance(apply_intents, bool):
        return _research_error(
            "apply_intents must be a boolean", operation="kdbg_attach",
        )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    client = _kdbg_client(cfg)
    if client.session_alive():
        info = client.session_info() or {}
        return _research_error(
            f"another session is active "
            f"(target {info.get('target_name', '?')}({info.get('target_pid', '?')}), "
            f"daemon_pid={info.get('daemon_pid', '?')}); call kdbg_detach first",
            operation="kdbg_attach",
        )

    from winbox.kdbg.staging import (
        StagingError as _KdbgStagingError,
        preflight_user_module_staging as _kdbg_preflight_staging,
        prepare_user_module_manifest as _kdbg_prepare_manifest,
    )
    try:
        from winbox.kdbg.breakpoint_intent import (
            BreakpointIntentError,
            BreakpointIntentStore,
        )
        intent_snapshot = (
            BreakpointIntentStore(cfg).inventory()["intents"]
            if apply_intents else None
        )
        if preflight:
            plan = _kdbg_preflight_staging(
                cfg, _kdbg_get_store(), pid, policy=staging_policy,
            )
            plan["prewarm_requested"] = bool(prewarm)
            plan["breakpoint_intents"] = {
                "apply_requested": bool(apply_intents),
                "count": len(intent_snapshot or []),
                "intents": intent_snapshot or [],
            }
            return _research_ok(plan)
        manifest = _kdbg_prepare_manifest(
            cfg, ga, _kdbg_get_store(), pid,
            enrich_symbols=staging_policy == "full", policy=staging_policy,
        )
    except (
        _KdbgStagingError, _KdbgStoreError, _KdbgSymbolLoadError,
        BreakpointIntentError,
    ) as e:
        return _research_error(e, operation="kdbg_attach")

    _kdbg_stop_reader(cfg)
    from winbox.kdbg.hmp import gdbstub_has_client
    if gdbstub_has_client(port):
        return _research_error(
            f"another gdb client is already connected to port {port}. "
            f"Disconnect it first — QEMU's gdbstub accepts only one client.",
            operation="kdbg_attach",
        )

    try:
        daemon_pid = _fork_daemon(
            cfg, pid, gdbstub_port=port, module_manifest=manifest,
            breakpoint_intents=intent_snapshot,
        )
    except _DaemonError as e:
        return _research_error(e, operation="kdbg_attach")
    info = client.session_info() or {}
    result = {
        "daemon_pid": daemon_pid,
        "target": {
            "pid": info.get("target_pid", pid),
            "dtb": info.get("target_dtb", "?"),
            "name": info.get("target_name", "?"),
        },
        "gdbstub_port": info.get("gdbstub_port", port),
        "auto_stage": manifest.summary(),
    }
    if isinstance(info.get("breakpoint_intents"), dict):
        result["breakpoint_intents"] = info["breakpoint_intents"]
    if prewarm:
        from winbox.kdbg.decomp import DecompError, start_prepare_background
        modules = sorted({
            item.store_name for item in manifest.modules if item.store_build
        })
        try:
            if not modules:
                raise DecompError("no symbol-enriched exact modules are available")
            result["prewarm"] = start_prepare_background(cfg, modules=modules)
        except DecompError as exc:
            result["prewarm_error"] = _research_error(
                exc, operation="kdbg_decomp_prepare",
            )["error"]

    try:
        from winbox import hvci as _hvci
        hvci_state = _hvci.status(ga)
        if hvci_state.hvci_enabled:
            result["warning"] = (
                "HVCI is enabled — kernel breakpoints will not work. "
                "Run hvci_disable(confirm=true) first."
            )
    except Exception:
        pass

    return _research_ok(result)


@mcp.tool()
def kdbg_session() -> dict[str, Any]:
    """Show current kdbg session info, or report no session.

    Safe to call when nothing is attached — returns ``{"attached": false}``
    rather than erroring. Use this to check session state before
    operations that require an attached daemon.
    """
    cfg = _kdbg_cfg_only()
    client = _kdbg_client(cfg)
    if not client.session_alive():
        return _research_ok({"attached": False, "pagewalk": cfg.kdbg_pagewalk})
    try:
        result = client.call("status")
    except _ClientError as e:
        return _research_error(e, operation="kdbg_session")
    return _research_ok({"attached": True, "pagewalk": cfg.kdbg_pagewalk, **result})


@mcp.tool()
def kdbg_target_status() -> dict[str, Any]:
    """Probe the captured target identity as alive, exiting, gone, or unknown.

    The probe is bounded and compares EPROCESS plus create-time evidence. It
    reports PID reuse as the original target being gone and never rebinds the
    debugger session to the replacement process.
    """
    try:
        return _research_ok(_kdbg_client(_kdbg_cfg_only()).call("target_status"))
    except _ClientError as exc:
        return _research_error(exc, operation="kdbg_target_status")


@mcp.tool()
def kdbg_bp_intent_add(
    target: str,
    mode: str = "hw",
    condition: str | None = None,
    wp_type: str | None = None,
    wp_size: int = 1,
    actions: list[str] | None = None,
) -> dict[str, Any]:
    """Persist a detached module-relative breakpoint intent without touching the VM.

    The target must use ``module+0xoffset``. No virtual address is saved and
    no breakpoint is installed until a later explicit
    ``kdbg_attach(..., apply_intents=true)`` resolves it against that attach's
    fresh staged manifest.
    """
    from winbox.kdbg.breakpoint_intent import (
        BreakpointIntentError,
        BreakpointIntentStore,
    )

    try:
        result = BreakpointIntentStore(_kdbg_cfg_only()).add(
            target, mode=mode, condition=condition, wp_type=wp_type,
            wp_size=wp_size, actions=actions,
        )
        return _research_ok(result)
    except BreakpointIntentError as exc:
        return _research_error(exc, operation="kdbg_bp_intent_add")


@mcp.tool()
def kdbg_bp_intents() -> dict[str, Any]:
    """List durable breakpoint intents without attaching or touching the VM."""
    from winbox.kdbg.breakpoint_intent import (
        BreakpointIntentError,
        BreakpointIntentStore,
    )

    try:
        return _research_ok(BreakpointIntentStore(_kdbg_cfg_only()).inventory())
    except BreakpointIntentError as exc:
        return _research_error(exc, operation="kdbg_bp_intents")


@mcp.tool()
def kdbg_bp_intent_remove(intent_id: int) -> dict[str, Any]:
    """Remove one durable breakpoint intent by its stable non-negative ID."""
    from winbox.kdbg.breakpoint_intent import (
        BreakpointIntentError,
        BreakpointIntentStore,
    )

    try:
        return _research_ok(
            BreakpointIntentStore(_kdbg_cfg_only()).remove(intent_id)
        )
    except BreakpointIntentError as exc:
        return _research_error(exc, operation="kdbg_bp_intent_remove")


@mcp.tool()
def kdbg_bp(
    target: str,
    mode: str = "hw",
    condition: str | None = None,
    wp_type: str | None = None,
    wp_size: int = 1,
    actions: list[str] | None = None,
) -> dict[str, Any]:
    """Install a breakpoint or watchpoint at TARGET in the attached process.

    Defaults to **hardware breakpoint** (CPU debug register, Z1
    packet) — invisible to PatchGuard (no code modification) AND
    invisible to in-guest ``GetThreadContext(CONTEXT_DEBUG_REGISTERS)``
    checks because KVM virtualizes DR access (the guest sees its
    own shadow DRs which are zero, not the actual hardware DRs we
    set). Limit: 4 active per vCPU.

    Args:
        target: Symbol (``module!sym``), hex VA, or staged
            ``module+0xoffset``.
        mode: ``"hw"`` (default) or ``"soft"``.
        condition: Optional predicate expression.
        wp_type: ``"write"``, ``"read"``, or ``"access"`` for watchpoints.
        wp_size: Watched region size (1, 2, 4, or 8).
        actions: Up to 16 expression strings for auto-continue trace logging.
    """
    cfg = _kdbg_cfg_only()
    if condition is not None and not condition.strip():
        condition = None
    if wp_type is not None and not wp_type.strip():
        wp_type = None
    kwargs = {"target": target, "mode": mode, "condition": condition}
    if wp_type is not None:
        kwargs["wp_type"] = wp_type
        kwargs["wp_size"] = int(wp_size)
    if actions is not None:
        kwargs["actions"] = actions
    try:
        return _research_ok(_kdbg_client(cfg).call("bp_add", **kwargs))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_bp")


@mcp.tool()
def kdbg_bps() -> dict[str, Any]:
    """List all installed breakpoints in the current session."""
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("bp_list"))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_bps")


@mcp.tool()
def kdbg_bp_trace(
    bp_id: int,
    tail: int = 20,
    from_hit: int | None = None,
    limit: int = 20,
    expression: str | None = None,
    value: str | None = None,
    errors_only: bool = False,
    summary: bool = False,
    top: int = 10,
) -> dict[str, Any]:
    """Query the trace log for a breakpoint with actions.

    Args:
        bp_id: Breakpoint id (from ``kdbg_bp`` / ``kdbg_bps``).
        tail: Newest matching entries (1-200, default 20).
        from_hit: Inclusive hit-id cursor for forward pagination.
        limit: Maximum entries in a forward page (1-200).
        expression: Exact action expression to filter.
        value: Exact value filter.
        errors_only: Return only hits containing errors.
        summary: Include bounded per-expression distributions.
        top: Top values per expression in summary (1-20).
    """
    cfg = _kdbg_cfg_only()
    kwargs = {
        "id": bp_id,
        "tail": int(tail),
        "limit": int(limit),
        "errors_only": errors_only,
        "summary": summary,
        "top": int(top),
    }
    if from_hit is not None:
        kwargs["from_hit"] = int(from_hit)
    if expression is not None:
        kwargs["expression"] = expression
    if value is not None:
        kwargs["value"] = value
    try:
        return _research_ok(_kdbg_client(cfg).call("bp_trace", **kwargs))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_bp_trace")


@mcp.tool()
def kdbg_rm(bp_id: int) -> dict[str, Any]:
    """Remove a breakpoint by id.

    Args:
        bp_id: The id reported by ``kdbg_bp`` / ``kdbg_bps``.
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("bp_remove", id=bp_id))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_rm")
