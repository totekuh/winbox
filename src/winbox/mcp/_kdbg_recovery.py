"""kdbg session recovery tools — detach, resume."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp._common import _get_state, _research_ok, _research_error
from winbox.mcp._kdbg_session import _kdbg_client, _kdbg_cfg_only

from winbox.kdbg.debugger.client import ClientError as _ClientError
from winbox.kdbg.debugger.rsp import RspClient as _RspClient
from winbox.kdbg.debugger.rsp import RspError as _RspError
from winbox.vm import VMState


@mcp.tool()
def kdbg_detach() -> dict[str, Any]:
    """Tear down kdbg and resume only when the daemon certifies it is safe.

    A poisoned or indeterminate session releases daemon ownership but leaves
    the VM untouched and returns explicit recovery guidance. Safe to call when
    no session is active — returns "no session".
    """
    cfg = _kdbg_cfg_only()
    client = _kdbg_client(cfg)
    if not client.session_alive():
        return _research_ok({"detached": False, "already_detached": True})
    from winbox.kdbg.debugger.continue_job import (
        ACTIVE_STATES, ContinueJobError, cancel_continue, poll_continue,
        wait_continue,
    )
    try:
        job = poll_continue(cfg)
        if job.get("state") in ACTIVE_STATES:
            cancel_continue(cfg, token=str(job["token"]))
            wait_continue(cfg, token=str(job["token"]), timeout=5.0)
    except ContinueJobError as exc:
        return _research_error(exc, operation="kdbg_detach")
    detach_result: dict[str, Any] | None = None
    detach_error: _ClientError | None = None
    try:
        detach_result = client.call("detach")
    except _ClientError as exc:
        detach_error = exc
    import time as _time
    from winbox.kdbg.hmp import ensure_not_paused

    deadline = _time.monotonic() + 5.0
    detached = False
    warning: str | None = "daemon didn't exit within 5s; lock may be stale"
    while _time.monotonic() < deadline:
        if not client.session_alive():
            detached = True
            warning = None
            break
        _time.sleep(0.1)
    if detach_error is not None:
        warning = (
            f"detach request failed: {detach_error}; automatic resume skipped "
            "because the daemon did not certify it as safe"
        )

    resume_safe = bool(
        detach_result is not None and detach_result.get("resume_safe") is True
    )
    note = None
    if detached and resume_safe:
        note = ensure_not_paused(cfg.vm_name)
    recovery = detach_result.get("recovery") if detach_result else None
    return _research_ok({
        "detached": detached,
        "warning": warning,
        "resume_safe": resume_safe,
        "cr3_poisoned": bool(
            detach_result and detach_result.get("cr3_poisoned") is True
        ),
        "recovery": recovery or note or None,
    })


@mcp.tool()
def kdbg_resume(port: int = 1234) -> dict[str, Any]:
    """Recovery valve — resume a VM stuck in 'paused (debug)' state.

    Connects briefly to the gdbstub and sends cont+detach so QEMU's
    gdb_continue() runs the VM. Use when a daemon crashed mid-session
    or a script bailed without cleanup. No-op if VM is already running.

    Args:
        port: gdbstub port to talk through.
    """
    cfg, vm, _ = _get_state()
    if vm.state() == VMState.RUNNING:
        return _research_ok({"resumed": False, "already_running": True})

    client = _kdbg_client(cfg)
    if client.session_alive():
        return _research_error(
            "a kdbg session is active; call kdbg_detach instead",
            operation="kdbg_resume",
        )

    from winbox.kdbg.hmp import probe_port as _kdbg_probe_port
    if not _kdbg_probe_port("127.0.0.1", port):
        return _research_error(
            f"gdbstub not listening on 127.0.0.1:{port}", operation="kdbg_resume"
        )

    try:
        c = _RspClient.connect("127.0.0.1", port, timeout=5)
    except (OSError, _RspError) as e:
        return _research_error(
            f"gdbstub connect failed: {e}", operation="kdbg_resume"
        )
    try:
        try:
            c.handshake()
            c.query_halt_reason()
            c.cont()
        except (_RspError, OSError) as e:
            return _research_error(
                f"gdbstub resume failed: {e}", operation="kdbg_resume"
            )
    finally:
        c.close()

    import time as _time
    _time.sleep(0.3)
    final = vm.state()
    if final == VMState.RUNNING:
        return _research_ok({"resumed": True, "state": final.value})
    return _research_error(
        f"VM state after release: {final.value}", operation="kdbg_resume"
    )
