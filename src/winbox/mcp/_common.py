"""Shared helpers for all MCP tool modules — envelopes, state, guest-exec."""

from __future__ import annotations

import json as _json
import shutil
import threading as _threading
import uuid
from contextlib import contextmanager
from typing import Any

from winbox.config import Config
from winbox.vm import (
    VM,
    VMState,
    GuestAgent,
    GuestAgentError,
    GuestAgentUnreachable,
    GuestExecAbandoned,
)
from winbox.jobs import Job, JobMode, JobStore
from winbox.kdbg.errors import bounded_details


# ─── Research envelope ────────────────────────────────────────────────────────

_RESEARCH_ENVELOPE = "winbox.mcp/1"


def _research_ok(result: Any) -> dict[str, Any]:
    """Structured, compact contract for AI-facing research tools."""
    return {
        "schema": _RESEARCH_ENVELOPE,
        "ok": True,
        "result": result,
        "error": None,
    }


def _research_error(exc: BaseException | str, *, operation: str) -> dict[str, Any]:
    """Classify common failures so an agent can recover without prose parsing."""
    message = str(getattr(exc, "message", exc))
    lower = message.lower()
    code = "operation_failed"
    retryable = False
    recovery: list[str] = []
    details: dict[str, Any] = {}
    typed_code = getattr(exc, "code", None)
    if (
        isinstance(typed_code, str)
        and 1 <= len(typed_code) <= 64
        and all(c.islower() or c.isdigit() or c == "_" for c in typed_code)
    ):
        code = typed_code
        retryable = bool(getattr(exc, "retryable", False))
        details = bounded_details(getattr(exc, "details", {}))
        recovery_by_code = {
            "no_session": ["Call kdbg_attach with the target PID, then retry."],
            "stale_stop": ["Call kdbg_context at the current halt and retry without the stale cursor."],
            "busy": ["Poll the active operation or interrupt it before retrying."],
            "timeout": ["Check status before retrying with a bounded larger timeout."],
            "worker_version_mismatch": ["Reload the MCP client or run kdbg_decomp_status, then retry."],
            "identity_mismatch": ["Refresh the target module and symbols, then retry with the verified binary."],
            "worker_not_running": ["Run kdbg_ghidra_run or retry the decompilation request."],
            "stale_heartbeat": ["Inspect kdbg_decomp_status and restart the worker if the heartbeat remains stale."],
            "analysis_required": ["Detach or continue the halted target, run kdbg_decomp_prepare for the verified module, then retry."],
            "incomplete_result": ["Retry after the kernel list is stable, or set require_complete=false to inspect the validated prefix."],
            "snapshot_budget_exceeded": ["Retry with a narrower scope or filter; the guest was already resumed."],
            "cr3_poisoned": ["Detach without resuming and restore a safe VM snapshot or original CR3."],
        }
        recovery = recovery_by_code.get(code, [])
    elif ("no kdbg session" in lower or "no session is attached" in lower
            or "no kdbg daemon" in lower or "daemon is not running" in lower):
        code = "no_session"
        recovery = ["Call kdbg_attach with the target PID, then retry."]
    elif ("stop changed" in lower or "stale" in lower
          or "continuation no longer matches" in lower
          or "stop id" in lower and "does not match" in lower):
        code = "stale_stop"
        retryable = True
        recovery = ["Call kdbg_context at the current halt and retry without the stale cursor."]
    elif "busy" in lower or "already active" in lower:
        code = "busy"
        retryable = True
        recovery = ["Poll the active operation or interrupt it before retrying."]
    elif "timeout must be" in lower:
        code = "invalid_argument"
    elif "timed out" in lower or "timeout" in lower:
        code = "timeout"
        retryable = True
        recovery = ["Check status before retrying with a bounded larger timeout."]
    elif "worker api" in lower or "reload/version" in lower:
        code = "worker_version_mismatch"
        recovery = ["Reload the MCP client or run kdbg_decomp_status, then retry."]
    elif ("identity" in lower or "wrong build" in lower
          or "exact cached pe" in lower or "codeview" in lower):
        code = "identity_mismatch"
        recovery = ["Refresh the target module and symbols, then retry with the verified binary."]
    elif ("not installed" in lower or "unavailable" in lower
          or "not listening" in lower or "not found" in lower):
        code = "prerequisite_missing"
        recovery = ["Inspect the relevant status tool and install or start the missing prerequisite."]
    elif ("must be" in lower or "between" in lower or "at most" in lower
          or "cap is" in lower or "mutually exclusive" in lower
          or "invalid" in lower or "not a valid" in lower or "requires detail" in lower
          or "too large" in lower
          or "does not match the current job" in lower):
        code = "invalid_argument"
    error = {
        "code": code,
        "message": message[:2048],
        "operation": operation,
        "retryable": retryable,
        "recovery": recovery[:3],
    }
    if details:
        error["details"] = details
    return {
        "schema": _RESEARCH_ENVELOPE,
        "ok": False,
        "result": None,
        "error": error,
    }


# ─── Shared state ───────────────────────────────────────────────────────────

_cfg: Config | None = None
_vm: VM | None = None
_ga: GuestAgent | None = None
_initialized = False
_state_lock = _threading.Lock()


def _get_state() -> tuple[Config, VM, GuestAgent]:
    global _cfg, _vm, _ga, _initialized
    if not _initialized:
        with _state_lock:
            if not _initialized:
                cfg = Config.load()
                vm = VM(cfg)
                ga = GuestAgent(cfg)
                _cfg, _vm, _ga = cfg, vm, ga
                _initialized = True
    return _cfg, _vm, _ga


def _ensure_vm_ready() -> tuple[Config, VM, GuestAgent]:
    """Ensure VM is running and guest agent is responding. Starts if needed."""
    cfg, vm, ga = _get_state()
    state = vm.state()

    if state == VMState.NOT_FOUND:
        raise RuntimeError("VM not found. Run 'winbox setup' first.")

    if state == VMState.RUNNING:
        if not ga.ping():
            try:
                ga.wait(timeout=60)
            except GuestAgentError:
                raise RuntimeError("Guest agent not responding.")
        return cfg, vm, ga

    if state == VMState.SHUTOFF:
        vm.start()
    elif state == VMState.PAUSED:
        from winbox.kdbg.debugger.client import DaemonClient
        if DaemonClient(cfg).session_alive():
            raise RuntimeError(
                "VM is halted by a kdbg debug session. "
                "Run kdbg_cont to resume, or kdbg_detach to end the session."
            )
        vm.resume()
    elif state == VMState.SAVED:
        vm.start()
    else:
        raise RuntimeError(f"VM in unexpected state: {state.value}")

    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        raise RuntimeError("Guest agent not responding after starting VM.")

    return cfg, vm, ga


# ─── Internal: guest-exec error translation ────────────────────────────────

def _guest_error_message(exc: GuestAgentError, vm: VM) -> str:
    """Turn a guest-exec failure into an actionable one-liner for the client."""
    base = str(exc)
    try:
        state = vm.state()
    except Exception:
        state = None
    if state is not None and state != VMState.RUNNING:
        return f"{base}\nVM state: {state.value} — try 'winbox up' and retry."
    if isinstance(exc, (GuestExecAbandoned, GuestAgentUnreachable)):
        return (
            f"{base}\nGuest agent unreachable — the VM may have rebooted or "
            f"paused; try 'winbox up --reboot' and retry."
        )
    return base


@contextmanager
def _guest_errors(vm: VM):
    """Re-raise a guest-exec failure as a RuntimeError with an actionable hint."""
    try:
        yield
    except GuestAgentError as e:
        raise RuntimeError(_guest_error_message(e, vm)) from e


# ─── Internal: Python execution ────────────────────────────────────────────

def _exec_python(
    code: str,
    timeout: int = 300,
    args: dict | None = None,
    user: str | None = None,
    password: str | None = None,
) -> dict:
    """Write Python code to VirtIO-FS and execute in VM.

    Each call gets its own subdirectory under ``Z:\\.mcp\\<uuid>\\`` so
    two concurrent tool invocations cannot clobber each other's
    script.py / args.json.

    Returns dict with exitcode, stdout, stderr.
    """
    cfg, vm, ga = _ensure_vm_ready()

    call_id = uuid.uuid4().hex
    call_dir = cfg.shared_dir / ".mcp" / call_id
    call_dir.mkdir(parents=True, exist_ok=True)

    vm_call_dir = f"Z:\\.mcp\\{call_id}"
    vm_script = f"{vm_call_dir}\\script.py"
    vm_args = f"{vm_call_dir}\\args.json"

    rewritten = code.replace(r"Z:\.mcp\args.json", vm_args)

    script_path = call_dir / "script.py"
    args_path = call_dir / "args.json"
    script_path.write_text(rewritten, encoding="utf-8")

    if args is not None:
        args_path.write_text(_json.dumps(args), encoding="utf-8")

    try:
        with _guest_errors(vm):
            if user is None and password is None:
                result = ga.exec(f"python.exe {vm_script}", timeout=timeout)
            else:
                result = ga.exec_argv(
                    "python.exe", [vm_script], timeout=timeout,
                    user=user, password=password,
                )
        return {
            "exitcode": result.exitcode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    finally:
        shutil.rmtree(call_dir, ignore_errors=True)


def _format_exec_result(result: dict) -> str:
    """Flatten an _exec_python result into the prose blob the MCP tool wrappers
    return today.
    """
    if isinstance(result, dict):
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        exitcode = result.get("exitcode", 0)
    else:
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""
        exitcode = getattr(result, "exitcode", 0)

    parts: list[str] = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(f"\n[stderr]\n{stderr}")
    if exitcode != 0:
        parts.append(f"\n[exit code: {exitcode}]")
        if not stdout and not stderr:
            parts.append(
                "\n(no output on either stream — the in-guest process most "
                "likely died before it could flush: killed externally, e.g. "
                "by Defender behavior monitoring, or crashed in native code)"
            )
    return "".join(parts) or "(no output)"


# ─── Background jobs ─────────────────────────────────────────────────────────


def _bg_label(kind: str, code: str) -> str:
    """A short, non-leaky command label for `winbox jobs list`."""
    first = next((ln.strip() for ln in code.splitlines() if ln.strip()), "")
    if len(first) > 50:
        first = first[:47] + "..."
    return f"{kind} (bg): {first}" if first else f"{kind} (bg)"


def _launch_bg_job(cfg: Config, launch, label: str) -> str:
    """Claim a job id, run ``launch(job_id, nonce) -> pid`` under the store
    lock, persist a BUFFERED Job with a PID-recycle nonce, and return a
    ``{background, job_id, pid}`` handle.
    """
    store = JobStore(cfg)
    nonce = f"__wbx{uuid.uuid4().hex[:16]}__"

    def _build(job_id: int) -> Job:
        pid = launch(job_id, nonce)
        return Job(
            id=job_id, pid=pid, command=label,
            mode=JobMode.BUFFERED, nonce=nonce,
        )

    job = store.claim(_build)
    return _json.dumps({"background": True, "job_id": job.id, "pid": job.pid})


def _execution_json(result) -> str:
    return _json.dumps({
        "stdout": result.stdout, "stderr": result.stderr,
        "exitcode": result.exitcode,
    })
