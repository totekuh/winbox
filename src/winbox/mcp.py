"""MCP control plane for the winbox Windows vulnerability-research platform."""

from __future__ import annotations

import json as _json
import shutil
import textwrap
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from winbox.config import Config
from winbox import __version__ as _winbox_version
from winbox.vm import (
    VM,
    VMState,
    GuestAgent,
    GuestAgentError,
    GuestAgentUnreachable,
    GuestExecAbandoned,
)
from winbox.jobs import Job, JobMode, JobStatus, JobStore
# Private, but reused deliberately: it decodes PowerShell's CLIXML stderr to
# plain text and is a no-op on anything else, so job_result can apply it to
# both python and powershell job output without knowing which is which.
from winbox.vm.guest import _clixml_to_text
from winbox.kdbg.errors import bounded_details
from winbox.kdbg.doctor import collect_doctor as _kdbg_collect_doctor
from winbox.kdbg.catalog import (
    MCP_CATALOG_REVISION as _MCP_CATALOG_REVISION,
    MCP_TOOL_COUNT as _MCP_TOOL_COUNT,
)
from winbox.kdbg.presentation import (
    filetime_utc as _kdbg_filetime_utc,
    thread_presentation_fields as _kdbg_thread_presentation_fields,
)
from winbox.kdbg.thread_baseline import (
    ThreadBaselineError as _KdbgThreadBaselineError,
    ThreadBaselineStore as _KdbgThreadBaselineStore,
    capture_threads as _kdbg_capture_thread_baseline,
)
from winbox.kdbg.thread_triage import (
    GlobalThreadTriageError as _KdbgGlobalThreadTriageError,
    GlobalThreadTriageIncomplete as _KdbgGlobalThreadTriageIncomplete,
    triage_all_process_threads as _kdbg_triage_all_process_threads,
)
from winbox.kdbg.capture import (
    CaptureError as _KdbgCaptureError,
    CaptureStore as _KdbgCaptureStore,
    capture_live as _kdbg_capture_live,
    diff_captures as _kdbg_diff_captures,
)
from winbox.kdbg.objects import (
    ObjectEvidenceError as _KdbgObjectEvidenceError,
    ensure_object_layouts as _kdbg_ensure_object_layouts,
    handle_table_status as _kdbg_handle_table_status,
    object_header as _kdbg_object_header,
    token_evidence as _kdbg_token_evidence,
)
from winbox.kdbg.telemetry import summary as _kdbg_operation_summary
from winbox.kdbg.vad import (
    VadError as _KdbgVadError,
    ensure_vad_layouts as _kdbg_ensure_vad_layouts,
    list_vads as _kdbg_list_vads,
    lookup_vad as _kdbg_lookup_vad,
)

mcp = FastMCP(
    "winbox",
    instructions=(
        "Isolated Windows vulnerability-research platform for AI agents. "
        "Manage a QEMU/KVM Windows lab; execute and instrument targets; "
        "debug from the hypervisor with PDB symbols, breakpoints, and memory "
        "access; combine live stops with exact-binary static decompilation; "
        "exercise drivers and IPC; control defenses and networking; "
        "and collect bounded evidence."
    ),
)

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

import threading as _threading

_cfg: Config | None = None
_vm: VM | None = None
_ga: GuestAgent | None = None
# Set last, inside the lock, once all three globals are published. The
# fast-path guard keys on this flag rather than on _cfg so a thread that is
# preempted mid-init can never expose a half-built state (_cfg set but _vm/_ga
# still None) to a racing reader.
_initialized = False
# Guards the lazy init so two concurrent first-calls don't both build
# a Config / VM / GuestAgent. FastMCP can dispatch concurrent tool calls;
# while construction is idempotent today, the pattern is fragile.
_state_lock = _threading.Lock()


def _get_state() -> tuple[Config, VM, GuestAgent]:
    global _cfg, _vm, _ga, _initialized
    if not _initialized:
        with _state_lock:
            # Re-check inside the lock; another thread may have raced us here.
            if not _initialized:
                cfg = Config.load()
                vm = VM(cfg)
                ga = GuestAgent(cfg)
                _cfg, _vm, _ga = cfg, vm, ga
                # Publish the flag last: a racing reader on the fast path only
                # skips the lock once all three globals are in place.
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
    """Turn a guest-exec failure into an actionable one-liner for the client.

    Mirrors the UX ``cli/exec.py`` already gives on the terminal: surface the
    error, and — when the VM is no longer running, or the transport was lost
    mid-command — say what likely happened and what to do about it. Without
    this, a lost guest agent reached the MCP client as a bare exception string.
    """
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
    """Re-raise a guest-exec failure as a RuntimeError with an actionable hint.

    FastMCP renders a raised RuntimeError as a tool error the client sees —
    the same path ``_ensure_vm_ready`` already uses for VM-not-ready states.
    Only GA transport/exec failures are translated; a command that *ran* and
    merely exited non-zero still flows back as a normal result.
    """
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
    script.py / args.json. The hardcoded ``Z:\\.mcp\\args.json`` path
    in legacy script bodies is rewritten to point at the per-call file
    before the script is written to disk.

    The whole per-call subdir is removed in a finally block so the
    previous tool's code (which may include sensitive snippets) does
    not sit on the host share until the next invocation.

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

    13 wrappers used to inline the same six lines; one helper means a future
    formatting tweak (or a switch to structured JSON) is one change point.
    Accepts either the dict returned by _exec_python or any object with
    ``stdout`` / ``stderr`` / ``exitcode`` attributes (subprocess.run-style).
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
            # A bare "[exit code: 1]" is indistinguishable from a tool that
            # simply says nothing, and it is exactly what an externally
            # killed process leaves behind: Python block-buffers stdout to a
            # pipe, so a kill before interpreter shutdown discards it. Say so
            # rather than handing back a near-blank string.
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

    The caller's ``launch`` function must prefix its command with
    ``echo {nonce}&&`` so the nonce appears at the start of stdout.
    ``job_result`` later verifies this nonce before accepting output,
    preventing a recycled PID's unrelated output from being attributed
    to this job.

    Shares the JobStore that backs ``winbox exec --bg``, so a job launched here
    is visible to ``winbox jobs list`` and killable with ``winbox jobs kill``.
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


# ─── Tool 1: python ────────────────────────────────────────────────────────

def _execution_json(result) -> str:
    return _json.dumps({
        "stdout": result.stdout, "stderr": result.stderr,
        "exitcode": result.exitcode,
    })


@mcp.tool()
def python(
    code: str, timeout: int = 300,
    user: str | None = None, password: str | None = None,
    background: bool = False,
) -> str:
    """Execute Python code inside the Windows VM.

    By default the code runs in winbox's privileged guest-agent context. Pass
    both user and password to run it as that local Windows user instead.

    Returns a JSON-encoded ``{"stdout": str, "stderr": str, "exitcode": int}``.
    Structured (not prose) so a script that prints valid JSON to stdout can be
    safely json.loads-ed by the caller without stderr/exitcode noise mixing in.

    With ``background=True`` the call is fire-and-forget: it launches the script
    and returns ``{"background": true, "job_id": N, "pid": P}`` immediately
    without waiting for exit. Use this when the code may hang the guest (e.g. it
    triggers something you have halted at a kdbg breakpoint) — a synchronous
    call would block polling for a completion the frozen guest cannot report.
    Retrieve the output later with ``job_result(job_id)``.

    Args:
        code: Python source code to execute.
        timeout: Execution timeout in seconds (default 300). Ignored when
            background=True (the job is never waited on here).
        background: Launch detached and return a job handle instead of waiting.
    """
    if background:
        cfg, vm, ga = _ensure_vm_ready()

        def _launch(job_id: int, nonce: str) -> int:
            job_dir = cfg.shared_dir / ".mcp" / "jobs" / str(job_id)
            job_dir.mkdir(parents=True, exist_ok=True)
            (job_dir / "script.py").write_text(code, encoding="utf-8")
            kwargs = {}
            if user is not None or password is not None:
                kwargs.update(user=user, password=password)
            return ga.exec_background(
                f"echo {nonce}&&python.exe Z:\\.mcp\\jobs\\{job_id}\\script.py",
                **kwargs,
            )

        return _launch_bg_job(cfg, _launch, _bg_label("python", code))

    if user is None and password is None:
        result = _exec_python(code, timeout=timeout)
    else:
        result = _exec_python(
            code, timeout=timeout, user=user, password=password,
        )
    return _json.dumps({
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "exitcode": result["exitcode"],
    })


# ─── powershell ─────────────────────────────────────────────────────────────

@mcp.tool()
def powershell(
    script: str,
    timeout: int = 600,
    user: str | None = None,
    password: str | None = None,
    background: bool = False,
) -> str:
    """Execute PowerShell (Windows PowerShell 5.1) inside the Windows VM.

    Runs in the privileged guest-agent context by default, or as the specified
    local user when both ``user`` and ``password`` are supplied. Use this
    instead of shelling out to powershell.exe from the `python` tool — it
    removes the nested-quoting tax (backslash paths and quotes pass through
    verbatim) and returns errors as readable plain text (PowerShell's CLIXML
    stderr serialization is decoded for you; progress noise is dropped).

    Returns a JSON-encoded ``{"stdout": str, "stderr": str, "exitcode": int}``,
    same shape as `python`, so a script that prints JSON to stdout can be
    json.loads-ed cleanly.

    With ``background=True`` the call is fire-and-forget: it launches the script
    and returns ``{"background": true, "job_id": N, "pid": P}`` immediately
    without waiting for exit. Use this when the code may hang the guest (e.g. it
    triggers something you have halted at a kdbg breakpoint) — a synchronous
    call would block polling for a completion the frozen guest cannot report.
    Retrieve the output later with ``job_result(job_id)``.

    The script is sent via -EncodedCommand, which caps it at roughly 12k
    characters. For anything larger, use the `python` tool or upload a .ps1.
    Note: exitcode reflects ``exit N`` and terminating errors; a non-terminating
    PowerShell error lands on stderr with exitcode 0 (standard PS behavior).

    Args:
        script: PowerShell source to execute.
        timeout: Execution timeout in seconds (default 600). Ignored when
            background=True (the job is never waited on here).
        user: Optional local Windows username.
        password: Password for ``user``; both must be supplied together.
        background: Launch detached and return a job handle instead of waiting.
    """
    cfg, vm, ga = _ensure_vm_ready()
    if background:
        import base64 as _b64

        tagged_script = f"$ProgressPreference = 'SilentlyContinue'\n{script}"
        encoded = _b64.b64encode(
            tagged_script.encode("utf-16-le"),
        ).decode("ascii")
        ps_cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        kwargs = {}
        if user is not None or password is not None:
            kwargs.update(user=user, password=password)
        return _launch_bg_job(
            cfg,
            lambda job_id, nonce: ga.exec_background(
                f"echo {nonce}&&{ps_cmd}", **kwargs,
            ),
            _bg_label("powershell", script),
        )
    kwargs = {"timeout": timeout}
    if user is not None or password is not None:
        kwargs.update(user=user, password=password)
    result = ga.exec_powershell(script, **kwargs)
    return _execution_json(result)


# ─── exec ────────────────────────────────────────────────────────────────────

@mcp.tool()
def exec(  # noqa: A001
    command: str,
    timeout: int = 300,
    user: str | None = None,
    password: str | None = None,
    background: bool = False,
) -> str:
    """Run a command line in the Windows VM via cmd.exe.

    The plain-command counterpart to `python`/`powershell`: run a native exe, a
    built-in, a batch line — anything cmd.exe accepts — in the privileged
    guest-agent context by default or as the specified local user, with no
    Python-subprocess wrapper. Returns a JSON-encoded
    ``{"stdout": str, "stderr": str, "exitcode": int}``.

    With ``background=True`` the call is fire-and-forget: it launches the command
    and returns ``{"background": true, "job_id": N, "pid": P}`` immediately
    without waiting for exit — use it when the command may hang the guest (e.g.
    it triggers something you have halted at a kdbg breakpoint), which a
    synchronous call cannot survive. Retrieve the output with
    ``job_result(job_id)``.

    Args:
        command: The command line to run (as passed to ``cmd.exe /c``).
        timeout: Execution timeout in seconds (default 300). Ignored when
            background=True (the job is never waited on here).
        user: Optional local Windows username.
        password: Password for ``user``; both must be supplied together.
        background: Launch detached and return a job handle instead of waiting.
    """
    cfg, vm, ga = _ensure_vm_ready()
    if background:
        kwargs = {}
        if user is not None or password is not None:
            kwargs.update(user=user, password=password)
        return _launch_bg_job(
            cfg,
            lambda job_id, nonce: ga.exec_background(
                f"echo {nonce}&&{command}", **kwargs,
            ),
            _bg_label("exec", command),
        )
    kwargs = {"timeout": timeout}
    if user is not None or password is not None:
        kwargs.update(user=user, password=password)
    result = ga.exec(command, **kwargs)
    return _execution_json(result)


# ─── job_result ──────────────────────────────────────────────────────────────

@mcp.tool()
def job_result(job_id: int) -> str:
    """Fetch the result of a background exec()/python()/powershell() job.

    Background launches return a job_id immediately; this retrieves the output
    once the process has exited. It is a single, non-blocking poll: if the
    process is still running — including because the guest is halted at a kdbg
    breakpoint — it returns ``{"running": true}``. Call again after the guest
    resumes rather than blocking here (blocking would re-create the hang the
    background launch exists to avoid).

    Finished: ``{"job_id", "pid", "exitcode", "stdout", "stderr",
    "running": false}`` — PowerShell errors are CLIXML-decoded to plain text.
    Still running: ``{"job_id", "pid", "running": true}``.

    Args:
        job_id: The id returned by a background python()/powershell() call.
    """
    cfg, vm, ga = _ensure_vm_ready()
    store = JobStore(cfg)
    job = store.get(job_id)
    if job is None:
        return _json.dumps({"error": f"job {job_id} not found"})

    # Terminal already: the guest agent frees its result slot on the read that
    # first saw the exit, so the cached copy is the only one left — re-polling
    # could only ever collide with a recycled PID.
    if job.status in (JobStatus.DONE, JobStatus.FAILED):
        return _json.dumps({
            "job_id": job.id, "pid": job.pid, "exitcode": job.exitcode,
            "stdout": job.stdout, "stderr": job.stderr, "running": False,
        })
    if job.status is JobStatus.LOST:
        return _json.dumps({
            "job_id": job.id, "pid": job.pid,
            "error": "job lost — the VM was unavailable, output is unrecoverable",
        })

    try:
        status = ga.exec_status(job.pid)
    except GuestAgentError as e:
        # A transient poll failure is not proof the job is gone — report it as
        # still-running so the caller retries rather than losing the result.
        return _json.dumps({
            "job_id": job.id, "pid": job.pid, "running": True,
            "note": f"could not poll guest: {e}",
        })

    if not status["exited"]:
        return _json.dumps({"job_id": job.id, "pid": job.pid, "running": True})

    # ── Nonce verification (PID-recycle protection) ──────────────────────
    # BUFFERED jobs carry a nonce that was echo'd at the start of the
    # command.  If the output doesn't contain it, this PID was recycled
    # and the output belongs to an unrelated process.
    stdout = status["stdout"]
    if job.nonce:
        if job.nonce not in stdout:
            job.status = JobStatus.LOST
            store.update(job)
            return _json.dumps({
                "job_id": job.id, "pid": job.pid,
                "error": "PID recycled — nonce mismatch",
            })
        # Strip the nonce line from stdout — it's bookkeeping, not output.
        for sep in ("\r\n", "\n", ""):
            prefix = job.nonce + sep
            if stdout.startswith(prefix):
                stdout = stdout[len(prefix):]
                break

    job.exitcode = status["exitcode"]
    job.stdout = stdout
    job.stderr = _clixml_to_text(status["stderr"])
    job.status = JobStatus.DONE if job.exitcode == 0 else JobStatus.FAILED
    store.update(job)
    # The process is done with its script; drop the per-job scratch dir.
    shutil.rmtree(cfg.shared_dir / ".mcp" / "jobs" / str(job.id), ignore_errors=True)
    return _json.dumps({
        "job_id": job.id, "pid": job.pid, "exitcode": job.exitcode,
        "stdout": job.stdout, "stderr": job.stderr, "running": False,
    })


# ─── Tool 2: ioctl ─────────────────────────────────────────────────────────

@mcp.tool()
def ioctl(
    device: str,
    code: int,
    input_hex: str = "",
    output_size: int = 0,
    timeout: int = 30,
) -> str:
    """Send an IOCTL to a Windows device driver.

    Opens the device with CreateFileW, sends DeviceIoControl with the given
    control code and input buffer, returns the output buffer as hex.

    Args:
        device: Device path, e.g. '\\\\.\\C:' or '\\\\.\\PhysicalDrive0'.
        code: IOCTL control code (integer, e.g. 0x222000).
        input_hex: Input buffer as hex string (e.g. 'deadbeef'). Empty for no input.
        output_size: Expected output buffer size in bytes. 0 for no output.
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        device = args['device']
        ioctl_code = args['code']
        input_hex = args.get('input_hex', '')
        output_size = args.get('output_size', 0)

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            device,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            print(f"CreateFileW failed: error {err}", file=sys.stderr)
            sys.exit(1)

        try:
            in_buf = bytes.fromhex(input_hex) if input_hex else None
            in_size = len(in_buf) if in_buf else 0
            out_buf = ctypes.create_string_buffer(output_size) if output_size > 0 else None
            bytes_returned = wintypes.DWORD(0)

            ok = kernel32.DeviceIoControl(
                handle,
                ioctl_code,
                in_buf, in_size,
                out_buf, output_size,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ok:
                err = ctypes.get_last_error()
                print(f"DeviceIoControl failed: error {err}", file=sys.stderr)
                sys.exit(1)

            returned = bytes_returned.value
            if out_buf and returned > 0:
                print(out_buf.raw[:returned].hex())
            else:
                print(f"ok ({returned} bytes returned)")
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _exec_python(
        script,
        timeout=timeout,
        args={"device": device, "code": code, "input_hex": input_hex, "output_size": output_size},
    )
    return _format_exec_result(result)


# ─── Registry helpers (shared across reg_query / reg_set / reg_delete) ────

# Each `reg_*` tool sends an in-VM Python script. The hive-lookup and
# type-table snippets below used to be inlined five times across the
# three tools; one fix to the hive map (e.g. adding HKCC) had to happen
# in five places. Extracted as concatenable string blocks so each tool
# composes its body from these + tool-specific logic.

_REG_HIVE_LOOKUP = '''\
hive_map = {
    'HKLM': winreg.HKEY_LOCAL_MACHINE,
    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
    'HKCU': winreg.HKEY_CURRENT_USER,
    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
    'HKCR': winreg.HKEY_CLASSES_ROOT,
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKU': winreg.HKEY_USERS,
    'HKEY_USERS': winreg.HKEY_USERS,
}
parts = key_path.split('\\\\', 1)
hive_name = parts[0].rstrip(':')
subkey = parts[1] if len(parts) > 1 else ''
hive = hive_map.get(hive_name.upper())
if hive is None:
    print(f"Unknown hive: {hive_name}", file=sys.stderr)
    sys.exit(1)
'''

_REG_TYPE_NAMES = '''\
type_names = {
    winreg.REG_SZ: 'REG_SZ',
    winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
    winreg.REG_DWORD: 'REG_DWORD',
    winreg.REG_QWORD: 'REG_QWORD',
    winreg.REG_BINARY: 'REG_BINARY',
    winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
}
'''

_REG_TYPE_MAP = '''\
type_map = {
    'REG_SZ':        (winreg.REG_SZ,        lambda d: d),
    'REG_EXPAND_SZ': (winreg.REG_EXPAND_SZ, lambda d: d),
    'REG_DWORD':     (winreg.REG_DWORD,     lambda d: int(d, 0)),
    'REG_QWORD':     (winreg.REG_QWORD,     lambda d: int(d, 0)),
    'REG_BINARY':    (winreg.REG_BINARY,    lambda d: bytes.fromhex(d)),
    'REG_MULTI_SZ':  (winreg.REG_MULTI_SZ,  lambda d: d.split('\\n')),
}
'''


# ─── Tool 3: reg_query ─────────────────────────────────────────────────────

@mcp.tool()
def reg_query(key: str, value: str | None = None, timeout: int = 30) -> str:
    """Query a Windows registry key or value.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion').
        value: Specific value name to query. If omitted, lists all values under the key.
        timeout: Execution timeout in seconds (default 30).
    """
    if value is not None:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\nvalue_name = {value!r}\n\n"
            + _REG_HIVE_LOOKUP
            + _REG_TYPE_NAMES
            + textwrap.dedent('''\
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        data, reg_type = winreg.QueryValueEx(k, value_name)
                        type_name = type_names.get(reg_type, f'type({reg_type})')
                        if reg_type == winreg.REG_BINARY:
                            print(f"{value_name} ({type_name}): {data.hex()}")
                        elif reg_type == winreg.REG_MULTI_SZ:
                            print(f"{value_name} ({type_name}):")
                            for item in data:
                                print(f"  {item}")
                        else:
                            print(f"{value_name} ({type_name}): {data}")
                except FileNotFoundError:
                    print(f"Not found: {key_path}\\\\{value_name}", file=sys.stderr)
                    sys.exit(1)
            ''')
        )
    else:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\n\n"
            + _REG_HIVE_LOOKUP
            + _REG_TYPE_NAMES
            + textwrap.dedent('''\
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                name, data, reg_type = winreg.EnumValue(k, i)
                                type_name = type_names.get(reg_type, f'type({reg_type})')
                                if reg_type == winreg.REG_BINARY:
                                    print(f"{name} ({type_name}): {data.hex()}")
                                else:
                                    print(f"{name} ({type_name}): {data}")
                                i += 1
                            except OSError:
                                break
                        if i == 0:
                            print("(no values)")

                        # Enumerate subkeys
                        j = 0
                        subkeys = []
                        while True:
                            try:
                                subkeys.append(winreg.EnumKey(k, j))
                                j += 1
                            except OSError:
                                break
                        if subkeys:
                            print(f"\\nSubkeys ({j}):")
                            for sk in subkeys:
                                print(f"  {sk}")
                except FileNotFoundError:
                    print(f"Key not found: {key_path}", file=sys.stderr)
                    sys.exit(1)
            ''')
        )

    result = _exec_python(script, timeout=timeout)
    return _format_exec_result(result)


# ─── Tool 4: reg_set ───────────────────────────────────────────────────────

@mcp.tool()
def reg_set(
    key: str,
    value: str,
    data: str,
    value_type: str = "REG_SZ",
    timeout: int = 30,
) -> str:
    """Set a Windows registry value.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\MyKey'). Created if it doesn't exist.
        value: Value name to set.
        data: Data to write. For REG_DWORD/REG_QWORD pass the integer as a string.
              For REG_BINARY pass hex. For REG_MULTI_SZ pass items separated by '\\n'.
        value_type: Registry type - REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ.
        timeout: Execution timeout in seconds (default 30).
    """
    script = (
        f"import winreg\nimport sys\n\n"
        f"key_path = {key!r}\nvalue_name = {value!r}\n"
        f"raw_data = {data!r}\nreg_type_name = {value_type!r}\n\n"
        + _REG_HIVE_LOOKUP
        + _REG_TYPE_MAP
        + textwrap.dedent('''\
            # Accept the obvious shorthands ("dword", "reg_dword") rather than
            # failing a write over spelling.
            reg_type_name = reg_type_name.strip().upper()
            if not reg_type_name.startswith("REG_"):
                reg_type_name = "REG_" + reg_type_name
            if reg_type_name not in type_map:
                print(
                    f"Unknown type: {reg_type_name}. "
                    f"Expected one of: {', '.join(sorted(type_map))}",
                    file=sys.stderr,
                )
                sys.exit(1)

            reg_type, converter = type_map[reg_type_name]
            try:
                converted = converter(raw_data)
            except (ValueError, OverflowError) as e:
                print(f"Bad data for {reg_type_name}: {raw_data!r} ({e})",
                      file=sys.stderr)
                sys.exit(1)

            try:
                with winreg.CreateKey(hive, subkey) as k:
                    winreg.SetValueEx(k, value_name, 0, reg_type, converted)
            except (ValueError, OverflowError) as e:
                print(f"Bad data for {reg_type_name}: {raw_data!r} ({e})",
                      file=sys.stderr)
                sys.exit(1)
            except FileNotFoundError:
                print(f"Not found: {key_path}", file=sys.stderr)
                sys.exit(1)
            except PermissionError:
                print(f"Access denied: {key_path}", file=sys.stderr)
                sys.exit(1)
            print(f"Set {key_path}\\\\{value_name} = {raw_data} ({reg_type_name})")
        ''')
    )

    result = _exec_python(script, timeout=timeout)
    return _format_exec_result(result)


# ─── Tool 5: reg_delete ─────────────────────────────────────────────────────

@mcp.tool()
def reg_delete(key: str, value: str | None = None, timeout: int = 30) -> str:
    """Delete a Windows registry value or entire key.

    If value is provided, deletes that specific value. If omitted,
    deletes the entire key and all its subkeys.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\MyKey').
        value: Specific value name to delete. If omitted, deletes the entire key tree.
        timeout: Execution timeout in seconds (default 30).
    """
    if value is not None:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\nvalue_name = {value!r}\n\n"
            + _REG_HIVE_LOOKUP
            + textwrap.dedent('''\
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                        winreg.DeleteValue(k, value_name)
                    print(f"Deleted value {key_path}\\\\{value_name}")
                except FileNotFoundError:
                    print(f"Not found: {key_path}\\\\{value_name}", file=sys.stderr)
                    sys.exit(1)
                except PermissionError:
                    print(f"Access denied: {key_path}\\\\{value_name}", file=sys.stderr)
                    sys.exit(1)
            ''')
        )
    else:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\n\n"
            + _REG_HIVE_LOOKUP
            + textwrap.dedent('''\
                def delete_key_tree(hive, subkey):
                    try:
                        with winreg.OpenKey(hive, subkey, 0,
                                            winreg.KEY_ALL_ACCESS) as k:
                            while True:
                                try:
                                    child = winreg.EnumKey(k, 0)
                                    delete_key_tree(hive, f"{subkey}\\\\{child}")
                                except OSError:
                                    break
                        winreg.DeleteKey(hive, subkey)
                    except FileNotFoundError:
                        print(f"Not found: {key_path}", file=sys.stderr)
                        sys.exit(1)
                    except PermissionError:
                        print(f"Access denied: {key_path}", file=sys.stderr)
                        sys.exit(1)

                delete_key_tree(hive, subkey)
                print(f"Deleted key {key_path}")
            ''')
        )

    result = _exec_python(script, timeout=timeout)
    return _format_exec_result(result)


# ─── Tool 6: ps ────────────────────────────────────────────────────────────

@mcp.tool()
def ps(filter: str | None = None, timeout: int = 60) -> str:
    """List processes in the Windows VM with PID, name, path, and memory usage.

    Args:
        filter: Optional filter string. Matches against process name (case-insensitive).
                Example: 'svc' matches svchost.exe, 'lsass' matches lsass.exe.
        timeout: Execution timeout in seconds (default 60).
    """
    filter_repr = repr(filter) if filter else "None"
    script = textwrap.dedent(f"""\
        import json
        import subprocess
        import sys

        filter_str = {filter_repr}

        ps_script = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId, Name, ExecutablePath, WorkingSetSize, VirtualSize | "
            "Sort-Object WorkingSetSize -Descending | "
            "ForEach-Object {{ "
            "  $path = if ($_.ExecutablePath) {{ $_.ExecutablePath }} else {{ $null }}; "
            "  [PSCustomObject]@{{ "
            "    pid = $_.ProcessId; "
            "    name = $_.Name; "
            "    path = $path; "
            "    working_set_mb = [math]::Round($_.WorkingSetSize / 1MB, 1); "
            "    virtual_mb = [math]::Round($_.VirtualSize / 1MB, 1) "
            "  }} "
            "}} | ConvertTo-Json -Depth 1"
        )
        r = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_script],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            sys.exit(r.returncode)

        procs = json.loads(r.stdout)
        if isinstance(procs, dict):
            procs = [procs]
        if filter_str:
            procs = [p for p in procs if filter_str.lower() in p.get('name', '').lower()]
        print(json.dumps(procs, indent=2))
    """)

    result = _exec_python(script, timeout=timeout)
    return _format_exec_result(result)


# ─── Tool 5b: eventlogs ────────────────────────────────────────────────────

@mcp.tool()
def eventlogs(
    log: list[str] | str | None = None,
    since: str = "1h",
    ids: list[int] | None = None,
    provider: str | None = None,
    level: str | None = None,
    max_events: int = 100,
    timeout: int = 60,
) -> str:
    """Query Windows event logs via Get-WinEvent in the VM.

    Returns a JSON array of event objects with TimeCreated, LogName, Level,
    LevelDisplayName, Id, ProviderName, Message. Useful right after running
    a tool to see what Defender / Sysmon / Security audit logged in
    response.

    Args:
        log: Channel name(s). String or list. Default ['Security'].
             Examples: 'System', 'Microsoft-Windows-Sysmon/Operational',
             'Microsoft-Windows-Windows Defender/Operational'.
        since: Time range. 'Nh' / 'Nm' / 'Nd' / 'Nw' or ISO 8601. Default '1h'.
        ids: Event IDs to match (OR'd). Example [4624, 4625].
        provider: Provider name filter.
        level: 'Critical' | 'Error' | 'Warning' | 'Information' | 'Verbose'.
        max_events: Cap on returned events. Default 100.
        timeout: Seconds to wait for Get-WinEvent. Default 60.
    """
    from winbox.eventlogs import (
        EventQuery,
        build_powershell,
        parse_events,
        parse_since,
    )

    cfg, vm, ga = _ensure_vm_ready()

    if log is None:
        logs = ["Security"]
    elif isinstance(log, str):
        logs = [log]
    else:
        logs = list(log)

    try:
        since_dt = parse_since(since)
    except ValueError as e:
        return f"error: {e}"

    try:
        script = build_powershell(
            EventQuery(
                logs=logs,
                since=since_dt,
                ids=list(ids) if ids else [],
                provider=provider,
                level=level,
                max_events=int(max_events),
            )
        )
    except ValueError as e:
        return f"error: {e}"

    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        msg = (result.stderr or result.stdout or "Get-WinEvent failed").strip()
        return f"error (exit {result.exitcode}): {msg}"

    try:
        events = parse_events(result.stdout)
    except (ValueError, _json.JSONDecodeError) as e:
        return f"error: could not parse JSON: {e}"

    return _json.dumps(events, indent=2, default=str)


@mcp.tool()
def eventlogs_clear(
    log: list[str] | str | None = None,
    all_logs: bool = False,
    confirm: bool = False,
    timeout: int = 180,
) -> str:
    """Clear one or more Windows event log channels via wevtutil cl.

    DESTRUCTIVE: cleared logs cannot be recovered. The ``confirm`` flag
    must be set to True or the call is refused without touching the VM.
    Useful for setting up a clean slate before a controlled test.

    Returns a JSON object: ``{cleared, failed, total, errors}``.

    Args:
        log: Channel name(s). String or list of strings. Mutually
             exclusive with all_logs.
        all_logs: Clear EVERY channel reported by 'wevtutil el'. Many
                  channels are read-only / system-protected and will
                  fail; failures are counted but not surfaced
                  individually.
        confirm: Must be True to actually run. Default False is a
                 no-op safety so an LLM cannot accidentally wipe logs.
        timeout: Seconds to wait. Raise for all_logs on busy systems.
    """
    from winbox.eventlogs import build_clear_powershell, parse_clear_result

    if not confirm:
        return (
            "error: refusing to clear logs without confirm=True. "
            "Pass confirm=True to actually run; this is a destructive operation."
        )

    if log is None:
        logs: list[str] = []
    elif isinstance(log, str):
        logs = [log]
    else:
        logs = list(log)

    if all_logs and logs:
        return "error: log and all_logs are mutually exclusive"
    if not all_logs and not logs:
        return "error: either log (channel name) or all_logs=True is required"

    cfg, vm, ga = _ensure_vm_ready()

    try:
        script = build_clear_powershell(logs or None, all_logs=all_logs)
    except ValueError as e:
        return f"error: {e}"

    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        msg = (result.stderr or result.stdout or "wevtutil cl failed").strip()
        return f"error (exit {result.exitcode}): {msg}"

    try:
        info = parse_clear_result(result.stdout)
    except (ValueError, _json.JSONDecodeError) as e:
        return f"error: could not parse JSON: {e}"

    return _json.dumps(info, indent=2)


# ─── Tool 6: upload ────────────────────────────────────────────────────────

@mcp.tool()
def upload(src: str, dst: str | None = None, timeout: int = 60) -> str:
    """Upload a file from Kali to the Windows VM via VirtIO-FS.

    Copies the file to the shared directory on Kali, which is mounted
    as Z:\\ inside the VM. Optionally moves it to a different location
    in the VM afterwards.

    Args:
        src: Linux path on Kali (e.g. '/tmp/payload.dll' or '/opt/tools/mimikatz.exe').
        dst: Optional Windows destination path inside the VM. If omitted, the file
             stays at Z:\\<filename>. If provided, the file is copied from Z:\\ to dst.
        timeout: Execution timeout in seconds for the in-VM copy step (default 60).
    """
    import shutil

    # The host-side staging copy works regardless of VM state, but the
    # in-VM copy step needs a running VM + GA. _ensure_vm_ready surfaces
    # a clear "VM not running" error instead of letting a later
    # ga.exec timeout look like a network problem.
    cfg, vm, ga = _ensure_vm_ready() if dst is not None else _get_state()
    src_path = Path(src)

    if not src_path.exists():
        return f"Source not found on Kali: {src}"

    # Copy to shared dir (appears as Z:\ in VM)
    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    shared_dest = cfg.shared_dir / src_path.name
    shutil.copy2(src_path, shared_dest)
    size = shared_dest.stat().st_size

    if dst is None:
        return f"Uploaded {src_path.name} to Z:\\{src_path.name} ({size} bytes)"

    # Copy from Z:\ to final destination inside VM
    script = textwrap.dedent("""\
        import json
        import os
        import shutil
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        src = args['src']
        dst = args['dst']

        dst_dir = os.path.dirname(dst)
        if dst_dir:
            os.makedirs(dst_dir, exist_ok=True)

        shutil.copy2(src, dst)
        print(f"ok")
    """)
    vm_src = f"Z:\\{src_path.name}"
    result = _exec_python(
        script,
        timeout=timeout,
        args={"src": vm_src, "dst": dst},
    )
    if result["exitcode"] != 0:
        stderr = result["stderr"].strip() if result["stderr"] else "unknown error"
        return f"Uploaded to Z:\\{src_path.name} but copy to {dst} failed: {stderr}"

    return f"Uploaded {src_path.name} -> {dst} ({size} bytes)"


# ─── Tool 7: file_copy ─────────────────────────────────────────────────────

@mcp.tool()
def file_copy(src: str, dst: str, timeout: int = 60) -> str:
    """Copy a file within the Windows VM.

    Use for DLL sideloading, planting payloads, staging binaries, etc.
    Both paths are Windows paths inside the VM.
    Z:\\ is the VirtIO-FS share (~/.winbox/shared/ on Kali).

    Args:
        src: Source path (e.g. 'Z:\\\\tools\\\\cytool.exe' or 'C:\\\\Windows\\\\System32\\\\cmd.exe').
        dst: Destination path (e.g. 'C:\\\\temp\\\\cytool.exe').
        timeout: Execution timeout in seconds (default 60).
    """
    script = textwrap.dedent("""\
        import json
        import os
        import shutil
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        src = args['src']
        dst = args['dst']

        if not os.path.exists(src):
            print(f"Source not found: {src}", file=sys.stderr)
            sys.exit(1)

        # Create destination directory if needed
        dst_dir = os.path.dirname(dst)
        if dst_dir:
            os.makedirs(dst_dir, exist_ok=True)

        shutil.copy2(src, dst)
        size = os.path.getsize(dst)
        print(f"Copied {src} -> {dst} ({size} bytes)")
    """)

    result = _exec_python(
        script,
        timeout=timeout,
        args={"src": src, "dst": dst},
    )
    return _format_exec_result(result)


# ─── Tool 7: mem_read ──────────────────────────────────────────────────────

@mcp.tool()
def mem_read(pid: int, address: str, length: int, timeout: int = 30) -> str:
    """Read memory from a process in the Windows VM.

    Enables SeDebugPrivilege, opens the process with PROCESS_VM_READ,
    and calls ReadProcessMemory. Returns the data as a hex string.

    Address is a string (hex like '0x7ff600001000' or decimal) so kernel
    pointers above 2^53 do not lose precision on the JSON wire.
    PPL processes (lsass+RunAsPPL, MsMpEng) still cannot be opened from
    user-mode even with SeDebugPrivilege - use kdbg_read_va for those.

    Args:
        pid: Target process ID.
        address: Memory address (hex like '0x...' or decimal).
        length: Number of bytes to read (capped at 1MB).
        timeout: Execution timeout in seconds (default 30).
    """
    if length <= 0:
        return f"invalid length: {length} (must be > 0)"
    if length > 1024 * 1024:
        return f"invalid length: {length} (max 1MB per read)"
    try:
        addr_int = int(address, 0)
    except (ValueError, TypeError):
        return f"invalid address: {address!r}"
    if addr_int < 0:
        return f"invalid address: {addr_int} (must be >= 0)"

    script = textwrap.dedent(f"""\
        import ctypes
        from ctypes import wintypes
        import sys

        pid = {pid}
        address = {addr_int}
        size = {length}

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.ReadProcessMemory.restype = wintypes.BOOL
        kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
        advapi32.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE, wintypes.BOOL,
            ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD,
            ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD),
        ]

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        token = wintypes.HANDLE(0)
        if advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            try:
                luid = LUID()
                if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                    tp = TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid = luid
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                    advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
                    err = ctypes.get_last_error()
                    if err == 1300:
                        print("warn: SeDebugPrivilege not held (ERROR_NOT_ALL_ASSIGNED)", file=sys.stderr)
                else:
                    print(f"warn: LookupPrivilegeValueW failed: {{ctypes.get_last_error()}}", file=sys.stderr)
            finally:
                kernel32.CloseHandle(token)
        else:
            print(f"warn: OpenProcessToken failed: {{ctypes.get_last_error()}}", file=sys.stderr)

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400

        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            print(f"OpenProcess failed: error {{err}}", file=sys.stderr)
            sys.exit(1)

        try:
            buf = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buf,
                size,
                ctypes.byref(bytes_read),
            )
            if not ok:
                err = ctypes.get_last_error()
                print(f"ReadProcessMemory failed: error {{err}}", file=sys.stderr)
                sys.exit(1)

            data = buf.raw[:bytes_read.value]
            print(data.hex())
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _exec_python(script, timeout=timeout)
    return _format_exec_result(result)


# ─── Tool 8: service_stop / service_start ───────────────────────────────────

@mcp.tool()
def service_stop(name: str, timeout: int = 30) -> str:
    """Stop a Windows service.

    Uses sc.exe to stop the service. Useful for unloading drivers,
    stopping EDR agents, etc.

    Args:
        name: Service name (e.g. 'CyProtectDrv' or 'WinDefend').
        timeout: Execution timeout in seconds (default 30).
    """
    cfg, vm, ga = _ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec(f"sc.exe stop {name}", timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def service_start(name: str, timeout: int = 30) -> str:
    """Start a Windows service.

    Uses sc.exe to start the service. Useful for loading drivers,
    restarting services after modification, etc.

    Args:
        name: Service name (e.g. 'CyProtectDrv' or 'WinDefend').
        timeout: Execution timeout in seconds (default 30).
    """
    cfg, vm, ga = _ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec(f"sc.exe start {name}", timeout=timeout)
    return _format_exec_result(result)


# ─── Tool 8b: av_enable / av_disable / av_status ────────────────────────────
# Thin frontends over winbox.defender — the same enable/disable/status
# operations the `winbox av` CLI group calls, so the two never drift.

@mcp.tool()
def av_status(timeout: int = 15) -> str:
    """Report Windows Defender / AMSI protection state in the VM.

    Runs Get-MpComputerStatus + Get-MpPreference and summarises as
    ON / OFF / partial plus the individual RealTimeProtection, AMSI
    (ScriptScanning), BehaviorMonitoring, and IOAVProtection flags.
    Read-only — safe to call any time.

    Args:
        timeout: Execution timeout in seconds (default 15).
    """
    from winbox import defender

    cfg, vm, ga = _ensure_vm_ready()
    with _guest_errors(vm):
        status = defender.status(ga, timeout=timeout)
    return _format_exec_result(status)


@mcp.tool()
def av_enable() -> str:
    """Re-enable Windows Defender real-time protection, AMSI, and behavior monitoring.

    Removes the GP / non-policy registry overrides, starts the WinDefend
    service via sc.exe (PowerShell Start-Service is ACL-blocked), adds
    exclusions for the QEMU guest agent and the Z:\\ VirtIO-FS share so
    winbox tooling keeps working, then re-asserts the Set-MpPreference
    flags, and finally reports Defender's own status. May require a reboot
    to finish (WdFilter is a boot-start driver) — the return value says so
    when it does. Undo with av_disable.
    """
    from winbox import defender

    cfg, vm, ga = _ensure_vm_ready()
    steps: list[str] = []
    try:
        with _guest_errors(vm):
            outcome = defender.enable(ga, progress=steps.append)
    except defender.DefenderError as e:
        detail = _format_exec_result(e.result) if e.result is not None else ""
        return f"error: {e}\n{detail}".rstrip()

    if outcome.reboot_required:
        # A Win11 image built with the offline Defender disable keeps
        # WinDefend marked disabled in the SCM for the life of this boot, so
        # the corrected start types only apply after a restart — *if* they
        # were corrected at all. Verify before promising a reboot will help.
        unwritten = outcome.start_types_unwritten
        if unwritten:
            return (
                "error: WinDefend is disabled in this boot's SCM and the service "
                f"start types could NOT be restored from inside the guest "
                f"({', '.join(unwritten)} still wrong). Defender's "
                "Services\\*\\Start values are ACL-protected, so reg.exe cannot "
                "undo an offline disable from within Windows — rebooting and "
                "calling av_enable again will produce this same result. Run the "
                "host CLI `winbox av enable`, which powers the VM down and edits "
                "the SYSTEM hive offline."
            )
        return (
            "Defender service start types restored, but WinDefend is still "
            "disabled in this boot's SCM. Reboot the VM and call av_enable "
            "again to finish (the CLI `winbox av enable` does this for you)."
        )

    # Report what Defender says, not what we hoped for. WdFilter is a
    # boot-start driver: if it was disabled when this boot began, real-time
    # protection cannot arm this boot no matter what we just did — and an
    # agent told "enabled" runs its sample believing it is being scanned.
    # The CLI already verifies this (cli/av.py::_defender_fully_on); the MCP
    # twin is the frontend agents actually drive, so it must too.
    try:
        status_text = (defender.status(ga, timeout=60).stdout or "").strip()
    except GuestAgentError:
        status_text = ""
    if "Defender: ON" in status_text:
        return "Defender enabled (real-time, AMSI, behavior monitoring). Undo with av_disable."
    return (
        "Defender services started, but not every protection is active. "
        "WdFilter is a boot-start driver, so real-time protection cannot arm "
        "until the VM is rebooted. Reboot and call av_enable again (or run the "
        "host CLI `winbox av enable`, which reboots for you), then confirm with "
        "av_status.\n" + status_text
    ).rstrip()


@mcp.tool()
def av_disable(confirm: bool = False) -> str:
    """Disable Windows Defender completely — sets GP registry keys then REBOOTS the VM.

    WinDefend is a protected process (PPL) that no user-mode caller,
    including SYSTEM, can stop while running — only a reboot with the
    GP keys set (DisableAntiSpyware + Real-Time Protection overrides)
    actually kills it. This tool therefore reboots the VM, which DROPS
    any live kdbg session and open named-pipe handles.

    Because of the reboot, ``confirm`` must be True or the call is a
    no-op. Undo with av_enable.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import defender

    if not confirm:
        return (
            "error: av_disable reboots the VM (kills live kdbg / pipe sessions). "
            "Pass confirm=True to proceed."
        )

    cfg, vm, ga = _ensure_vm_ready()

    # Steps 0-1 talk to the guest agent (reg.exe / status): a dropped or
    # timed-out GA must surface as the clean guest-error string the rest of
    # the module returns, not an uncaught GuestAgentError.
    try:
        with _guest_errors(vm):
            # Step 0: On Win11 client, Tamper Protection silently neuters the
            # GP-key disable. Refuse rather than reboot into a still-protected VM.
            if defender.tamper_protection_on(ga):
                return (
                    "error: Tamper Protection is ON — Defender cannot be disabled from the "
                    "running OS. It should have been cleared offline by `winbox setup --os "
                    "win11`; otherwise turn it off in Windows Security (Virus & threat "
                    "protection > Manage settings > Tamper Protection) and retry."
                )

            # Step 1: Set the GP registry keys (shared with the CLI).
            defender.set_disable_regkeys(ga)
    except defender.DefenderError as e:
        detail = _format_exec_result(e.result) if e.result is not None else ""
        return f"error: {e}\n{detail}".rstrip()

    # Step 2: Reboot — the only way to actually stop the WinDefend service.
    # The MCP server does its own wait (no console) rather than the CLI's
    # reboot_and_wait, but the reason it must reboot lives in winbox.defender.
    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        # Expected: the VM dies before the GA can ACK.
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "Registry keys set and reboot issued, but the guest agent did not "
            "come back within 120s. Check with: virsh console " + cfg.vm_name
        )

    # Step 3: Verify — Win11 can ignore the keys even with TP off, so confirm
    # rather than assert a disable we may not have achieved.
    try:
        out = (defender.status(ga, timeout=20).stdout or "").strip()
    except GuestAgentError:
        out = ""
    if "Defender: OFF" in out or "Defender: off" in out:
        return "Defender disabled — GP keys set and VM rebooted; protections off."
    return (
        "Registry keys set and VM rebooted, but Defender still reports active "
        "(on Win11 the DisableAntiSpyware key is ignored on client SKUs). "
        "Current status:\n" + (out or "(status unavailable)")
    )


# ─── Tool 8c: hvci_status / hvci_disable / hvci_enable ─────────────────────
# Thin frontends over winbox.hvci — the same operations the `winbox hvci`
# CLI group calls, so the two never drift.

@mcp.tool()
def hvci_status(timeout: int = 15) -> str:
    """Report HVCI / Virtualization Based Security state in the VM.

    Queries the DeviceGuard registry keys and bcdedit hypervisorlaunchtype
    to determine whether VBS and HVCI are enabled. Read-only — safe to call
    any time.

    Args:
        timeout: Execution timeout in seconds (default 15).
    """
    from winbox import hvci

    cfg, vm, ga = _ensure_vm_ready()
    s = hvci.status(ga)
    return _json.dumps({
        "vbs": "on" if s.vbs_enabled else "off",
        "hvci": "on" if s.hvci_enabled else "off",
        "hypervisor_off": s.hypervisor_off,
        "note": ("kernel breakpoints will not work while HVCI is on"
                 if s.hvci_enabled else None),
    }, indent=2)


@mcp.tool()
def hvci_disable(confirm: bool = False) -> str:
    """Disable HVCI and VBS — sets registry keys + bcdedit then REBOOTS the VM.

    HVCI (Hypervisor-enforced Code Integrity) blocks unsigned kernel code and
    prevents hardware breakpoints from working. This tool disables both VBS
    and HVCI, then reboots the VM for the changes to take effect.

    Because of the reboot, ``confirm`` must be True or the call is a no-op.
    Undo with hvci_enable.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import hvci

    if not confirm:
        return (
            "pass confirm=true to disable HVCI/VBS (will reboot the VM)"
        )

    cfg, vm, ga = _ensure_vm_ready()
    s = hvci.status(ga)
    if not s.hvci_enabled and not s.vbs_enabled:
        return "HVCI/VBS already disabled"

    hvci.disable(ga)

    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        # Expected: the VM dies before the GA can ACK.
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "HVCI registry keys set and reboot issued, but the guest agent "
            "did not come back within 120s. Check with: virsh console "
            + cfg.vm_name
        )

    s = hvci.status(ga)
    if not s.hvci_enabled:
        return "HVCI disabled successfully"
    return (
        "HVCI registry set but still reporting enabled — may need a "
        "second reboot or Secure Boot change"
    )


@mcp.tool()
def hvci_enable(confirm: bool = False) -> str:
    """Re-enable HVCI and VBS. Reboots the VM.

    Sets the DeviceGuard registry keys and bcdedit hypervisorlaunchtype
    to re-enable VBS and HVCI. Note that HVCI requires Secure Boot in
    the VM's UEFI firmware to actually activate.

    Because of the reboot, ``confirm`` must be True or the call is a no-op.
    Undo with hvci_disable.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import hvci

    if not confirm:
        return (
            "pass confirm=true to enable HVCI/VBS (will reboot the VM)"
        )

    cfg, vm, ga = _ensure_vm_ready()
    s = hvci.status(ga)
    if s.hvci_enabled and s.vbs_enabled:
        return "HVCI/VBS already enabled"

    hvci.enable(ga)

    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        # Expected: the VM dies before the GA can ACK.
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "HVCI registry keys set and reboot issued, but the guest agent "
            "did not come back within 120s. Check with: virsh console "
            + cfg.vm_name
        )

    s = hvci.status(ga)
    if s.hvci_enabled:
        return "HVCI enabled successfully"
    return (
        "HVCI registry set but not active — may need Secure Boot "
        "enabled in UEFI"
    )


# ─── Tool 9: net_isolate / net_unplug / net_connect ─────────────────────────

@mcp.tool()
def net_isolate() -> str:
    """Block internet on the VM via libvirt nwfilter (guest-proof).

    Attaches the 'winbox-isolate' nwfilter to the VM's interface so only
    intra-192.168.122.0/24 IPv4, ARP, and DHCPv4 traffic is allowed.
    Enforcement is at the host bridge -- DHCP renewals or in-guest route
    changes cannot defeat it. Kali <-> VM (guest agent, VirtIO-FS, SSH)
    stays up. For a full NIC disconnect, use net_unplug(). Undo with
    net_connect().
    """
    from winbox import nwfilter

    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    try:
        nwfilter.ensure_filter_defined(cfg)
        changed = nwfilter.attach_filter(vm.name)
    except Exception as e:
        # Not just RuntimeError: attach_filter -> _dumpxml -> ET.fromstring can
        # raise ET.ParseError on malformed virsh output, which would otherwise
        # escape as an unhandled traceback instead of a clean tool error.
        return f"Failed to attach nwfilter: {e}"

    # If the NIC link is down (e.g. after net_unplug's full air-gap), the filter
    # alone does nothing until traffic can flow. Bring it up so filtered access
    # works — but that WEAKENS a full air-gap to filter-only, so say so instead
    # of silently downgrading, and honor net_set_link's result.
    downgrade_note = ""
    if vm.net_link_state() == "down":
        if not vm.net_set_link("up"):
            return (
                "nwfilter attached, but failed to bring the NIC link up "
                "(no interface found?) — internet-isolation is not yet active."
            )
        downgrade_note = (
            " (note: the NIC was unplugged/air-gapped; brought the link up for "
            "filtered access — Kali<->VM is reachable again, internet stays blocked)"
        )

    if changed:
        return "Internet isolated — nwfilter enforced at host bridge" + downgrade_note
    return "Already isolated — nwfilter already attached" + downgrade_note


@mcp.tool()
def net_unplug() -> str:
    """Unplug the VM's virtual NIC entirely (full air-gap).

    Kills all IP traffic including Kali <-> VM. GA and VirtIO-FS stay
    up over virtio-serial. For internet-only isolation that keeps
    Kali <-> VM working, use net_isolate(). Undo with net_connect().
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    if not vm.net_set_link("down"):
        return "Failed to set link down (no interface found?)"
    return "NIC unplugged — VM is fully air-gapped"


@mcp.tool()
def net_connect() -> str:
    """Restore full network access (undo net_isolate or net_unplug).

    Detaches the 'winbox-isolate' nwfilter (idempotent), brings the NIC
    link up if needed, then runs a full DHCP cycle (release + renew)
    to re-add the default gateway.
    """
    import time
    from winbox import nwfilter

    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"

    # A failed detach means the winbox-isolate filter is STILL attached and the
    # bridge is STILL dropping egress — the VM is not un-isolated. Reporting
    # "Network connected" (with a live intra-LAN IP) would read as success, so
    # fail loudly and stop rather than bury it in a suffix.
    try:
        nwfilter.detach_filter(vm.name)
    except Exception as e:
        return (
            f"error: nwfilter detach FAILED — the VM is STILL internet-isolated: "
            f"{e}. Retry, or inspect the domain XML / `virsh nwfilter-list`."
        )

    if vm.net_link_state() == "down":
        if not vm.net_set_link("up"):
            return "Failed to set link up (no interface found?)"
        # Best-effort: the DHCP poll below is the real readiness signal.
        try:
            ga.exec_powershell(
                "Restart-NetAdapter -Name (Get-NetAdapter | Select -First 1).Name "
                "-Confirm:$false",
                timeout=30,
            )
        except GuestAgentError:
            pass

    # Both DHCP steps are best-effort — the filter is already detached and the
    # link is up, so a guest-agent hiccup here must not error the whole tool
    # (the vm.ip() poll below reflects the true outcome).
    try:
        ga.exec("ipconfig /release", timeout=15)
    except GuestAgentError:
        pass
    try:
        ga.exec("ipconfig /renew", timeout=30)
    except GuestAgentError:
        pass

    for _ in range(15):
        ip = vm.ip()
        if ip:
            return f"Network connected — IP: {ip}"
        time.sleep(1)
    return "Network connected (DHCP pending)"


# ─── Tool 10: pipe_list / pipe_info / pipe_connect ──────────────────────────

@mcp.tool()
def pipe_list(filter: str | None = None, timeout: int = 30) -> str:
    """Enumerate named pipes in the Windows VM matching a pattern.

    Uses Get-ChildItem on \\\\.\\pipe\\ via PowerShell. Returns a JSON array
    of pipe names, sorted alphabetically.

    Args:
        filter: Optional substring filter (case-insensitive). None = all pipes.
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import json
        import subprocess
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        filter_str = (args.get('filter') or '').lower()

        r = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-ChildItem \\\\\\\\.\\\\pipe\\\\ | Select-Object -ExpandProperty Name | Sort-Object'],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            sys.exit(r.returncode)

        pipes = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        if filter_str:
            pipes = [p for p in pipes if filter_str in p.lower()]
        print(json.dumps(pipes))
    """)

    result = _exec_python(script, timeout=timeout, args={"filter": filter})
    return _format_exec_result(result)


@mcp.tool()
def pipe_info(name: str, timeout: int = 30) -> str:
    """Get security and configuration details for a named pipe.

    Returns a JSON object with keys: pipe, mode, end, out_buf, in_buf,
    max_instances, sddl. sddl is null if it could not be retrieved.

    Args:
        name: Pipe name without prefix (e.g. 'lsass' not '\\\\\\\\.\\\\pipe\\\\lsass').
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        name = args['name']
        pipe_path = f'\\\\\\\\.\\\\pipe\\\\{name}'

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.GetNamedPipeInfo.restype = wintypes.BOOL
        kernel32.GetNamedPipeInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityInfo.restype = wintypes.DWORD
        advapi32.GetSecurityInfo.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            pipe_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            print(json.dumps({
                "pipe": pipe_path,
                "error": f"Cannot open (error {err})",
                "sddl": None,
            }))
            sys.exit(1)

        try:
            # GetNamedPipeInfo
            flags = wintypes.DWORD(0)
            out_buf = wintypes.DWORD(0)
            in_buf = wintypes.DWORD(0)
            max_inst = wintypes.DWORD(0)
            ok = kernel32.GetNamedPipeInfo(
                handle,
                ctypes.byref(flags), ctypes.byref(out_buf),
                ctypes.byref(in_buf), ctypes.byref(max_inst),
            )
            if not ok:
                err = ctypes.get_last_error()
                print(json.dumps({
                    "pipe": pipe_path,
                    "error": f"GetNamedPipeInfo failed (error {err})",
                    "sddl": None,
                }))
                kernel32.CloseHandle(handle)
                sys.exit(1)
            PIPE_TYPE_MESSAGE = 0x4
            PIPE_SERVER_END = 0x1
            mode = "message" if (flags.value & PIPE_TYPE_MESSAGE) else "byte"
            end = "server" if (flags.value & PIPE_SERVER_END) else "client"
            max_i = max_inst.value if max_inst.value != 255 else "unlimited"

            # SDDL
            SE_KERNEL_OBJECT = 6
            DACL_SECURITY_INFORMATION = 4
            OWNER_SECURITY_INFORMATION = 1
            GROUP_SECURITY_INFORMATION = 2
            sd_ptr = ctypes.c_void_p()
            sddl = None
            ret = advapi32.GetSecurityInfo(
                handle, SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None, None, None, None,
                ctypes.byref(sd_ptr),
            )
            if ret == 0 and sd_ptr.value:
                sddl_ptr = wintypes.LPWSTR()
                SDDL_REVISION_1 = 1
                advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd_ptr, SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    ctypes.byref(sddl_ptr), None,
                )
                if sddl_ptr.value:
                    sddl = sddl_ptr.value
                    kernel32.LocalFree(sddl_ptr)
                kernel32.LocalFree(sd_ptr)

            print(json.dumps({
                "pipe": pipe_path,
                "mode": mode,
                "end": end,
                "out_buf": out_buf.value,
                "in_buf": in_buf.value,
                "max_instances": max_i,
                "sddl": sddl,
            }))
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _exec_python(script, timeout=timeout, args={"name": name})
    return _format_exec_result(result)


@mcp.tool()
def pipe_connect(name: str, access: str = "read", timeout: int = 30) -> str:
    """Open a handle to a named pipe and return the result.

    Attempts to connect to the pipe with the specified access. Useful for
    testing pipe ACLs, impersonation opportunities, and access control.
    Returns success + handle info, or the Win32 error on failure.

    Args:
        name: Pipe name without prefix (e.g. 'lsass').
        access: Access mode — 'read', 'write', or 'readwrite' (default: 'read').
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        name = args['name']
        access_str = args.get('access', 'read').lower()

        GENERIC_READ  = 0x80000000
        GENERIC_WRITE = 0x40000000
        access_map = {
            'read':      GENERIC_READ,
            'write':     GENERIC_WRITE,
            'readwrite': GENERIC_READ | GENERIC_WRITE,
        }
        desired_access = access_map.get(access_str, GENERIC_READ)

        pipe_path = f'\\\\\\\\.\\\\pipe\\\\{name}'

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            pipe_path, desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            msgs = {
                5:   'ACCESS_DENIED',
                2:   'NOT_FOUND',
                231: 'PIPE_BUSY (all instances in use)',
            }
            msg = msgs.get(err, f'error {err}')
            print(f"FAILED: {pipe_path} [{access_str}] -> {msg}", file=sys.stderr)
            sys.exit(1)

        kernel32.CloseHandle(handle)
        print(f"OK: opened {pipe_path} [{access_str}] successfully")
    """)

    result = _exec_python(script, timeout=timeout, args={"name": name, "access": access})
    return _format_exec_result(result)


# ─── Pipe session broker ────────────────────────────────────────────────────
# Written to Z:\.mcp\pipes\<session_id>\broker.py and run as a detached
# background process that holds the pipe handle open between tool calls.
# IPC is file-based via the VirtIO-FS shared directory.
#
# The protocol is sequence-numbered: the host writes cmd.<seq>.json and waits
# only for result.<seq>.json. It used to be a single fixed cmd.json/result.json
# pair with no correlation at all, which desynchronised the session for good
# after the first timed-out call — the late answer was consumed by whatever
# call polled next, so a pipe_recv could be handed a *write*'s result (and
# blow up on the missing data_hex), while a command written during a blocked
# read was silently overwritten by the next one.

_BROKER_SCRIPT = """\
import ctypes
from ctypes import wintypes
import json
import os
import time

script_dir = os.path.dirname(os.path.abspath(__file__))

# Record our own PID up front — before the config load and the (possibly
# blocking) CreateFileW below — so the host can always taskkill this broker on
# a failure path. Relying on the spawner's stdout 'pid:' line alone leaked a
# python.exe (and one pipe instance) whenever that line was lost or the broker
# wedged on CreateFileW before ever writing status 'ready'.
try:
    with open(os.path.join(script_dir, 'broker.pid'), 'w') as _pf:
        _pf.write(str(os.getpid()))
except OSError:
    pass

config = json.load(open(os.path.join(script_dir, 'config.json')))
name = config['name']
access_str = config.get('access', 'readwrite').lower()

bs = chr(92)
pipe_path = bs * 2 + '.' + bs + 'pipe' + bs + name

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.PeekNamedPipe.restype = wintypes.BOOL
kernel32.PeekNamedPipe.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ  = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

access_map = {
    'read':      GENERIC_READ,
    'write':     GENERIC_WRITE,
    'readwrite': GENERIC_READ | GENERIC_WRITE,
}
desired_access = access_map.get(access_str, GENERIC_READ | GENERIC_WRITE)

status_file = os.path.join(script_dir, 'status.json')
config_file = os.path.join(script_dir, 'config.json')

handle = kernel32.CreateFileW(
    pipe_path, desired_access,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    None, OPEN_EXISTING, 0, None,
)
if handle == INVALID_HANDLE_VALUE:
    err = ctypes.get_last_error()
    msgs = {5: 'ACCESS_DENIED', 2: 'NOT_FOUND', 231: 'PIPE_BUSY'}
    msg = msgs.get(err, f'error {err}')
    with open(status_file, 'w') as f:
        json.dump({'status': 'error', 'error': f'{pipe_path} -> {msg}'}, f)
    raise SystemExit(1)

with open(status_file, 'w') as f:
    json.dump({'status': 'ready'}, f)


def next_command():
    # Commands are numbered; always take the lowest pending seq so they are
    # executed in the order the host issued them.
    try:
        names = os.listdir(script_dir)
    except OSError:
        return None
    best = None
    for n in names:
        if n.startswith('cmd.') and n.endswith('.json'):
            try:
                seq = int(n[4:-5])
            except ValueError:
                continue
            if best is None or seq < best[0]:
                best = (seq, n)
    return best


def do_read(cmd):
    # ReadFile on this synchronous handle blocks forever when the pipe server
    # has sent nothing, and the host has no way to cancel it — one quiet
    # pipe_recv used to wedge this loop past every host-side timeout, so the
    # close command was never seen and the broker leaked. Peek first and read
    # only what is already queued, so a quiet pipe times out here instead.
    size = cmd['size']
    wait_ms = cmd.get('wait_ms', 5000)
    avail = wintypes.DWORD(0)
    deadline = time.time() + (wait_ms / 1000.0)
    while True:
        ok = kernel32.PeekNamedPipe(
            handle, None, 0, None, ctypes.byref(avail), None
        )
        if not ok:
            err = ctypes.get_last_error()
            return {'ok': False, 'error': 'PeekNamedPipe failed: error %d' % err}
        if avail.value:
            break
        if time.time() >= deadline:
            return {
                'ok': False,
                'timed_out': True,
                'error': 'no data available within %.1fs' % (wait_ms / 1000.0),
            }
        time.sleep(0.02)

    # Clamp defensively: a negative size would make create_string_buffer raise
    # ValueError and (before the dispatch guard below) kill the broker.
    want = max(0, min(size, avail.value))
    buf = ctypes.create_string_buffer(want)
    nread = wintypes.DWORD(0)
    ok = kernel32.ReadFile(handle, buf, want, ctypes.byref(nread), None)
    if ok:
        return {'ok': True, 'data_hex': buf.raw[:nread.value].hex()}
    err = ctypes.get_last_error()
    return {'ok': False, 'error': 'ReadFile failed: error %d' % err}


while True:
    # pipe_close deletes the session dir. Once it is gone nothing can ever
    # reach us again, so exit rather than spin forever holding the pipe
    # handle open — that leaked one python.exe (and one pipe instance) per
    # session until the VM was rebooted.
    if not os.path.exists(config_file):
        kernel32.CloseHandle(handle)
        break

    pending = next_command()
    if pending is None:
        time.sleep(0.05)
        continue
    seq, fname = pending
    cmd_path = os.path.join(script_dir, fname)

    try:
        with open(cmd_path) as f:
            cmd = json.load(f)
        os.remove(cmd_path)
    except Exception:
        time.sleep(0.05)
        continue

    action = cmd.get('cmd')
    closing = False

    # Any exception raised while dispatching a command must become an error
    # result, never escape the loop -- an uncaught exception kills the broker
    # process and silently wedges the session for every later command (no
    # result file is ever written, so the host just times out).
    try:
        if action == 'write':
            # Guard the decode: the host validates hex before sending, but a bad
            # payload from any future path must not crash the broker (which would
            # silently wedge the session for every later command).
            try:
                data = bytes.fromhex(cmd['data_hex'])
            except (ValueError, KeyError, TypeError) as e:
                result = {'ok': False, 'error': 'bad write payload: %s' % e}
            else:
                buf  = ctypes.create_string_buffer(data)
                written = wintypes.DWORD(0)
                ok = kernel32.WriteFile(handle, buf, len(data), ctypes.byref(written), None)
                if ok:
                    result = {'ok': True, 'written': written.value}
                else:
                    err = ctypes.get_last_error()
                    result = {'ok': False, 'error': 'WriteFile failed: error %d' % err}

        elif action == 'read':
            result = do_read(cmd)

        elif action == 'close':
            kernel32.CloseHandle(handle)
            result = {'ok': True}
            closing = True

        else:
            result = {'ok': False, 'error': 'unknown command: %s' % action}
    except Exception as e:
        result = {'ok': False, 'error': 'broker dispatch failed: %s' % e}

    # Echo the seq into a per-seq result file: a result the host already gave
    # up waiting for can then never be mistaken for the answer to a later call.
    result['seq'] = seq
    with open(os.path.join(script_dir, 'result.%d.json' % seq), 'w') as f:
        json.dump(result, f)

    if closing:
        break
"""


def _session_dir(session_id: str) -> Path:
    cfg, _, _ = _get_state()
    return cfg.shared_dir / ".mcp" / "pipes" / session_id


def _poll_result(result_file: Path, timeout: int) -> dict | None:
    """Poll for result.json on the Kali side (VirtIO-FS). Returns parsed dict or None on timeout."""
    import time as _time
    # monotonic so an NTP step (forward or backward) during the poll
    # can't cause a premature timeout or an infinite hang.
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if result_file.exists():
            try:
                data = _json.loads(result_file.read_text())
                result_file.unlink(missing_ok=True)
                return data
            except _json.JSONDecodeError:
                pass  # partial write — retry
        _time.sleep(0.1)
    return None


def _next_seq(session_dir: Path) -> int:
    """Allocate this session's next command sequence number.

    Persisted in the session dir rather than in memory: the MCP server can be
    restarted (or a session inspected by another process) between calls, and a
    reused seq would let a stale result be read as a fresh one.

    Locked across the read-modify-write (same idiom as JobStore._exclusive()
    in jobs.py): a readwrite pipe session is meant to have concurrent
    pipe_send/pipe_recv calls in flight, and two of them racing this
    unlocked would allocate the same seq -- one command's cmd.<seq>.json
    silently overwriting the other's before the broker ever reads it.
    """
    import fcntl

    seq_file = session_dir / "seq"
    lock_file = session_dir / "seq.lock"
    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            current = int(seq_file.read_text().strip())
        except (OSError, ValueError):
            current = 0
        current += 1
        seq_file.write_text(str(current))
        return current


def _broker_cmd(session_dir: Path, cmd: dict, timeout: int) -> dict | None:
    """Send one command to the in-guest broker and wait for *its* answer.

    Returns the parsed result dict, or None if the broker didn't answer this
    specific command in time. Correlation is by sequence number, so a caller
    that gave up earlier can never steal (or be handed) another call's result.
    """
    seq = _next_seq(session_dir)
    payload = dict(cmd)
    payload["seq"] = seq

    # No sweep of other result.*.json files here on purpose: a readwrite
    # session has pipe_send/pipe_recv in flight concurrently by design (see
    # pipe_open's docstring), and a blanket sweep would delete a *live*
    # result some other in-flight call hasn't polled for yet -- data
    # already dequeued off the real pipe on the guest side, gone for good.
    # A call's own result is cleaned up by _poll_result on a successful
    # read; a genuinely abandoned (timed-out) one is a harmless leftover
    # JSON file until pipe_close rmtrees the whole session dir.
    (session_dir / f"cmd.{seq}.json").write_text(_json.dumps(payload))
    return _poll_result(session_dir / f"result.{seq}.json", timeout)


def _is_broker_alive(ga, pid: int) -> bool:
    """Check if PID is still a python.exe process (our broker)."""
    try:
        r = ga.exec(f'tasklist /FI "PID eq {pid}" /FI "IMAGENAME eq python.exe" /NH', timeout=5)
        return "python.exe" in r.stdout.lower()
    except GuestAgentError:
        return False


# ─── Tool 11: pipe_open / pipe_send / pipe_recv / pipe_close ─────────────────

@mcp.tool()
def pipe_open(name: str, access: str = "readwrite", timeout: int = 10) -> str:
    """Open a named pipe and return a session ID for subsequent send/recv/close calls.

    Starts a persistent broker process inside the VM that holds the handle open.
    The broker communicates with MCP tools via files on the VirtIO-FS share.

    Args:
        name: Pipe name without prefix (e.g. 'srvsvc').
        access: 'read', 'write', or 'readwrite' (default: 'readwrite').
        timeout: Seconds to wait for broker to start (default: 10).

    Returns:
        session_id string on success, or an error message.
    """
    import time as _time
    import uuid

    cfg, _, _ = _ensure_vm_ready()

    session_id = uuid.uuid4().hex[:12]
    session_dir = cfg.shared_dir / ".mcp" / "pipes" / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    (session_dir / "config.json").write_text(
        _json.dumps({"name": name, "access": access})
    )
    (session_dir / "broker.py").write_text(_BROKER_SCRIPT)

    # Windows path to broker on Z: (VirtIO-FS)
    broker_win = f"Z:\\.mcp\\pipes\\{session_id}\\broker.py"

    spawner = textwrap.dedent("""\
        import subprocess
        import json

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        broker_path = args['broker_path']

        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW  = 0x08000000

        proc = subprocess.Popen(
            ['python.exe', broker_path],
            creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"pid:{proc.pid}")
    """)

    result = _exec_python(spawner, args={"broker_path": broker_win})
    if result["exitcode"] != 0:
        import shutil
        shutil.rmtree(session_dir, ignore_errors=True)
        return f"spawner failed: {result['stderr'].strip()}"

    # The broker is already running detached in the VM at this point. Parse
    # its PID so we can kill it on any failure path — otherwise a broken
    # pipe_open leaves zombie python.exe processes accumulating forever. The
    # broker also writes its own broker.pid file at startup (see _BROKER_SCRIPT),
    # so _abort can recover the PID even when this stdout line is lost.
    broker_pid: int | None = None
    for line in result["stdout"].splitlines():
        line = line.strip()
        if line.startswith("pid:"):
            try:
                broker_pid = int(line[4:])
            except ValueError:
                pass
            break
    if broker_pid is not None:
        (session_dir / "broker.pid").write_text(str(broker_pid))

    def _abort(reason: str) -> str:
        """Kill the orphaned broker (if any) and clean up the session dir."""
        import shutil
        # Prefer the parsed PID, but fall back to the file the broker wrote
        # itself — otherwise a lost 'pid:' line left a wedged broker unkillable.
        pid = broker_pid
        if pid is None:
            try:
                pid = int((session_dir / "broker.pid").read_text().strip())
            except (OSError, ValueError):
                pid = None
        if pid is not None:
            try:
                _, _, ga = _ensure_vm_ready()
                if _is_broker_alive(ga, pid):
                    ga.exec_argv("taskkill.exe", ["/F", "/PID", str(pid)], timeout=5)
            except Exception:
                pass  # best-effort — broker may already have exited
        shutil.rmtree(session_dir, ignore_errors=True)
        return reason

    # Poll status.json on Kali side via VirtIO-FS. monotonic so a clock
    # step during the poll can't break the deadline.
    status_file = session_dir / "status.json"
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if status_file.exists():
            try:
                status = _json.loads(status_file.read_text())
            except _json.JSONDecodeError:
                _time.sleep(0.1)
                continue
            if status.get("status") == "ready":
                return session_id
            else:
                return _abort(f"broker error: {status.get('error', 'unknown')}")
        _time.sleep(0.1)

    return _abort(f"timeout waiting for broker (session: {session_id})")


@mcp.tool()
def pipe_send(session_id: str, data_hex: str, timeout: int = 10) -> str:
    """Write bytes to an open pipe session.

    Args:
        session_id: Session ID returned by pipe_open.
        data_hex: Bytes to write as a hex string (e.g. 'deadbeef0a').
        timeout: Seconds to wait for the write to complete (default: 10).
    """
    session_dir = _session_dir(session_id)
    if not session_dir.exists():
        return f"session not found: {session_id}"

    # Validate hex host-side so a malformed payload fails fast with a clear
    # message and never reaches the broker — an unguarded bytes.fromhex there
    # would crash the broker process and wedge the whole session silently.
    try:
        bytes.fromhex(data_hex)
    except (ValueError, TypeError):
        return f"error: data_hex is not valid hex: {data_hex!r}"

    res = _broker_cmd(session_dir, {"cmd": "write", "data_hex": data_hex}, timeout)
    if res is None:
        return (
            "timeout waiting for write result — the write may still be executed "
            "by the broker; its result is discarded, not returned to a later call."
        )
    if res.get("ok"):
        return f"wrote {res.get('written', 0)} bytes"
    return f"error: {res.get('error')}"


def _recover_orphaned_read(session_dir: Path) -> str | None:
    """Reclaim data from a previous read that the host timed out on.

    If a prior pipe_recv timed out after the broker already dequeued bytes
    from the pipe, the result file is orphaned — the bytes are gone from the
    pipe and the next pipe_recv would skip them. Scan for the oldest such
    file and return its data, consuming the file so it's not returned twice.
    """
    best_seq = None
    best_path = None
    try:
        for name in session_dir.iterdir():
            if name.name.startswith("result.") and name.name.endswith(".json"):
                try:
                    seq = int(name.name[7:-5])
                except ValueError:
                    continue
                if best_seq is None or seq < best_seq:
                    best_seq = seq
                    best_path = name
    except OSError:
        return None
    if best_path is None:
        return None
    try:
        data = _json.loads(best_path.read_text())
    except (OSError, _json.JSONDecodeError):
        return None
    if data.get("ok") and data.get("data_hex"):
        best_path.unlink(missing_ok=True)
        return data["data_hex"]
    return None


@mcp.tool()
def pipe_recv(session_id: str, size: int, timeout: int = 10) -> str:
    """Read bytes from an open pipe session.

    Returns received bytes as a hex string, or an error message.

    Args:
        session_id: Session ID returned by pipe_open.
        size: Maximum number of bytes to read.
        timeout: Seconds to wait for data (default: 10).
    """
    session_dir = _session_dir(session_id)
    if not session_dir.exists():
        return f"session not found: {session_id}"

    if size < 0:
        return f"error: size must be >= 0, got {size}"

    recovered = _recover_orphaned_read(session_dir)
    if recovered is not None:
        return recovered

    wait_ms = max(500, int((timeout - 1) * 1000))
    res = _broker_cmd(
        session_dir, {"cmd": "read", "size": size, "wait_ms": wait_ms}, timeout
    )
    if res is None:
        return "timeout waiting for read result"
    if res.get("ok"):
        data_hex = res.get("data_hex")
        if data_hex is None:
            return f"error: broker returned no data for a read: {res}"
        return data_hex
    if res.get("timed_out"):
        return f"no data available on the pipe within {timeout}s"
    return f"error: {res.get('error')}"


@mcp.tool()
def pipe_close(session_id: str) -> str:
    """Close an open pipe session and clean up.

    Args:
        session_id: Session ID returned by pipe_open.
    """
    import shutil

    session_dir = _session_dir(session_id)
    if not session_dir.exists():
        return f"session not found: {session_id}"

    # Read the PID *before* the rmtree. broker.pid is the only record of the
    # in-guest process, and a broker that never ACKs the close is still
    # holding the pipe handle (and one of the pipe's instances) open. Deleting
    # the session dir first made that orphan unkillable — it accumulated one
    # python.exe per session until the VM was rebooted.
    broker_pid: int | None = None
    try:
        broker_pid = int((session_dir / "broker.pid").read_text().strip())
    except (OSError, ValueError):
        pass

    res = _broker_cmd(session_dir, {"cmd": "close"}, timeout=5)

    killed: bool | None = None
    if res is None and broker_pid is not None:
        try:
            _, _, ga = _ensure_vm_ready()
            if _is_broker_alive(ga, broker_pid):
                kill = ga.exec_argv(
                    "taskkill.exe", ["/F", "/T", "/PID", str(broker_pid)], timeout=10
                )
                killed = kill.exitcode == 0
            else:
                killed = None  # broker already gone, PID possibly recycled
        except Exception:
            killed = False

    shutil.rmtree(session_dir, ignore_errors=True)

    if res is not None:
        return f"closed session {session_id}"
    if killed:
        return (
            f"closed session {session_id} — the broker never acknowledged the "
            f"close and was force-killed (PID {broker_pid}); the pipe handle "
            "is released."
        )
    if broker_pid is None:
        return (
            f"closed session {session_id} locally, but the broker never "
            "acknowledged the close and no broker.pid was recorded, so it "
            "could not be killed. A python.exe may still hold the pipe handle "
            "open in the VM."
        )
    if killed is None:
        # _is_broker_alive returned False — the PID is no longer python.exe.
        # The broker exited on its own; taskkill was skipped to avoid hitting
        # an unrelated process that recycled the same PID.
        return (
            f"closed session {session_id} — the broker (PID {broker_pid}) "
            "is already gone (PID no longer belongs to python.exe); "
            "taskkill skipped to avoid killing an unrelated process."
        )
    return (
        f"closed session {session_id} locally, but the broker (PID "
        f"{broker_pid}) neither acknowledged the close nor could be killed. "
        "It may still hold the pipe handle open in the VM."
    )


# ── removed: old pipe_recv(name, size) — superseded by pipe_open/pipe_recv ───


# ─── Tool 12: kdbg_start / kdbg_stop / kdbg_status ─────────────────────────

def _kdbg_hmp(vm_name: str, command: str) -> tuple[int, str, str]:
    """Tuple-mode HMP wrapper — defers to the canonical hmp() in
    winbox.kdbg.hmp. Kept as a 1-line shim so call sites stay readable."""
    from winbox.kdbg.hmp import hmp as _hmp_call
    return _hmp_call(vm_name, command, mode="tuple")


from winbox.kdbg.hmp import probe_port as _kdbg_probe  # canonical, no shim needed


@mcp.tool()
def kdbg_start(port: int = 1234, any_interface: bool = False) -> dict[str, Any]:
    """Start the QEMU gdb stub for hypervisor-level kernel debug.

    This exposes a gdb remote-protocol endpoint on the Kali host (inside
    the QEMU process) — completely transparent to the guest. No
    KdDebuggerEnabled flag, no bcdedit, no guest-visible artifacts. An
    external gdb client can then attach with `target remote :<port>`
    and set hardware breakpoints at any guest virtual address (kernel
    or userland). Undo with kdbg_stop().

    Args:
        port: TCP port for the gdb stub (default 1234).
        any_interface: Bind to 0.0.0.0 instead of 127.0.0.1. Exposes
            full r/w on guest kernel memory + registers to the LAN —
            opt-in only. Default False (localhost).
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return _research_error(
            f"VM is not running (state: {vm.state().value})", operation="kdbg_start"
        )

    bind = "0.0.0.0" if any_interface else "127.0.0.1"

    active_reader = _kdbg_reader_info(cfg)
    if active_reader is not None:
        owned_port = active_reader.get("port", 1234)
        return _research_error(
            f"Persistent kdbg reader already owns the gdbstub on port "
            f"{owned_port}. Call kdbg_stop() first.", operation="kdbg_start"
        )

    if _kdbg_probe("127.0.0.1", port):
        return _research_error(
            f"Something is already listening on 127.0.0.1:{port}. "
            "Call kdbg_stop() first, or pick a different port.",
            operation="kdbg_start",
        )

    rc, out, err = _kdbg_hmp(cfg.vm_name, f"gdbserver tcp:{bind}:{port}")
    if rc != 0:
        return _research_error(
            f"Failed to start gdb stub: {err or out}", operation="kdbg_start"
        )
    if "Waiting for gdb connection" not in out:
        return _research_error(
            f"Unexpected HMP response: {out}", operation="kdbg_start"
        )

    return _research_ok({
        "listening": True, "bind": bind, "port": port,
        "lan_accessible": bool(any_interface),
        "gdb_command": (
            "gdb -ex 'set architecture i386:x86-64' "
            f"-ex 'target remote :{port}'"
        ),
    })


@mcp.tool()
def kdbg_stop() -> dict[str, Any]:
    """Stop the QEMU gdb stub. Any attached gdb session gets EOF."""
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return _research_error(
            f"VM is not running (state: {vm.state().value})", operation="kdbg_stop"
        )

    _kdbg_stop_reader(cfg)
    rc, out, err = _kdbg_hmp(cfg.vm_name, "gdbserver none")
    if rc != 0:
        return _research_error(
            f"Failed to stop gdb stub: {err or out}", operation="kdbg_stop"
        )
    return _research_ok({"stopped": True})


@mcp.tool()
def kdbg_status(port: int = 1234) -> dict[str, Any]:
    """Show whether the gdb stub is listening.

    Probes 127.0.0.1:<port> with a TCP connect. QEMU's stub only
    accepts one client at a time, so "listening but probe fails" is
    the usual signal that a gdb session is already attached.
    """
    cfg, vm, ga = _get_state()
    vm_state = vm.state()
    if vm_state != VMState.RUNNING:
        return _research_ok({
            "state": "vm_not_running", "vm_state": vm_state.value,
            "listening": False, "port": port,
        })

    active_reader = _kdbg_reader_info(cfg)
    if active_reader is not None:
        owned_port = active_reader.get("port", port)
        return _research_ok({
            "state": "connected", "listening": True, "host": "127.0.0.1",
            "port": owned_port, "owner": "persistent_reader",
        })

    if _kdbg_probe("127.0.0.1", port):
        return _research_ok({
            "state": "listening", "listening": True,
            "host": "127.0.0.1", "port": port,
        })
    return _research_ok({
        "state": "stopped", "listening": False,
        "host": "127.0.0.1", "port": port,
    })


# ─── Tool 13: kdbg symbol / walker / CR3-read tools ────────────────────────
#
# These wrap the winbox.kdbg package so Claude can drive symbol loads,
# process walks, and cross-CR3 memory reads without shelling out to the CLI.
# Responses are deliberately terse: symbol/struct lookups return single
# numbers, never the full table (30k+ entries would blow the context).

from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStore as _KdbgStore,
    SymbolStoreError as _KdbgStoreError,
    WalkCache as _KdbgWalkCache,
    copy_user_module as _kdbg_copy_user_module,
    ensure_types_loaded as _kdbg_ensure_types_loaded,
    load_module as _kdbg_load_module,
    load_nt as _kdbg_load_nt,
    read_virt_cr3 as _kdbg_read_virt_cr3,
    resolve_nt_base as _kdbg_resolve_nt_base,
)
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.kdbg.debugger.reader import (
    debug_snapshot as _kdbg_debug_snapshot,
    reader_info as _kdbg_reader_info,
    snapshot_metadata as _kdbg_snapshot_metadata,
    stop_reader as _kdbg_stop_reader,
)
from winbox.kdbg.cet import (
    CetSafetyError as _KdbgCetSafetyError,
    format_status as _kdbg_format_cet_status,
    prepare as _kdbg_prepare_cet,
    query_status as _kdbg_query_cet_status,
    restore as _kdbg_restore_cet_policy,
)
from winbox.kdbg.pe import PeError as _KdbgPeError
from winbox.kdbg.walk import ThreadWalkIncomplete as _KdbgThreadWalkIncomplete
from winbox.kdbg.walk import find_process as _kdbg_find_process
from winbox.kdbg.walk import list_current_vcpu_threads as _kdbg_list_current_vcpu_threads
from winbox.kdbg.walk import list_modules as _kdbg_list_modules
from winbox.kdbg.walk import list_processes as _kdbg_list_processes
from winbox.kdbg.walk import list_threads as _kdbg_list_threads
from winbox.kdbg.walk import thread_walk_truncation as _kdbg_thread_walk_truncation
from winbox.kdbg.walk import list_user_modules as _kdbg_list_user_modules, is_wow64 as _kdbg_is_wow64
from winbox.kdbg.walk import resolve_thread_wait_objects as _kdbg_resolve_thread_wait_objects
from winbox.kdbg.walk import resolve_thread_start_addresses as _kdbg_resolve_thread_start_addresses
from winbox.kdbg.walk import select_threads as _kdbg_select_threads


@mcp.tool()
def kdbg_doctor(port: int = 1234) -> dict[str, Any]:
    """Fast, non-disruptive kdbg readiness report.

    Reports VM and guest-agent reachability, CET safety, cached nt symbol
    identity, gdbstub/reader ownership, and this MCP catalog revision.  It
    never attaches to the RSP socket or stops the guest.  Consequently,
    ``symbols.nt.live_base`` is honestly ``not_checked``: a walker or explicit
    base refresh performs that live RSP verification.
    """
    cfg, vm, ga = _get_state()
    try:
        return _research_ok(_kdbg_collect_doctor(
            cfg, vm, ga, port=port,
            catalog_revision=_MCP_CATALOG_REVISION,
            tool_count=_MCP_TOOL_COUNT,
            version=_winbox_version,
        ))
    except Exception as exc:
        return _research_error(exc, operation="kdbg_doctor")


@mcp.tool()
def kdbg_cet_status() -> dict[str, Any]:
    """Report whether Windows CET state is safe for QEMU GDB stop/resume.

    Repeated debug stops on affected QEMU/KVM versions can bugcheck Windows
    while UserShadowStack is active. This read-only check must report OFF
    before kdbg memory/walker/attach operations are allowed.
    """
    _, _, ga = _ensure_vm_ready()
    try:
        status = _kdbg_query_cet_status(ga)
    except _KdbgCetSafetyError as exc:
        return _research_error(exc, operation="kdbg_cet_status")
    return _research_ok({
        "safe_for_debug": bool(status.safe_for_debug),
        "summary": _kdbg_format_cet_status(status),
    })


@mcp.tool()
def kdbg_prepare(confirm: bool = False) -> dict[str, Any]:
    """Hide CET-SS from the VM for stable kdbg use; reboot required.

    This weakens a Windows exploit mitigation, so ``confirm`` must be true.
    The original raw Windows policy and libvirt CPU XML are backed up on the
    host and can be restored with ``kdbg_restore_cet``.
    """
    if not confirm:
        return _research_error(
            "refused: this disables Windows CET UserShadowStack and hides "
            "the VM cet-ss CPU feature; "
            "call again with confirm=true, then reboot the VM",
            operation="kdbg_prepare",
        )
    cfg, _, ga = _ensure_vm_ready()
    _kdbg_stop_reader(cfg)
    try:
        backup = _kdbg_prepare_cet(cfg, ga)
    except _KdbgCetSafetyError as exc:
        return _research_error(exc, operation="kdbg_prepare")
    if backup is None:
        return _research_ok({"changed": False, "safe_for_debug": True})
    return _research_ok({
        "changed": True, "backup": str(backup), "reboot_required": True,
    })


@mcp.tool()
def kdbg_restore_cet(confirm: bool = False) -> dict[str, Any]:
    """Restore the CET policy backed up by ``kdbg_prepare``; reboot required."""
    if not confirm:
        return _research_error(
            "refused: call again with confirm=true to restore the CET policy",
            operation="kdbg_restore_cet",
        )
    cfg, _, ga = _ensure_vm_ready()
    _kdbg_stop_reader(cfg)
    try:
        _kdbg_restore_cet_policy(cfg, ga)
    except _KdbgCetSafetyError as exc:
        return _research_error(exc, operation="kdbg_restore_cet")
    return _research_ok({"restored": True, "reboot_required": True})


def _kdbg_get_store() -> _KdbgStore:
    """The symbol store, with its nt base re-pointed if ASLR moved it.

    Every kdbg tool that walks kernel structures comes through here, and
    every one of them fails as "PDPTE not present" against a base left over
    from a previous boot. Correcting it here means a reboot no longer breaks
    kdbg until the user knows to run kdbg_base_refresh by hand.
    """
    from winbox.kdbg.symbols import ensure_nt_base_current

    cfg, _, _ = _get_state()
    store = _KdbgStore(cfg.symbols_dir)
    ensure_nt_base_current(cfg, store)
    return store


@mcp.tool()
def kdbg_symbols_load() -> dict[str, Any]:
    """Load symbols + struct offsets for nt.

    Pulls ntoskrnl.exe from the running VM, fetches ntkrnlmp.pdb from
    Microsoft's symbol server, extracts public symbols and key struct
    layouts (EPROCESS/KPROCESS/KTHREAD/LDR_DATA_TABLE_ENTRY/etc),
    resolves the live load base via the IDT, and persists everything
    to ``~/.winbox/symbols/``.

    The map itself is never returned inline - use ``kdbg_sym`` and
    ``kdbg_struct`` for lookups.
    """
    cfg, vm, ga = _ensure_vm_ready()
    store = _kdbg_get_store()
    try:
        info = _kdbg_load_nt(cfg, ga, store)
    except (_KdbgSymbolLoadError, _KdbgStoreError, _KdbgPeError) as e:
        return _research_error(e, operation="kdbg_symbols_load")
    return _research_ok({
        "module": "nt", "build": info.build,
        "symbol_count": info.symbol_count, "type_count": info.type_count,
        "base": f"0x{info.base:x}" if info.base else None,
    })


@mcp.tool()
def kdbg_sym(
    name: str, search: bool = False, limit: int = 16, rva: bool = False,
) -> dict[str, Any]:
    """Resolve a kernel symbol. Use ``mod!sym`` to pick a module (default nt).

    By default returns the absolute virtual address. Pass ``rva=True`` to
    get the raw RVA (no base required). Pass ``search=True`` with a
    substring pattern to get the first ``limit`` matches.

    Args:
        name: Symbol name (e.g. 'NtCreateFile', 'nt!PsActiveProcessHead').
        search: If True, treat ``name`` as a substring pattern.
        limit: Max results when searching (default 16).
        rva: Return RVA instead of absolute VA.
    """
    from winbox.kdbg.format import format_sym

    store = _kdbg_get_store()
    try:
        lines = format_sym(store, name, search=search, limit=limit, rva=rva)
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_sym")
    if not lines:
        return _research_error(f"no matches for {name}", operation="kdbg_sym")
    return _research_ok({"query": name, "matches": lines})


@mcp.tool()
def kdbg_struct(
    type_name: str, field: str = "", module: str = "nt",
) -> dict[str, Any]:
    """Return a struct layout or a single field offset from the symbol store.

    Without ``field``, returns the whole struct as a compact list of
    ``name +0xoffset type`` lines. With ``field``, returns just
    ``off=0xN type=...`` for that one member.

    Args:
        type_name: Struct type name (e.g. '_EPROCESS').
        field: Optional field name to look up by itself.
        module: Module the type lives in (default 'nt').
    """
    from winbox.kdbg.format import format_struct

    store = _kdbg_get_store()
    try:
        lines = format_struct(store, type_name, field=field or None, module=module)
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_struct")
    return _research_ok({
        "module": module, "type": type_name, "field": field or None,
        "lines": lines,
    })


@mcp.tool()
def kdbg_ps() -> dict[str, Any]:
    """Walk ``PsActiveProcessHead`` and return all running processes.

    The envelope result is ``{processes, count}``; each process contains
    ``{pid, dtb, eprocess, name}``. ``dtb`` is the DirectoryTableBase.

    Requires ``kdbg_symbols_load`` to have been run first.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_ps"
        )
    try:
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            procs = _kdbg_list_processes(cfg.vm_name, store)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_ps")
    out = [
        {
            "pid": p.pid,
            "dtb": f"0x{p.directory_table_base:012x}",
            "eprocess": f"0x{p.eprocess:016x}",
            "name": p.name,
        }
        for p in procs
    ]
    return _research_ok({
        "processes": out, "count": len(out), "snapshot_metadata": snapshot_metadata,
    })


def _kdbg_target_for_evidence(cfg: Config, store: _KdbgStore, pid: int, cache: _KdbgWalkCache):
    target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
    if target is None:
        raise _KdbgHmpError(f"pid {pid} not found")
    return target


@mcp.tool()
def kdbg_vad(
    pid: int, address: str = "", executable: bool = False, limit: int = 128,
    probe_header: bool = False, require_complete: bool = False,
) -> dict[str, Any]:
    """Resolve one user VA or list bounded executable VAD evidence.

    The default address lookup follows only one PDB-validated AVL path.  With
    no address, returns a bounded in-order executable VAD map.  A loader miss
    remains a lead unless this walker proves a range; `private` or `image`
    labels are kernel VAD facts, not a malware verdict.

    Args:
        pid: Target process ID from kdbg_ps.
        address: Optional canonical user VA (for one direct lookup).
        executable: Include only executable mappings in map mode.
        limit: Map result cap (1..4096).
        probe_header: Read two bytes at each returned range base for MZ evidence.
        require_complete: Reject a truncated map instead of returning its prefix.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 4096:
        return _research_error("limit must be an integer between 1 and 4096", operation="kdbg_vad")
    if not isinstance(executable, bool) or not isinstance(probe_header, bool) or not isinstance(require_complete, bool):
        return _research_error("executable, probe_header, and require_complete must be booleans", operation="kdbg_vad")
    parsed_address: int | None = None
    if address:
        try:
            parsed_address = int(address, 0)
        except (TypeError, ValueError):
            return _research_error(f"invalid address: {address!r}", operation="kdbg_vad")
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_vad")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_vad_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="vad") as snapshot:
            cache = _KdbgWalkCache()
            target = _kdbg_target_for_evidence(cfg, store, pid, cache)
            if parsed_address is not None:
                record = _kdbg_lookup_vad(
                    cfg.vm_name, store, target, parsed_address, cache=cache,
                    probe_header=probe_header,
                )
                result = {
                    "pid": pid, "address": f"0x{parsed_address:016x}",
                    "found": record is not None,
                    "vad": record.public() if record is not None else None,
                    "complete": True,
                }
            else:
                walked = _kdbg_list_vads(
                    cfg.vm_name, store, target, cache=cache,
                    executable_only=executable, limit=limit, probe_header=probe_header,
                )
                if require_complete and not walked.complete:
                    error = _KdbgVadError("VAD map is incomplete")
                    error.code = "incomplete_result"
                    error.retryable = True
                    error.details = {"truncation": walked.truncation}
                    raise error
                result = {"pid": pid, "executable_only": executable, **walked.public()}
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgVadError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_vad")


@mcp.tool()
def kdbg_token(pid: int) -> dict[str, Any]:
    """Return PDB-backed primary-token identity and raw privilege masks."""
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_token")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_object_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="token") as snapshot:
            target = _kdbg_target_for_evidence(cfg, store, pid, _KdbgWalkCache())
            result = _kdbg_token_evidence(cfg.vm_name, store, target)
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_token")


@mcp.tool()
def kdbg_handles(pid: int) -> dict[str, Any]:
    """Return a validated process handle-table root and enumeration support state.

    Public PDBs may omit the private entry union.  In that case this returns
    the proven root and a refusal rather than guessed 16-byte slot decoding.
    """
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_handles")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_object_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="handles") as snapshot:
            target = _kdbg_target_for_evidence(cfg, store, pid, _KdbgWalkCache())
            result = _kdbg_handle_table_status(cfg.vm_name, store, target)
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_handles")


@mcp.tool()
def kdbg_object(body: str) -> dict[str, Any]:
    """Decode a kernel object header for a caller-proven object body pointer."""
    try:
        value = int(body, 0)
    except (TypeError, ValueError):
        return _research_error(f"invalid object body: {body!r}", operation="kdbg_object")
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_object")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_object_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="object") as snapshot:
            result = _kdbg_object_header(cfg.vm_name, store, value).public()
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_object")


@mcp.tool()
def kdbg_capture(
    profile: str = "process", pid: int = 0, name: str = "", require_complete: bool = False,
) -> dict[str, Any]:
    """Take one bounded, immutable process or system evidence capture.

    Exact PDB extraction occurs before the single RSP stop.  Optional `name`
    atomically saves the resulting artifact under the host-owned kdbg capture
    store; without it the same bounded artifact is returned directly.
    """
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_capture")
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgCaptureError("require_complete must be a boolean")
        store = _kdbg_get_store()
        capture = _kdbg_capture_live(
            cfg, store, profile=profile, pid=(pid if pid else None),
            require_complete=require_complete,
        )
        if name:
            saved = _KdbgCaptureStore(cfg).save(name, capture)
            return _research_ok({"capture": capture, "saved": saved})
        return _research_ok({"capture": capture, "saved": None})
    except (_KdbgCaptureError, _KdbgVadError, _KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_capture")


@mcp.tool()
def kdbg_capture_diff(
    left: str, right: str, limit: int = 128, allow_identity_mismatch: bool = False,
) -> dict[str, Any]:
    """Diff two named captures entirely offline; no VM/RSP access occurs."""
    cfg, _, _ = _get_state()
    try:
        if not isinstance(allow_identity_mismatch, bool):
            raise _KdbgCaptureError("allow_identity_mismatch must be a boolean")
        captures = _KdbgCaptureStore(cfg)
        result = _kdbg_diff_captures(
            captures.load(left), captures.load(right), limit=limit,
            allow_identity_mismatch=allow_identity_mismatch,
        )
        return _research_ok(result)
    except _KdbgCaptureError as exc:
        return _research_error(exc, operation="kdbg_capture_diff")


def _kdbg_thread_address(attribution: Any) -> dict[str, Any]:
    result = {
        "address": f"0x{attribution.address:016x}",
        "mapping": attribution.mapping,
        "module": attribution.module,
        "module_base": (
            f"0x{attribution.module_base:016x}"
            if attribution.module_base is not None else None
        ),
        "module_size": (
            f"0x{attribution.module_size:x}"
            if attribution.module_size is not None else None
        ),
        "rva": f"0x{attribution.rva:x}" if attribution.rva is not None else None,
        "architecture": attribution.architecture,
        "symbol": attribution.symbol,
        "symbol_offset": (
            f"0x{attribution.symbol_offset:x}"
            if attribution.symbol_offset is not None else None
        ),
    }
    if getattr(attribution, "vad", None) is not None:
        result["vad"] = attribution.vad
    return result


def _kdbg_current_vcpu_record(record: Any) -> dict[str, Any]:
    return {
        "vcpu": record.vcpu,
        "status": record.status,
        "ethread": f"0x{record.ethread:016x}" if record.ethread is not None else None,
        "eprocess": f"0x{record.eprocess:016x}" if record.eprocess is not None else None,
        "pid": record.pid,
        "process_name": record.process_name,
        "tid": record.tid,
        "in_target_process": record.in_target_process,
        "reason": record.reason,
    }


def _kdbg_thread_record(
    thread: Any, *, attribution: Any = None, running_on_vcpus: tuple[int, ...] | list[int] = (),
    wait_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize ThreadRecord with both stable raw and best-effort enum names."""
    result = {
        "tid": thread.tid,
        "ethread": f"0x{thread.ethread:016x}",
        "state": {"raw": thread.state, "name": thread.state_name},
        "wait_reason": {
            "raw": thread.wait_reason,
            "name": thread.wait_reason_name,
        },
        "priority": thread.priority,
        "base_priority": thread.base_priority,
        "context_switches": thread.context_switches,
        "teb": f"0x{thread.teb:016x}",
        "kernel_stack": f"0x{thread.kernel_stack:016x}",
        "stack_limit": f"0x{thread.stack_limit:016x}",
        "stack_base": f"0x{thread.stack_base:016x}",
        "start_address": f"0x{thread.start_address:016x}",
        "win32_start_address": f"0x{thread.win32_start_address:016x}",
        "create_time": thread.create_time,
        "exit_status": thread.exit_status,
    }
    result.update(_kdbg_thread_presentation_fields(thread))
    if attribution is not None:
        result["start_attribution"] = {
            "start_address": _kdbg_thread_address(attribution.start_address),
            "win32_start_address": _kdbg_thread_address(
                attribution.win32_start_address,
            ),
        }
    if running_on_vcpus:
        result["running_on_vcpus"] = list(running_on_vcpus)
    if wait_evidence is not None:
        result["wait_object"] = wait_evidence
    return result


@mcp.tool()
def kdbg_threads(
    pid: int,
    detail: str = "full",
    state: str = "",
    wait_reason: str = "",
    sort: str = "tid",
    limit: int = 256,
    resolve: bool = False,
    include_current: bool = True,
    wait_objects: bool = False,
    wait_object_limit: int = 32,
    wait_owner_depth: int = 2,
    require_complete: bool = False,
) -> dict[str, Any]:
    """Walk one process's kernel thread list without injecting into the guest.

    Returns bounded scheduler metadata, ETHREAD identity, thread start
    addresses, TEB, and stack bounds from ``EPROCESS.ThreadListHead``.
    ``kernel_stack`` is the raw KTHREAD field, not an asserted saved RSP;
    use ``kdbg_context`` only for the currently stopped debugger thread.

    Each ``state`` and ``wait_reason`` reports an invariant raw byte plus a
    best-effort current-Windows enum name; wait-reason names are intentionally
    omitted unless the scheduler state is ``Waiting``. A malformed list/read
    or the hard safety cap returns the validated prefix with ``complete=false``
    and a truthful ``truncated_reason`` plus structured ``truncation`` evidence.
    Set ``require_complete=true`` to reject that prefix with typed
    ``incomplete_result`` instead. ``limit`` only bounds returned detail
    rows: ``walk_complete`` remains independent, and summary metadata reports
    all walked/matching/filtered rows. ``resolve`` maps returned start VAs to
    live modules and already-local symbols without downloading anything.

    Args:
        pid: Target process ID (find it with ``kdbg_ps`` first).
        detail: ``full`` returns bounded rows; ``summary`` returns counts only.
        state: Optional raw scheduler-state byte or enum name (e.g. Waiting).
        wait_reason: Optional raw wait byte or enum name; matches Waiting only.
        sort: ``tid``, ``state``, ``wait``, ``priority``, ``context-switches``,
            ``start``, ``win32-start``, or ``create-time``.
        limit: Maximum returned detailed rows (1..1024; default 256).
        resolve: Attribute returned start addresses against live module lists.
        include_current: Return validated current ETHREAD identity per halted vCPU.
        wait_objects: Add bounded exact-PDB wait-object and mutant-owner evidence.
        wait_object_limit: Maximum Waiting detail rows inspected (1..128).
        wait_owner_depth: Maximum proven mutant-owner hops per row (1..4).
        require_complete: Refuse an incomplete kernel-list prefix instead of returning it.
    """
    cfg, vm, _ = _get_state()
    vm_state = vm.state()
    if vm_state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {vm_state.value})", operation="kdbg_threads"
        )
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgHmpError("require_complete must be a boolean")
        if not isinstance(wait_objects, bool):
            raise _KdbgHmpError("wait_objects must be a boolean")
        if detail not in {"full", "summary"}:
            raise _KdbgHmpError("detail must be 'full' or 'summary'")
        if wait_objects and detail != "full":
            raise _KdbgHmpError("wait_objects requires detail='full'")
        if (not isinstance(wait_object_limit, int) or isinstance(wait_object_limit, bool)
                or not 1 <= wait_object_limit <= 128):
            raise _KdbgHmpError("wait_object_limit must be an integer between 1 and 128")
        if (not isinstance(wait_owner_depth, int) or isinstance(wait_owner_depth, bool)
                or not 1 <= wait_owner_depth <= 4):
            raise _KdbgHmpError("wait_owner_depth must be an integer between 1 and 4")
        if wait_objects:
            # Type extraction can parse a large local PDB. Do it before the
            # RSP stop so optional visibility never lengthens guest downtime.
            _kdbg_ensure_types_loaded(
                cfg, _kdbg_get_store(),
                ["_KWAIT_BLOCK", "_DISPATCHER_HEADER", "_KMUTANT"], module="nt",
            )
        if resolve:
            # Like wait-object layouts, VAD type extraction is host-side work
            # and must finish before the finite stopped-guest transaction.
            try:
                _kdbg_ensure_vad_layouts(cfg, _kdbg_get_store())
            except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError):
                # Optional VAD attribution never invalidates the already
                # proven ETHREAD/loader result.
                pass
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(f"pid {pid} not found", operation="kdbg_threads")
            walked = _kdbg_list_threads(
                cfg.vm_name, store, target, cache=cache,
            )
            if require_complete and not walked.complete:
                raise _KdbgThreadWalkIncomplete(walked)
            selected = _kdbg_select_threads(
                walked.threads, state=state or None, wait_reason=wait_reason or None,
                sort=sort, limit=limit,
            )
            displayed = selected.threads if detail == "full" else ()
            attributions: dict[int, Any] = {}
            attribution_warnings: tuple[str, ...] = ()
            if resolve:
                attributions, attribution_warnings = _kdbg_resolve_thread_start_addresses(
                    cfg.vm_name, store, target, displayed, cache=cache,
                )
            wait_view: dict[str, Any] = {"enabled": False}
            wait_records: dict[int, dict[str, Any]] = {}
            if wait_objects:
                wait_result = _kdbg_resolve_thread_wait_objects(
                    cfg.vm_name, store, target, displayed, cache=cache,
                    limit=wait_object_limit, owner_depth=wait_owner_depth,
                )
                wait_view = {"enabled": True, **wait_result["scope"]}
                wait_records = wait_result["records"]
            current_vcpus: list[Any] = []
            current_vcpus_error: str | None = None
            if include_current:
                try:
                    current_vcpus = _kdbg_list_current_vcpu_threads(
                        cfg.vm_name, store, target, threads=walked.threads, cache=cache,
                    )
                except (_KdbgStoreError, _KdbgHmpError) as exc:
                    current_vcpus_error = str(exc)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
    except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_threads")
    running_by_ethread: dict[int, list[int]] = {}
    for current in current_vcpus:
        if current.status == "current" and current.in_target_process and current.ethread is not None:
            running_by_ethread.setdefault(current.ethread, []).append(current.vcpu)
    response = {
        "pid": target.pid,
        "name": target.name,
        "eprocess": f"0x{target.eprocess:016x}",
        "process_create_time": target.create_time,
        "process_create_time_filetime": target.create_time,
        "process_create_time_utc": _kdbg_filetime_utc(target.create_time),
        "threads": [
            _kdbg_thread_record(
                thread,
                attribution=attributions.get(thread.ethread),
                running_on_vcpus=running_by_ethread.get(thread.ethread, ()),
                wait_evidence=wait_records.get(thread.ethread),
            )
            for thread in displayed
        ],
        "count": len(displayed),
        "total_count": selected.total_count,
        "matched_count": selected.matched_count,
        "filtered_out": selected.filtered_out,
        "returned": len(displayed),
        "output_truncated": selected.output_truncated,
        "detail_rows_omitted": detail == "summary" and selected.matched_count > 0,
        "detail": detail,
        "summary": {
            "states": selected.state_counts,
            "wait_reasons": selected.wait_reason_counts,
        },
        "complete": walked.complete,
        "walk_complete": walked.complete,
        "truncated_reason": walked.truncated_reason,
        "truncation": _kdbg_thread_walk_truncation(walked),
        "current_vcpus": [_kdbg_current_vcpu_record(current) for current in current_vcpus],
        "wait_objects": wait_view,
        "snapshot_metadata": snapshot_metadata,
    }
    if attribution_warnings:
        response["attribution_warnings"] = list(attribution_warnings)
    if current_vcpus_error is not None:
        response["current_vcpus_error"] = current_vcpus_error
    return _research_ok(response)


@mcp.tool()
def kdbg_thread_baseline(pid: int, name: str = "default") -> dict[str, Any]:
    """Save one explicit complete host-side ETHREAD baseline for ``pid``.

    This performs one CET-gated RSP snapshot and writes a bounded baseline only
    when the complete kernel list validates.  The identity binds VM, active nt
    symbol-store revision, boot/System process, target PID/EPROCESS/CreateTime,
    and each ETHREAD/CreateTime; a later diff cannot accidentally compare a
    reboot, PID reuse, or changed symbol store.

    Args:
        pid: Target process ID.
        name: Baseline label (default ``default``; letters/digits/dot/dash/underscore).
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_thread_baseline",
        )
    baseline = _KdbgThreadBaselineStore(cfg)
    try:
        baseline.validate_name(name)
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            capture = _kdbg_capture_thread_baseline(cfg, store, pid)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
        result = baseline.save(name, capture)
        result["snapshot_metadata"] = snapshot_metadata
        return _research_ok(result)
    except (_KdbgThreadBaselineError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_thread_baseline")


@mcp.tool()
def kdbg_thread_diff(
    pid: int, name: str = "default", limit: int = 128,
) -> dict[str, Any]:
    """Compare one explicit current ETHREAD snapshot to a named baseline.

    Returns bounded created, exited, and changed categories.  A changed thread
    reports raw scheduler transitions and a 32-bit ContextSwitches delta with
    explicit counter-wrap status.  It does not poll: every call is one fresh,
    CET-gated snapshot.  Missing/incompatible baselines produce typed errors
    rather than a potentially cross-boot comparison.

    Args:
        pid: Target process ID, which must still match the saved EPROCESS/CreateTime.
        name: Existing baseline label (default ``default``).
        limit: Maximum returned rows per created/exited/changed category (1..1024).
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1024:
        return _research_error(
            "limit must be an integer between 1 and 1024", operation="kdbg_thread_diff",
        )
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_thread_diff",
        )
    baseline = _KdbgThreadBaselineStore(cfg)
    try:
        # Check the host prerequisite before opening an RSP transaction.
        baseline.load(name)
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            capture = _kdbg_capture_thread_baseline(cfg, store, pid)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
        result = baseline.diff(name, capture, limit=limit)
        result["snapshot_metadata"] = snapshot_metadata
        return _research_ok(result)
    except (_KdbgThreadBaselineError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_thread_diff")


def _kdbg_triage_module(module: Any) -> dict[str, Any]:
    return {
        "base": f"0x{module.base:016x}",
        "size": f"0x{module.size:x}",
        "name": module.name,
        "full_path": getattr(module, "full_path", None),
        "architecture": getattr(module, "architecture", "kernel"),
    }


def _kdbg_triage_unmapped_rows(threads: Any, attributions: dict[int, Any]) -> list[dict[str, Any]]:
    """Conservative module/loader mismatches: leads, not a verdict."""
    rows: list[dict[str, Any]] = []
    for thread in threads:
        attribution = attributions.get(thread.ethread)
        if attribution is None:
            continue
        for field, value in (
            ("start_address", attribution.start_address),
            ("win32_start_address", attribution.win32_start_address),
        ):
            if value.mapping not in {"kernel_unmapped", "user_not_in_loader_module"}:
                continue
            rows.append({
                "tid": thread.tid,
                "ethread": f"0x{thread.ethread:016x}",
                "field": field,
                "address": f"0x{value.address:016x}",
                "mapping": value.mapping,
            })
    return rows


@mcp.tool()
def kdbg_triage(
    pid: int, thread_limit: int = 16, require_complete: bool = False,
) -> dict[str, Any]:
    """Capture one bounded, coherent process-research snapshot.

    One RSP stop collects process identity, the complete ETHREAD walk and its
    scheduler summary, the busiest bounded thread rows, current-vCPU ETHREAD
    identities, and a capped PEB module view.  Start mappings are resolved
    only for those top rows; ``unmapped_starts_scope`` makes that boundary
    explicit.  ``user_not_in_loader_module`` is a lead (JIT/private/VAD work
    may explain it), not a malware classification.

    Args:
        pid: Target process ID.
        thread_limit: Top context-switch rows to resolve and return (1..64).
        require_complete: Refuse an incomplete kernel-list prefix instead of returning it.
    """
    if not 1 <= thread_limit <= 64:
        return _research_error(
            "thread_limit must be between 1 and 64", operation="kdbg_triage",
        )
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_triage",
        )
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgHmpError("require_complete must be a boolean")
        try:
            _kdbg_ensure_vad_layouts(cfg, _kdbg_get_store())
        except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError):
            pass
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(f"pid {pid} not found", operation="kdbg_triage")
            walked = _kdbg_list_threads(cfg.vm_name, store, target, cache=cache)
            if require_complete and not walked.complete:
                raise _KdbgThreadWalkIncomplete(walked)
            selected = _kdbg_select_threads(
                walked.threads, sort="context-switches", limit=thread_limit,
            )
            kernel_modules = _kdbg_list_modules(cfg.vm_name, store, cache=cache)
            module_error: str | None = None
            try:
                _kdbg_ensure_types_loaded(
                    cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt",
                )
                user_modules = _kdbg_list_user_modules(
                    cfg.vm_name, store, target, cache=cache,
                )
            except (_KdbgStoreError, _KdbgSymbolLoadError, _KdbgHmpError) as exc:
                user_modules = []
                module_error = str(exc)
            attributions, attribution_warnings = _kdbg_resolve_thread_start_addresses(
                cfg.vm_name, store, target, selected.threads, cache=cache,
                kernel_modules=kernel_modules, user_modules=user_modules,
            )
            current_vcpus: list[Any] = []
            current_vcpus_error: str | None = None
            try:
                current_vcpus = _kdbg_list_current_vcpu_threads(
                    cfg.vm_name, store, target, threads=walked.threads, cache=cache,
                )
            except (_KdbgStoreError, _KdbgHmpError) as exc:
                current_vcpus_error = str(exc)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
    except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_triage")

    running_by_ethread: dict[int, list[int]] = {}
    for current in current_vcpus:
        if current.status == "current" and current.in_target_process and current.ethread is not None:
            running_by_ethread.setdefault(current.ethread, []).append(current.vcpu)
    module_limit = 64
    result: dict[str, Any] = {
        "snapshot": "single_rsp_stop",
        "process": {
            "pid": target.pid, "name": target.name,
            "eprocess": f"0x{target.eprocess:016x}",
            "dtb": f"0x{target.directory_table_base:012x}",
            "create_time": target.create_time,
            "create_time_filetime": target.create_time,
            "create_time_utc": _kdbg_filetime_utc(target.create_time),
        },
        "thread_summary": {
            "total_count": selected.total_count,
            "walk_complete": walked.complete,
            "truncated_reason": walked.truncated_reason,
            "truncation": _kdbg_thread_walk_truncation(walked),
            "states": selected.state_counts,
            "wait_reasons": selected.wait_reason_counts,
            "top_rows_returned": len(selected.threads),
            "top_rows_truncated": selected.output_truncated,
            "sort": "context-switches",
        },
        "threads": [
            _kdbg_thread_record(
                thread, attribution=attributions.get(thread.ethread),
                running_on_vcpus=running_by_ethread.get(thread.ethread, ()),
            ) for thread in selected.threads
        ],
        "current_vcpus": [_kdbg_current_vcpu_record(current) for current in current_vcpus],
        "user_modules": {
            "count": len(user_modules),
            "returned": min(len(user_modules), module_limit),
            "output_truncated": len(user_modules) > module_limit,
            "modules": [_kdbg_triage_module(module) for module in user_modules[:module_limit]],
        },
        "unmapped_starts": _kdbg_triage_unmapped_rows(selected.threads, attributions),
        "unmapped_starts_scope": "top_rows_only",
        "snapshot_metadata": snapshot_metadata,
    }
    if module_error:
        result["user_modules"]["error"] = module_error
    if attribution_warnings:
        result["attribution_warnings"] = list(attribution_warnings)
    if current_vcpus_error:
        result["current_vcpus_error"] = current_vcpus_error
    return _research_ok(result)


@mcp.tool()
def kdbg_thread_triage(
    process_cap: int = 128,
    total_thread_cap: int = 4096,
    sample_per_process: int = 8,
    result_limit: int = 32,
    resolve: bool = True,
    require_complete: bool = False,
) -> dict[str, Any]:
    """Rank bounded process-wide scheduler evidence from one coherent RSP stop.

    Returns compact rankings by thread/runnable counts, newest threads, high
    context-switch samples, and module/loader-unmapped starts. Start mapping
    only examines the top context-switch rows per process. Every process,
    thread-budget, malformed-list, and attribution boundary is explicit in
    ``scope``; this never presents a capped subset as the entire kernel.

    Args:
        process_cap: Active-process records to examine (1..256).
        total_thread_cap: ETHREAD records examined across that process scope (1..8192).
        sample_per_process: Top context-switch rows sampled per process (1..32).
        result_limit: Rows returned in each ranking (1..64).
        resolve: Resolve only bounded start samples against live module loaders.
        require_complete: Reject a cap- or corruption-limited scope with typed
            ``incomplete_result`` rather than returning its validated prefix.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_thread_triage",
        )
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgGlobalThreadTriageError("require_complete must be a boolean")
        if resolve:
            try:
                _kdbg_ensure_vad_layouts(cfg, _kdbg_get_store())
            except (_KdbgVadError, _KdbgStoreError, _KdbgSymbolLoadError):
                pass
        with _kdbg_debug_snapshot(cfg) as snapshot:
            result = _kdbg_triage_all_process_threads(
                cfg.vm_name, _kdbg_get_store(), cache=_KdbgWalkCache(),
                process_cap=process_cap, total_thread_cap=total_thread_cap,
                sample_per_process=sample_per_process, result_limit=result_limit,
                resolve=resolve,
            )
            if require_complete and not result["scope"]["complete"]:
                raise _KdbgGlobalThreadTriageIncomplete(result)
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
    except (
        _KdbgGlobalThreadTriageError, _KdbgGlobalThreadTriageIncomplete,
        _KdbgVadError, _KdbgStoreError, _KdbgHmpError,
    ) as exc:
        return _research_error(exc, operation="kdbg_thread_triage")
    return _research_ok(result)


@mcp.tool()
def kdbg_lm() -> dict[str, Any]:
    """Walk ``PsLoadedModuleList`` and return all loaded kernel modules.

    The envelope result is ``{modules, count}``; each module contains
    ``{base, size, name}``. ``base`` is DllBase and ``size`` is SizeOfImage.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_lm"
        )
    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
            mods = _kdbg_list_modules(cfg.vm_name, store)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_lm")
    out = [
        {
            "base": f"0x{m.base:016x}",
            "size": f"0x{m.size:08x}",
            "name": m.name,
        }
        for m in mods
    ]
    return _research_ok({"modules": out, "count": len(out)})


@mcp.tool()
def kdbg_user_lm(pid: int) -> dict[str, Any]:
    """Walk PEB.Ldr and return all user-mode modules in ``pid``.

    The user-space mirror of ``kdbg_lm``. Shows the EXE plus every DLL
    Windows mapped into the target's address space, in load order.

    The envelope result is ``{pid, modules, count, wow64}``; each module
    contains ``{base, size, name, full_path, architecture}``. WoW64 processes
    include both loader views with x86/x64 same-name DLLs kept distinct.
    ``base`` is a user VA meaningful only against that process's CR3.

    First call after a fresh VM auto-extracts the PEB struct layouts
    from the cached PDB if they're missing — no kdbg_symbols_load
    re-run needed.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_user_lm"
        )
    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
        _kdbg_ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt"
        )
    except (_KdbgStoreError, _KdbgSymbolLoadError) as e:
        return _research_error(e, operation="kdbg_user_lm")

    try:
        with _kdbg_debug_snapshot(cfg):
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(
                    f"pid {pid} not found", operation="kdbg_user_lm"
                )
            mods = _kdbg_list_user_modules(cfg.vm_name, store, target, cache=cache)
            try:
                wow64 = _kdbg_is_wow64(cfg.vm_name, store, target, cache=cache)
            except Exception:
                wow64 = False
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_user_lm")
    out = [
        {
            "base": f"0x{m.base:016x}",
            "size": f"0x{m.size:08x}",
            "name": m.name,
            "full_path": m.full_path,
            "architecture": m.architecture,
        }
        for m in mods
    ]
    result: dict = {
        "pid": pid, "modules": out, "count": len(out), "wow64": wow64,
    }
    return _research_ok(result)


@mcp.tool()
def kdbg_user_symbols_load(
    pid: int, module: str, architecture: str = "auto",
) -> dict[str, Any]:
    """Load PDB symbols for a user-mode module in ``pid``.

    Pulls the binary out of the VM via VirtIO-FS, fetches the matching
    PDB from msdl, persists it under a short module name (e.g.
    ``notepad`` for notepad.exe). Subsequent ``kdbg_sym`` calls with
    ``<short>!<symbol>`` resolve against this store.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
        module: Substring matched against PEB.Ldr BaseDllName, then
            FullDllName. Examples: 'notepad.exe', 'ntdll', 'kernelbase'.
        architecture: ``auto``, ``x86``, or ``x64``. Auto refuses an
            ambiguous same-name WoW64 match instead of mixing symbol stores.

    Returns module/build/symbol-count/base metadata in the common envelope.
    """
    cfg, vm, ga = _ensure_vm_ready()
    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
        _kdbg_ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt"
        )
    except (_KdbgStoreError, _KdbgSymbolLoadError) as e:
        return _research_error(e, operation="kdbg_user_symbols_load")

    try:
        with _kdbg_debug_snapshot(cfg):
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(
                    f"pid {pid} not found", operation="kdbg_user_symbols_load"
                )
            mods = _kdbg_list_user_modules(cfg.vm_name, store, target, cache=cache)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_user_symbols_load")

    architecture = architecture.lower().strip()
    if architecture not in {"auto", "x86", "x64"}:
        return _research_error(
            "architecture must be 'auto', 'x86', or 'x64'",
            operation="kdbg_user_symbols_load",
        )
    needle = module.lower()
    matches = [m for m in mods if needle in m.name.lower()]
    if not matches:
        matches = [m for m in mods if needle in m.full_path.lower()]
    if architecture != "auto":
        matches = [m for m in matches if m.architecture == architecture]
    if not matches:
        return _research_error(
            f"no module matching {module!r} in pid {pid}",
            operation="kdbg_user_symbols_load",
        )
    identities = {(m.name.lower(), m.architecture) for m in matches}
    if architecture == "auto" and len(identities) > 1:
        choices = ", ".join(f"{name}@{arch}" for name, arch in sorted(identities))
        return _research_error(
            f"ambiguous module {module!r}; choose architecture: {choices}",
            operation="kdbg_user_symbols_load",
        )
    match = matches[0]

    short_name = match.name.rsplit(".", 1)[0].lower()
    if match.architecture == "x86":
        short_name += "_x86"
    cached_basename = match.name

    try:
        pe_path = _kdbg_copy_user_module(
            cfg, ga, match.full_path, cached_basename,
            architecture=match.architecture,
            expected_size=match.size,
        )
        info = _kdbg_load_module(
            cfg, store,
            pe_path=pe_path,
            module_name=short_name,
            base=match.base,
            wanted_types=(),
        )
    except (_KdbgSymbolLoadError, _KdbgStoreError, _KdbgPeError) as e:
        return _research_error(e, operation="kdbg_user_symbols_load")

    return _research_ok({
        "pid": pid, "module": short_name, "build": info.build,
        "symbol_count": info.symbol_count, "base": f"0x{info.base:x}",
        "architecture": match.architecture,
    })


@mcp.tool()
def kdbg_read_va(pid: int, address: str, length: int) -> dict[str, Any]:
    """Read virtual memory from an arbitrary process WITHOUT an attached
    debugger session through the persistent RSP reader.

    Looks up the target's EPROCESS, grabs its ``DirectoryTableBase``,
    temporarily selects that CR3 through QEMU's gdbstub, and reads
    ``length`` bytes at ``address``. One broker owns the single RSP client
    across calls and serializes concurrent MCP/CLI transactions.

    For in-session reads after ``kdbg_attach``, use ``kdbg_mem`` because the
    interactive daemon already owns the same gdbstub connection.

    Returns ``{pid, va, bytes}`` in the common envelope. Pair with
    ``kdbg_ps`` to find a PID first.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
        address: Virtual address, hex string (e.g. '0x7ff600001000').
        length: Number of bytes to read (capped at 1MB).
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_read_va"
        )
    if length <= 0:
        return _research_error("length must be > 0", operation="kdbg_read_va")
    if length > 1024 * 1024:
        return _research_error(
            f"length {length} too large - cap at 1MB", operation="kdbg_read_va"
        )
    try:
        va = int(address, 0)
    except ValueError:
        return _research_error(
            f"invalid address: {address!r}", operation="kdbg_read_va"
        )

    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(
                    f"pid {pid} not found", operation="kdbg_read_va"
                )
            data = _kdbg_read_virt_cr3(
                cfg.vm_name, target.directory_table_base, va, length, cache=cache,
            )
    except _KdbgHmpError as e:
        return _research_error(f"read failed: {e}", operation="kdbg_read_va")
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_read_va")
    return _research_ok({"pid": pid, "va": f"0x{va:x}", "bytes": data.hex()})


@mcp.tool()
def kdbg_base_refresh() -> dict[str, Any]:
    """Re-resolve and persist the nt load base from the live guest.

    ASLR re-randomizes the kernel base on every reboot. After a VM
    reboot the cached symbol map still has the old base — this call
    re-reads the IDT, computes the fresh base, and updates the store.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_base_refresh"
        )
    store = _kdbg_get_store()
    try:
        data = store.load("nt")
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_base_refresh")
    try:
        base = _kdbg_resolve_nt_base(cfg, data.get("symbols", {}))
    except Exception as e:
        return _research_error(
            f"could not resolve nt base: {e}", operation="kdbg_base_refresh"
        )
    store.set_base("nt", base)
    return _research_ok({"module": "nt", "base": f"0x{base:x}"})


# ─── Tool 14: kdbg session daemon (interactive debugger) ─────────────────
#
# These wrap the long-running session daemon's Unix-socket protocol. The
# daemon is forked by ``kdbg_attach`` and persists across MCP tool calls
# until ``kdbg_detach``. While attached, every other tool here calls into
# the daemon via DaemonClient on a fresh socket connection per call.
# Single-session-at-a-time is enforced by an fcntl lock on the daemon's
# lock file (kernel auto-releases on daemon death).

from winbox.kdbg.debugger.client import DaemonClient as _DaemonClient
from winbox.kdbg.debugger.client import ClientError as _ClientError
from winbox.kdbg.debugger.daemon import DaemonError as _DaemonError
from winbox.kdbg.debugger.daemon import fork_daemon as _fork_daemon
from winbox.kdbg.debugger.rsp import RspClient as _RspClient
from winbox.kdbg.debugger.rsp import RspError as _RspError


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

    Returns:
        The common envelope with daemon PID, target, gdbstub metadata, and
        bounded ``auto_stage`` counts/failures.
    """
    cfg, vm, ga = _ensure_vm_ready()
    client = _kdbg_client(cfg)
    if client.session_alive():
        info = client.session_info() or {}
        return _research_error(
            f"another session is active "
            f"(target {info.get('target_name', '?')}({info.get('target_pid', '?')}), "
            f"daemon_pid={info.get('daemon_pid', '?')}); call kdbg_detach first",
            operation="kdbg_attach",
        )

    # Freeze exact user binaries while the guest agent and background RSP
    # reader are both available. Once the daemon owns QEMU's one gdb client it
    # is too late to discover and copy a decommitted unwind dependency.
    from winbox.kdbg.staging import (
        StagingError as _KdbgStagingError,
        preflight_user_module_staging as _kdbg_preflight_staging,
        prepare_user_module_manifest as _kdbg_prepare_manifest,
    )
    try:
        if preflight:
            plan = _kdbg_preflight_staging(
                cfg, _kdbg_get_store(), pid, policy=staging_policy,
            )
            plan["prewarm_requested"] = bool(prewarm)
            return _research_ok(plan)
        manifest = _kdbg_prepare_manifest(
            cfg, ga, _kdbg_get_store(), pid,
            enrich_symbols=staging_policy == "full", policy=staging_policy,
        )
    except (_KdbgStagingError, _KdbgStoreError, _KdbgSymbolLoadError) as e:
        return _research_error(e, operation="kdbg_attach")

    # Transfer ownership from the background read broker to the interactive
    # debugger daemon without tearing down the listening gdbserver.
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

    # Warn if HVCI is on — kernel breakpoints will not fire.
    try:
        from winbox import hvci as _hvci
        hvci_state = _hvci.status(ga)
        if hvci_state.hvci_enabled:
            result["warning"] = (
                "HVCI is enabled — kernel breakpoints will not work. "
                "Run hvci_disable(confirm=true) first."
            )
    except Exception:
        pass  # GA might be unresponsive after gdbstub connected

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
        return _research_ok({"attached": False})
    try:
        result = client.call("status")
    except _ClientError as e:
        return _research_error(e, operation="kdbg_session")
    return _research_ok({"attached": True, **result})


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
        target: Symbol (``module!sym``) or hex VA.
        mode: Breakpoint mechanism (ignored when ``wp_type`` is set):
            ``"hw"`` (default) — hardware bp via Z1. PG-safe and
                anti-debug-invisible. Limit 4 per vCPU.
            ``"soft"`` — software 0xCC patch via Z0. Unlimited
                count but visible to code self-hashing and
                PatchGuard. Use when >4 hw bps needed.
        condition: Optional predicate evaluated server-side on every
            in-target fire. False predicate -> silent-cont (no halt
            surfaced). True predicate -> halt as today. Use this to
            cut through high-frequency dispatchers (IOCTL switches,
            adoption helpers) that would otherwise drown analysis.
            Bad syntax is rejected at install time, not at first fire.

            Grammar (qword unsigned 64-bit semantics):
              regs    = rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip eflags
              memory  = ``[reg]``, ``[reg+0xN]``, ``[reg-0xN]``, ``[0xABS]``
                        (qword little-endian read in target's CR3)
              deref   = ``poi(atom)`` or ``poi(atom+0xN)`` — chained
                        qword read; ``poi()`` nests for pointer chases
              typed   = ``byte(atom)``, ``word(atom)``, ``dword(atom)``, or
                        ``qword(atom)`` for exact little-endian widths
              ops     = ``== != < <= > >=``, ``&`` (bitwise AND),
                        ``&& ||`` (short-circuit), parens
              literal = ``0x...`` or decimal

            Examples:
              ``rcx == 0xdeadbeef``
              ``[rsp+0x18] == 0x226048``
              ``(rax & 0x80000000) != 0``
              ``rcx == 0x4 && [rdx] != 0``
              ``poi(poi(rcx+0x10)+0x8) == 0x1234``

            For string compares, encode the bytes as a little-endian
            qword literal yourself (e.g. ``"w00t"`` -> ``0x74303077``).
        wp_type: Set to install a **watchpoint** instead of an execution
            breakpoint. Values:
            ``"write"`` — break on write (Z2). The WinDbg ``ba w``
                equivalent.
            ``"read"`` — break on read (Z3).
            ``"access"`` — break on read or write (Z4). The WinDbg
                ``ba r`` equivalent.
            Watchpoints use a hardware debug register and share the
            4-slot DR0..3 pool with hw execution breakpoints.
        wp_size: Watched region size in bytes (1, 2, 4, or 8).
            Only meaningful when ``wp_type`` is set. Default 1.
        actions: Up to 16 expression strings evaluated on each in-target
            fire. Scalar expressions use the condition grammar. A complete
            action may additionally be ``bytes(addr,literal_len)``,
            ``ascii(addr,literal_len)``, or ``utf16(addr,literal_len)``.
            Captures are capped at 256 bytes each, 1024 raw bytes per hit,
            and 16 MiB per trace. Action hits append JSONL and auto-continue.

    Returns:
        JSON ``{id, va, user_mode, hw, condition, elapsed_ms}``. For
        watchpoints, also includes ``wp_type`` and ``wp_size``. For
        action bps, includes ``actions`` and ``trace_path``. The
        ``predicate_*_count`` fields appear in ``kdbg_bps`` output.
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
    """List all installed breakpoints in the current session.

    Returns:
        JSON ``{"bps": [...]}`` where each entry is
        ``{id, va, target, target_pretty, user_mode, hw, hits,
        condition, predicate_hit_count, predicate_skip_count,
        predicate_error_count, age_s}``. For unconditional bps,
        ``condition`` is null and the predicate counts stay at 0;
        ``hits`` counts every in-target fire regardless of mode.
    """
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

    Action breakpoints auto-continue and log expression values to a
    JSONL trace file on each fire. The default returns the newest 20
    records without loading the whole file. Use ``from_hit`` for forward
    pagination, filters to isolate interesting records, and ``summary``
    for compact per-expression distributions. Every page and summary is
    bounded and reports truncation explicitly.

    Args:
        bp_id: Breakpoint id (from ``kdbg_bp`` / ``kdbg_bps``).
        tail: Newest matching entries to return when ``from_hit`` is unset
            (1-200, default 20).
        from_hit: Inclusive hit-id cursor for forward pagination. When set,
            ``limit`` is used and ``tail`` is ignored.
        limit: Maximum entries in a forward page (1-200, default 20).
        expression: Exact action expression to filter and project, such as
            ``"[rsp+0x18]"``. Omit to retain all expressions.
        value: Exact value filter. Decimal and hexadecimal integers compare
            numerically, so ``34`` matches ``0x22``. With no expression,
            any action value may match.
        errors_only: Return only hits containing an ``"error: ..."`` value
            (within ``expression`` when supplied).
        summary: Aggregate every matching record into bounded per-expression
            counts, errors, distinct values, top values, min/max, and
            representative hit ids. Returned entries remain independently
            capped by ``tail``/``limit``.
        top: Top values per expression in summary output (1-20, default 10).

    Returns:
        JSON containing ``id``, ``entries``, ``total``, ``returned``,
        ``truncated``, scan/malformed metadata, optional ``next_hit``, and
        optional ``summary``.
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

    Returns:
        JSON ``{removed, va}`` on success.
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("bp_remove", id=bp_id))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_rm")


@mcp.tool()
def kdbg_cont(timeout: float = 30.0) -> dict[str, Any]:
    """Resume the VM; block until next bp hit in target's CR3.

    The daemon silent-continues fires that aren't in the target process
    (so cortex-XDR / dwm / other noise is filtered out at stop time).
    Returns when a bp fires *in the target* OR when the timeout
    expires OR when ``kdbg_interrupt`` is called from another flow.

    Args:
        timeout: Wall-clock budget in seconds (default 30). Sock timeout
            is set to ``timeout + 10`` so the daemon's wait can run
            its full budget.

    Returns:
        JSON with ``reason`` (bp/timeout/interrupt/signal/step) plus
        register summary on hit.
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

    Only valid after a stop (call ``kdbg_cont`` first or attach to a
    halted state).

    Args:
        over: Step OVER call/syscall — temp hw bp at next instruction,
            cont until it fires. Falls back to regular step for non-call.
        out: Step OUT of current function — temp hw bp at return address
            ([rsp]), cont until it fires.

    Returns:
        JSON with stop info at the new RIP.
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

    Reads up to ~16*count bytes (instructions are 1-15 bytes each) from
    the target's address space via CR3-masquerade ``mem``, then runs
    Capstone over them. Returns the first ``count`` instructions.

    Use this after a halt to see what's about to execute, or after a
    ``kdbg_step`` to see the next sequence. ``addr=""`` (default) reads
    from current RIP — the most common case.

    Args:
        addr: Hex VA (``0x7ff7b04eeabc``), decimal, or empty for RIP.
        count: How many instructions to decode (1..64).

    Returns:
        The common envelope with ``{base, instruction_bytes, instructions}``.
        Raw bytes appear only when ``instruction_bytes=true``.
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

    # Resolve start address
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
    # Cap at 15 bytes per instruction; over-read is harmless, gets discarded
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
    allow_cold: bool = False,
) -> dict[str, Any]:
    """Return focused Ghidra pseudocode for ADDR or the current RIP.

    Combines live debugger state with static analysis safely: resolves ADDR
    through a fresh target/kernel loader walk, computes an ASLR-independent
    RVA, verifies the host PE against the live module's CodeView GUID+age and
    PE headers, then asks an isolated persistent PyGhidra worker to decompile
    only the containing function. A stale or same-named wrong binary is
    refused. The JVM never runs inside the MCP server or kdbg daemon.

    A cold Ghidra project is refused by default: the target remains halted
    while its live identity is verified, and background/offline preparation
    must happen after detach or continue. Set ``allow_cold=true`` only when
    deliberately accepting cold analysis while the target is stopped. Compact
    output returns the live location, nearby assembly,
    focused pseudocode, explicit RVA-based assembly-to-pseudocode mapping,
    concise verification, and warnings. Standard or diagnostic evidence is
    available only when explicitly requested.

    Args:
        addr: Runtime VA as hex/decimal. Empty (default) means current RIP.
        symbol: Loaded symbol such as ``services!RQueryServiceStatus``.
        module: Live module name; use together with ``rva``.
        rva: Module-relative address as hex/decimal; requires ``module``.
        cursor: Opaque ``next_cursor`` from a previous page. It is pinned to
            the same debugger stop and analysis and excludes other locations.
        before: Source context lines before the mapped line (0..20).
        after: Source context lines after the mapped line (0..20).
        full: Include the whole containing function (bounded to 256 KiB).
        binary: Exact host-side PE path. Empty uses the winbox symbols cache.
        timeout: Per-function Ghidra decompilation timeout (5..300 seconds).
        analysis_timeout: Cold import/auto-analysis budget (5..1800 seconds).
        detail: Response detail: compact (default), standard, or diagnostic.
        lines: Absolute pseudocode line or range (for example ``1-22``).
            Empty uses ``before``/``after`` context around the mapped RIP.
        assembly: ``nearby`` (default) or ``mapped`` to attach corresponding
            assembly to every address-bearing selected pseudocode line.
        instruction_bytes: Include raw instruction bytes (off by default).
        runtime_vas: Include repeated static/runtime VAs in addition to RVAs.
        allow_cold: Explicitly permit a cold import/analysis while the target is halted.
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
            allow_cold=allow_cold,
        )
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_decomp")
    return _research_ok(result)


@mcp.tool()
def kdbg_decomp_status() -> dict[str, Any]:
    """Show Docker/PyGhidra API, worker/JVM state, and analysis-cache status.

    This is safe without an attached debugger and does not start the JVM.
    ``running=false`` is normal before the first ``kdbg_decomp`` request.
    """
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
    """Delete and rebuild one exact digest-keyed Ghidra project cache.

    The exact hash-addressed binary is retained. Only that digest's project
    pair is removed, then one clean rebuild is attempted; rebuilds never loop.
    """
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

    This is the one-time dependency installation for ``kdbg_decomp``. It
    downloads checksum-pinned Ghidra/PyGhidra artifacts during the Docker
    build; normal analysis containers subsequently run with networking off.

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
    """Start and verify the private persistent headless Ghidra API.

    No TCP port is exposed. The current-UID container communicates through a
    mode-0600 Unix socket and stays warm for low-latency repeated queries.
    ``kdbg_decomp`` also starts it lazily when the image is installed.
    """
    from winbox.kdbg.decomp import DecompError, start_service

    try:
        return _research_ok(start_service(_kdbg_cfg_only()))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_ghidra_run")


@mcp.tool()
def kdbg_ghidra_stop() -> dict[str, Any]:
    """Stop and remove only the labelled winbox headless Ghidra container.

    Analyzed projects and immutable binary caches remain on the host so the
    next service start does not repeat Ghidra auto-analysis.
    """
    from winbox.kdbg.decomp import DecompError, stop_service

    try:
        return _research_ok(stop_service(_kdbg_cfg_only()))
    except DecompError as exc:
        return _research_error(exc, operation="kdbg_ghidra_stop")


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
        # Direct daemon interrupt below remains the recovery path when the
        # durable state is unavailable or corrupt.
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


@mcp.tool()
def kdbg_mem(
    va: str, length: int = 64, decode: str = "hex",
) -> dict[str, Any]:
    """Read LENGTH bytes at VA in the attached target's address space.

    Uses the same CR3-masquerade trick as bp install — temporarily
    sets the firing vCPU's CR3 to target's DTB, reads via gdb ``m``,
    restores. ~40x faster than HMP page-walks. Requires an attached
    session (``kdbg_attach`` first); for session-less reads against
    arbitrary PIDs use ``kdbg_read_va`` instead.

    Args:
        va: Virtual address as hex string (``0x7ff7b04eeabc``) or
            decimal.
        length: Bytes to read (capped at 64 KiB by the daemon).
        decode: How to render the bytes:
            ``hex`` (default) — pure hex string, no decode
            ``utf-16le`` / ``utf16`` — UTF-16 little-endian, common
                for Windows wide strings (e.g. notepad's text buffer)
            ``utf-8`` / ``utf8`` — UTF-8 (saved file content, etc.)
            ``ascii`` — ASCII (control bytes shown as ``.``)
            ``cstr`` — null-terminated ASCII (truncates at first 0x00)
            ``qwords`` — array of little-endian 64-bit hex values

    Returns:
        JSON ``{va, bytes, decoded?}`` where ``bytes`` is the raw hex
        and ``decoded`` (when ``decode != 'hex'``) is the textual form.
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
            # strip trailing nulls common in fixed-size buffers
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

    Mirror of ``kdbg_mem`` but for writes. Uses CR3-masquerade so the
    write lands in the target process's address space regardless of
    which process is on-CPU. Use for fault injection, fuzzing struct
    fields, faking function returns (write 0 to RAX before step over
    return), or any modification you'd do in WinDbg with ``ed``/``eb``.

    The write is REAL — patches physical memory backing the target's
    VA. If the target reads this region next, it sees your bytes.
    Don't aim at code segments unless you mean it (that'd be a bp
    install gone wrong).

    Args:
        va: Virtual address (hex string ``0x...`` or decimal).
        data: Hex-encoded bytes (no ``0x`` prefix needed). E.g.
            ``"deadbeef"`` writes 4 bytes, ``"00"`` writes one zero.

    Returns:
        The common envelope with ``{va, length}``.
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

    The response pins registers, architecture-correct nearby assembly, native
    stack words, metadata-driven backtrace frames, active breakpoints, and up to four optional
    memory reads to one debugger ``stop_id``. This is the preferred first
    call after a breakpoint because it avoids mixing evidence across stops.

    Args:
        disasm_count: Instructions at RIP (0..32).
        stack_qwords: Native stack words to return (0..32). The name is kept
            for API compatibility; WoW64 stops return 4-byte dwords.
        bt_depth: Backtrace frames to return (0..16).
        memory: Optional list of up to four ``{va, length}`` reads; each is
            capped at 256 bytes and their combined size at 1024 bytes.
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

    Reads target's address space via CR3 masquerade, so this works
    even if the firing vCPU isn't currently in target context (rare
    but possible mid-step).

    Args:
        n: Number of words to read (1..256): 8-byte qwords in x64 code or
            4-byte dwords at a WoW64 x86 stop.

    Returns:
        JSON ``{sp, stack_register, architecture, word_size, entries}`` where
        each entry is ``{offset, va, value}``. Compatibility aliases ``rsp``
        and either ``qwords`` or ``dwords`` are also returned.
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("stack", n=int(n)))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_stack")


@mcp.tool()
def kdbg_bt(depth: int = 8) -> dict[str, Any]:
    """Unwind the live Windows x64 or WoW64 x86 stack.

    x64 uses RUNTIME_FUNCTION metadata, including unwind-v2 epilogs, chained
    records, nonvolatile restores, and machine frames. Metadata provenance is
    explicit: live image pages are preferred; Windows-discarded pages may use
    only an exact hash/identity-verified cached PE. Stack values always come
    from the pinned live stop. WoW64 x86 uses exact-build PDB old-FPO/frame
    records, then strict EBP chains and bounded straight-line prologue analysis.
    Speculative stack hits are kept in a separate ``candidates`` array and are
    never promoted to frames unless a PDB recipe explicitly requires a return
    search. At a native active WoW64 bridge, exact-build instruction-derived
    CPU-area offsets recover the saved x86 context. At an arbitrary x86 stop,
    exact nt PDB layouts validate the current KTHREAD's persisted x64 user trap
    and native TEB stack bounds. Both directions return one explicitly bounded
    ``windows-wow64-mixed`` trace; malformed or missing metadata preserves the
    truthful single-architecture trace with ``transition_error``.

    Args:
        depth: Max frames to return (1..64).

    Returns:
        JSON ``{rsp, method, complete, frames, candidates?, error?}``; frames include
        address, RSP, module/RVA, symbol, unwind operations, and metadata source.
    """
    cfg = _kdbg_cfg_only()
    try:
        return _research_ok(_kdbg_client(cfg).call("bt", depth=int(depth)))
    except _ClientError as e:
        return _research_error(e, operation="kdbg_bt")


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
        # The daemon may have exited after accepting the request. We still
        # wait for ownership release, but without its explicit safety
        # certificate we must never reconnect to the gdbstub and resume.
        detach_error = exc
    # Wait for lock release (daemon exit) up to 5s.
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
        # Already running: there is nothing to continue, and connecting to
        # the gdbstub anyway halts a healthy VM (QEMU stops the guest CPU
        # the moment a client attaches) — a "no-op" that isn't one.
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
        # close() does interrupt+detach which leaves VM running -- but its
        # own docstring warns the sequence can race QEMU and leave the VM
        # paused instead. Don't report success without checking.
        c.close()

    import time as _time
    _time.sleep(0.3)
    final = vm.state()
    if final == VMState.RUNNING:
        return _research_ok({"resumed": True, "state": final.value})
    return _research_error(
        f"VM state after release: {final.value}", operation="kdbg_resume"
    )


# ─── Entry point ────────────────────────────────────────────────────────────

def run_server() -> None:
    """Start the MCP server on stdio transport."""
    mcp.run(transport="stdio")
