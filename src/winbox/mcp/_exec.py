"""Guest execution tools — python, powershell, exec, job_result."""

from __future__ import annotations

import json as _json
import shutil

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (
    _bg_label,

    _execution_json,
    _launch_bg_job,
)
from winbox.jobs import JobStatus, JobStore
from winbox.vm import GuestAgentError
from winbox.vm.guest import _clixml_to_text


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
        cfg, vm, ga = _mcp_common._ensure_vm_ready()

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
        result = _mcp_common._exec_python(code, timeout=timeout)
    else:
        result = _mcp_common._exec_python(
            code, timeout=timeout, user=user, password=password,
        )
    return _json.dumps({
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "exitcode": result["exitcode"],
    })


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
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
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
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
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
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    store = JobStore(cfg)
    job = store.get(job_id)
    if job is None:
        return _json.dumps({"error": f"job {job_id} not found"})

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
        return _json.dumps({
            "job_id": job.id, "pid": job.pid, "running": True,
            "note": f"could not poll guest: {e}",
        })

    if not status["exited"]:
        return _json.dumps({"job_id": job.id, "pid": job.pid, "running": True})

    stdout = status["stdout"]
    if job.nonce:
        if job.nonce not in stdout:
            job.status = JobStatus.LOST
            store.update(job)
            return _json.dumps({
                "job_id": job.id, "pid": job.pid,
                "error": "PID recycled — nonce mismatch",
            })
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
    shutil.rmtree(cfg.shared_dir / ".mcp" / "jobs" / str(job.id), ignore_errors=True)
    return _json.dumps({
        "job_id": job.id, "pid": job.pid, "exitcode": job.exitcode,
        "stdout": job.stdout, "stderr": job.stderr, "running": False,
    })
