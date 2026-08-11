"""Command execution logic — the core `winbox exec` feature."""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.vm.guest import ExecResult, GuestAgent
from winbox.jobs import Job, JobMode, JobStatus, JobStore
from winbox.utils import human_size

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


def resolve_exe(exe: str, tools_dir: Path) -> str:
    """Resolve executable to Z:\\tools\\ path.

    Handles three cases:
    - Local Linux path (/tmp/foo.exe, ./foo.exe) → copy to tools dir
    - Bare .exe name (foo.exe) → check tools dir
    - Windows path or system command → pass through
    """
    # Local Linux path → copy to VirtIO-FS share
    if "/" in exe:
        local = Path(exe).resolve()
        if local.is_file():
            dest = tools_dir / local.name
            if local != dest.resolve():
                tools_dir.mkdir(parents=True, exist_ok=True)
                if dest.exists():
                    console.print(f"[yellow][!][/] Overwriting {local.name} in tools dir")
                shutil.copy2(local, dest)
            return f"Z:\\tools\\{local.name}"

    # Bare .exe name → check tools dir (case-insensitive on Linux)
    if exe.lower().endswith(".exe") and "\\" not in exe:
        if tools_dir.exists():
            for f in tools_dir.iterdir():
                if f.name.lower() == exe.lower():
                    return f"Z:\\tools\\{f.name}"

    return exe


def _quote_cmd_arg(s: str) -> str:
    """Wrap a token in double quotes if it has whitespace, so cmd.exe's own
    parser doesn't re-split it into multiple arguments."""
    return f'"{s}"' if any(c.isspace() for c in s) else s


def run_command(
    cfg: Config,
    ga: GuestAgent,
    exe: str,
    args: tuple[str, ...],
    *,
    timeout: int = 300,
    user: str | None = None,
    password: str | None = None,
) -> int:
    """Execute a command in the Windows VM and display results.

    Returns the exit code from the guest process.
    """
    # Resolve tool path
    resolved = resolve_exe(exe, cfg.tools_dir)

    # Build the full command: cd to tools dir, then run
    args_str = " ".join(args)
    quoted_args = " ".join(_quote_cmd_arg(a) for a in args)
    full_cmd = f"cd /d Z:\\tools && {_quote_cmd_arg(resolved)}"
    if quoted_args:
        full_cmd += f" {quoted_args}"

    console.print(f"[blue][*][/] Executing: {resolved} {args_str}")

    # Touch marker for detecting new output files
    marker = cfg.shared_dir / ".exec_marker"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    marker_time = time.time()

    # The launch-transport retry (the GA pipe/transport race that fails *before*
    # the process starts) now lives one layer down, in GuestAgent.exec via
    # _start_guest_exec — a single layer, so it is not re-wrapped here (wrapping
    # it stacked the two 3x loops into up to 9 attempts). A GuestAgentError that
    # still escapes ga.exec has either already run (timeout/abandoned) or
    # exhausted the launch retry, so it must propagate untouched — cli/exec.py
    # renders it with a VM-state hint.
    #
    # What remains here is the os-path-only retry for the *post-launch* pipe
    # race: a result that comes back carrying "handle is invalid" in its own
    # output (the process launched but its stdio handle broke). Re-running can
    # double-execute, so this stays an interactive-only convenience and is
    # deliberately not applied to the automated python/powershell MCP tools.
    # Uses cmd.exe /c for cd /d and tools PATH; exec_argv() is available for
    # callers that don't need shell features (pipes, redirects, cd).
    max_retries = 3
    result: ExecResult | None = None
    for attempt in range(max_retries):
        if user is None and password is None:
            result = ga.exec(full_cmd, timeout=timeout)
        else:
            result = ga.exec(
                full_cmd, timeout=timeout, user=user, password=password,
            )
        if "handle is invalid" not in result.stdout.lower() + result.stderr.lower():
            break
        if attempt < max_retries - 1:
            console.print(f"[yellow][!][/] GA pipe race detected, retrying ({attempt + 1}/{max_retries})...")
            time.sleep(0.5)
    assert result is not None  # the loop body runs at least once

    # Print stdout/stderr
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)

    # List new output files (already on host via VirtIO-FS)
    _show_new_files(cfg.loot_dir, marker_time)

    return result.exitcode


def run_command_bg(
    cfg: Config,
    ga: GuestAgent,
    exe: str,
    args: tuple[str, ...],
    *,
    log: bool = False,
    user: str | None = None,
    password: str | None = None,
) -> Job:
    """Launch a command in the Windows VM as a background job.

    If log=True, redirects stdout/stderr to files on VirtIO-FS (supports
    tail -f). Otherwise uses GA-buffered output (retrieved via exec_status).
    """
    resolved = resolve_exe(exe, cfg.tools_dir)
    args_str = " ".join(args)
    quoted_args = " ".join(_quote_cmd_arg(a) for a in args)
    full_cmd = f"cd /d Z:\\tools && {_quote_cmd_arg(resolved)}"
    if quoted_args:
        full_cmd += f" {quoted_args}"

    store = JobStore(cfg)

    def _spawn(job_id: int) -> Job:
        if log:
            cfg.jobs_log_dir.mkdir(parents=True, exist_ok=True)
            stdout_path = store.vm_log_path(job_id, "stdout")
            stderr_path = store.vm_log_path(job_id, "stderr")
            wrapped = f"{full_cmd} > {stdout_path} 2> {stderr_path}"
            if user is None and password is None:
                pid = ga.exec_detached(wrapped)
            else:
                pid = ga.exec_detached(wrapped, user=user, password=password)
            mode = JobMode.LOG
        else:
            if user is None and password is None:
                pid = ga.exec_background(full_cmd)
            else:
                pid = ga.exec_background(
                    full_cmd, user=user, password=password,
                )
            mode = JobMode.BUFFERED
        return Job(
            id=job_id, pid=pid,
            command=f"{resolved} {args_str}".strip(),
            mode=mode,
        )

    return store.claim(_spawn)


def _show_new_files(loot_dir: Path, since: float) -> None:
    """Find and display files created after the given timestamp."""
    if not loot_dir.exists():
        return

    jobs_dir = loot_dir / ".jobs"
    new_files = []
    for f in loot_dir.rglob("*"):
        if str(f).startswith(str(jobs_dir)):
            continue
        try:
            # The guest may unlink a file (VirtIO-FS loot churn during a
            # detonation) between rglob yielding it and this stat — skip
            # vanished files instead of crashing the output display.
            if f.is_file() and f.stat().st_mtime > since:
                new_files.append(f)
        except OSError:
            continue

    if new_files:
        console.print()
        console.print("[green][+][/] Output files:")
        for f in new_files:
            try:
                size = human_size(f.stat().st_size)
            except OSError:
                continue
            console.print(f"    {f} ({size})")
