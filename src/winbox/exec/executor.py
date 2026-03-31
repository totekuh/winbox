"""Command execution logic — the core `winbox exec` feature."""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.vm.guest import ExecResult, GuestAgent, GuestAgentError
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


def run_command(
    cfg: Config,
    ga: GuestAgent,
    exe: str,
    args: tuple[str, ...],
    *,
    timeout: int = 300,
) -> int:
    """Execute a command in the Windows VM and display results.

    Returns the exit code from the guest process.
    """
    # Resolve tool path
    resolved = resolve_exe(exe, cfg.tools_dir)

    # Build the full command: cd to tools dir, then run
    args_str = " ".join(args)
    full_cmd = f"cd /d Z:\\tools && {resolved}"
    if args_str:
        full_cmd += f" {args_str}"

    console.print(f"[blue][*][/] Executing: {resolved} {args_str}")

    # Touch marker for detecting new output files
    marker = cfg.shared_dir / ".exec_marker"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    marker_time = time.time()

    # Execute via guest agent (retry on "handle is invalid" — GA pipe race).
    # Uses cmd.exe /c for cd /d and tools PATH; exec_argv() is available for
    # callers that don't need shell features (pipes, redirects, cd).
    max_retries = 3
    result: ExecResult | None = None
    for attempt in range(max_retries):
        try:
            result = ga.exec(full_cmd, timeout=timeout)
        except GuestAgentError as e:
            if attempt < max_retries - 1:
                console.print(f"[yellow][!][/] GA error, retrying ({attempt + 1}/{max_retries})...")
                time.sleep(0.5)
                continue
            raise
        if "handle is invalid" not in result.stdout.lower() + result.stderr.lower():
            break
        if attempt < max_retries - 1:
            console.print(f"[yellow][!][/] GA pipe race detected, retrying ({attempt + 1}/{max_retries})...")
            time.sleep(0.5)
    assert result is not None

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
) -> Job:
    """Launch a command in the Windows VM as a background job.

    If log=True, redirects stdout/stderr to files on VirtIO-FS (supports
    tail -f). Otherwise uses GA-buffered output (retrieved via exec_status).
    """
    resolved = resolve_exe(exe, cfg.tools_dir)
    args_str = " ".join(args)
    full_cmd = f"cd /d Z:\\tools && {resolved}"
    if args_str:
        full_cmd += f" {args_str}"

    store = JobStore(cfg)
    job_id = store.next_id()

    if log:
        cfg.jobs_log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = store.vm_log_path(job_id, "stdout")
        stderr_path = store.vm_log_path(job_id, "stderr")
        wrapped = f"{full_cmd} > {stdout_path} 2> {stderr_path}"
        pid = ga.exec_detached(wrapped)
        mode = JobMode.LOG
    else:
        pid = ga.exec_background(full_cmd)
        mode = JobMode.BUFFERED

    job = Job(id=job_id, pid=pid, command=f"{resolved} {args_str}".strip(), mode=mode)
    store.add(job)
    return job


def _show_new_files(loot_dir: Path, since: float) -> None:
    """Find and display files created after the given timestamp."""
    if not loot_dir.exists():
        return

    new_files = [
        f for f in loot_dir.rglob("*")
        if f.is_file() and f.stat().st_mtime > since
    ]

    if new_files:
        console.print()
        console.print("[green][+][/] Output files:")
        for f in new_files:
            size = human_size(f.stat().st_size)
            console.print(f"    {f} ({size})")
