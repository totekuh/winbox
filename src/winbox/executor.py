"""Command execution logic — the core `winbox exec` feature."""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.guest import ExecResult, GuestAgent
from winbox.utils import human_size

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


def resolve_exe(exe: str, tools_dir: Path) -> str:
    """Resolve a bare .exe name to Z:\\tools\\ path if it exists locally."""
    if exe.lower().endswith(".exe") and "\\" not in exe and "/" not in exe:
        if (tools_dir / exe).exists():
            return f"Z:\\tools\\{exe}"
    return exe


def _build_command(resolved: str, args: tuple[str, ...]) -> str:
    """Build the full Windows command string with cd to tools dir."""
    parts = [resolved] + list(args)
    cmd = " ".join(parts)
    return f"cd /d Z:\\tools && {cmd}"


def _ssh_base_args(cfg: Config, ip: str) -> list[str]:
    """Build the base SSH argument list for connecting to the VM."""
    args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    ]
    if cfg.ssh_key.exists():
        args += ["-i", str(cfg.ssh_key)]
    args.append(f"{cfg.vm_user}@{ip}")
    return args


def _run_ssh(cfg: Config, ip: str, cmd: str, timeout: int) -> int:
    """Execute a command over SSH with streaming output. Returns exit code."""
    ssh_args = _ssh_base_args(cfg, ip)
    ssh_args.append(cmd)

    # Prepend sshpass if available
    if shutil.which("sshpass"):
        ssh_args = ["sshpass", "-p", cfg.vm_password] + ssh_args

    try:
        proc = subprocess.run(
            ssh_args,
            timeout=timeout,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        return proc.returncode
    except subprocess.TimeoutExpired:
        console.print(f"\n[yellow][!][/] Command timed out after {timeout}s")
        return 1


def _run_guest_agent(ga: GuestAgent, cmd: str, timeout: int) -> int:
    """Execute a command via guest agent. Returns exit code."""
    result: ExecResult = ga.exec(cmd, timeout=timeout)

    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)

    return result.exitcode


def run_command(
    cfg: Config,
    ga: GuestAgent,
    exe: str,
    args: tuple[str, ...],
    *,
    timeout: int = 300,
    use_ssh: bool = True,
    vm_ip: str | None = None,
) -> int:
    """Execute a command in the Windows VM and display results.

    Uses SSH by default for streaming output. Falls back to guest agent
    if SSH is unavailable.

    Returns the exit code from the guest process.
    """
    resolved = resolve_exe(exe, cfg.tools_dir)
    full_cmd = _build_command(resolved, args)

    args_str = " ".join(args)
    console.print(f"[blue][*][/] Executing: {resolved} {args_str}")

    # Touch marker for detecting new output files
    marker = cfg.shared_dir / ".exec_marker"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    marker_time = time.time()

    if use_ssh and vm_ip:
        exitcode = _run_ssh(cfg, vm_ip, full_cmd, timeout)
    else:
        exitcode = _run_guest_agent(ga, full_cmd, timeout)

    # List new output files (already on host via SMB share)
    _show_new_files(cfg.loot_dir, marker_time)

    return exitcode


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
