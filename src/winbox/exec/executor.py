"""Command execution logic — the core `winbox exec` feature."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.vm.guest import ExecResult, GuestAgent
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

    # Execute via guest agent (retry on "handle is invalid" — GA pipe race)
    max_retries = 3
    for attempt in range(max_retries):
        result: ExecResult = ga.exec(full_cmd, timeout=timeout)
        if "handle is invalid" not in result.stdout.lower() + result.stderr.lower():
            break
        if attempt < max_retries - 1:
            time.sleep(0.5)

    # Print stdout/stderr
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)

    # List new output files (already on host via VirtIO-FS)
    _show_new_files(cfg.loot_dir, marker_time)

    return result.exitcode


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
