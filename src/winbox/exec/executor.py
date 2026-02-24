"""Command execution logic — the core `winbox exec` feature."""

from __future__ import annotations

import shutil
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

    # Execute via guest agent (retry on "handle is invalid" — GA pipe race)
    max_retries = 3
    result: ExecResult = ga.exec(full_cmd, timeout=timeout)
    for attempt in range(1, max_retries):
        if "handle is invalid" not in result.stdout.lower() + result.stderr.lower():
            break
        time.sleep(0.5)
        result = ga.exec(full_cmd, timeout=timeout)

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
