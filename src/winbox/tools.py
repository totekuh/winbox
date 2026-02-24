"""Shared tools directory management."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from winbox.utils import human_size

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

# Internal files that shouldn't show up in tools list
_HIDDEN = {".ssh_pubkey", "tools.txt", "provision.ps1"}


def add(cfg: Config, files: tuple[str, ...]) -> None:
    """Copy files into the shared tools directory."""
    cfg.tools_dir.mkdir(parents=True, exist_ok=True)
    for f in files:
        src = Path(f)
        if not src.exists():
            console.print(f"[yellow][!][/] File not found: {f}")
            continue
        dest = cfg.tools_dir / src.name
        shutil.copy2(src, dest)
        if src.name.lower().endswith(".exe"):
            dest.chmod(dest.stat().st_mode | 0o755)
        console.print(f"[green][+][/] Added: {src.name}")


def list_tools(cfg: Config) -> None:
    """List tools in the shared directory."""
    if not cfg.tools_dir.exists():
        console.print("[yellow][!][/] Tools directory does not exist")
        return

    files = sorted(
        f for f in cfg.tools_dir.iterdir()
        if f.is_file() and f.name not in _HIDDEN
    )

    if not files:
        console.print("No tools found.")
        return

    table = Table(title="Tools", show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Size", justify="right")

    for f in files:
        size = human_size(f.stat().st_size)
        table.add_row(f.name, size)

    console.print(table)


def remove(cfg: Config, name: str) -> None:
    """Remove a tool from the shared directory."""
    target = (cfg.tools_dir / name).resolve()
    if not str(target).startswith(str(cfg.tools_dir.resolve())):
        console.print(f"[red][-][/] Invalid name: {name}")
        return
    if target.exists():
        target.unlink()
        console.print(f"[green][+][/] Removed: {name}")
    else:
        console.print(f"[yellow][!][/] Not found: {name}")
