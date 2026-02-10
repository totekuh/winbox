"""File management commands — tools (add, list, remove), iso (download, status)."""

from __future__ import annotations

import click

from winbox import tools as tools_mod
from winbox.cli import console
from winbox.config import Config
from winbox.iso import ISO_FILENAME, download_iso
from winbox.utils import human_size


# ─── tools ───────────────────────────────────────────────────────────────────


@click.group()
def tools() -> None:
    """Manage tools in the shared directory."""
    pass


@tools.command("add")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.pass_context
def tools_add(ctx: click.Context, files: tuple[str, ...]) -> None:
    """Copy files into the shared tools directory."""
    cfg: Config = ctx.obj["cfg"]
    tools_mod.add(cfg, files)


@tools.command("list")
@click.pass_context
def tools_list(ctx: click.Context) -> None:
    """List tools in the shared directory."""
    cfg: Config = ctx.obj["cfg"]
    tools_mod.list_tools(cfg)


@tools.command("remove")
@click.argument("name")
@click.pass_context
def tools_remove(ctx: click.Context, name: str) -> None:
    """Remove a tool from the shared directory."""
    cfg: Config = ctx.obj["cfg"]
    tools_mod.remove(cfg, name)


# ─── iso ─────────────────────────────────────────────────────────────────────


@click.group()
def iso() -> None:
    """Manage the Windows ISO."""
    pass


@iso.command("download")
@click.option("--force", "-f", is_flag=True, help="Re-download even if ISO exists.")
@click.pass_context
def iso_download(ctx: click.Context, force: bool) -> None:
    """Download the Windows Server 2022 Evaluation ISO (~5GB)."""
    cfg: Config = ctx.obj["cfg"]
    download_iso(cfg, force=force)


@iso.command("status")
@click.pass_context
def iso_status(ctx: click.Context) -> None:
    """Check if the Windows ISO is downloaded."""
    cfg: Config = ctx.obj["cfg"]
    path = cfg.iso_dir / ISO_FILENAME
    if path.exists():
        size = path.stat().st_size
        console.print(f"[green][+][/] ISO found: {path} ({human_size(size)})")
    else:
        console.print("[yellow][!][/] ISO not downloaded")
        console.print("    Run: [bold]winbox iso download[/]")
