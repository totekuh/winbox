"""binfmt_misc CLI commands — enable, disable, status."""

from __future__ import annotations

import os

import click

from winbox import binfmt as binfmt_mod
from winbox.cli import console
from winbox.config import Config


@click.group()
def binfmt() -> None:
    """Manage binfmt_misc .exe handler for transparent execution."""
    pass


@binfmt.command("enable")
@click.option("--no-persist", is_flag=True, help="Don't persist across reboots.")
@click.pass_context
def binfmt_enable(ctx: click.Context, no_persist: bool) -> None:
    """Register .exe handler so Windows tools run transparently."""
    cfg: Config = ctx.obj["cfg"]

    console.print("[blue][*][/] Installing handler script...")
    try:
        handler_path = binfmt_mod.register(cfg, persist=not no_persist)
    except FileNotFoundError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    except RuntimeError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    except PermissionError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    console.print(f"[green][+][/] Handler: {handler_path}")
    console.print("[green][+][/] .exe files will now execute via winbox")

    if not no_persist:
        console.print(
            f"[green][+][/] Persistent across reboots ({binfmt_mod.BINFMT_PERSIST})"
        )

    count = binfmt_mod.mark_tools_executable(cfg)
    if count:
        console.print(f"[green][+][/] Marked {count} tool{'s' if count != 1 else ''} executable")

    tools_dir = cfg.tools_dir
    path_dirs = os.environ.get("PATH", "").split(":")
    if str(tools_dir) not in path_dirs:
        console.print()
        console.print("Add tools dir to PATH:")
        console.print(f'    export PATH="{tools_dir}:$PATH"')


@binfmt.command("disable")
def binfmt_disable() -> None:
    """Unregister .exe handler."""
    if not binfmt_mod.is_registered() and not binfmt_mod.BINFMT_PERSIST.exists():
        console.print("[yellow][!][/] Not registered")
        return

    try:
        binfmt_mod.unregister()
    except PermissionError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    console.print("[green][+][/] .exe handler unregistered")


@binfmt.command("status")
@click.pass_context
def binfmt_status(ctx: click.Context) -> None:
    """Show binfmt_misc registration status."""
    cfg: Config = ctx.obj["cfg"]

    registered = binfmt_mod.is_registered()
    handler = binfmt_mod.handler_path(cfg)
    handler_exists = handler.exists()
    persistent = binfmt_mod.BINFMT_PERSIST.exists()

    # Status convention: green[+] for ON state, dim for OFF state (neutral
    # — not an error or warning). yellow[!] is reserved for genuine
    # inconsistencies the user should fix (e.g. registered but handler
    # missing).
    if registered:
        console.print("[green][+][/] Registered: enabled")
    else:
        console.print("[dim]·[/] Registered: no")

    if handler_exists:
        console.print(f"[green][+][/] Handler: {handler}")
    elif registered:
        console.print("[yellow][!][/] Handler: not found")
        console.print("    [yellow]Warning: registered but handler missing — re-run [bold]winbox binfmt enable[/][/]")
    else:
        console.print("[dim]·[/] Handler: not found")

    if persistent:
        console.print(f"[green][+][/] Persistent: {binfmt_mod.BINFMT_PERSIST}")
    else:
        console.print("[dim]·[/] Persistent: no")

    tools_dir = cfg.tools_dir
    path_dirs = os.environ.get("PATH", "").split(":")
    if str(tools_dir) in path_dirs:
        console.print(f"[green][+][/] PATH: tools dir included ({tools_dir})")
    else:
        console.print(f"[dim]·[/] PATH: tools dir not included")
        console.print(f'    export PATH="{tools_dir}:$PATH"')


REGISTER = ("Integrations", [binfmt])
