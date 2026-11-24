"""AD computer account management — list."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.cli.ad import ad, _require_server
from winbox.config import Config
from winbox.ps import render_ps
from winbox.vm import GuestAgent, VM


@ad.group("computer")
def ad_computer() -> None:
    """Manage Active Directory computer accounts."""
    pass


@ad_computer.command("list")
@needs_vm()
def computer_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List domain computer accounts."""
    _require_server(cfg)

    result = ga.exec_powershell(
        render_ps("ad_computer_list"),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list computers: {result.stderr.strip()}")
        raise SystemExit(1)
    if result.stdout.strip():
        console.print(result.stdout, end="", markup=False, highlight=False)
    else:
        console.print("[dim].[/] No computer accounts found")
