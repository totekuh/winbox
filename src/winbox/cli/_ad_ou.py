"""AD organizational unit management — create, delete, list."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.cli.ad import ad, _require_server
from winbox.config import Config
from winbox.ps import ps_quote, render_ps
from winbox.validate import check_ou_dn
from winbox.vm import GuestAgent, VM


@ad.group("ou")
def ad_ou() -> None:
    """Manage Active Directory organizational units."""
    pass


@ad_ou.command("create")
@click.argument("name")
@click.option("--path", default=None, help="Parent OU distinguished name.")
@needs_vm()
def ou_create(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str, path: str | None,
) -> None:
    """Create an organizational unit.

    \b
    Example:
        winbox ad ou create ServiceAccounts
        winbox ad ou create Servers --path 'DC=TESTLAB,DC=LOCAL'
    """
    _require_server(cfg)
    if path:
        err = check_ou_dn(path)
        if err:
            raise click.BadParameter(err)

    result = ga.exec_powershell(
        render_ps("ad_ou_create", ou_name=ps_quote(name),
                  path=ps_quote(path or "")),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create OU: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] OU {name} created")


@ad_ou.command("delete")
@click.argument("dn")
@needs_vm()
def ou_delete(
    cfg: Config, vm: VM, ga: GuestAgent,
    dn: str,
) -> None:
    """Delete an organizational unit by distinguished name."""
    _require_server(cfg)
    err = check_ou_dn(dn)
    if err:
        raise click.BadParameter(err)

    result = ga.exec_powershell(
        render_ps("ad_ou_delete", dn=ps_quote(dn)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to delete OU: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] OU deleted: {dn}")


@ad_ou.command("list")
@needs_vm()
def ou_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List organizational units."""
    _require_server(cfg)

    result = ga.exec_powershell(
        render_ps("ad_ou_list"),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list OUs: {result.stderr.strip()}")
        raise SystemExit(1)
    if result.stdout.strip():
        console.print(result.stdout, end="", markup=False, highlight=False)
    else:
        console.print("[dim].[/] No organizational units found")
