"""AD group management — create, delete, list, add-member, remove-member."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.cli.ad import ad, _require_server
from winbox.config import Config
from winbox.ps import ps_quote, render_ps
from winbox.validate import check_ad_username, check_ou_dn
from winbox.vm import GuestAgent, VM


def _validate_group_name(name: str) -> None:
    err = check_ad_username(name)
    if err:
        raise click.BadParameter(err)


@ad.group("group")
def ad_group() -> None:
    """Manage Active Directory groups."""
    pass


@ad_group.command("create")
@click.argument("name")
@click.option(
    "--scope", type=click.Choice(["Global", "Universal", "DomainLocal"]),
    default="Global", help="Group scope (default: Global).",
)
@click.option("--ou", default=None, help="OU distinguished name.")
@needs_vm()
def group_create(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str, scope: str, ou: str | None,
) -> None:
    """Create an AD security group.

    \b
    Example:
        winbox ad group create IT-Admins
        winbox ad group create DBAs --scope Universal --ou 'OU=Groups,DC=TESTLAB,DC=LOCAL'
    """
    _require_server(cfg)
    _validate_group_name(name)
    if ou:
        err = check_ou_dn(ou)
        if err:
            raise click.BadParameter(err)

    result = ga.exec_powershell(
        render_ps("ad_group_create",
                  group_name=ps_quote(name), scope=scope,
                  ou=ps_quote(ou or "")),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create group: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Group {name} created ({scope})")


@ad_group.command("delete")
@click.argument("name")
@needs_vm()
def group_delete(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str,
) -> None:
    """Delete an AD group."""
    _require_server(cfg)
    _validate_group_name(name)

    result = ga.exec_powershell(
        render_ps("ad_group_delete", group_name=ps_quote(name)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to delete group: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Group {name} deleted")


@ad_group.command("list")
@needs_vm()
def group_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List AD groups."""
    _require_server(cfg)

    result = ga.exec_powershell(
        render_ps("ad_group_list"),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list groups: {result.stderr.strip()}")
        raise SystemExit(1)
    if result.stdout.strip():
        console.print(result.stdout, end="", markup=False, highlight=False)
    else:
        console.print("[dim].[/] No groups found")


@ad_group.command("add-member")
@click.argument("group")
@click.argument("member")
@needs_vm()
def group_add_member(
    cfg: Config, vm: VM, ga: GuestAgent,
    group: str, member: str,
) -> None:
    """Add a member to an AD group.

    \b
    Example:
        winbox ad group add-member IT-Admins jdoe
    """
    _require_server(cfg)
    _validate_group_name(group)

    result = ga.exec_powershell(
        render_ps("ad_group_add_member",
                  group=ps_quote(group), member=ps_quote(member)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] {member} added to {group}")


@ad_group.command("remove-member")
@click.argument("group")
@click.argument("member")
@needs_vm()
def group_remove_member(
    cfg: Config, vm: VM, ga: GuestAgent,
    group: str, member: str,
) -> None:
    """Remove a member from an AD group."""
    _require_server(cfg)
    _validate_group_name(group)

    result = ga.exec_powershell(
        render_ps("ad_group_remove_member",
                  group=ps_quote(group), member=ps_quote(member)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] {member} removed from {group}")
