"""AD Group Policy management — create, edit, remove, list, link."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.cli.ad import ad, _require_server
from winbox.config import Config
from winbox.ps import ps_quote, render_ps
from winbox.validate import check_gpo_name, check_ou_dn
from winbox.vm import GuestAgent, VM


def _validate_gpo_name(name: str) -> None:
    err = check_gpo_name(name)
    if err:
        raise click.BadParameter(err)


@ad.group("gpo")
def ad_gpo() -> None:
    """Manage Group Policy objects."""
    pass


@ad_gpo.command("create")
@click.argument("name")
@needs_vm()
def gpo_create(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str,
) -> None:
    """Create a Group Policy object.

    \b
    Example:
        winbox ad gpo create 'Disable Defender'
    """
    _require_server(cfg)
    _validate_gpo_name(name)

    result = ga.exec_powershell(
        render_ps("ad_gpo_create", gpo_name=ps_quote(name)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create GPO: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] GPO '{name}' created")


@ad_gpo.command("edit")
@click.argument("name")
@click.option("--key", required=True, help="Registry key path.")
@click.option("--value-name", required=True, help="Registry value name.")
@click.option(
    "--type", "reg_type", required=True,
    type=click.Choice(["String", "ExpandString", "DWord", "QWord", "MultiString", "Binary"]),
    help="Registry value type.",
)
@click.option("--value", required=True, help="Registry value data.")
@needs_vm()
def gpo_edit(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str, key: str, value_name: str, reg_type: str, value: str,
) -> None:
    """Set a registry-based GPO setting.

    \b
    Example:
        winbox ad gpo edit 'Disable Defender' \\
            --key 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' \\
            --value-name DisableAntiSpyware --type DWord --value 1
    """
    _require_server(cfg)
    _validate_gpo_name(name)

    result = ga.exec_powershell(
        render_ps("ad_gpo_edit",
                  gpo_name=ps_quote(name), key=ps_quote(key),
                  value_name=ps_quote(value_name),
                  reg_type=reg_type, value=ps_quote(value)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to edit GPO: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] GPO '{name}' updated: {value_name} = {value}")


@ad_gpo.command("remove")
@click.argument("name")
@needs_vm()
def gpo_remove(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str,
) -> None:
    """Delete a Group Policy object."""
    _require_server(cfg)
    _validate_gpo_name(name)

    result = ga.exec_powershell(
        render_ps("ad_gpo_remove", gpo_name=ps_quote(name)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to remove GPO: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] GPO '{name}' removed")


@ad_gpo.command("list")
@needs_vm()
def gpo_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List all Group Policy objects."""
    _require_server(cfg)

    result = ga.exec_powershell(
        render_ps("ad_gpo_list"),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list GPOs: {result.stderr.strip()}")
        raise SystemExit(1)
    if result.stdout.strip():
        console.print(result.stdout, end="", markup=False, highlight=False)
    else:
        console.print("[dim].[/] No GPOs found")


@ad_gpo.command("link")
@click.argument("name")
@click.option("--target", required=True, help="OU distinguished name to link the GPO to.")
@needs_vm()
def gpo_link(
    cfg: Config, vm: VM, ga: GuestAgent,
    name: str, target: str,
) -> None:
    """Link a GPO to an organizational unit.

    \b
    Example:
        winbox ad gpo link 'Disable Defender' --target 'OU=Workstations,DC=TESTLAB,DC=LOCAL'
    """
    _require_server(cfg)
    _validate_gpo_name(name)
    err = check_ou_dn(target)
    if err:
        raise click.BadParameter(err)

    result = ga.exec_powershell(
        render_ps("ad_gpo_link", gpo_name=ps_quote(name), target=ps_quote(target)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to link GPO: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] GPO '{name}' linked to {target}")
