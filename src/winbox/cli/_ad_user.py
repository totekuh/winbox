"""AD domain user management — create, delete, list."""

from __future__ import annotations

import click

from winbox.ad import encode_password
from winbox.cli import console, needs_vm
from winbox.cli.ad import ad, _require_server
from winbox.config import Config
from winbox.ps import ps_quote, render_ps
from winbox.validate import check_ad_username, check_ou_dn
from winbox.vm import GuestAgent, VM


def _validate_ad_user(name: str) -> None:
    err = check_ad_username(name)
    if err:
        raise click.BadParameter(err)


@ad.group("user")
def ad_user() -> None:
    """Manage Active Directory domain users."""
    pass


@ad_user.command("create")
@click.argument("sam")
@click.option("--password", prompt=True, hide_input=True, help="User password.")
@click.option("--upn", default=None, help="User principal name (default: sam@domain).")
@click.option("--ou", default=None, help="OU distinguished name to place the user in.")
@needs_vm()
def user_create(
    cfg: Config, vm: VM, ga: GuestAgent,
    sam: str, password: str, upn: str | None, ou: str | None,
) -> None:
    """Create a domain user account.

    \b
    Example:
        winbox ad user create jdoe --password Secret123!
        winbox ad user create svc_sql --password P@ss --ou 'OU=Service,DC=TESTLAB,DC=LOCAL'
    """
    _require_server(cfg)
    _validate_ad_user(sam)
    if ou:
        err = check_ou_dn(ou)
        if err:
            raise click.BadParameter(err)

    pass_b64 = encode_password(password)
    result = ga.exec_powershell(
        render_ps("ad_user_create",
                  sam=ps_quote(sam),
                  pass_b64=pass_b64,
                  upn=ps_quote(upn or ""),
                  ou=ps_quote(ou or "")),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create user: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Domain user {sam} created")


@ad_user.command("delete")
@click.argument("sam")
@needs_vm()
def user_delete(
    cfg: Config, vm: VM, ga: GuestAgent,
    sam: str,
) -> None:
    """Delete a domain user account."""
    _require_server(cfg)
    _validate_ad_user(sam)

    result = ga.exec_powershell(
        render_ps("ad_user_delete", sam=ps_quote(sam)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to delete user: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Domain user {sam} deleted")


@ad_user.command("list")
@click.option("--ou", default=None, help="Scope to a specific OU (distinguished name).")
@needs_vm()
def user_list(
    cfg: Config, vm: VM, ga: GuestAgent,
    ou: str | None,
) -> None:
    """List domain user accounts."""
    _require_server(cfg)

    search_base = f" -SearchBase '{ps_quote(ou)}'" if ou else ""
    result = ga.exec_powershell(
        render_ps("ad_user_list", search_base=search_base),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list users: {result.stderr.strip()}")
        raise SystemExit(1)
    if result.stdout.strip():
        console.print(result.stdout, end="", markup=False, highlight=False)
    else:
        console.print("[dim].[/] No domain users found")
