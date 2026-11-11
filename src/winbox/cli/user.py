"""Local Windows user management commands — user (create, delete, list)."""

from __future__ import annotations

import base64

import click

from winbox.cli import console, needs_vm
from winbox.cli.share import _validate_username
from winbox.config import Config
from winbox.ps import render_ps, ps_quote
from winbox.vm import GuestAgent, VM


@click.group()
def user() -> None:
    """Manage local Windows users on the VM."""
    pass


@user.command("create")
@click.argument("username")
@click.option("--password", required=True, help="Password for the new user.")
@click.option("--full-name", default="", help="Display name.")
@click.option(
    "--no-password-expire/--password-expire",
    default=True,
    help="Password never expires (default: never expires).",
)
@needs_vm()
def user_create(
    cfg: Config,
    vm: VM,
    ga: GuestAgent,
    username: str,
    password: str,
    full_name: str,
    no_password_expire: bool,
) -> None:
    """Create a local Windows user.

    \b
    Examples:
        winbox user create alice --password 'P@ssw0rd!'
        winbox user create bob --password secret --full-name 'Bob Smith'
    """
    _validate_username(username)

    pass_b64 = base64.b64encode(password.encode()).decode()
    no_expire = "$true" if no_password_expire else "$false"

    console.print(f"[blue][*][/] Creating user '{username}'...")
    result = ga.exec_powershell(
        render_ps("user_create",
                  username=ps_quote(username),
                  pass_b64=pass_b64,
                  full_name=ps_quote(full_name),
                  no_expire=no_expire),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create user: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] User '{username}' created")


@user.command("delete")
@click.argument("username")
@needs_vm()
def user_delete(cfg: Config, vm: VM, ga: GuestAgent, username: str) -> None:
    """Delete a local Windows user.

    \b
    Example: winbox user delete alice
    """
    _validate_username(username)

    console.print(f"[blue][*][/] Deleting user '{username}'...")
    result = ga.exec_powershell(
        f"Remove-LocalUser -Name '{ps_quote(username)}' -ErrorAction Stop",
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to delete user: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] User '{username}' deleted")


@user.command("list")
@needs_vm()
def user_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List local Windows users."""
    result = ga.exec_powershell(render_ps("user_list"), timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list users: {result.stderr.strip()}")
        raise SystemExit(1)

    output = result.stdout.strip()
    if not output:
        console.print("No users found")
        return
    console.print(output, highlight=False)


REGISTER = ("Network", [user])
