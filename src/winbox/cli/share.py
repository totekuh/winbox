"""Share management commands — share (create, delete, list, grant, revoke).

Filesystem operations (ls, mkdir, write, rm) live in share_files.py.
User management (create, delete, list) lives in user.py.
"""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.config import Config
from winbox.ps import render_ps, ps_quote
from winbox.validate import check_share_name, check_username, check_relative_path
from winbox.vm import GuestAgent, VM


# ─── Validation (thin wrappers raising click-specific errors) ────────────────


def _validate_share_name(name: str) -> None:
    err = check_share_name(name)
    if err:
        raise click.BadParameter(err)


def _validate_username(username: str) -> None:
    err = check_username(username)
    if err:
        raise click.BadParameter(err)


def _validate_relative_path(path: str) -> str:
    err, normalized = check_relative_path(path)
    if err:
        raise click.BadParameter(err)
    return normalized


# ─── Helpers ────────────────────────────────────────────────────────────────


def _resolve_share_path(ga: GuestAgent, share_name: str) -> str:
    """Query a share's backing folder path on the guest."""
    result = ga.exec_powershell(
        f"(Get-SmbShare -Name '{ps_quote(share_name)}' -ErrorAction Stop).Path",
        timeout=15,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Share '{share_name}' not found: {result.stderr.strip()}")
        raise SystemExit(1)
    base = result.stdout.strip()
    if not base:
        console.print(f"[red][-][/] Share '{share_name}' has no backing path")
        raise SystemExit(1)
    return base


def _guarded_path_script(share_name: str, relpath: str, action_lines: str) -> str:
    """Build a PS script that resolves + guards a path inside a share, then runs action_lines."""
    return (
        f"$base = (Get-SmbShare -Name '{ps_quote(share_name)}' -ErrorAction Stop).Path\n"
        f"$full = [IO.Path]::GetFullPath((Join-Path $base '{ps_quote(relpath)}'))\n"
        "if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {{\n"
        "    Write-Error 'Path escapes share boundary'; exit 1\n"
        "}}\n"
        f"{action_lines}"
    )


def _build_access_params(
    full_access: tuple[str, ...],
    change_access: tuple[str, ...],
    read_access: tuple[str, ...],
) -> str:
    """Build the access-control flags for New-SmbShare."""
    parts: list[str] = []
    if full_access:
        quoted = ",".join(f"'{ps_quote(u)}'" for u in full_access)
        parts.append(f"-FullAccess {quoted}")
    if change_access:
        quoted = ",".join(f"'{ps_quote(u)}'" for u in change_access)
        parts.append(f"-ChangeAccess {quoted}")
    if read_access:
        quoted = ",".join(f"'{ps_quote(u)}'" for u in read_access)
        parts.append(f"-ReadAccess {quoted}")
    return " ".join(parts)


# ─── share ──────────────────────────────────────────────────────────────────


@click.group()
def share() -> None:
    """Manage SMB shares on the VM."""
    pass


@share.command("create")
@click.argument("name")
@click.argument("path", required=False, default=None)
@click.option("--full-access", multiple=True, help="Accounts with FullAccess (default: Everyone).")
@click.option("--change-access", multiple=True, help="Accounts with Change access.")
@click.option("--read-access", multiple=True, help="Accounts with Read access.")
@needs_vm()
def share_create(
    cfg: Config,
    vm: VM,
    ga: GuestAgent,
    name: str,
    path: str | None,
    full_access: tuple[str, ...],
    change_access: tuple[str, ...],
    read_access: tuple[str, ...],
) -> None:
    """Create an SMB share.

    Default backing folder: C:\\Shares\\<NAME>.

    \b
    Examples:
        winbox share create Data
        winbox share create Docs D:\\Documents --read-access bob
    """
    _validate_share_name(name)
    if path is None:
        path = f"C:\\Shares\\{name}"

    if not full_access and not change_access and not read_access:
        full_access = ("Everyone",)

    access_params = _build_access_params(full_access, change_access, read_access)

    console.print(f"[blue][*][/] Creating share '{name}' at {path}...")
    result = ga.exec_powershell(
        render_ps("share_create",
                  share_name=ps_quote(name),
                  path=ps_quote(path),
                  access_params=access_params),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create share: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(f"[green][+][/] Share '{name}' created at {path}")


@share.command("delete")
@click.argument("name")
@click.option("--purge", is_flag=True, help="Also delete the backing folder.")
@needs_vm()
def share_delete(
    cfg: Config, vm: VM, ga: GuestAgent, name: str, purge: bool
) -> None:
    """Remove an SMB share.

    Use --purge to also delete the backing folder and its contents.
    """
    _validate_share_name(name)

    backing_path = None
    if purge:
        backing_path = _resolve_share_path(ga, name)

    console.print(f"[blue][*][/] Removing share '{name}'...")
    result = ga.exec_powershell(
        f"Remove-SmbShare -Name '{ps_quote(name)}' -Force -ErrorAction Stop",
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to remove share: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Share '{name}' removed")

    if purge and backing_path:
        result = ga.exec_powershell(
            f"Remove-Item -Path '{ps_quote(backing_path)}' -Recurse -Force -ErrorAction Stop",
            timeout=30,
        )
        if result.exitcode != 0:
            console.print(f"[yellow][!][/] Share removed but folder cleanup failed: {result.stderr.strip()}")
        else:
            console.print(f"[green][+][/] Backing folder {backing_path} deleted")


@share.command("list")
@needs_vm()
def share_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List SMB shares on the VM."""
    result = ga.exec_powershell(render_ps("share_list"), timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list shares: {result.stderr.strip()}")
        raise SystemExit(1)

    output = result.stdout.strip()
    if not output:
        console.print("No shares found")
        return
    console.print(output, highlight=False)


@share.command("grant")
@click.argument("name")
@click.argument("user")
@click.option(
    "--permission",
    type=click.Choice(["full", "change", "read"], case_sensitive=False),
    default="full",
    help="Permission level (default: full).",
)
@needs_vm()
def share_grant(
    cfg: Config, vm: VM, ga: GuestAgent, name: str, user: str, permission: str
) -> None:
    """Grant share access to a user.

    \b
    Example: winbox share grant Data bob --permission read
    """
    _validate_share_name(name)
    perm_map = {"full": "Full", "change": "Change", "read": "Read"}
    ps_perm = perm_map[permission.lower()]

    console.print(f"[blue][*][/] Granting {ps_perm} access on '{name}' to {user}...")
    result = ga.exec_powershell(
        render_ps("share_grant",
                  share_name=ps_quote(name),
                  account=ps_quote(user),
                  permission=ps_perm),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to grant access: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] {user} granted {ps_perm} on '{name}'")


@share.command("revoke")
@click.argument("name")
@click.argument("user")
@needs_vm()
def share_revoke(cfg: Config, vm: VM, ga: GuestAgent, name: str, user: str) -> None:
    """Revoke share access from a user.

    \b
    Example: winbox share revoke Data bob
    """
    _validate_share_name(name)

    console.print(f"[blue][*][/] Revoking access on '{name}' from {user}...")
    result = ga.exec_powershell(
        render_ps("share_revoke", share_name=ps_quote(name), account=ps_quote(user)),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to revoke access: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] {user} access revoked on '{name}'")


import winbox.cli._share_files as _share_files  # noqa: E402, F401 — registers subcommands on import

REGISTER = ("Network", [share])
