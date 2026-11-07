"""Share and user management commands — share (create, delete, list, grant, revoke,
ls, mkdir, write, rm), user (create, delete, list)."""

from __future__ import annotations

import base64
import re
import shutil
from pathlib import Path

import click

from winbox.cli import console, needs_vm
from winbox.config import Config
from winbox.ps import render_ps, ps_quote
from winbox.vm import GuestAgent, VM


# ─── Validation ─────────────────────────────────────────────────────────────

_SHARE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,20}$")


def _validate_share_name(name: str) -> None:
    if not _SHARE_NAME_RE.match(name):
        raise click.BadParameter(
            f"Invalid share name: {name!r} "
            "(alphanumeric, hyphens, underscores, dots; max 80 chars)"
        )


def _validate_username(username: str) -> None:
    if not _USERNAME_RE.match(username):
        raise click.BadParameter(
            f"Invalid username: {username!r} "
            "(alphanumeric, hyphens, underscores, dots, spaces; max 20 chars)"
        )


def _validate_relative_path(path: str) -> str:
    """Validate and normalize a relative path within a share.

    Returns the normalized backslash path.
    """
    if not path:
        raise click.BadParameter("Path cannot be empty")

    normalized = path.replace("/", "\\")

    if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("\\"):
        raise click.BadParameter(f"Path must be relative, not absolute: {path!r}")

    parts = normalized.split("\\")
    for part in parts:
        if part == "..":
            raise click.BadParameter(f"Path traversal ('..') not allowed: {path!r}")

    if re.search(r'[<>"|?*:]', normalized):
        raise click.BadParameter(f"Invalid characters in path: {path!r}")

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
    """Build a PS script that resolves + guards a path inside a share, then runs action_lines.

    action_lines can reference $full (the validated absolute path) and $base.
    """
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


@share.command("ls")
@click.argument("name")
@click.argument("path", default="")
@needs_vm()
def share_ls(cfg: Config, vm: VM, ga: GuestAgent, name: str, path: str) -> None:
    """List files inside a share.

    \b
    Examples:
        winbox share ls Data
        winbox share ls Data subdir/nested
    """
    _validate_share_name(name)

    if path:
        relpath = _validate_relative_path(path)
        script = _guarded_path_script(
            name, relpath,
            "Get-ChildItem -Path $full | "
            "Format-Table Name,Length,LastWriteTime -AutoSize | "
            "Out-String -Width 200",
        )
    else:
        script = (
            f"$base = (Get-SmbShare -Name '{ps_quote(name)}' -ErrorAction Stop).Path\n"
            "Get-ChildItem -Path $base | "
            "Format-Table Name,Length,LastWriteTime -AutoSize | "
            "Out-String -Width 200"
        )

    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    output = result.stdout.strip()
    if not output:
        console.print("(empty)")
        return
    console.print(output, highlight=False)


@share.command("mkdir")
@click.argument("name")
@click.argument("path")
@needs_vm()
def share_mkdir(cfg: Config, vm: VM, ga: GuestAgent, name: str, path: str) -> None:
    """Create a directory inside a share.

    \b
    Example: winbox share mkdir Data reports/2024
    """
    _validate_share_name(name)
    relpath = _validate_relative_path(path)

    script = _guarded_path_script(
        name, relpath,
        "New-Item -ItemType Directory -Path $full -Force | Out-Null\n"
        "Write-Host $full",
    )

    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create directory: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Created {result.stdout.strip()}")


@share.command("write")
@click.argument("name")
@click.argument("path")
@click.option("--content", help="Inline text content to write.")
@click.option("--source", type=click.Path(exists=True, dir_okay=False),
              help="Upload a file from Kali.")
@needs_vm()
def share_write(
    cfg: Config,
    vm: VM,
    ga: GuestAgent,
    name: str,
    path: str,
    content: str | None,
    source: str | None,
) -> None:
    """Write a file inside a share.

    Provide either --content for inline text or --source to upload from Kali.

    \b
    Examples:
        winbox share write Data config.ini --content "[db]\\nhost=10.0.0.1"
        winbox share write Data tools/mimikatz.exe --source /opt/tools/mimikatz.exe
    """
    if content is None and source is None:
        raise click.UsageError("Provide either --content or --source")
    if content is not None and source is not None:
        raise click.UsageError("--content and --source are mutually exclusive")

    _validate_share_name(name)
    relpath = _validate_relative_path(path)

    if content is not None:
        # Base64-encode to avoid quoting issues with special chars
        content_b64 = base64.b64encode(content.encode()).decode()
        script = _guarded_path_script(
            name, relpath,
            "$dir = Split-Path $full -Parent\n"
            "if ($dir -and -not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}\n"
            f"$bytes = [Convert]::FromBase64String('{content_b64}')\n"
            "[IO.File]::WriteAllBytes($full, $bytes)\n"
            "Write-Host $full",
        )
        result = ga.exec_powershell(script, timeout=30)
        if result.exitcode != 0:
            console.print(f"[red][-][/] Failed to write file: {result.stderr.strip()}")
            raise SystemExit(1)
        console.print(f"[green][+][/] Written {result.stdout.strip()}")

    else:
        src_path = Path(source)
        cfg.shared_dir.mkdir(parents=True, exist_ok=True)
        staged = cfg.shared_dir / src_path.name
        shutil.copy2(src_path, staged)

        vm_staged = f"Z:\\{src_path.name}"
        script = _guarded_path_script(
            name, relpath,
            "$dir = Split-Path $full -Parent\n"
            "if ($dir -and -not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}\n"
            f"Copy-Item -Path '{ps_quote(vm_staged)}' -Destination $full -Force -ErrorAction Stop\n"
            "Write-Host $full",
        )
        result = ga.exec_powershell(script, timeout=60)
        # Clean up staged file regardless of outcome
        staged.unlink(missing_ok=True)
        if result.exitcode != 0:
            console.print(f"[red][-][/] Failed to write file: {result.stderr.strip()}")
            raise SystemExit(1)
        console.print(f"[green][+][/] Uploaded {src_path.name} to {result.stdout.strip()}")


@share.command("rm")
@click.argument("name")
@click.argument("path")
@needs_vm()
def share_rm(cfg: Config, vm: VM, ga: GuestAgent, name: str, path: str) -> None:
    """Delete a file or directory inside a share.

    \b
    Example: winbox share rm Data old-reports
    """
    _validate_share_name(name)
    relpath = _validate_relative_path(path)

    script = _guarded_path_script(
        name, relpath,
        "Remove-Item -Path $full -Recurse -Force -ErrorAction Stop\n"
        "Write-Host $full",
    )

    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to remove: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Removed {result.stdout.strip()}")


# ─── user ───────────────────────────────────────────────────────────────────


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

    # Base64-encode password to avoid shell-quoting issues
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


REGISTER = ("Network", [share, user])
