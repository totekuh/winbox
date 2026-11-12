"""SMB share and local user management MCP tools."""

from __future__ import annotations

import json as _json

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (

    _format_exec_result,
    _guest_errors,
)
from winbox.validate import check_share_name, check_username


def _validate_share_name(name: str) -> None:
    err = check_share_name(name)
    if err:
        raise ValueError(err)


def _validate_mcp_username(username: str) -> None:
    err = check_username(username)
    if err:
        raise ValueError(err)


def _build_share_access_params(
    full_access: list[str] | None,
    change_access: list[str] | None,
    read_access: list[str] | None,
) -> str:
    from winbox.ps import ps_quote
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


@mcp.tool()
def share_create(
    name: str,
    path: str | None = None,
    full_access: list[str] | None = None,
    change_access: list[str] | None = None,
    read_access: list[str] | None = None,
    timeout: int = 30,
) -> str:
    """Create an SMB share on the Windows VM.

    Creates the backing folder if it does not exist, then registers
    the SMB share with the specified access controls.

    Args:
        name: Share name (e.g. 'Data'). Alphanumeric, hyphens, underscores, dots.
        path: Backing folder path on the VM (default: C:\\Shares\\<name>).
        full_access: Accounts with FullAccess (default: ['Everyone']).
        change_access: Accounts with Change access.
        read_access: Accounts with Read access.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    _validate_share_name(name)
    if path is None:
        path = f"C:\\Shares\\{name}"
    if not full_access and not change_access and not read_access:
        full_access = ["Everyone"]

    access_params = _build_share_access_params(full_access, change_access, read_access)

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("share_create",
                      share_name=ps_quote(name),
                      path=ps_quote(path),
                      access_params=access_params),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "name": name,
        "path": path,
        "full_access": full_access or [],
        "change_access": change_access or [],
        "read_access": read_access or [],
    })


@mcp.tool()
def share_delete(
    name: str,
    purge: bool = False,
    confirm: bool = False,
    timeout: int = 30,
) -> str:
    """Remove an SMB share from the Windows VM.

    With purge=True, also deletes the backing folder and all its contents.
    Requires confirm=True when purge is set, as a guard against accidental
    data loss.

    Args:
        name: Share name to remove.
        purge: Also delete the backing folder on disk (default False).
        confirm: Must be True when purge=True (guards data destruction).
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote

    _validate_share_name(name)
    if purge and not confirm:
        return (
            "purge=True requires confirm=True. This will permanently delete "
            "the share AND its backing folder with all contents."
        )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()

    backing_path = None
    if purge:
        with _guest_errors(vm):
            result = ga.exec_powershell(
                f"(Get-SmbShare -Name '{ps_quote(name)}' -ErrorAction Stop).Path",
                timeout=timeout,
            )
        backing_path = result.stdout.strip() if result.exitcode == 0 else None

    with _guest_errors(vm):
        result = ga.exec_powershell(
            f"Remove-SmbShare -Name '{ps_quote(name)}' -Force -ErrorAction Stop",
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    purged = False
    purge_error = None
    if purge and backing_path:
        with _guest_errors(vm):
            purge_result = ga.exec_powershell(
                f"Remove-Item -Path '{ps_quote(backing_path)}' -Recurse -Force -ErrorAction Stop",
                timeout=timeout,
            )
        if purge_result.exitcode == 0:
            purged = True
        else:
            purge_error = purge_result.stderr.strip()

    return _json.dumps({
        "name": name,
        "removed": True,
        "purged": purged,
        "purge_error": purge_error,
    })


@mcp.tool()
def share_list(timeout: int = 30) -> str:
    """List SMB shares on the Windows VM.

    Returns a JSON array of non-special shares (excludes C$, IPC$, ADMIN$).
    Each object has: name, path, description.

    Args:
        timeout: Execution timeout in seconds (default 30).
    """
    script = (
        "Get-SmbShare | Where-Object { $_.Special -eq $false } | "
        "Select-Object @{N='name';E={$_.Name}}, @{N='path';E={$_.Path}}, "
        "@{N='description';E={$_.Description}} | ConvertTo-Json -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def share_grant(
    name: str,
    user: str,
    permission: str = "full",
    timeout: int = 30,
) -> str:
    """Grant access to an SMB share.

    Args:
        name: Share name.
        user: Account name (e.g. 'bob' or 'Everyone').
        permission: 'full', 'change', or 'read' (default 'full').
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    _validate_share_name(name)
    perm_map = {"full": "Full", "change": "Change", "read": "Read"}
    ps_perm = perm_map.get(permission.lower())
    if ps_perm is None:
        return f"Invalid permission: {permission!r}. Must be 'full', 'change', or 'read'."

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("share_grant",
                      share_name=ps_quote(name),
                      account=ps_quote(user),
                      permission=ps_perm),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "share": name,
        "account": user,
        "permission": ps_perm,
        "granted": True,
    })


@mcp.tool()
def share_revoke(name: str, user: str, timeout: int = 30) -> str:
    """Revoke an account's access to an SMB share.

    Args:
        name: Share name.
        user: Account name to revoke.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    _validate_share_name(name)
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("share_revoke",
                      share_name=ps_quote(name),
                      account=ps_quote(user)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "share": name,
        "account": user,
        "revoked": True,
    })


@mcp.tool()
def user_create(
    username: str,
    password: str,
    full_name: str = "",
    no_password_expire: bool = True,
    timeout: int = 30,
) -> str:
    """Create a local Windows user on the VM.

    Args:
        username: Username for the new account (max 20 chars).
        password: Password for the new account.
        full_name: Optional display name.
        no_password_expire: Set password to never expire (default True).
        timeout: Execution timeout in seconds (default 30).
    """
    import base64 as _b64
    from winbox.ps import ps_quote, render_ps

    _validate_mcp_username(username)
    pass_b64 = _b64.b64encode(password.encode()).decode()
    no_expire = "$true" if no_password_expire else "$false"

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("user_create",
                      username=ps_quote(username),
                      pass_b64=pass_b64,
                      full_name=ps_quote(full_name),
                      no_expire=no_expire),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "username": username,
        "full_name": full_name,
        "password_expires": not no_password_expire,
        "created": True,
    })


@mcp.tool()
def user_delete(
    username: str,
    confirm: bool = False,
    timeout: int = 30,
) -> str:
    """Delete a local Windows user from the VM.

    Args:
        username: Username to delete.
        confirm: Must be True (guards account deletion).
        timeout: Execution timeout in seconds (default 30).
    """
    if not confirm:
        return "confirm=True required. This permanently deletes the user account."

    from winbox.ps import ps_quote

    _validate_mcp_username(username)
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(
            f"Remove-LocalUser -Name '{ps_quote(username)}' -ErrorAction Stop",
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "username": username,
        "deleted": True,
    })


@mcp.tool()
def user_list(timeout: int = 30) -> str:
    """List local Windows users on the VM.

    Returns a JSON array. Each object has: name, enabled, lastLogon
    (ISO 8601 or null), description.

    Args:
        timeout: Execution timeout in seconds (default 30).
    """
    script = (
        "Get-LocalUser | Select-Object "
        "@{N='name';E={$_.Name}}, "
        "@{N='enabled';E={$_.Enabled}}, "
        "@{N='lastLogon';E={if($_.LastLogon){$_.LastLogon.ToString('o')}else{$null}}}, "
        "@{N='description';E={$_.Description}} | ConvertTo-Json -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)
