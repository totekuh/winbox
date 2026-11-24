"""AD user, group, OU, and computer object MCP tools."""

from __future__ import annotations

import json as _json

from winbox.ad import encode_password, require_server
from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import _format_exec_result, _guest_errors
from winbox.validate import check_ad_username, check_ou_dn


def _validate_sam(name: str) -> None:
    err = check_ad_username(name)
    if err:
        raise ValueError(err)


def _validate_ou(dn: str) -> None:
    err = check_ou_dn(dn)
    if err:
        raise ValueError(err)


# ── Users ────────────────────────────────────────────────────────────────────

@mcp.tool()
def ad_user_create(
    sam: str, password: str,
    upn: str | None = None, ou: str | None = None,
    timeout: int = 30,
) -> str:
    """Create a domain user account.

    Args:
        sam: SAM account name (max 20 chars).
        password: User password.
        upn: User principal name (default: sam@domain).
        ou: OU distinguished name to place the user in.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_sam(sam)
    if ou:
        _validate_ou(ou)
    pass_b64 = encode_password(password)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_user_create", sam=ps_quote(sam), pass_b64=pass_b64,
                      upn=ps_quote(upn or ""), ou=ps_quote(ou or "")),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"sam": sam, "created": True})


@mcp.tool()
def ad_user_delete(sam: str, timeout: int = 30) -> str:
    """Delete a domain user account.

    Args:
        sam: SAM account name to delete.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_sam(sam)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_user_delete", sam=ps_quote(sam)), timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"sam": sam, "deleted": True})


@mcp.tool()
def ad_user_list(ou: str | None = None, timeout: int = 30) -> str:
    """List domain user accounts as JSON.

    Args:
        ou: Scope to a specific OU (distinguished name).
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    if ou:
        _validate_ou(ou)
    search_base = f" -SearchBase '{ps_quote(ou)}'" if ou else ""
    script = (
        f"Get-ADUser -Server localhost -Filter *{search_base}"
        " -Properties SamAccountName, Enabled, UserPrincipalName, DistinguishedName |"
        " Select-Object @{N='sam';E={$_.SamAccountName}},"
        " @{N='enabled';E={$_.Enabled}}, @{N='upn';E={$_.UserPrincipalName}},"
        " @{N='dn';E={$_.DistinguishedName}} | ConvertTo-Json -Compress"
    )
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)


# ── Groups ───────────────────────────────────────────────────────────────────

@mcp.tool()
def ad_group_create(
    name: str, scope: str = "Global",
    ou: str | None = None, timeout: int = 30,
) -> str:
    """Create an AD security group.

    Args:
        name: Group name.
        scope: Global, Universal, or DomainLocal.
        ou: OU distinguished name.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_sam(name)
    if ou:
        _validate_ou(ou)
    if scope not in ("Global", "Universal", "DomainLocal"):
        raise ValueError(f"Invalid scope: {scope!r}. Must be Global, Universal, or DomainLocal.")
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_group_create", group_name=ps_quote(name), scope=scope,
                      ou=ps_quote(ou or "")),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"name": name, "scope": scope, "created": True})


@mcp.tool()
def ad_group_delete(name: str, timeout: int = 30) -> str:
    """Delete an AD group.

    Args:
        name: Group name to delete.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_sam(name)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_group_delete", group_name=ps_quote(name)), timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"name": name, "deleted": True})


@mcp.tool()
def ad_group_list(timeout: int = 30) -> str:
    """List AD groups (excluding builtins) as JSON.

    Args:
        timeout: Execution timeout in seconds.
    """
    script = (
        "Get-ADGroup -Server localhost -Filter * -Properties GroupScope, Description |"
        " Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin,' } |"
        " Select-Object @{N='name';E={$_.Name}}, @{N='scope';E={$_.GroupScope.ToString()}},"
        " @{N='description';E={$_.Description}}, @{N='dn';E={$_.DistinguishedName}} |"
        " ConvertTo-Json -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def ad_group_add_member(group: str, member: str, timeout: int = 30) -> str:
    """Add a member to an AD group.

    Args:
        group: Group name.
        member: SAM account name to add.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_sam(group)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_group_add_member",
                      group=ps_quote(group), member=ps_quote(member)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"group": group, "member": member, "added": True})


@mcp.tool()
def ad_group_remove_member(group: str, member: str, timeout: int = 30) -> str:
    """Remove a member from an AD group.

    Args:
        group: Group name.
        member: SAM account name to remove.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_sam(group)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_group_remove_member",
                      group=ps_quote(group), member=ps_quote(member)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"group": group, "member": member, "removed": True})


# ── OUs ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def ad_ou_create(name: str, path: str | None = None, timeout: int = 30) -> str:
    """Create an organizational unit.

    Args:
        name: OU name.
        path: Parent OU distinguished name.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    if path:
        _validate_ou(path)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_ou_create", ou_name=ps_quote(name),
                      path=ps_quote(path or "")),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"name": name, "created": True})


@mcp.tool()
def ad_ou_delete(dn: str, timeout: int = 30) -> str:
    """Delete an organizational unit by distinguished name.

    Args:
        dn: Distinguished name of the OU to delete.
        timeout: Execution timeout in seconds.
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_ou(dn)
    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_ou_delete", dn=ps_quote(dn)), timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)
    return _json.dumps({"dn": dn, "deleted": True})


@mcp.tool()
def ad_ou_list(timeout: int = 30) -> str:
    """List organizational units as JSON.

    Args:
        timeout: Execution timeout in seconds.
    """
    script = (
        "Get-ADOrganizationalUnit -Server localhost -Filter * -Properties Description |"
        " Select-Object @{N='name';E={$_.Name}}, @{N='dn';E={$_.DistinguishedName}},"
        " @{N='description';E={$_.Description}} | ConvertTo-Json -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)


# ── Computers ────────────────────────────────────────────────────────────────

@mcp.tool()
def ad_computer_list(timeout: int = 30) -> str:
    """List domain computer accounts as JSON.

    Args:
        timeout: Execution timeout in seconds.
    """
    script = (
        "Get-ADComputer -Server localhost -Filter * -Properties OperatingSystem, Enabled, DNSHostName |"
        " Select-Object @{N='name';E={$_.Name}}, @{N='dnsHostName';E={$_.DNSHostName}},"
        " @{N='os';E={$_.OperatingSystem}}, @{N='enabled';E={$_.Enabled}},"
        " @{N='dn';E={$_.DistinguishedName}} | ConvertTo-Json -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)
