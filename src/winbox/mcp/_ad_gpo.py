"""AD Group Policy object MCP tools."""

from __future__ import annotations

import json as _json

from winbox.ad import require_server
from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (
    _format_exec_result,
    _guest_errors,
)
from winbox.validate import check_gpo_name, check_ou_dn


def _validate_gpo(name: str) -> None:
    err = check_gpo_name(name)
    if err:
        raise ValueError(err)


@mcp.tool()
def ad_gpo_create(name: str, timeout: int = 30) -> str:
    """Create a Group Policy object.

    Args:
        name: GPO display name.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_gpo(name)

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_gpo_create", gpo_name=ps_quote(name)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({"name": name, "created": True})


@mcp.tool()
def ad_gpo_edit(
    name: str,
    key: str,
    value_name: str,
    reg_type: str,
    value: str,
    timeout: int = 30,
) -> str:
    """Set a registry-based GPO setting.

    Args:
        name: GPO display name.
        key: Registry key path.
        value_name: Registry value name.
        reg_type: Registry type (String, ExpandString, DWord, QWord, MultiString, Binary).
        value: Registry value data.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_gpo(name)
    valid_types = ("String", "ExpandString", "DWord", "QWord", "MultiString", "Binary")
    if reg_type not in valid_types:
        raise ValueError(f"Invalid reg_type: {reg_type!r}. Must be one of {valid_types}.")

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_gpo_edit",
                      gpo_name=ps_quote(name), key=ps_quote(key),
                      value_name=ps_quote(value_name),
                      reg_type=reg_type, value=ps_quote(value)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "name": name,
        "key": key,
        "value_name": value_name,
        "reg_type": reg_type,
        "value": value,
        "updated": True,
    })


@mcp.tool()
def ad_gpo_remove(name: str, timeout: int = 30) -> str:
    """Delete a Group Policy object.

    Args:
        name: GPO display name to remove.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_gpo(name)

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_gpo_remove", gpo_name=ps_quote(name)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({"name": name, "removed": True})


@mcp.tool()
def ad_gpo_list(timeout: int = 30) -> str:
    """List all Group Policy objects as JSON.

    Args:
        timeout: Execution timeout in seconds (default 30).
    """
    script = (
        "Get-GPO -All -ErrorAction Stop |"
        " Select-Object"
        " @{N='name';E={$_.DisplayName}},"
        " @{N='id';E={$_.Id.ToString()}},"
        " @{N='status';E={$_.GpoStatus.ToString()}},"
        " @{N='created';E={$_.CreationTime.ToString('o')}} |"
        " ConvertTo-Json -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)

    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def ad_gpo_link(name: str, target: str, timeout: int = 30) -> str:
    """Link a GPO to an organizational unit.

    Args:
        name: GPO display name.
        target: OU distinguished name to link the GPO to.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_gpo(name)
    err = check_ou_dn(target)
    if err:
        raise ValueError(err)

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_gpo_link", gpo_name=ps_quote(name),
                      target=ps_quote(target)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({"name": name, "target": target, "linked": True})
