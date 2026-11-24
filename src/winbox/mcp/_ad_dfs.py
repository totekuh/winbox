"""AD DFS namespace MCP tools."""

from __future__ import annotations

import json as _json

from winbox.ad import require_server, wait_for_dfsr
from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (
    _format_exec_result,
    _guest_errors,
)
from winbox.validate import check_dfs_namespace, check_unc_path


def _validate_namespace(name: str) -> None:
    err = check_dfs_namespace(name)
    if err:
        raise ValueError(err)


def _validate_unc(path: str) -> None:
    err = check_unc_path(path)
    if err:
        raise ValueError(err)


@mcp.tool()
def ad_dfs_create(namespace: str, target: str, timeout: int = 120) -> str:
    r"""Create a domain-based DFS namespace (DomainV2).

    Installs the FS-DFS-Namespace feature if needed, then creates the
    DFS root with the specified target.

    Args:
        namespace: DFS namespace name (e.g. lab-dfs).
        target: UNC target path (e.g. \\DC\ShareName).
        timeout: Execution timeout in seconds (default 120).
    """
    from winbox.ps import ps_quote, render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_namespace(namespace)
    _validate_unc(target)

    with _guest_errors(vm):
        install = ga.exec_powershell(
            render_ps("ad_dfs_install"), timeout=timeout,
        )
    if install.exitcode != 0:
        return _format_exec_result(install)

    try:
        wait_for_dfsr(ga)
    except RuntimeError:
        pass

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_dfs_create",
                      namespace=ps_quote(namespace),
                      target=ps_quote(target)),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({"namespace": namespace, "target": target, "created": True})


@mcp.tool()
def ad_dfs_add_target(
    namespace: str,
    folder: str,
    target: str,
    timeout: int = 30,
) -> str:
    r"""Add a folder target to an existing DFS namespace.

    Args:
        namespace: DFS namespace name.
        folder: Folder name within the namespace.
        target: UNC target path for the folder.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_namespace(namespace)
    _validate_unc(target)

    script = (
        f"$domain = (Get-ADDomain -Server localhost).DNSRoot\n"
        f"New-DfsnFolder "
        f"-Path \"\\\\$domain\\{ps_quote(namespace)}\\{ps_quote(folder)}\" "
        f"-TargetPath '{ps_quote(target)}' "
        f"-ErrorAction Stop"
    )
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "namespace": namespace,
        "folder": folder,
        "target": target,
        "added": True,
    })


@mcp.tool()
def ad_dfs_delete(namespace: str, timeout: int = 30) -> str:
    """Remove a DFS namespace.

    Args:
        namespace: DFS namespace name to delete.
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_namespace(namespace)

    script = (
        f"$domain = (Get-ADDomain -Server localhost).DNSRoot\n"
        f"$root = \"\\\\$domain\\{ps_quote(namespace)}\"\n"
        f"Get-DfsnFolder -Path \"$root\\*\" -EA SilentlyContinue | "
        f"ForEach-Object {{ Remove-DfsnFolder -Path $_.Path -Force }}\n"
        f"try {{ Remove-DfsnRoot -Path $root -Force -EA Stop }}\n"
        f"catch {{\n"
        f"  $dn = \"CN={ps_quote(namespace)},CN=Dfs-Configuration,CN=System,\"\n"
        f"  $dn += (Get-ADDomain -Server localhost).DistinguishedName\n"
        f"  Remove-ADObject -Identity $dn -Server localhost -Recursive "
        f"-Confirm:$false -EA Stop\n"
        f"}}"
    )
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({"namespace": namespace, "deleted": True})


@mcp.tool()
def ad_dfs_list(timeout: int = 30) -> str:
    """List DFS namespaces and folder targets as JSON.

    Args:
        timeout: Execution timeout in seconds (default 30).
    """
    script = (
        "$domain = (Get-ADDomain -Server localhost -ErrorAction Stop).DNSRoot\n"
        "$roots = Get-DfsnRoot -ErrorAction SilentlyContinue |"
        " Where-Object { $_.Path -match $domain }\n"
        "if (-not $roots) { '[]'; exit 0 }\n"
        "$out = @()\n"
        "foreach ($root in $roots) {\n"
        "    $entry = @{ path = $root.Path; state = $root.State.ToString(); folders = @() }\n"
        "    $folders = Get-DfsnFolder -Path \"$($root.Path)\\*\" -ErrorAction SilentlyContinue\n"
        "    foreach ($f in $folders) {\n"
        "        $targets = Get-DfsnFolderTarget -Path $f.Path -ErrorAction SilentlyContinue\n"
        "        foreach ($t in $targets) {\n"
        "            $entry.folders += @{ folder = $f.Path; target = $t.TargetPath; state = $t.State.ToString() }\n"
        "        }\n"
        "    }\n"
        "    $out += $entry\n"
        "}\n"
        "$out | ConvertTo-Json -Depth 3 -Compress"
    )
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)

    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)
