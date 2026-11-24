"""AD DFS namespace management — create, add-target, delete, list."""

from __future__ import annotations

import click

from winbox.ad import wait_for_dfsr
from winbox.cli import console, needs_vm
from winbox.cli.ad import ad, _require_server
from winbox.config import Config
from winbox.ps import ps_quote, render_ps
from winbox.validate import check_dfs_namespace, check_unc_path
from winbox.vm import GuestAgent, VM


def _validate_namespace(name: str) -> None:
    err = check_dfs_namespace(name)
    if err:
        raise click.BadParameter(err)


def _validate_unc(path: str) -> None:
    err = check_unc_path(path)
    if err:
        raise click.BadParameter(err)


@ad.group("dfs")
def ad_dfs() -> None:
    """Manage DFS namespaces on the domain controller."""
    pass


@ad_dfs.command("create")
@click.argument("namespace")
@click.option("--target", required=True, help=r"UNC target path (e.g. \\DC\ShareName).")
@needs_vm()
def dfs_create(
    cfg: Config, vm: VM, ga: GuestAgent,
    namespace: str, target: str,
) -> None:
    r"""Create a domain-based DFS namespace (DomainV2).

    Installs the FS-DFS-Namespace feature if needed, creates a DFS root,
    and adds the target. This populates msDFS-TargetListv2 in AD.

    \b
    Example:
        winbox ad dfs create lab-dfs --target '\\WIN-DC\Data'
    """
    _require_server(cfg)
    _validate_namespace(namespace)
    _validate_unc(target)

    console.print("[blue][*][/] Ensuring DFS Namespace feature is installed...")
    result = ga.exec_powershell(
        render_ps("ad_dfs_install"),
        timeout=120,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to install DFS feature: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print("[blue][*][/] Ensuring DFSR is ready...")
    try:
        wait_for_dfsr(ga)
    except RuntimeError as exc:
        console.print(f"[yellow][!][/] {exc}")

    console.print(f"[blue][*][/] Creating DFS namespace: {namespace}...")
    result = ga.exec_powershell(
        render_ps("ad_dfs_create",
                  namespace=ps_quote(namespace),
                  target=ps_quote(target)),
        timeout=60,
    )
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create DFS namespace: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] DFS namespace \\\\<domain>\\{namespace} created")


@ad_dfs.command("add-target")
@click.argument("namespace")
@click.argument("folder")
@click.option("--target", required=True, help=r"UNC target path for the folder.")
@needs_vm()
def dfs_add_target(
    cfg: Config, vm: VM, ga: GuestAgent,
    namespace: str, folder: str, target: str,
) -> None:
    r"""Add a folder target to an existing DFS namespace.

    \b
    Example:
        winbox ad dfs add-target lab-dfs docs --target '\\WIN-DC\Docs'
    """
    _require_server(cfg)
    _validate_namespace(namespace)
    _validate_unc(target)

    console.print(f"[blue][*][/] Adding folder target {folder} to {namespace}...")
    script = (
        f"$domain = (Get-ADDomain -Server localhost).DNSRoot\n"
        f"New-DfsnFolder "
        f"-Path \"\\\\$domain\\{ps_quote(namespace)}\\{ps_quote(folder)}\" "
        f"-TargetPath '{ps_quote(target)}' "
        f"-ErrorAction Stop"
    )
    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Folder target added: {folder} -> {target}")


@ad_dfs.command("delete")
@click.argument("namespace")
@needs_vm()
def dfs_delete(
    cfg: Config, vm: VM, ga: GuestAgent,
    namespace: str,
) -> None:
    """Remove a DFS namespace."""
    _require_server(cfg)
    _validate_namespace(namespace)

    console.print(f"[blue][*][/] Removing DFS namespace: {namespace}...")
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
    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] DFS namespace {namespace} removed")


@ad_dfs.command("list")
@needs_vm()
def dfs_list(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """List DFS namespaces and folder targets."""
    _require_server(cfg)

    result = ga.exec_powershell(
        render_ps("ad_dfs_list"),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to list DFS: {result.stderr.strip()}")
        raise SystemExit(1)
    if result.stdout.strip():
        console.print(result.stdout, end="", markup=False, highlight=False)
    else:
        console.print("[dim].[/] No DFS namespaces configured")
