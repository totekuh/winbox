"""Active Directory provisioning — promote, demote, status."""

from __future__ import annotations

import click

from winbox.ad import encode_password, netbios_from_fqdn, require_server, wait_for_adws, wait_for_dfsr
from winbox.cli import console, needs_vm, reboot_and_wait
from winbox.config import Config
from winbox.ps import render_ps
from winbox.validate import check_domain_fqdn
from winbox.vm import GuestAgent, VM


def _require_server(cfg: Config) -> None:
    try:
        require_server(cfg)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from None


def _validate_domain(name: str) -> None:
    err = check_domain_fqdn(name)
    if err:
        raise click.BadParameter(err)


@click.group()
def ad() -> None:
    """Manage Active Directory on the VM."""
    pass


@ad.command("promote")
@click.option(
    "--domain", required=True,
    help="FQDN for the new forest root (e.g. TESTLAB.LOCAL).",
)
@click.option(
    "--password", prompt=True, hide_input=True,
    help="Directory Services Restore Mode (DSRM) password.",
)
@needs_vm()
def ad_promote(
    cfg: Config, vm: VM, ga: GuestAgent,
    domain: str, password: str,
) -> None:
    """Promote the VM to a domain controller (new forest)."""
    _require_server(cfg)
    _validate_domain(domain)
    netbios = netbios_from_fqdn(domain)
    pass_b64 = encode_password(password)

    console.print("[blue][*][/] Installing AD Domain Services...")
    result = ga.exec_powershell(
        render_ps("ad_promote", domain=domain, netbios=netbios,
                  pass_b64=pass_b64),
        timeout=600,
    )
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.exitcode != 0:
        console.print(f"[red][-][/] DC promotion failed: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] AD DS installed — promoting to DC for {domain}")

    reboot_and_wait(cfg, ga, msg="Rebooting after DC promotion...",
                    wait_timeout=300)

    console.print("[blue][*][/] Waiting for AD Web Services...")
    try:
        hostname = wait_for_adws(ga)
        console.print(f"[green][+][/] Domain controller active: {hostname}")
    except RuntimeError as exc:
        console.print(f"[yellow][!][/] {exc}")

    console.print("[blue][*][/] Waiting for DFSR (SYSVOL replication)...")
    try:
        wait_for_dfsr(ga)
        console.print("[green][+][/] DFSR ready — SYSVOL share available")
    except RuntimeError as exc:
        console.print(f"[yellow][!][/] {exc}")

    console.print(f"[green][+][/] Forest {domain} ready")
    console.print(f"    NetBIOS: {netbios}")
    console.print("    Undo with: [bold]winbox ad demote[/]")


@ad.command("demote")
@click.option(
    "--password", prompt=True, hide_input=True,
    help="Local administrator password after demotion.",
)
@click.option(
    "--admin-password", default=None, hide_input=True,
    help="Domain admin password (default: same as --password).",
)
@needs_vm()
def ad_demote(
    cfg: Config, vm: VM, ga: GuestAgent,
    password: str, admin_password: str | None,
) -> None:
    """Demote the domain controller back to a standalone server."""
    _require_server(cfg)
    pass_b64 = encode_password(password)
    admin_b64 = encode_password(admin_password or cfg.vm_password)

    console.print("[blue][*][/] Demoting domain controller...")
    result = ga.exec_powershell(
        render_ps("ad_demote", pass_b64=pass_b64, admin_b64=admin_b64),
        timeout=600,
    )
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Demotion failed: {result.stderr.strip()}")
        raise SystemExit(1)

    reboot_and_wait(cfg, ga, msg="Rebooting after demotion...",
                    wait_timeout=300)
    console.print("[green][+][/] Domain controller demoted — back to standalone")


@ad.command("status")
@needs_vm()
def ad_status(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Show Active Directory status on the VM."""
    _require_server(cfg)

    result = ga.exec_powershell(render_ps("ad_status"), timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to query AD status: {result.stderr.strip()}")
        raise SystemExit(1)

    import json
    try:
        info = json.loads(result.stdout)
    except json.JSONDecodeError:
        console.print(result.stdout, markup=False, highlight=False)
        return

    if info.get("is_dc"):
        console.print(f"[green][+][/] Domain Controller: {info.get('hostname', '?')}")
        console.print(f"    Domain:  {info.get('domain', '?')}")
        console.print(f"    NetBIOS: {info.get('netbios', '?')}")
        console.print(f"    Forest:  {info.get('forest', '?')}")
        console.print(f"    Site:    {info.get('site', '?')}")
        console.print(f"    DFS:     {'installed' if info.get('dfs_installed') else 'not installed'}")
    elif info.get("feature_installed"):
        console.print("[yellow][!][/] AD DS feature installed but not promoted")
        if info.get("ad_error"):
            console.print(f"    Error: {info['ad_error']}")
    else:
        console.print("[dim].[/] AD DS not installed")

    services = info.get("services", {})
    if any(v != "NotInstalled" for v in services.values()):
        console.print("    Services:")
        for svc, state in services.items():
            if state != "NotInstalled":
                color = "green" if state == "Running" else "yellow"
                console.print(f"      {svc}: [{color}]{state}[/]")


# Import subgroup modules — underscore prefix prevents auto-discovery,
# they piggyback on this module's REGISTER.
import winbox.cli._ad_dfs as _ad_dfs  # noqa: E402, F401
import winbox.cli._ad_user as _ad_user  # noqa: E402, F401
import winbox.cli._ad_group as _ad_group  # noqa: E402, F401
import winbox.cli._ad_ou as _ad_ou  # noqa: E402, F401
import winbox.cli._ad_gpo as _ad_gpo  # noqa: E402, F401
import winbox.cli._ad_computer as _ad_computer  # noqa: E402, F401


REGISTER = ("Active Directory", [ad])
