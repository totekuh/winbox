"""Domain membership commands — join, leave."""

from __future__ import annotations

import base64

import click

from winbox.cli import console, needs_vm, reboot_and_wait
from winbox.cli._ps import render_ps
from winbox.cli.network_dns_hosts import _validate_domain, _validate_ip, _validate_user
from winbox.config import Config
from winbox.vm import GuestAgent, VM


@click.group()
def domain() -> None:
    """Manage VM domain membership."""
    pass


@domain.command("join")
@click.argument("name")
@click.option("--ns", "ns_ip", required=True, help="DNS server IP for domain resolution.")
@click.option("--user", required=True, help="Domain user (e.g. Administrator).")
@click.option(
    "--password", prompt=True, hide_input=True,
    help="Domain user password (prompted if not given).",
)
@needs_vm()
def domain_join(
    cfg: Config,
    vm: VM,
    ga: GuestAgent,
    name: str,
    ns_ip: str,
    user: str,
    password: str,
) -> None:
    """Join the VM to an Active Directory domain.

    Undo with: winbox domain leave
    """
    _validate_domain(name)
    _validate_ip(ns_ip)
    _validate_user(user)

    console.print(f"[blue][*][/] Setting DNS to {ns_ip}...")
    result = ga.exec_powershell(
        render_ps("set_dns", servers=ns_ip),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to set DNS: {result.stderr}")
        raise SystemExit(1)
    console.print(f"[green][+][/] DNS set to {ns_ip}")

    verify = ga.exec_powershell(
        f"Resolve-DnsName {name} -DnsOnly -ErrorAction Stop", timeout=15,
    )
    if verify.exitcode != 0:
        console.print(f"[red][-][/] Cannot resolve {name} via {ns_ip}")
        raise SystemExit(1)

    pass_b64 = base64.b64encode(password.encode()).decode()
    console.print("[blue][*][/] Checking machine account quota...")
    quota_script = (
        f"$b = [Convert]::FromBase64String('{pass_b64}')\n"
        f"$p = [Text.Encoding]::UTF8.GetString($b)\n"
        f"$e = New-Object System.DirectoryServices.DirectoryEntry("
        f"'LDAP://{name}', '{name}\\{user}', $p)\n"
        "try {\n"
        "  $null = $e.distinguishedName\n"
        "  $q = $e.Properties['ms-DS-MachineAccountQuota']\n"
        "  if ($q.Count -gt 0) { Write-Output $q[0] } else { Write-Output 'unknown' }\n"
        "} catch {\n"
        "  Write-Error $_.Exception.Message\n"
        "  exit 1\n"
        "}"
    )
    result = ga.exec_powershell(quota_script, timeout=15)
    if result.exitcode != 0:
        console.print(f"[yellow][!][/] Could not check quota: {result.stderr.strip()}")
        console.print("    Credentials may be wrong or LDAP unreachable")
        raise SystemExit(1)
    quota = result.stdout.strip()
    if quota == "0":
        console.print("[red][-][/] Machine account quota is 0 — this user cannot join machines")
        console.print("    Use a Domain Admin or ask for delegation")
        raise SystemExit(1)
    console.print(f"[green][+][/] Machine account quota: {quota}")

    console.print(f"[blue][*][/] Joining {name}...")
    join_script = (
        f"$b = [Convert]::FromBase64String('{pass_b64}')\n"
        f"$p = [Text.Encoding]::UTF8.GetString($b)\n"
        f"$s = ConvertTo-SecureString $p -AsPlainText -Force\n"
        f"$c = New-Object System.Management.Automation.PSCredential("
        f"'{name}\\{user}', $s)\n"
        f"Add-Computer -DomainName {name} -Credential $c -Force"
    )
    result = ga.exec_powershell(join_script, timeout=60)
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)
    if result.exitcode != 0:
        console.print("[red][-][/] Domain join failed")
        raise SystemExit(1)
    console.print(f"[green][+][/] Joined {name}")

    reboot_and_wait(cfg, ga, msg="Rebooting...")
    console.print(f"[green][+][/] VM back up — domain-joined to {name}")
    console.print("    Undo with: [bold]winbox domain leave[/]")


@domain.command("leave")
@needs_vm()
def domain_leave(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Leave the domain and return to workgroup (preserves all files)."""
    console.print("[blue][*][/] Leaving domain...")
    leave_script = "Remove-Computer -WorkgroupName WORKGROUP -Force"
    result = ga.exec_powershell(leave_script, timeout=30)
    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)
    if result.exitcode != 0:
        console.print("[red][-][/] Failed to leave domain")
        raise SystemExit(1)

    console.print("[blue][*][/] Resetting DNS to DHCP...")
    ga.exec_powershell(render_ps("reset_dns"), timeout=15)

    reboot_and_wait(cfg, ga, msg="Rebooting...")
    console.print("[green][+][/] Domain left — back to workgroup, all files intact")


REGISTER = ("Network", [domain])
