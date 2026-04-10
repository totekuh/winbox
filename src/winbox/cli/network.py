"""Network commands — dns (sync, view), domain (join, leave), net (isolate, connect)."""

from __future__ import annotations

import base64
import ipaddress
import re
import time
from pathlib import Path

import click

from winbox.cli import console, ensure_running, _ensure_z_drive
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM, VMState


# ─── net ─────────────────────────────────────────────────────────────────────


@click.group()
def net() -> None:
    """Control VM network connectivity."""
    pass


@net.command("isolate")
@click.pass_context
def net_isolate(ctx: click.Context) -> None:
    """Block internet access by removing the default gateway.

    The NIC stays up — traffic to directly routed targets still works.
    Undo with: winbox net connect
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    ga.exec_powershell(
        "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue",
        timeout=15,
    )
    console.print("[green][+][/] Internet isolated — default gateway removed")
    console.print("    Undo with: [bold]winbox net connect[/]")


@net.command("connect")
@click.pass_context
def net_connect(ctx: click.Context) -> None:
    """Reconnect VM to the network (plug the cable back in)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    # Renew DHCP — restores default gateway and DNS without releasing the IP
    console.print("[blue][*][/] Renewing DHCP lease...")
    ga.exec("ipconfig /renew", timeout=30)

    ip = None
    for _ in range(15):
        ip = vm.ip()
        if ip:
            break
        time.sleep(1)

    if ip:
        console.print(f"[green][+][/] Network connected — IP: {ip}")
    else:
        console.print("[green][+][/] Network connected (DHCP pending)")


@net.command("status")
@click.pass_context
def net_status(ctx: click.Context) -> None:
    """Show VM internet connectivity status."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        return

    if not ga.ping():
        console.print("[yellow][!][/] Guest agent not responding")
        return

    result = ga.exec_powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count",
        timeout=10,
    )
    if result.exitcode != 0 or not result.stdout.strip().isdigit():
        console.print("[yellow][!][/] Could not determine internet status")
        return

    if int(result.stdout.strip()) > 0:
        console.print("Internet: [green]connected[/]")
    else:
        console.print("Internet: [red]isolated[/]")


# ─── dns ─────────────────────────────────────────────────────────────────────


@click.group()
def dns() -> None:
    """Manage VM DNS settings."""
    pass


@dns.command("set")
@click.argument("ip")
@click.pass_context
def dns_set(ctx: click.Context, ip: str) -> None:
    """Set a DNS nameserver on the VM.

    Example: winbox dns set 192.168.56.11
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)
    _validate_ip(ip)

    console.print(f"[blue][*][/] Setting DNS to {ip}...")
    dns_script = (
        "$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
        "| Select-Object -First 1\n"
        f"Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
        f"-ServerAddresses {ip}\n"
        "Clear-DnsClientCache"
    )
    result = ga.exec_powershell(dns_script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(f"[green][+][/] DNS set to {ip}")


@dns.command("sync")
@click.pass_context
def dns_sync(ctx: click.Context) -> None:
    """Push Kali's /etc/resolv.conf nameservers to the VM."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        console.print("[red][-][/] /etc/resolv.conf not found")
        raise SystemExit(1)

    nameservers = []
    for line in resolv.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            ns = parts[1]
            try:
                ipaddress.ip_address(ns)
            except ValueError:
                console.print(f"[yellow][!][/] Skipping invalid nameserver: {ns}")
                continue
            nameservers.append(ns)

    if not nameservers:
        console.print("[red][-][/] No nameservers found in /etc/resolv.conf")
        raise SystemExit(1)

    ensure_running(vm, ga, cfg)

    ns_joined = ", ".join(nameservers)
    console.print(f"[blue][*][/] Setting DNS to {ns_joined}...")
    ns_ps_array = ", ".join(f"'{ns}'" for ns in nameservers)
    dns_script = (
        "$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
        "| Select-Object -First 1\n"
        f"Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
        f"-ServerAddresses @({ns_ps_array})\n"
        "Clear-DnsClientCache"
    )
    result = ga.exec_powershell(dns_script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)

    for ns in nameservers:
        console.print(f"[green][+][/] {ns}")
    console.print("[green][+][/] VM DNS synced")


@dns.command("view")
@click.pass_context
def dns_view(ctx: click.Context) -> None:
    """Show current DNS settings on both Kali and the VM."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    # Kali side
    console.print("[bold]Kali (/etc/resolv.conf):[/]")
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        for line in resolv.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                console.print(f"  {parts[1]}")
    else:
        console.print("  [red]not found[/]")

    # VM side
    console.print("[bold]VM:[/]")
    if vm.state() != VMState.RUNNING or not ga.ping():
        console.print("  [yellow]VM not running[/]")
        return

    result = ga.exec_powershell(
        "(Get-DnsClientServerAddress -AddressFamily IPv4"
        " | Where-Object { $_.ServerAddresses }).ServerAddresses",
        timeout=15,
    )
    if result.exitcode == 0 and result.stdout.strip():
        for ns in result.stdout.strip().splitlines():
            console.print(f"  {ns.strip()}")
    else:
        console.print("  [yellow]no DNS configured[/]")


# ─── hosts ────────────────────────────────────────────────────────────────────


HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

# Validation patterns for user-supplied values interpolated into PowerShell
_HOSTNAME_RE = re.compile(r"^[\w.\-]+$")  # hostname/FQDN
_DOMAIN_RE = re.compile(r"^[\w.\-]+$")    # domain name


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise click.BadParameter(f"Invalid IP address: {ip}")


def _validate_hostname(hostname: str) -> None:
    if not _HOSTNAME_RE.match(hostname):
        raise click.BadParameter(f"Invalid hostname: {hostname}")


def _validate_user(user: str) -> None:
    if not _HOSTNAME_RE.match(user):
        raise click.BadParameter(f"Invalid username: {user}")


def _validate_domain(name: str) -> None:
    if not _DOMAIN_RE.match(name):
        raise click.BadParameter(f"Invalid domain name: {name}")


@click.group()
def hosts() -> None:
    """Manage VM hosts file entries."""
    pass


@hosts.command("view")
@click.pass_context
def hosts_view(ctx: click.Context) -> None:
    """Show the VM hosts file."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    result = ga.exec_powershell(f"Get-Content '{HOSTS_PATH}'", timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    entries = [
        line.strip() for line in result.stdout.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not entries:
        console.print("[yellow]No entries[/]")
        return
    for entry in entries:
        console.print(f"  {entry}")


@hosts.command("add")
@click.argument("ip")
@click.argument("hostname")
@click.pass_context
def hosts_add(ctx: click.Context, ip: str, hostname: str) -> None:
    """Append an entry to the VM hosts file.

    Example: winbox hosts add 10.0.0.5 dc01.corp.local
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)
    _validate_ip(ip)
    _validate_hostname(hostname)

    script = f"Add-Content -Path '{HOSTS_PATH}' -Value \"{ip}`t{hostname}\""
    result = ga.exec_powershell(script, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(f"[green][+][/] {ip}\t{hostname}")


@hosts.command("set")
@click.argument("ip")
@click.argument("hostname")
@click.pass_context
def hosts_set(ctx: click.Context, ip: str, hostname: str) -> None:
    """Set a hosts entry (replaces existing entry for hostname, or adds new).

    Example: winbox hosts set 10.0.0.5 dc01.corp.local
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)
    _validate_ip(ip)
    _validate_hostname(hostname)

    hostname_escaped = hostname.replace('.', '\\.').replace('-', '\\-')
    script = (
        f"$f = '{HOSTS_PATH}'\n"
        f"$lines = Get-Content $f\n"
        f"$lines = @($lines | Where-Object {{ $_ -match '^\\s*#' -or $_ -notmatch '\\s{hostname_escaped}(\\s|$)' }})\n"
        f"$lines += \"{ip}`t{hostname}\"\n"
        f"Set-Content -Path $f -Value $lines"
    )
    result = ga.exec_powershell(script, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(f"[green][+][/] {ip}\t{hostname}")


@hosts.command("delete")
@click.argument("hostname")
@click.pass_context
def hosts_delete(ctx: click.Context, hostname: str) -> None:
    """Remove all entries for a hostname from the VM hosts file.

    Example: winbox hosts delete dc01.corp.local
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)
    _validate_hostname(hostname)

    hostname_escaped = hostname.replace('.', '\\.').replace('-', '\\-')
    script = (
        f"$f = '{HOSTS_PATH}'\n"
        f"$lines = Get-Content $f\n"
        f"$lines = @($lines | Where-Object {{ $_ -match '^\\s*#' -or $_ -notmatch '\\s{hostname_escaped}(\\s|$)' }})\n"
        f"Set-Content -Path $f -Value $lines"
    )
    result = ga.exec_powershell(script, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(f"[green][+][/] Removed {hostname}")


# ─── domain ──────────────────────────────────────────────────────────────────


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
@click.pass_context
def domain_join(
    ctx: click.Context,
    name: str,
    ns_ip: str,
    user: str,
    password: str,
) -> None:
    """Join the VM to an Active Directory domain.

    Undo with: winbox domain leave
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)
    _validate_domain(name)
    _validate_ip(ns_ip)
    _validate_user(user)

    # Set DNS to domain name server
    console.print(f"[blue][*][/] Setting DNS to {ns_ip}...")
    dns_script = (
        "$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
        "| Select-Object -First 1\n"
        f"Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
        f"-ServerAddresses {ns_ip}\n"
        "Clear-DnsClientCache"
    )
    result = ga.exec_powershell(dns_script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to set DNS: {result.stderr}")
        raise SystemExit(1)
    console.print(f"[green][+][/] DNS set to {ns_ip}")

    # Verify DNS resolves the domain
    verify = ga.exec_powershell(
        f"Resolve-DnsName {name} -DnsOnly -ErrorAction Stop", timeout=15,
    )
    if verify.exitcode != 0:
        console.print(f"[red][-][/] Cannot resolve {name} via {ns_ip}")
        raise SystemExit(1)

    # Check machine account quota — if 0, user can't join machines
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

    # Join domain
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

    # Reboot to apply
    console.print("[blue][*][/] Rebooting...")
    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except Exception:
        pass  # Expected — VM reboots before we get a response

    time.sleep(10)
    console.print("[blue][*][/] Waiting for VM to come back...")
    try:
        ga.wait(timeout=120)
        _ensure_z_drive(ga)
    except GuestAgentError:
        console.print("[yellow][!][/] Guest agent not responding after reboot")
        console.print(f"    Check with: virsh console {cfg.vm_name}")
        raise SystemExit(1)
    console.print(f"[green][+][/] VM back up — domain-joined to {name}")
    console.print("    Undo with: [bold]winbox domain leave[/]")


@domain.command("leave")
@click.pass_context
def domain_leave(ctx: click.Context) -> None:
    """Leave the domain and return to workgroup (preserves all files)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # Remove from domain
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

    # Reset DNS back to DHCP
    console.print("[blue][*][/] Resetting DNS to DHCP...")
    dns_script = (
        "$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
        "| Select-Object -First 1\n"
        "Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses"
    )
    ga.exec_powershell(dns_script, timeout=15)

    # Reboot
    console.print("[blue][*][/] Rebooting...")
    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except Exception:
        pass

    time.sleep(10)
    console.print("[blue][*][/] Waiting for VM to come back...")
    try:
        ga.wait(timeout=120)
        _ensure_z_drive(ga)
    except GuestAgentError:
        console.print("[yellow][!][/] Guest agent not responding after reboot")
        console.print(f"    Check with: virsh console {cfg.vm_name}")
        raise SystemExit(1)
    console.print("[green][+][/] Domain left — back to workgroup, all files intact")
