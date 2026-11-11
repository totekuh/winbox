"""DNS and hosts-file commands for the VM."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import click

from winbox.cli import console, needs_vm
from winbox.cli._ps import ps_array, render_ps
from winbox.config import Config
from winbox.vm import GuestAgent, VM, VMState


# ─── validators ─────────────────────────────────────────────────────────────

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

_HOSTNAME_RE = re.compile(r"^[\w.\-]+$")
_DOMAIN_RE = re.compile(r"^[\w.\-]+$")


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


# ─── dns ─────────────────────────────────────────────────────────────────────


@click.group()
def dns() -> None:
    """Manage VM DNS settings."""
    pass


@dns.command("set")
@click.argument("ip")
@needs_vm()
def dns_set(cfg: Config, vm: VM, ga: GuestAgent, ip: str) -> None:
    """Set a DNS nameserver on the VM.

    Example: winbox dns set 192.168.56.11
    """
    _validate_ip(ip)

    console.print(f"[blue][*][/] Setting DNS to {ip}...")
    result = ga.exec_powershell(
        render_ps("set_dns", servers=ip),
        timeout=30,
    )
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(f"[green][+][/] DNS set to {ip}")


@dns.command("sync")
@needs_vm()
def dns_sync(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Push Kali's /etc/resolv.conf nameservers to the VM."""
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

    ns_joined = ", ".join(nameservers)
    console.print(f"[blue][*][/] Setting DNS to {ns_joined}...")
    result = ga.exec_powershell(
        render_ps("set_dns", servers=ps_array(nameservers)),
        timeout=30,
    )
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

    console.print("[bold]Kali (/etc/resolv.conf):[/]")
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        for line in resolv.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                console.print(f"  {parts[1]}")
    else:
        console.print("  [red]not found[/]")

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


@click.group()
def hosts() -> None:
    """Manage VM hosts file entries."""
    pass


@hosts.command("view")
@needs_vm()
def hosts_view(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Show the VM hosts file."""
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
@needs_vm()
def hosts_add(cfg: Config, vm: VM, ga: GuestAgent, ip: str, hostname: str) -> None:
    """Append an entry to the VM hosts file.

    Example: winbox hosts add 10.0.0.5 dc01.corp.local
    """
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
@needs_vm()
def hosts_set(cfg: Config, vm: VM, ga: GuestAgent, ip: str, hostname: str) -> None:
    """Set a hosts entry (replaces existing entry for hostname, or adds new).

    Example: winbox hosts set 10.0.0.5 dc01.corp.local
    """
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
@needs_vm()
def hosts_delete(cfg: Config, vm: VM, ga: GuestAgent, hostname: str) -> None:
    """Remove all entries for a hostname from the VM hosts file.

    Example: winbox hosts delete dc01.corp.local
    """
    _validate_hostname(hostname)

    hostname_escaped = hostname.replace('.', '\\.').replace('-', '\\-')
    script = (
        f"$f = '{HOSTS_PATH}'\n"
        f"$lines = @(Get-Content $f)\n"
        f"$keep = @($lines | Where-Object {{ $_ -match '^\\s*#' -or $_ -notmatch '\\s{hostname_escaped}(\\s|$)' }})\n"
        f"$removed = $lines.Count - $keep.Count\n"
        f"if ($removed -gt 0) {{ Set-Content -Path $f -Value $keep }}\n"
        f"Write-Host \"REMOVED=$removed\""
    )
    result = ga.exec_powershell(script, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    removed = 0
    for line in (result.stdout or "").splitlines():
        if line.startswith("REMOVED="):
            removed = int(line.split("=", 1)[1].strip() or 0)
    if removed:
        plural = "entry" if removed == 1 else "entries"
        console.print(f"[green][+][/] Removed {removed} {plural} for {hostname}")
    else:
        console.print(f"[yellow][!][/] No hosts entry for {hostname} — nothing to remove")


REGISTER = ("Network", [dns, hosts])
