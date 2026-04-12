"""Autologin commands — enable/disable/status for persistent Administrator auto-login."""

from __future__ import annotations

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM

# Winlogon is where Windows reads autologin credentials.
_WINLOGON_REG = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# Server 2022 gate: unless DevicePasswordLessBuildVersion=0 under PasswordLess\Device,
# Winlogon silently ignores AutoAdminLogon even when the credentials are present.
_PWDLESS_REG = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device"

_WINLOGON_PS = _WINLOGON_REG.replace("HKLM", "HKLM:", 1)
_PWDLESS_PS = _PWDLESS_REG.replace("HKLM", "HKLM:", 1)


def _enable_argv(user: str, password: str) -> list[list[str]]:
    """Build the reg.exe argv lists for enabling autologin.

    ForceAutoLogon=1 prevents Winlogon from clearing AutoAdminLogon after a
    failed logon. DevicePasswordLessBuildVersion=0 disables the Server 2022
    passwordless gate that otherwise silently blocks AutoAdminLogon.
    """
    return [
        ["add", _WINLOGON_REG, "/v", "AutoAdminLogon", "/t", "REG_SZ", "/d", "1", "/f"],
        ["add", _WINLOGON_REG, "/v", "DefaultUserName", "/t", "REG_SZ", "/d", user, "/f"],
        ["add", _WINLOGON_REG, "/v", "DefaultDomainName", "/t", "REG_SZ", "/d", ".", "/f"],
        ["add", _WINLOGON_REG, "/v", "DefaultPassword", "/t", "REG_SZ", "/d", password, "/f"],
        ["add", _WINLOGON_REG, "/v", "ForceAutoLogon", "/t", "REG_SZ", "/d", "1", "/f"],
        ["add", _PWDLESS_REG, "/v", "DevicePasswordLessBuildVersion", "/t", "REG_DWORD", "/d", "0", "/f"],
    ]


# For disable we wipe the three credential-bearing values so Winlogon has
# nothing to act on. DefaultUserName/DefaultDomainName are harmless to leave.
_DISABLE_ARGV: list[list[str]] = [
    ["add", _WINLOGON_REG, "/v", "AutoAdminLogon", "/t", "REG_SZ", "/d", "0", "/f"],
    ["delete", _WINLOGON_REG, "/v", "DefaultPassword", "/f"],
    ["delete", _WINLOGON_REG, "/v", "ForceAutoLogon", "/f"],
]


_STATUS_SCRIPT = f"""
$wl = Get-ItemProperty -Path '{_WINLOGON_PS}' -ErrorAction SilentlyContinue
$pl = Get-ItemProperty -Path '{_PWDLESS_PS}' -ErrorAction SilentlyContinue

$aal = if ($wl.AutoAdminLogon) {{ $wl.AutoAdminLogon }} else {{ '0' }}
$user = if ($wl.DefaultUserName) {{ $wl.DefaultUserName }} else {{ '(unset)' }}
$domain = if ($wl.DefaultDomainName) {{ $wl.DefaultDomainName }} else {{ '(unset)' }}
$force = if ($wl.ForceAutoLogon) {{ $wl.ForceAutoLogon }} else {{ '0' }}
$hasPwd = [bool]($wl.PSObject.Properties.Name -contains 'DefaultPassword')
$pwdless = if ($pl -and $pl.PSObject.Properties.Name -contains 'DevicePasswordLessBuildVersion') {{
    $pl.DevicePasswordLessBuildVersion
}} else {{ '(unset)' }}

$enabled = ($aal -eq '1') -and $hasPwd -and ($pwdless -eq 0)
if ($enabled) {{
    Write-Host "Autologin: ON"
}} elseif ($aal -eq '1' -or $hasPwd) {{
    Write-Host "Autologin: partial"
}} else {{
    Write-Host "Autologin: OFF"
}}
Write-Host "  AutoAdminLogon:                 $aal"
Write-Host "  DefaultUserName:                $user"
Write-Host "  DefaultDomainName:              $domain"
Write-Host "  DefaultPassword set:            $hasPwd"
Write-Host "  ForceAutoLogon:                 $force"
Write-Host "  DevicePasswordLessBuildVersion: $pwdless"
"""


@click.group()
def autologin() -> None:
    """Toggle persistent Administrator auto-login on the VM."""
    pass


@autologin.command("enable")
@click.pass_context
def autologin_enable(ctx: click.Context) -> None:
    """Enable persistent auto-login for the configured VM user.

    Writes Winlogon credentials plus the Server 2022 PasswordLess gate.
    Undo with: winbox autologin disable
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    console.print(f"[blue][*][/] Enabling autologin for {cfg.vm_user}...")
    for args in _enable_argv(cfg.vm_user, cfg.vm_password):
        result = ga.exec_argv("reg.exe", args, timeout=15)
        if result.exitcode != 0:
            console.print(f"[red][-][/] Failed: reg.exe {' '.join(args)}")
            console.print(f"    {result.stderr.strip()}", markup=False, highlight=False)
            raise SystemExit(1)

    console.print(f"[green][+][/] Autologin enabled for {cfg.vm_user}")
    console.print("    Takes effect on next boot. Try: [bold]winbox up --reboot[/]")


@autologin.command("disable")
@click.pass_context
def autologin_disable(ctx: click.Context) -> None:
    """Disable auto-login — clears DefaultPassword and ForceAutoLogon."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    console.print("[blue][*][/] Disabling autologin...")
    for args in _DISABLE_ARGV:
        result = ga.exec_argv("reg.exe", args, timeout=15)
        # reg delete returns 1 if the value is already absent — that's fine.
        if result.exitcode != 0 and args[0] != "delete":
            console.print(f"[red][-][/] Failed: reg.exe {' '.join(args)}")
            console.print(f"    {result.stderr.strip()}", markup=False, highlight=False)
            raise SystemExit(1)

    console.print("[green][+][/] Autologin disabled")


@autologin.command("status")
@click.pass_context
def autologin_status(ctx: click.Context) -> None:
    """Show current autologin status."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    result = ga.exec_powershell(_STATUS_SCRIPT, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to query status: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(result.stdout.strip(), markup=False, highlight=False)
