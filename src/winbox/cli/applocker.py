"""AppLocker commands — enable/disable/status with default rules."""

from __future__ import annotations

import importlib.resources
import time
from pathlib import Path

import click

from winbox.cli import console, ensure_running, needs_vm, _ensure_z_drive
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM

# AppLocker policy XMLs live in src/winbox/data/applocker/ -- the previous
# inlined-as-Python-strings approach made the rule layout unsearchable and
# unlintable. Loaded lazily so unit tests don't need importlib.resources
# stubbing.

def _read_data(*parts: str) -> str:
    res = importlib.resources.files("winbox.data").joinpath(*parts)
    return Path(str(res)).read_text(encoding="utf-8")


def _default_policy_xml() -> str:
    return _read_data("applocker", "default-policy.xml")


def _clear_policy_xml() -> str:
    return _read_data("applocker", "clear-policy.xml")

# Enable/disable scripts read the policy XML from Z:\ (VirtIO-FS share)
# to avoid command-line length limits with -EncodedCommand.
_POLICY_PATH = r"Z:\.applocker-policy.xml"

_SET_POLICY_SCRIPT = r"""
$xmlPath = '{path}'
if (-not (Test-Path $xmlPath)) {{
    Write-Error "Policy file not found: $xmlPath"
    exit 1
}}
Set-AppLockerPolicy -XmlPolicy $xmlPath
""".format(path=_POLICY_PATH)

_DISABLE_APPLY_SCRIPT = r"""
$xmlPath = '{path}'
if (-not (Test-Path $xmlPath)) {{
    Write-Error "Policy file not found: $xmlPath"
    exit 1
}}
# Clear policy while service is running (service must be up to process the change)
Set-AppLockerPolicy -XmlPolicy $xmlPath
Remove-Item $xmlPath -ErrorAction SilentlyContinue

# Restart service so it processes the empty policy and notifies appid.sys
Restart-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Delete compiled rule cache
Remove-Item 'C:\Windows\System32\AppLocker\*.AppLocker' -Force -ErrorAction SilentlyContinue

# Stop the service
appidtel.exe stop
Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
""".format(path=_POLICY_PATH)

_STATUS_SCRIPT = r"""
$svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "AppLocker: not available"
    exit 0
}

$svcStatus = $svc.Status
if ($svcStatus -ne 'Running') {
    Write-Host "AppLocker: off (AppIDSvc $svcStatus)"
    exit 0
}

$policy = Get-AppLockerPolicy -Effective
$collections = $policy.RuleCollections
$enforced = @($collections | Where-Object { $_.EnforcementMode -eq 'Enabled' })
$audit = @($collections | Where-Object { $_.EnforcementMode -eq 'AuditOnly' })

if ($enforced.Count -eq 0 -and $audit.Count -eq 0) {
    Write-Host "AppLocker: off (no rules configured)"
    exit 0
}

if ($enforced.Count -gt 0) {
    Write-Host "AppLocker: ENFORCED"
} else {
    Write-Host "AppLocker: audit only"
}

foreach ($c in $collections) {
    $mode = $c.EnforcementMode
    $type = $c.RuleCollectionType
    $count = $c.Count
    if ($mode -ne 'NotConfigured') {
        Write-Host "  ${type}: $mode ($count rules)"
    }
}
"""


@click.group()
def applocker() -> None:
    """Toggle AppLocker on the VM (default rules, no DLLs)."""
    pass


@applocker.command("enable")
@needs_vm()
def applocker_enable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Enable AppLocker with default rules (Exe, Script, MSI, Appx).

    Standard corporate/exam config: allow C:\\Windows\\* and C:\\Program Files\\*
    for Everyone, Administrators can run anything. No DLL rules.
    Undo with: winbox applocker disable
    """
    # Write policy XML to VirtIO-FS share (avoids command-line length limits)
    policy_file = Path(cfg.shared_dir) / ".applocker-policy.xml"
    console.print("[blue][*][/] Applying default AppLocker policy...")
    policy_file.write_text(_default_policy_xml(), encoding="utf-8")
    try:
        result = ga.exec_powershell(_SET_POLICY_SCRIPT, timeout=30)
    finally:
        policy_file.unlink(missing_ok=True)

    if result.exitcode != 0:
        console.print("[red][-][/] Failed to set AppLocker policy:")
        console.print(f"    {result.stderr.strip()}", markup=False, highlight=False)
        raise SystemExit(1)

    # Each step must be a separate GA call — running inside a single
    # exec_powershell doesn't give the converter the right context.
    console.print("[blue][*][/] Starting AppLocker stack...")
    result = ga.exec("appidtel.exe start", timeout=15)
    if result.exitcode != 0:
        console.print("[red][-][/] Failed to start AppLocker stack (appidtel.exe):")
        console.print(f"    {result.stdout.strip()}", markup=False, highlight=False)
        raise SystemExit(1)
    time.sleep(5)

    console.print("[blue][*][/] Compiling rules...")
    result = ga.exec(r"C:\Windows\System32\AppIdPolicyConverter.exe", timeout=15)
    if result.exitcode != 0:
        console.print("[yellow][!][/] Rule compilation warning (AppIdPolicyConverter):")
        console.print(f"    {result.stdout.strip()}", markup=False, highlight=False)
    time.sleep(5)
    result = ga.exec("gpupdate /force", timeout=30)
    if result.exitcode != 0:
        console.print("[yellow][!][/] gpupdate warning:")
        console.print(f"    {result.stdout.strip()}", markup=False, highlight=False)

    console.print("[green][+][/] AppLocker enforced (Exe, Script, MSI, Appx)")
    console.print("    Allowed: %WINDIR%\\*, %PROGRAMFILES%\\*, Admins everywhere")
    console.print("    Blocked: everything else (e.g. Z:\\tools for non-admin)")
    console.print("    Undo with: [bold]winbox applocker disable[/]")


@applocker.command("disable")
@needs_vm()
def applocker_disable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Disable AppLocker — clear policy, stop stack, reboot.

    Reboot is required because appid.sys caches rules in kernel memory
    and continues enforcing even after AppIDSvc is stopped.
    """
    policy_file = Path(cfg.shared_dir) / ".applocker-policy.xml"
    console.print("[blue][*][/] Clearing AppLocker policies...")
    policy_file.write_text(_clear_policy_xml(), encoding="utf-8")
    try:
        ga.exec_powershell(_DISABLE_APPLY_SCRIPT, timeout=30)
    finally:
        policy_file.unlink(missing_ok=True)

    console.print("[blue][*][/] Rebooting VM (kernel caches enforcement)...")
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

    console.print("[green][+][/] AppLocker disabled")


@applocker.command("status")
@needs_vm()
def applocker_status(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Show current AppLocker enforcement status."""
    result = ga.exec_powershell(_STATUS_SCRIPT, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to query status: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(result.stdout.strip(), markup=False, highlight=False)


REGISTER = ("Target", [applocker])
