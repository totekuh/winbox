"""AppLocker commands — enable/disable/status with default rules."""

from __future__ import annotations

import time
from pathlib import Path

import click

from winbox.cli import console, ensure_running, _ensure_z_drive
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM

# Default AppLocker policy XML — Exe, Script, MSI, Appx (no DLL).
# Standard corporate/exam config: allow C:\Windows\* and C:\Program Files\*
# for Everyone, Administrators can run anything.
_DEFAULT_POLICY_XML = r"""<AppLockerPolicy Version="1">

  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
      Name="(Default Rule) All files"
      Description="Allows Administrators to run all applications."
      UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
      Name="(Default Rule) All files located in the Windows folder"
      Description="Allows Everyone to run applications in the Windows folder."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
      Name="(Default Rule) All files located in the Program Files folder"
      Description="Allows Everyone to run applications in the Program Files folder."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725"
      Name="(Default Rule) All scripts"
      Description="Allows Administrators to run all scripts."
      UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796bc5"
      Name="(Default Rule) All scripts located in the Windows folder"
      Description="Allows Everyone to run scripts in the Windows folder."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c"
      Name="(Default Rule) All scripts located in the Program Files folder"
      Description="Allows Everyone to run scripts in the Program Files folder."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54"
      Name="(Default Rule) All Windows Installer files"
      Description="Allows Administrators to run all Windows Installer files."
      UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePublisherRule Id="b7af7102-efde-4369-8a89-7a6a392d1473"
      Name="(Default Rule) All digitally signed Windows Installer files"
      Description="Allows Everyone to run digitally signed Windows Installer files."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d"
      Name="(Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer"
      Description="Allows Everyone to run Windows Installer files in %systemdrive%\Windows\Installer."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
      Name="(Default Rule) All signed packaged apps"
      Description="Allows Everyone to run signed packaged apps."
      UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>

</AppLockerPolicy>"""

_CLEAR_POLICY_XML = """<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Script" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />
</AppLockerPolicy>"""

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
@click.pass_context
def applocker_enable(ctx: click.Context) -> None:
    """Enable AppLocker with default rules (Exe, Script, MSI, Appx).

    Standard corporate/exam config: allow C:\\Windows\\* and C:\\Program Files\\*
    for Everyone, Administrators can run anything. No DLL rules.
    Undo with: winbox applocker disable
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # Write policy XML to VirtIO-FS share (avoids command-line length limits)
    policy_file = Path(cfg.shared_dir) / ".applocker-policy.xml"
    console.print("[blue][*][/] Applying default AppLocker policy...")
    policy_file.write_text(_DEFAULT_POLICY_XML, encoding="utf-8")
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
    ga.exec("appidtel.exe start", timeout=15)
    time.sleep(5)

    console.print("[blue][*][/] Compiling rules...")
    ga.exec(r"C:\Windows\System32\AppIdPolicyConverter.exe", timeout=15)
    time.sleep(5)
    ga.exec("gpupdate /force", timeout=30)

    console.print("[green][+][/] AppLocker enforced (Exe, Script, MSI, Appx)")
    console.print("    Allowed: %WINDIR%\\*, %PROGRAMFILES%\\*, Admins everywhere")
    console.print("    Blocked: everything else (e.g. Z:\\tools for non-admin)")
    console.print("    Undo with: [bold]winbox applocker disable[/]")


@applocker.command("disable")
@click.pass_context
def applocker_disable(ctx: click.Context) -> None:
    """Disable AppLocker — clear policy, stop stack, reboot.

    Reboot is required because appid.sys caches rules in kernel memory
    and continues enforcing even after AppIDSvc is stopped.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    policy_file = Path(cfg.shared_dir) / ".applocker-policy.xml"
    console.print("[blue][*][/] Clearing AppLocker policies...")
    policy_file.write_text(_CLEAR_POLICY_XML, encoding="utf-8")
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
@click.pass_context
def applocker_status(ctx: click.Context) -> None:
    """Show current AppLocker enforcement status."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    result = ga.exec_powershell(_STATUS_SCRIPT, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to query status: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(result.stdout.strip(), markup=False, highlight=False)
