"""AV commands — enable/disable/status for Windows Defender and AMSI."""

from __future__ import annotations

import time

import click

from winbox.cli import console, ensure_running, _ensure_z_drive
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM

# Registry paths that provision.ps1 sets to disable Defender persistently
_GP_DEFENDER = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
_GP_RTP = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
_MS_RTP = r"HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"

_ENABLE_SCRIPT = r"""
# Remove GP-level registry overrides (provisioning + av disable set these)
Remove-ItemProperty -Path '{gp_def}' -Name DisableAntiSpyware -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{gp_rtp}' -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{gp_rtp}' -Name DisableIOAVProtection -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{gp_rtp}' -Name DisableBehaviorMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{gp_rtp}' -Name DisableScriptScanning -ErrorAction SilentlyContinue

# Remove non-policy registry keys
Remove-ItemProperty -Path '{ms_rtp}' -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{ms_rtp}' -Name DisableIOAVProtection -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{ms_rtp}' -Name DisableBehaviorMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{ms_rtp}' -Name DisableScriptScanning -ErrorAction SilentlyContinue
""".format(gp_def=_GP_DEFENDER, gp_rtp=_GP_RTP, ms_rtp=_MS_RTP)

_EXCLUSION_SCRIPT = r"""
# Add exclusions so Defender doesn't block the QEMU guest agent or VirtIO-FS
Add-MpPreference -ExclusionPath 'C:\Program Files\Qemu-ga' -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'Z:\' -ErrorAction SilentlyContinue
"""

_PREFS_ENABLE_SCRIPT = """
# Wait for WinDefend to be fully running (sc.exe start is async)
for ($i = 0; $i -lt 15; $i++) {
    $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
    if ($svc.Status -eq 'Running') { break }
    Start-Sleep -Seconds 1
}
if ($svc.Status -ne 'Running') {
    Write-Error "WinDefend did not start (status: $($svc.Status))"
    exit 1
}
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop
Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
"""

# reg.exe argv lists for disable — bypasses AMSI entirely.
# AMSI flags Set-MpPreference -Disable* $true inside -EncodedCommand as
# Trojan:Win32/PowExcEnv.B!MTB, so we use reg.exe via exec_argv instead.
# exec_argv bypasses cmd.exe too, avoiding quote-stripping on paths with spaces.
_GP_DEFENDER_REG = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
_GP_RTP_REG = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
_MS_RTP_REG = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"

_DISABLE_REG_ARGS: list[list[str]] = [
    # GP-level overrides — these take precedence over everything else and
    # persist across reboots. The non-policy keys under
    # Microsoft\Windows Defender\Real-Time Protection are ACL-protected
    # by Defender when it's running, so we only use GP keys.
    ["add", _GP_DEFENDER_REG, "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", _GP_RTP_REG, "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", _GP_RTP_REG, "/v", "DisableIOAVProtection", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", _GP_RTP_REG, "/v", "DisableBehaviorMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", _GP_RTP_REG, "/v", "DisableScriptScanning", "/t", "REG_DWORD", "/d", "1", "/f"],
]


_STATUS_SCRIPT = """
$svc = Get-Service WinDefend -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "Defender: not installed"
    exit 0
}
if ($svc.Status -ne 'Running') {
    Write-Host "Defender: off (service stopped)"
    exit 0
}
$s = Get-MpComputerStatus
$rtp = $s.RealTimeProtectionEnabled
$bm = $s.BehaviorMonitorEnabled
$ioav = $s.IoavProtectionEnabled
$amsi = -not (Get-MpPreference).DisableScriptScanning
if ($rtp -and $amsi) {
    Write-Host "Defender: ON"
} elseif (-not $rtp -and -not $amsi -and -not $bm -and -not $ioav) {
    Write-Host "Defender: OFF (service running but all protections disabled)"
} else {
    Write-Host "Defender: partial"
}
Write-Host "  RealTimeProtection: $rtp"
Write-Host "  AMSI/ScriptScanning: $amsi"
Write-Host "  BehaviorMonitoring: $bm"
Write-Host "  IOAVProtection: $ioav"
"""


@click.group()
def av() -> None:
    """Toggle Windows Defender and AMSI on the VM."""
    pass


@av.command("enable")
@click.pass_context
def av_enable(ctx: click.Context) -> None:
    """Re-enable Defender real-time protection and AMSI.

    Persists across reboots. Adds exclusions for the QEMU guest agent
    and VirtIO-FS share so winbox commands keep working.
    Undo with: winbox av disable
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # Step 1: Remove registry blocks (best-effort — keys may already be gone)
    console.print("[blue][*][/] Removing registry overrides...")
    ga.exec_powershell(_ENABLE_SCRIPT, timeout=15)

    # Step 2: Start WinDefend service (PowerShell Start-Service is ACL-blocked,
    # but sc.exe works)
    console.print("[blue][*][/] Starting WinDefend service...")
    result = ga.exec("sc.exe start WinDefend", timeout=15)
    # sc.exe returns 0 on success, 1056 if already running — both are fine
    if result.exitcode not in (0, 1056):
        console.print(f"[red][-][/] Failed to start WinDefend: {result.stdout.strip()}")
        raise SystemExit(1)

    # Step 3: Add exclusions BEFORE enabling protections — Defender flags
    # the QEMU GA helper (gspawn-win64-helper.exe) as Trojan:Win32/PowExcEnv.B!MTB
    # when it executes encoded PowerShell, which would break winbox exec.
    console.print("[blue][*][/] Adding exclusions for QEMU GA and VirtIO-FS...")
    ga.exec_powershell(_EXCLUSION_SCRIPT, timeout=15)

    # Step 4: Set preferences (best-effort — removing the registry overrides
    # and starting the service is usually enough since the defaults are "enabled",
    # but we set them explicitly in case they were changed)
    console.print("[blue][*][/] Enabling protections...")
    ga.exec_powershell(_PREFS_ENABLE_SCRIPT, timeout=30)

    console.print("[green][+][/] Defender enabled (real-time, AMSI, behavior monitoring)")
    console.print("    QEMU GA and Z:\\ excluded — winbox commands still work")
    console.print("    Undo with: [bold]winbox av disable[/]")


@av.command("disable")
@click.pass_context
def av_disable(ctx: click.Context) -> None:
    """Disable Defender completely — service stopped, all protections off.

    Sets GP registry keys then reboots the VM. WinDefend is a protected process
    (PPL) that cannot be stopped by any user-mode process including SYSTEM —
    only a reboot with the right registry keys will actually kill it.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # Step 1: Set GP registry keys (only way to kill WinDefend — it's PPL)
    console.print("[blue][*][/] Setting registry keys...")
    for args in _DISABLE_REG_ARGS:
        result = ga.exec_argv("reg.exe", args, timeout=15)
        if result.exitcode != 0:
            console.print(f"[red][-][/] Failed: reg.exe {' '.join(args)}")
            console.print(f"    {result.stderr.strip()}", markup=False)
            raise SystemExit(1)

    # Step 2: Reboot — the only way to actually stop the WinDefend service
    console.print("[blue][*][/] Rebooting VM...")
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

    console.print("[green][+][/] Defender disabled — service stopped")


@av.command("status")
@click.pass_context
def av_status(ctx: click.Context) -> None:
    """Show current Defender and AMSI status."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    result = ga.exec_powershell(_STATUS_SCRIPT, timeout=15)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to query status: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(result.stdout.strip(), markup=False, highlight=False)
