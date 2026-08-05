"""Windows Defender / AMSI enable/disable/status, shared by the CLI and MCP server.

Both the ``winbox av`` CLI group (cli/av.py) and the MCP tools (mcp.py)
call the ``enable`` / ``set_disable_regkeys`` / ``status`` operations below,
so the payloads AND the step ordering live in exactly one place. Each
frontend only supplies I/O: a ``progress`` callback for step messages and
its own reboot + result formatting. The reboot itself is deliberately NOT
here — it's generic VM lifecycle the two frontends already do differently
(CLI's reboot_and_wait with console output vs. the MCP tool's own wait).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from winbox.vm import GuestAgent
    from winbox.vm.guest import ExecResult

# Registry paths — PowerShell uses "HKLM:\", reg.exe uses "HKLM\".
# Define reg.exe style, derive PowerShell style to avoid duplication.
GP_DEFENDER_REG = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
GP_RTP_REG = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
MS_RTP_REG = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"

GP_DEFENDER = GP_DEFENDER_REG.replace("HKLM", "HKLM:", 1)
GP_RTP = GP_RTP_REG.replace("HKLM", "HKLM:", 1)
MS_RTP = MS_RTP_REG.replace("HKLM", "HKLM:", 1)

ENABLE_SCRIPT = f"""
# Remove GP-level registry overrides (provisioning + av disable set these)
Remove-ItemProperty -Path '{GP_DEFENDER}' -Name DisableAntiSpyware -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{GP_RTP}' -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{GP_RTP}' -Name DisableIOAVProtection -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{GP_RTP}' -Name DisableBehaviorMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{GP_RTP}' -Name DisableScriptScanning -ErrorAction SilentlyContinue

# Remove non-policy registry keys
Remove-ItemProperty -Path '{MS_RTP}' -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{MS_RTP}' -Name DisableIOAVProtection -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{MS_RTP}' -Name DisableBehaviorMonitoring -ErrorAction SilentlyContinue
Remove-ItemProperty -Path '{MS_RTP}' -Name DisableScriptScanning -ErrorAction SilentlyContinue
"""

EXCLUSION_SCRIPT = r"""
# Add exclusions so Defender doesn't block the QEMU guest agent or VirtIO-FS
Add-MpPreference -ExclusionPath 'C:\Program Files\Qemu-ga' -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'Z:\' -ErrorAction SilentlyContinue
"""

PREFS_ENABLE_SCRIPT = """
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
DISABLE_REG_ARGS: list[list[str]] = [
    # GP-level overrides — these take precedence over everything else and
    # persist across reboots. The non-policy keys under
    # Microsoft\Windows Defender\Real-Time Protection are ACL-protected
    # by Defender when it's running, so we only use GP keys.
    ["add", GP_DEFENDER_REG, "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", GP_RTP_REG, "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", GP_RTP_REG, "/v", "DisableIOAVProtection", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", GP_RTP_REG, "/v", "DisableBehaviorMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"],
    ["add", GP_RTP_REG, "/v", "DisableScriptScanning", "/t", "REG_DWORD", "/d", "1", "/f"],
]

STATUS_SCRIPT = """
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
# Tamper Protection gates whether the disable keys even take effect. It's
# off on Server 2022 but on-by-default on Win11 client, where it silently
# neuters the GP/Set-MpPreference disable path.
$tp = $false
try { $tp = [bool]$s.IsTamperProtected } catch {}
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
Write-Host "  TamperProtection: $tp"
"""

# Reports just Tamper Protection state as OK/BLOCKED so the disable path can
# decide whether the registry keys will actually take effect (Win11).
TAMPER_CHECK_SCRIPT = """
try {
    $tp = [bool](Get-MpComputerStatus).IsTamperProtected
} catch {
    $tp = $false
}
if ($tp) { Write-Host "TAMPER_ON" } else { Write-Host "TAMPER_OFF" }
"""


# ─── Operations (shared step orchestration) ─────────────────────────────────
# A no-op default so callers that don't care about progress can omit it.
ProgressFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


class DefenderError(Exception):
    """A Defender operation step failed. ``result`` carries the failing
    ExecResult (may be None) so the frontend can format stdout/stderr/exit."""

    def __init__(self, message: str, result: "ExecResult | None" = None) -> None:
        super().__init__(message)
        self.result = result


def status(ga: "GuestAgent", *, timeout: int = 15) -> "ExecResult":
    """Query Defender / AMSI protection state. Returns the raw ExecResult
    (exitcode + the STATUS_SCRIPT summary on stdout) for the caller to format."""
    return ga.exec_powershell(STATUS_SCRIPT, timeout=timeout)


def tamper_protection_on(ga: "GuestAgent", *, timeout: int = 15) -> bool:
    """Return True if Defender Tamper Protection is currently active.

    When TP is on (the default on Win11 client), the GP/Set-MpPreference
    disable path is silently ignored, so ``av disable`` cannot actually turn
    Defender off. TP cannot be toggled from the running OS — it's cleared
    offline at setup time (``--os win11``) or from the Windows Security UI.
    A failure to determine state is treated as "off" so we never block the
    Server 2022 path (which has no TP) on a probe error.
    """
    try:
        result = ga.exec_powershell(TAMPER_CHECK_SCRIPT, timeout=timeout)
    except Exception:
        return False
    return "TAMPER_ON" in (result.stdout or "")


def enable(ga: "GuestAgent", *, progress: ProgressFn = _noop) -> bool:
    """Re-enable real-time protection, AMSI, and behavior monitoring.

    Returns True if a reboot is required to finish (see below), False if the
    operation completed.

    Removes the registry overrides, starts WinDefend (sc.exe — PowerShell
    Start-Service is ACL-blocked), adds the QEMU-GA / Z:\\ exclusions
    BEFORE re-asserting protections (otherwise Defender flags the GA
    helper's encoded PowerShell as Trojan:Win32/PowExcEnv.B!MTB and breaks
    winbox exec), then sets the Set-MpPreference flags best-effort.

    Raises DefenderError only if WinDefend fails to start — that's the one
    step the whole operation depends on; the rest are idempotent best-effort.
    """
    # Step 1: Remove registry blocks (best-effort — keys may already be gone).
    progress("Removing registry overrides...")
    ga.exec_powershell(ENABLE_SCRIPT, timeout=15)

    # Step 1.5: On Win11, `winbox setup` disables the Defender services in the
    # SYSTEM hive (Start=4) — otherwise Tamper Protection blocks every disable.
    # Restore their default start types so WinDefend can start again. WdFilter
    # is a boot-start driver, so real-time protection only fully re-arms after
    # a reboot (harmless no-op on Server 2022, where these are already set).
    progress("Re-enabling Defender service start types...")
    for svc, start in (("WinDefend", "2"), ("WdNisSvc", "3"), ("WdNisDrv", "3"), ("WdFilter", "0")):
        ga.exec_argv(
            "reg.exe",
            ["add", rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc}",
             "/v", "Start", "/t", "REG_DWORD", "/d", start, "/f"],
            timeout=15,
        )

    # Step 2: Start WinDefend (0 = started, 1056 = already running; both fine).
    progress("Starting WinDefend service...")
    result = ga.exec("sc.exe start WinDefend", timeout=15)
    if result.exitcode == 1058:
        # ERROR_SERVICE_DISABLED. The start types were just corrected above,
        # but the SCM caches them from boot — on a Win11 image built with the
        # offline Defender disable, WinDefend is still "disabled" as far as
        # this SCM instance is concerned. A reboot is the only way through,
        # and without it `av enable` could never re-enable Defender at all.
        progress("WinDefend still disabled in this boot's SCM — reboot required")
        return True
    if result.exitcode not in (0, 1056):
        raise DefenderError("Failed to start WinDefend", result)

    # Step 3: Exclusions must land before protections come up (see docstring).
    progress("Adding exclusions for QEMU GA and VirtIO-FS...")
    ga.exec_powershell(EXCLUSION_SCRIPT, timeout=15)

    # Step 4: Re-assert preferences (best-effort — defaults are already
    # "enabled" once the overrides are gone and the service is up).
    progress("Enabling protections...")
    ga.exec_powershell(PREFS_ENABLE_SCRIPT, timeout=30)
    return False


def set_disable_regkeys(ga: "GuestAgent", *, progress: ProgressFn = _noop) -> None:
    """Set the GP registry keys that disable Defender on next boot.

    This is the only user-mode-reachable way to kill WinDefend — it's a PPL
    that cannot be stopped while running. Uses reg.exe via exec_argv to
    bypass AMSI (which flags Set-MpPreference -Disable* $true). The caller
    MUST reboot afterwards for the change to take effect.

    Raises DefenderError on the first reg.exe step that fails.
    """
    progress("Setting registry keys...")
    for args in DISABLE_REG_ARGS:
        result = ga.exec_argv("reg.exe", args, timeout=15)
        if result.exitcode != 0:
            raise DefenderError(f"reg.exe {' '.join(args)} failed", result)


# ─── Offline (VM powered off) registry payloads ─────────────────────────────
# On a client SKU, Defender state can only be changed while the VM is off:
# once WinDefend has started, Tamper Protection is enforced by Defender's own
# kernel components and every in-guest disable is ignored or refused. These
# are merged into the offline hives by `winbox.offlinereg` — see that module
# for the mechanics and for why the disk must be shut down first.
#
# ControlSet001 is the current control set on these images (see SYSTEM\Select).

_DEFENDER_SERVICES = ("WinDefend", "WdFilter", "WdNisSvc", "WdNisDrv")

# Default start types, restored by the offline enable path. WdFilter is a
# boot-start driver (0); WinDefend is automatic (2); the network-inspection
# pair are demand-start (3).
_DEFENDER_DEFAULT_START = {
    "WinDefend": 2,
    "WdFilter": 0,
    "WdNisSvc": 3,
    "WdNisDrv": 3,
}


def _system_services_reg(start_values: dict[str, int]) -> str:
    """Render a .reg document setting Services\\<name>\\Start in SYSTEM."""
    lines = ["Windows Registry Editor Version 5.00", ""]
    for name, start in start_values.items():
        lines.append(
            f"[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\{name}]"
        )
        lines.append(f'"Start"=dword:{start:08x}')
        lines.append("")
    # Drop the trailing blank so the rendered document is byte-identical to
    # the hand-written payload this replaced — the build path is proven with
    # exactly those bytes.
    return "\r\n".join(lines).rstrip("\r\n") + "\r\n"


# Start=4 is "disabled". A WinDefend that never starts never arms Tamper
# Protection, so Defender stays fully inert and cannot quarantine winbox's
# tools. This is what `winbox setup` applies before the guest's first boot.
DEFENDER_OFF_SYSTEM_REG = _system_services_reg(
    {name: 4 for name in _DEFENDER_SERVICES}
)

# The inverse, for completeness — restoring the shipped start types offline.
DEFENDER_ON_SYSTEM_REG = _system_services_reg(_DEFENDER_DEFAULT_START)

# Tamper Protection lives in SOFTWARE, not SYSTEM. 5 = on, 4 = off. Clearing
# it offline (while Defender cannot defend it) is what keeps a subsequent
# in-guest `av disable` viable instead of forcing another power cycle.
#
# Note the build-time path deliberately avoids the SOFTWARE hive: editing it
# *before OOBE has completed* corrupts OOBE state. That constraint is about
# when, not about the hive itself — on a fully provisioned guest OOBE is long
# finished.
TAMPER_OFF_SOFTWARE_REG = (
    "Windows Registry Editor Version 5.00\r\n"
    "\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Features]\r\n"
    '"TamperProtection"=dword:00000004\r\n'
    '"TamperProtectionSource"=dword:00000002\r\n'
)


# ─── Offline operations (VM must be shut down) ──────────────────────────────


def disable_offline(cfg, *, progress: ProgressFn = _noop) -> None:
    """Disable Defender by editing the powered-off guest's SYSTEM hive.

    The only disable that works on a client SKU once Defender has run: with
    the VM off, Tamper Protection has nothing enforcing it. Caller must have
    shut the VM down.
    """
    from winbox import offlinereg

    progress("Disabling Defender services in the offline SYSTEM hive...")
    offlinereg.merge_hive(
        cfg.disk_path,
        hive=offlinereg.SYSTEM_HIVE,
        prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
        reg_body=DEFENDER_OFF_SYSTEM_REG,
        win_part=offlinereg.windows_partition(cfg),
    )


def enable_offline(cfg, *, progress: ProgressFn = _noop) -> None:
    """Restore the Defender services' shipped start types in the offline hive.

    The mirror of :func:`disable_offline`, and required rather than optional:
    Defender's ``Services\\*\\Start`` values are ACL-protected, so ``reg.exe``
    cannot undo an offline disable from inside the guest even with Defender
    stopped and Tamper Protection off. Without this, an offline disable would
    be one-way — exactly the trap the offline disable exists to remove.
    """
    from winbox import offlinereg

    progress("Restoring Defender service start types in the offline SYSTEM hive...")
    offlinereg.merge_hive(
        cfg.disk_path,
        hive=offlinereg.SYSTEM_HIVE,
        prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
        reg_body=DEFENDER_ON_SYSTEM_REG,
        win_part=offlinereg.windows_partition(cfg),
    )


def clear_tamper_protection_offline(cfg, *, progress: ProgressFn = _noop) -> None:
    """Turn Tamper Protection off in the powered-off guest's SOFTWARE hive.

    Lets Defender come back up without TP armed, so a later in-guest
    ``av disable`` still works instead of needing another power cycle. Caller
    must have shut the VM down.
    """
    from winbox import offlinereg

    progress("Clearing Tamper Protection in the offline SOFTWARE hive...")
    offlinereg.merge_hive(
        cfg.disk_path,
        hive=offlinereg.SOFTWARE_HIVE,
        prefix="HKEY_LOCAL_MACHINE\\SOFTWARE",
        reg_body=TAMPER_OFF_SOFTWARE_REG,
        win_part=offlinereg.windows_partition(cfg),
    )
