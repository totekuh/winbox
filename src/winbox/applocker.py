"""AppLocker enable/disable/status, shared by the CLI and MCP server.

Both the ``winbox applocker`` CLI group (cli/applocker.py) and the MCP tools
(mcp.py) call the ``enable`` / ``disable_apply`` / ``status`` operations below,
so the payloads AND the step ordering live in exactly one place.  Each frontend
only supplies I/O: console output or string returns.  The reboot after
``disable_apply`` is deliberately NOT here — each frontend handles it
differently (CLI's reboot_and_wait vs. MCP's own shutdown/wait).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from winbox import data as _data
from winbox.ps import render_ps

if TYPE_CHECKING:
    from winbox.vm import GuestAgent
    from winbox.vm.guest import ExecResult


class AppLockerError(Exception):
    """An AppLocker operation failed."""

    def __init__(self, message: str, result: ExecResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class AppLockerStatus:
    """Parsed AppLocker enforcement state."""

    raw_stdout: str
    enforced: bool
    active: bool


_POLICY_PATH = r"Z:\.applocker-policy.xml"

_SET_POLICY_SCRIPT = render_ps("applocker_apply", path=_POLICY_PATH)
_DISABLE_APPLY_SCRIPT = render_ps("applocker_clear", path=_POLICY_PATH)

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


def _default_policy_xml() -> str:
    return _data.read("applocker", "default-policy.xml")


def _clear_policy_xml() -> str:
    return _data.read("applocker", "clear-policy.xml")


def _parse_status(stdout: str) -> AppLockerStatus:
    text = stdout.strip()
    enforced = "AppLocker: ENFORCED" in text
    active = enforced or "audit only" in text
    return AppLockerStatus(raw_stdout=text, enforced=enforced, active=active)


def status(ga: GuestAgent, *, timeout: int = 90) -> AppLockerStatus:
    """Query current AppLocker enforcement state."""
    result = ga.exec_powershell(_STATUS_SCRIPT, timeout=timeout)
    if result.exitcode != 0:
        raise AppLockerError(
            f"Failed to query AppLocker status: {result.stderr.strip()}",
            result=result,
        )
    return _parse_status(result.stdout)


def enable(ga: GuestAgent, shared_dir: Path) -> None:
    """Enable AppLocker with default rules (Exe, Script, MSI, Appx).

    Writes policy XML to VirtIO-FS share, applies it, starts the AppID
    stack, compiles rules, and forces gpupdate.  Raises AppLockerError
    on failure.
    """
    policy_file = shared_dir / ".applocker-policy.xml"
    policy_file.write_text(_default_policy_xml(), encoding="utf-8")
    try:
        result = ga.exec_powershell(_SET_POLICY_SCRIPT, timeout=30)
    finally:
        policy_file.unlink(missing_ok=True)

    if result.exitcode != 0:
        raise AppLockerError(
            f"Failed to set AppLocker policy: {result.stderr.strip()}",
            result=result,
        )

    result = ga.exec("appidtel.exe start", timeout=60)
    if result.exitcode != 0:
        raise AppLockerError(
            f"Failed to start AppLocker stack: {result.stdout.strip()}",
            result=result,
        )
    time.sleep(5)

    result = ga.exec(r"C:\Windows\System32\AppIdPolicyConverter.exe", timeout=60)
    # Converter warnings are non-fatal
    time.sleep(5)

    result = ga.exec("gpupdate /force", timeout=180)
    # gpupdate warnings are non-fatal


def disable_apply(ga: GuestAgent, shared_dir: Path) -> None:
    """Clear AppLocker policy.  Caller must reboot afterward.

    appid.sys caches rules in kernel memory, so a reboot is required to
    fully disable enforcement.  This function only clears the policy in
    the registry — the caller is responsible for rebooting.
    """
    policy_file = shared_dir / ".applocker-policy.xml"
    policy_file.write_text(_clear_policy_xml(), encoding="utf-8")
    try:
        result = ga.exec_powershell(_DISABLE_APPLY_SCRIPT, timeout=30)
    finally:
        policy_file.unlink(missing_ok=True)

    if result.exitcode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AppLockerError(
            f"Failed to clear AppLocker policy: {detail}",
            result=result,
        )
