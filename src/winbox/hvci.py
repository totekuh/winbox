"""HVCI / Virtualization Based Security enable/disable/status.

Both the ``winbox hvci`` CLI group (cli/hvci.py) and the MCP tools (mcp.py)
call the ``enable`` / ``disable`` / ``status`` operations below, so the
payloads AND the step ordering live in exactly one place.  Each frontend only
supplies I/O and its own reboot + result formatting.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from winbox.vm import GuestAgent

# Registry paths (reg.exe style — backslash, no colon).
DEVICE_GUARD_REG = r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard"
HVCI_SCENARIO_REG = (
    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    r"\Scenarios\HypervisorEnforcedCodeIntegrity"
)


@dataclass
class HvciStatus:
    vbs_enabled: bool      # EnableVirtualizationBasedSecurity == 1
    hvci_enabled: bool     # HypervisorEnforcedCodeIntegrity\Enabled == 1
    hypervisor_off: bool   # bcdedit hypervisorlaunchtype == off


def _query_dword(ga: "GuestAgent", key: str, value_name: str) -> int | None:
    """Run ``reg query`` and parse a REG_DWORD value.

    Returns the integer value, or ``None`` if the key or value doesn't exist.
    """
    try:
        result = ga.exec(
            f'reg query "{key}" /v {value_name}', timeout=10,
        )
    except Exception:
        return None
    if result.exitcode != 0:
        return None
    match = re.search(
        rf"{re.escape(value_name)}\s+REG_DWORD\s+0x([0-9a-fA-F]+)",
        result.stdout or "",
    )
    if match is None:
        return None
    return int(match.group(1), 16)


def _is_hypervisor_off(ga: "GuestAgent") -> bool:
    """Check whether ``bcdedit /enum {{current}}`` says hypervisorlaunchtype is Off."""
    try:
        result = ga.exec("bcdedit /enum {current}", timeout=10)
    except Exception:
        return False
    stdout = result.stdout or ""
    # bcdedit output: "hypervisorlaunchtype    Off"
    match = re.search(
        r"hypervisorlaunchtype\s+(\S+)", stdout, re.IGNORECASE,
    )
    if match is None:
        # Key absent means the system default (Auto) is in effect.
        return False
    return match.group(1).lower() == "off"


def status(ga: "GuestAgent") -> HvciStatus:
    """Query HVCI/VBS state from registry + bcdedit."""
    vbs = _query_dword(ga, DEVICE_GUARD_REG, "EnableVirtualizationBasedSecurity")
    hvci = _query_dword(ga, HVCI_SCENARIO_REG, "Enabled")
    hyp_off = _is_hypervisor_off(ga)
    return HvciStatus(
        vbs_enabled=vbs == 1,
        hvci_enabled=hvci == 1,
        hypervisor_off=hyp_off,
    )


def disable(ga: "GuestAgent") -> None:
    """Set registry keys + bcdedit to disable HVCI/VBS.

    Caller must reboot the VM for changes to take effect.
    """
    ga.exec(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" '
        "/v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f",
        timeout=10,
    )
    ga.exec(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard'
        '\\Scenarios\\HypervisorEnforcedCodeIntegrity" '
        "/v Enabled /t REG_DWORD /d 0 /f",
        timeout=10,
    )
    ga.exec("bcdedit /set hypervisorlaunchtype off", timeout=10)


def enable(ga: "GuestAgent") -> None:
    """Set registry keys + bcdedit to enable HVCI/VBS.

    Caller must reboot the VM for changes to take effect.
    """
    ga.exec(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" '
        "/v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f",
        timeout=10,
    )
    ga.exec(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard'
        '\\Scenarios\\HypervisorEnforcedCodeIntegrity" '
        "/v Enabled /t REG_DWORD /d 1 /f",
        timeout=10,
    )
    ga.exec("bcdedit /set hypervisorlaunchtype auto", timeout=10)
