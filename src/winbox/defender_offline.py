"""Offline Defender registry operations for powered-off guest hive edits.

On a client SKU, Defender state can only be changed while the VM is off:
once WinDefend has started, Tamper Protection is enforced by its own kernel
components and every in-guest disable is ignored or refused.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from winbox.vm import GuestAgent

ProgressFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


_DEFENDER_SERVICES = ("WinDefend", "WdFilter", "WdNisSvc", "WdNisDrv")

_DEFENDER_DEFAULT_START = {
    "WinDefend": 2,
    "WdFilter": 0,
    "WdNisSvc": 3,
    "WdNisDrv": 3,
}


def _system_services_reg(
    start_values: dict[str, int],
    control_set: int = 1,
) -> str:
    """Render a .reg document setting Services\\<name>\\Start in SYSTEM."""
    cs = f"ControlSet{control_set:03d}"
    lines = ["Windows Registry Editor Version 5.00", ""]
    for name, start in start_values.items():
        lines.append(
            f"[HKEY_LOCAL_MACHINE\\SYSTEM\\{cs}\\Services\\{name}]"
        )
        lines.append(f'"Start"=dword:{start:08x}')
        lines.append("")
    return "\r\n".join(lines).rstrip("\r\n") + "\r\n"


DEFENDER_OFF_SYSTEM_REG = _system_services_reg(
    {name: 4 for name in _DEFENDER_SERVICES}
)

DEFENDER_ON_SYSTEM_REG = _system_services_reg(_DEFENDER_DEFAULT_START)

TAMPER_OFF_SOFTWARE_REG = (
    "Windows Registry Editor Version 5.00\r\n"
    "\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Features]\r\n"
    '"TamperProtection"=dword:00000004\r\n'
    '"TamperProtectionSource"=dword:00000002\r\n'
)


def start_types_unwritten(ga: "GuestAgent", *, timeout: int = 15) -> tuple[str, ...]:
    """Return Defender services whose Start value is still wrong."""
    unwritten: list[str] = []
    for svc, want in _DEFENDER_DEFAULT_START.items():
        try:
            result = ga.exec_argv(
                "reg.exe",
                ["query", rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc}",
                 "/v", "Start"],
                timeout=timeout,
            )
            match = re.search(
                r"Start\s+REG_DWORD\s+0x([0-9a-fA-F]+)", result.stdout or ""
            )
            ok = (
                result.exitcode == 0
                and match is not None
                and int(match.group(1), 16) == want
            )
        except Exception:
            ok = False
        if not ok:
            unwritten.append(svc)
    return tuple(unwritten)


def disable_offline(cfg, *, progress: ProgressFn = _noop) -> None:
    """Disable Defender by editing the powered-off guest's SYSTEM hive."""
    from winbox import offlinereg

    win_part = offlinereg.windows_partition(cfg)
    progress("Reading active ControlSet from SYSTEM hive...")
    cs = offlinereg.read_current_control_set(cfg.disk_path, win_part)
    reg_body = _system_services_reg(
        {name: 4 for name in _DEFENDER_SERVICES}, control_set=cs,
    )
    progress(f"Disabling Defender services in ControlSet{cs:03d}...")
    offlinereg.merge_hive(
        cfg.disk_path,
        hive=offlinereg.SYSTEM_HIVE,
        prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
        reg_body=reg_body,
        win_part=win_part,
    )


def enable_offline(cfg, *, progress: ProgressFn = _noop) -> None:
    """Restore Defender services' shipped start types in the offline hive."""
    from winbox import offlinereg

    win_part = offlinereg.windows_partition(cfg)
    progress("Reading active ControlSet from SYSTEM hive...")
    cs = offlinereg.read_current_control_set(cfg.disk_path, win_part)
    reg_body = _system_services_reg(_DEFENDER_DEFAULT_START, control_set=cs)
    progress(f"Restoring Defender service start types in ControlSet{cs:03d}...")
    offlinereg.merge_hive(
        cfg.disk_path,
        hive=offlinereg.SYSTEM_HIVE,
        prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
        reg_body=reg_body,
        win_part=win_part,
    )


def clear_tamper_protection_offline(cfg, *, progress: ProgressFn = _noop) -> None:
    """Turn Tamper Protection off in the powered-off guest's SOFTWARE hive."""
    from winbox import offlinereg

    progress("Clearing Tamper Protection in the offline SOFTWARE hive...")
    offlinereg.merge_hive(
        cfg.disk_path,
        hive=offlinereg.SOFTWARE_HIVE,
        prefix="HKEY_LOCAL_MACHINE\\SOFTWARE",
        reg_body=TAMPER_OFF_SOFTWARE_REG,
        win_part=offlinereg.windows_partition(cfg),
    )
