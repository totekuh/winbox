"""CET safety gate for QEMU/KVM debugger stop/resume operations.

On the affected QEMU/KVM stack, repeatedly stopping a busy Windows guest via
the gdbstub can lose ``IA32_PL3_SSP`` while Windows still considers user shadow
stacks active. The next kernel ``WRUSSQ`` then bugchecks at ``-8``. This is a
hypervisor state-synchronisation bug, not a page-walker bug, so every live RSP
session must fail closed unless the Windows system mitigation is explicitly
OFF for the current boot.

Preparation is explicit because it weakens a security mitigation and needs a
reboot. The original raw mitigation registry values are saved on the host so
the change is reversible without guessing which unrelated mitigation bits the
user had configured.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from winbox.config import Config

if TYPE_CHECKING:
    from winbox.vm import GuestAgent


class CetSafetyError(RuntimeError):
    pass


@dataclass(frozen=True)
class CetStatus:
    user_shadow_stack: str
    strict_mode: str

    @property
    def safe_for_debug(self) -> bool:
        return self.user_shadow_stack.upper() == "OFF"


_STATUS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$m = (Get-ProcessMitigation -System).UserShadowStack
[pscustomobject]@{
    UserShadowStack = [string]$m.UserShadowStack
    StrictMode = [string]$m.UserShadowStackStrictMode
} | ConvertTo-Json -Compress
""".strip()

_BACKUP_AND_DISABLE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
$props = Get-ItemProperty -LiteralPath $key
$saved = [ordered]@{}
foreach ($name in @('MitigationOptions', 'MitigationAuditOptions')) {
    $value = $props.PSObject.Properties[$name]
    if ($null -eq $value -or $null -eq $value.Value) {
        $saved[$name] = $null
    } else {
        $saved[$name] = [Convert]::ToBase64String([byte[]]$value.Value)
    }
}
Set-ProcessMitigation -System -Disable UserShadowStack
[pscustomobject]@{saved=$saved; reboot_required=$true} | ConvertTo-Json -Compress -Depth 4
""".strip()


def backup_path(cfg: Config) -> Path:
    return Path(cfg.winbox_dir) / "kdbg-cet-backup.json"


def _powershell_json(ga: GuestAgent, script: str, *, timeout: int = 30) -> Any:
    try:
        result = ga.exec_powershell(script, timeout=timeout)
    except Exception as exc:
        raise CetSafetyError(f"CET query/update failed: {exc}") from exc
    if result.exitcode != 0:
        raise CetSafetyError(
            f"CET query/update failed: {result.stderr or result.stdout or result.exitcode}"
        )
    try:
        return json.loads(result.stdout.strip())
    except (TypeError, json.JSONDecodeError) as exc:
        raise CetSafetyError(
            f"CET query/update returned invalid JSON: {result.stdout!r}"
        ) from exc


def query_status(ga: GuestAgent) -> CetStatus:
    data = _powershell_json(ga, _STATUS_SCRIPT)
    if not isinstance(data, dict):
        raise CetSafetyError("CET status response was not an object")
    return CetStatus(
        user_shadow_stack=str(data.get("UserShadowStack") or "UNKNOWN"),
        strict_mode=str(data.get("StrictMode") or "UNKNOWN"),
    )


def require_safe(cfg: Config, ga: GuestAgent | None = None) -> CetStatus:
    if ga is None:
        from winbox.vm import GuestAgent
        ga = GuestAgent(cfg)
    status = query_status(ga)
    if not status.safe_for_debug:
        raise CetSafetyError(
            "unsafe QEMU/KVM debugger state: Windows UserShadowStack is "
            f"{status.user_shadow_stack}, not OFF. Repeated GDB stop/resume can "
            "bugcheck this VM. Run `winbox kdbg prepare --confirm`, reboot, "
            "then retry. Restore the original policy later with "
            "`winbox kdbg restore-cet --confirm`."
        )
    return status


def _write_backup(cfg: Config, saved: dict[str, str | None]) -> Path:
    path = backup_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "vm_name": cfg.vm_name,
        "values": saved,
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return path


def prepare(cfg: Config, ga: GuestAgent) -> Path | None:
    """Disable UserShadowStack system-wide and save the original policy.

    Returns the backup path when a change was staged, or ``None`` when the
    running boot is already safe. The caller must reboot after a staged change.
    """
    status = query_status(ga)
    if status.safe_for_debug:
        return None
    path = backup_path(cfg)
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CetSafetyError(
                f"refusing to overwrite unreadable CET backup {path}: {exc}"
            ) from exc
        if existing.get("vm_name") != cfg.vm_name:
            raise CetSafetyError(
                f"CET backup {path} belongs to VM {existing.get('vm_name')!r}"
            )
        # The original policy is already saved; reassert the desired setting
        # without replacing the recovery data.
        try:
            result = ga.exec_powershell(
                "Set-ProcessMitigation -System -Disable UserShadowStack",
                timeout=30,
            )
        except Exception as exc:
            raise CetSafetyError(f"CET update failed: {exc}") from exc
        if result.exitcode != 0:
            raise CetSafetyError(result.stderr or result.stdout or "CET update failed")
        return path

    data = _powershell_json(ga, _BACKUP_AND_DISABLE_SCRIPT)
    saved = data.get("saved") if isinstance(data, dict) else None
    if not isinstance(saved, dict):
        raise CetSafetyError("CET preparation did not return registry backup data")
    normalized: dict[str, str | None] = {}
    for name in ("MitigationOptions", "MitigationAuditOptions"):
        value = saved.get(name)
        if value is not None and not isinstance(value, str):
            raise CetSafetyError(f"invalid saved CET registry value for {name}")
        normalized[name] = value
    return _write_backup(cfg, normalized)


def _restore_script(values: dict[str, str | None]) -> str:
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel'",
    ]
    for name in ("MitigationOptions", "MitigationAuditOptions"):
        value = values.get(name)
        if value is None:
            lines.append(
                f"Remove-ItemProperty -LiteralPath $key -Name '{name}' "
                "-ErrorAction SilentlyContinue"
            )
        else:
            lines.extend([
                f"$bytes = [Convert]::FromBase64String('{value}')",
                f"New-ItemProperty -LiteralPath $key -Name '{name}' "
                "-PropertyType Binary -Value $bytes -Force | Out-Null",
            ])
    lines.append("'{\"restored\":true,\"reboot_required\":true}'")
    return "\n".join(lines)


def restore(cfg: Config, ga: GuestAgent) -> None:
    path = backup_path(cfg)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CetSafetyError(f"no CET backup exists at {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CetSafetyError(f"cannot read CET backup {path}: {exc}") from exc
    if data.get("vm_name") != cfg.vm_name or not isinstance(data.get("values"), dict):
        raise CetSafetyError(f"CET backup {path} is invalid or belongs to another VM")
    _powershell_json(ga, _restore_script(data["values"]))
    path.unlink()
