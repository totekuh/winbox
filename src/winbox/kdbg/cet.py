"""CET safety gate for QEMU/KVM debugger stop/resume operations.

On the affected QEMU/KVM stack, repeatedly stopping a busy Windows guest via
the gdbstub can lose ``IA32_PL3_SSP`` while Windows still considers user shadow
stacks active. The next kernel ``WRUSSQ`` then bugchecks at ``-8``. This is a
hypervisor state-synchronisation bug, not a page-walker bug, so every live RSP
session must fail closed unless both the Windows system default is OFF *and*
no running process has user shadow stacks active.  The system setting is only
a default: CET-compatible Windows binaries can opt in even while
``Get-ProcessMitigation -System`` reports ``UserShadowStack=OFF``.

Preparation is explicit because it weakens a security mitigation and needs a
reboot. The original raw mitigation registry values and exact libvirt CPU XML
are saved on the host, so both changes are reversible without guessing which
unrelated settings the user had configured.
"""

from __future__ import annotations

import json
import os
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from winbox.config import Config
from winbox.vm import virsh_run

if TYPE_CHECKING:
    from winbox.vm import GuestAgent


class CetSafetyError(RuntimeError):
    pass


@dataclass(frozen=True)
class CetStatus:
    user_shadow_stack: str
    strict_mode: str
    enabled_processes: tuple[str, ...] = ()
    unqueryable_processes: tuple[str, ...] = ()

    @property
    def system_policy_off(self) -> bool:
        return self.user_shadow_stack.upper() == "OFF"

    @property
    def safe_for_debug(self) -> bool:
        return (
            self.system_policy_off
            and not self.enabled_processes
            and not self.unqueryable_processes
        )


def format_status(status: CetStatus) -> str:
    """Render the safety-relevant status without dumping a process table."""
    state = "SAFE" if status.safe_for_debug else "UNSAFE"
    parts = [
        f"{state}: UserShadowStack={status.user_shadow_stack}",
        f"StrictMode={status.strict_mode}",
        f"active_processes={len(status.enabled_processes)}",
        f"unqueryable_processes={len(status.unqueryable_processes)}",
    ]
    if status.enabled_processes:
        parts.append("active_sample=" + ",".join(status.enabled_processes[:5]))
    if status.unqueryable_processes:
        parts.append(
            "unqueryable_sample=" + ",".join(status.unqueryable_processes[:5])
        )
    return ", ".join(parts)


_STATUS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace WinboxCet {
    public static class Native {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(UInt32 access, bool inherit, UInt32 pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessMitigationPolicy(
            IntPtr process, int policy, out UInt32 flags, UIntPtr length);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);
        public static bool Query(UInt32 pid, out UInt32 flags, out int error) {
            const UInt32 PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            const int ProcessUserShadowStackPolicy = 15;
            flags = 0; error = 0;
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero) {
                error = Marshal.GetLastWin32Error();
                return false;
            }
            try {
                if (!GetProcessMitigationPolicy(
                        process, ProcessUserShadowStackPolicy, out flags,
                        (UIntPtr)4)) {
                    error = Marshal.GetLastWin32Error();
                    return false;
                }
                return true;
            } finally {
                CloseHandle(process);
            }
        }
    }
}
'@

$m = (Get-ProcessMitigation -System).UserShadowStack
$enabled = @()
$unqueryable = @()
foreach ($process in @(Get-Process | Sort-Object Id)) {
    if ($process.Id -eq 0) { continue }
    [uint32]$flags = 0
    [int]$win32Error = 0
    if ([WinboxCet.Native]::Query(
            [uint32]$process.Id, [ref]$flags, [ref]$win32Error)) {
        if (($flags -band 1) -ne 0) {
            $enabled += ('{0}[{1}]' -f $process.ProcessName, $process.Id)
        }
    } else {
        if ($null -ne (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) {
            $unqueryable += ('{0}[{1}]:win32={2}' -f
                $process.ProcessName, $process.Id, $win32Error)
        }
    }
}
[pscustomobject]@{
    UserShadowStack = [string]$m.UserShadowStack
    StrictMode = [string]$m.UserShadowStackStrictMode
    EnabledProcesses = @($enabled)
    UnqueryableProcesses = @($unqueryable)
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
    enabled = data.get("EnabledProcesses", [])
    unqueryable = data.get("UnqueryableProcesses", [])
    if not isinstance(enabled, list) or not all(
        isinstance(item, str) for item in enabled
    ):
        raise CetSafetyError("CET status EnabledProcesses was not a string list")
    if not isinstance(unqueryable, list) or not all(
        isinstance(item, str) for item in unqueryable
    ):
        raise CetSafetyError("CET status UnqueryableProcesses was not a string list")
    return CetStatus(
        user_shadow_stack=str(data.get("UserShadowStack") or "UNKNOWN"),
        strict_mode=str(data.get("StrictMode") or "UNKNOWN"),
        enabled_processes=tuple(enabled),
        unqueryable_processes=tuple(unqueryable),
    )


def require_safe(cfg: Config, ga: GuestAgent | None = None) -> CetStatus:
    if ga is None:
        from winbox.vm import GuestAgent
        ga = GuestAgent(cfg)
    status = query_status(ga)
    if not status.safe_for_debug:
        details = []
        if not status.system_policy_off:
            details.append(
                f"the system default is {status.user_shadow_stack}, not OFF"
            )
        if status.enabled_processes:
            details.append(
                f"{len(status.enabled_processes)} running process(es) have "
                "user shadow stacks active: "
                + ", ".join(status.enabled_processes[:5])
            )
        if status.unqueryable_processes:
            details.append(
                f"{len(status.unqueryable_processes)} running process(es) "
                "could not be queried: "
                + ", ".join(status.unqueryable_processes[:5])
            )
        raise CetSafetyError(
            "unsafe QEMU/KVM debugger state: " + "; ".join(details) + ". "
            "Repeated GDB stop/resume can bugcheck this VM. The Windows "
            "system OFF setting is only a default; hide the VM's cet-ss CPU "
            "feature and reboot before retrying."
        )
    return status


def _write_backup(
    cfg: Config,
    saved: dict[str, str | None],
    *,
    domain_cpu_xml: str | None,
    restore_domain_cpu: bool,
) -> Path:
    path = backup_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "vm_name": cfg.vm_name,
        "values": saved,
        "domain_cpu_xml": domain_cpu_xml,
        "restore_domain_cpu": restore_domain_cpu,
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return path


def _inactive_domain(cfg: Config) -> ET.Element:
    result = virsh_run("dumpxml", cfg.vm_name, "--inactive", check=False)
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip() or result.returncode
        raise CetSafetyError(f"cannot read inactive domain XML: {msg}")
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise CetSafetyError(f"inactive domain XML is invalid: {exc}") from exc


def _insert_cpu(domain: ET.Element, cpu: ET.Element) -> None:
    """Insert a CPU node before clock/devices to satisfy libvirt ordering."""
    children = list(domain)
    for index, child in enumerate(children):
        if child.tag in {"clock", "on_poweroff", "devices"}:
            domain.insert(index, cpu)
            return
    domain.append(cpu)


def _stage_cet_ss_disable(cfg: Config) -> tuple[str | None, str | None]:
    """Return original CPU XML and updated domain XML, without mutating it."""
    domain = _inactive_domain(cfg)
    cpu = domain.find("cpu")
    original = ET.tostring(cpu, encoding="unicode") if cpu is not None else None
    if cpu is None:
        cpu = ET.Element("cpu", {"mode": "host-passthrough", "check": "none"})
        _insert_cpu(domain, cpu)
    feature = cpu.find("feature[@name='cet-ss']")
    if feature is not None and feature.get("policy") == "disable":
        return original, None
    if feature is None:
        feature = ET.SubElement(cpu, "feature", {"name": "cet-ss"})
    feature.set("policy", "disable")
    return original, ET.tostring(domain, encoding="unicode")


def _define_domain(cfg: Config, domain_xml: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8",
        ) as handle:
            handle.write(domain_xml)
            temporary = handle.name
        result = virsh_run("define", temporary, check=False)
        if result.returncode != 0:
            msg = result.stderr.strip() or result.stdout.strip() or result.returncode
            raise CetSafetyError(f"cannot persist cet-ss CPU override: {msg}")
    finally:
        if temporary is not None:
            try:
                Path(temporary).unlink()
            except OSError:
                pass


def _restore_domain_cpu(cfg: Config, original_xml: str | None) -> None:
    domain = _inactive_domain(cfg)
    current = domain.find("cpu")
    if current is not None:
        index = list(domain).index(current)
        domain.remove(current)
    else:
        index = -1
    if original_xml is not None:
        try:
            original = ET.fromstring(original_xml)
        except ET.ParseError as exc:
            raise CetSafetyError(f"saved domain CPU XML is invalid: {exc}") from exc
        if original.tag != "cpu":
            raise CetSafetyError("saved domain CPU XML is not a <cpu> element")
        if index >= 0:
            domain.insert(index, original)
        else:
            _insert_cpu(domain, original)
    _define_domain(cfg, ET.tostring(domain, encoding="unicode"))


def prepare(cfg: Config, ga: GuestAgent) -> Path | None:
    """Disable CET-SS in Windows and at the VM CPU boundary.

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
        values = existing.get("values")
        if not isinstance(values, dict):
            raise CetSafetyError(f"CET backup {path} has invalid policy values")
        original_cpu, updated_domain = _stage_cet_ss_disable(cfg)
        if "restore_domain_cpu" not in existing:
            # Upgrade a backup created by older winbox before changing the
            # domain.  Its current CPU XML is still the original at this point.
            _write_backup(
                cfg,
                values,
                domain_cpu_xml=original_cpu,
                restore_domain_cpu=updated_domain is not None,
            )
        try:
            result = ga.exec_powershell(
                "Set-ProcessMitigation -System -Disable UserShadowStack",
                timeout=30,
            )
        except Exception as exc:
            raise CetSafetyError(f"CET update failed: {exc}") from exc
        if result.exitcode != 0:
            raise CetSafetyError(result.stderr or result.stdout or "CET update failed")
        if updated_domain is not None:
            _define_domain(cfg, updated_domain)
        return path

    original_cpu, updated_domain = _stage_cet_ss_disable(cfg)
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
    path = _write_backup(
        cfg,
        normalized,
        domain_cpu_xml=original_cpu,
        restore_domain_cpu=updated_domain is not None,
    )
    if updated_domain is not None:
        _define_domain(cfg, updated_domain)
    return path


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
    if data.get("restore_domain_cpu"):
        original_cpu = data.get("domain_cpu_xml")
        if original_cpu is not None and not isinstance(original_cpu, str):
            raise CetSafetyError(f"CET backup {path} has invalid domain CPU XML")
        _restore_domain_cpu(cfg, original_cpu)
    _powershell_json(ga, _restore_script(data["values"]))
    path.unlink()
