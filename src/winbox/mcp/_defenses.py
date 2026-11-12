"""Defender, HVCI, and AppLocker defense toggle MCP tools."""

from __future__ import annotations

import json as _json

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (

    _format_exec_result,
    _guest_errors,
    GuestAgentError,
)


@mcp.tool()
def av_status(timeout: int = 15) -> str:
    """Report Windows Defender / AMSI protection state in the VM.

    Runs Get-MpComputerStatus + Get-MpPreference and summarises as
    ON / OFF / partial plus the individual RealTimeProtection, AMSI
    (ScriptScanning), BehaviorMonitoring, and IOAVProtection flags.
    Read-only — safe to call any time.

    Args:
        timeout: Execution timeout in seconds (default 15).
    """
    from winbox import defender

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        status = defender.status(ga, timeout=timeout)
    return _format_exec_result(status)


@mcp.tool()
def av_enable() -> str:
    """Re-enable Windows Defender real-time protection, AMSI, and behavior monitoring.

    Removes the GP / non-policy registry overrides, starts the WinDefend
    service via sc.exe (PowerShell Start-Service is ACL-blocked), adds
    exclusions for the QEMU guest agent and the Z:\\ VirtIO-FS share so
    winbox tooling keeps working, then re-asserts the Set-MpPreference
    flags, and finally reports Defender's own status. May require a reboot
    to finish (WdFilter is a boot-start driver) — the return value says so
    when it does. Undo with av_disable.
    """
    from winbox import defender

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    steps: list[str] = []
    try:
        with _guest_errors(vm):
            outcome = defender.enable(ga, progress=steps.append)
    except defender.DefenderError as e:
        detail = _format_exec_result(e.result) if e.result is not None else ""
        return f"error: {e}\n{detail}".rstrip()

    if outcome.reboot_required:
        unwritten = outcome.start_types_unwritten
        if unwritten:
            return (
                "error: WinDefend is disabled in this boot's SCM and the service "
                f"start types could NOT be restored from inside the guest "
                f"({', '.join(unwritten)} still wrong). Defender's "
                "Services\\*\\Start values are ACL-protected, so reg.exe cannot "
                "undo an offline disable from within Windows — rebooting and "
                "calling av_enable again will produce this same result. Run the "
                "host CLI `winbox av enable`, which powers the VM down and edits "
                "the SYSTEM hive offline."
            )
        return (
            "Defender service start types restored, but WinDefend is still "
            "disabled in this boot's SCM. Reboot the VM and call av_enable "
            "again to finish (the CLI `winbox av enable` does this for you)."
        )

    try:
        status_text = (defender.status(ga, timeout=60).stdout or "").strip()
    except GuestAgentError:
        status_text = ""
    if "Defender: ON" in status_text:
        return "Defender enabled (real-time, AMSI, behavior monitoring). Undo with av_disable."
    return (
        "Defender services started, but not every protection is active. "
        "WdFilter is a boot-start driver, so real-time protection cannot arm "
        "until the VM is rebooted. Reboot and call av_enable again (or run the "
        "host CLI `winbox av enable`, which reboots for you), then confirm with "
        "av_status.\n" + status_text
    ).rstrip()


@mcp.tool()
def av_disable(confirm: bool = False) -> str:
    """Disable Windows Defender completely — sets GP registry keys then REBOOTS the VM.

    WinDefend is a protected process (PPL) that no user-mode caller,
    including SYSTEM, can stop while running — only a reboot with the
    GP keys set (DisableAntiSpyware + Real-Time Protection overrides)
    actually kills it. This tool therefore reboots the VM, which DROPS
    any live kdbg session and open named-pipe handles.

    Because of the reboot, ``confirm`` must be True or the call is a
    no-op. Undo with av_enable.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import defender

    if not confirm:
        return (
            "error: av_disable reboots the VM (kills live kdbg / pipe sessions). "
            "Pass confirm=True to proceed."
        )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()

    try:
        with _guest_errors(vm):
            if defender.tamper_protection_on(ga):
                return (
                    "error: Tamper Protection is ON — Defender cannot be disabled from the "
                    "running OS. It should have been cleared offline by `winbox setup --os "
                    "win11`; otherwise turn it off in Windows Security (Virus & threat "
                    "protection > Manage settings > Tamper Protection) and retry."
                )

            defender.set_disable_regkeys(ga)
    except defender.DefenderError as e:
        detail = _format_exec_result(e.result) if e.result is not None else ""
        return f"error: {e}\n{detail}".rstrip()

    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "Registry keys set and reboot issued, but the guest agent did not "
            "come back within 120s. Check with: virsh console " + cfg.vm_name
        )

    try:
        out = (defender.status(ga, timeout=20).stdout or "").strip()
    except GuestAgentError:
        out = ""
    if "Defender: OFF" in out or "Defender: off" in out:
        return "Defender disabled — GP keys set and VM rebooted; protections off."
    return (
        "Registry keys set and VM rebooted, but Defender still reports active "
        "(on Win11 the DisableAntiSpyware key is ignored on client SKUs). "
        "Current status:\n" + (out or "(status unavailable)")
    )


@mcp.tool()
def hvci_status(timeout: int = 15) -> str:
    """Report HVCI / Virtualization Based Security state in the VM.

    Queries the DeviceGuard registry keys and bcdedit hypervisorlaunchtype
    to determine whether VBS and HVCI are enabled. Read-only — safe to call
    any time.

    Args:
        timeout: Execution timeout in seconds (default 15).
    """
    from winbox import hvci

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    s = hvci.status(ga)
    return _json.dumps({
        "vbs": "on" if s.vbs_enabled else "off",
        "hvci": "on" if s.hvci_enabled else "off",
        "hypervisor_off": s.hypervisor_off,
        "note": ("kernel breakpoints will not work while HVCI is on"
                 if s.hvci_enabled else None),
    }, indent=2)


@mcp.tool()
def hvci_disable(confirm: bool = False) -> str:
    """Disable HVCI and VBS — sets registry keys + bcdedit then REBOOTS the VM.

    HVCI (Hypervisor-enforced Code Integrity) blocks unsigned kernel code and
    prevents hardware breakpoints from working. This tool disables both VBS
    and HVCI, then reboots the VM for the changes to take effect.

    Because of the reboot, ``confirm`` must be True or the call is a no-op.
    Undo with hvci_enable.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import hvci

    if not confirm:
        return (
            "pass confirm=true to disable HVCI/VBS (will reboot the VM)"
        )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    s = hvci.status(ga)
    if not s.hvci_enabled and not s.vbs_enabled:
        return "HVCI/VBS already disabled"

    hvci.disable(ga)

    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "HVCI registry keys set and reboot issued, but the guest agent "
            "did not come back within 120s. Check with: virsh console "
            + cfg.vm_name
        )

    s = hvci.status(ga)
    if not s.hvci_enabled:
        return "HVCI disabled successfully"
    return (
        "HVCI registry set but still reporting enabled — may need a "
        "second reboot or Secure Boot change"
    )


@mcp.tool()
def hvci_enable(confirm: bool = False) -> str:
    """Re-enable HVCI and VBS. Reboots the VM.

    Sets the DeviceGuard registry keys and bcdedit hypervisorlaunchtype
    to re-enable VBS and HVCI. Note that HVCI requires Secure Boot in
    the VM's UEFI firmware to actually activate.

    Because of the reboot, ``confirm`` must be True or the call is a no-op.
    Undo with hvci_disable.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import hvci

    if not confirm:
        return (
            "pass confirm=true to enable HVCI/VBS (will reboot the VM)"
        )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    s = hvci.status(ga)
    if s.hvci_enabled and s.vbs_enabled:
        return "HVCI/VBS already enabled"

    hvci.enable(ga)

    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "HVCI registry keys set and reboot issued, but the guest agent "
            "did not come back within 120s. Check with: virsh console "
            + cfg.vm_name
        )

    s = hvci.status(ga)
    if s.hvci_enabled:
        return "HVCI enabled successfully"
    return (
        "HVCI registry set but not active — may need Secure Boot "
        "enabled in UEFI"
    )


@mcp.tool()
def applocker_status(timeout: int = 90) -> str:
    """Report current AppLocker enforcement state.

    Returns the enforcement mode for each rule collection (Exe, Script,
    MSI, Appx) or reports that AppLocker is off / not available.

    Args:
        timeout: Guest agent timeout in seconds.
    """
    from winbox import applocker

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    try:
        result = applocker.status(ga, timeout=timeout)
    except applocker.AppLockerError as exc:
        return f"error: {exc}"
    return result.raw_stdout


@mcp.tool()
def applocker_enable() -> str:
    """Enable AppLocker with default rules (Exe, Script, MSI, Appx).

    Standard corporate config: allow C:\\Windows\\* and C:\\Program Files\\*
    for Everyone, Administrators can run anything.  No DLL rules.
    Undo with applocker_disable.
    """
    from winbox import applocker

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    try:
        applocker.enable(ga, cfg.shared_dir)
    except applocker.AppLockerError as exc:
        return f"error: {exc}"
    return "AppLocker enforced (Exe, Script, MSI, Appx). Undo with applocker_disable."


@mcp.tool()
def applocker_disable(confirm: bool = False) -> str:
    """Disable AppLocker — clear policy, reboot (kernel caches rules).

    The reboot is required because appid.sys caches enforcement rules
    in kernel memory.  Pass ``confirm=True`` to proceed.

    Args:
        confirm: Must be True to actually run (guards the reboot).
    """
    from winbox import applocker

    if not confirm:
        return "pass confirm=true to disable AppLocker (will reboot the VM)"

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    try:
        applocker.disable_apply(ga, cfg.shared_dir)
    except applocker.AppLockerError as exc:
        return f"error: {exc}"

    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except GuestAgentError:
        pass

    import time as _time
    _time.sleep(10)
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "AppLocker policy cleared and reboot issued, but the guest agent "
            "did not come back within 120s. Check with: virsh console "
            + cfg.vm_name
        )

    try:
        result = applocker.status(ga)
    except applocker.AppLockerError:
        return "AppLocker policy cleared, but post-reboot status check failed"

    if not result.active:
        return "AppLocker disabled"
    return f"AppLocker still active after disable:\n{result.raw_stdout}"
