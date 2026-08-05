"""AV commands — enable/disable/status for Windows Defender and AMSI."""

from __future__ import annotations

import click

from winbox import defender
from winbox.cli import console, needs_vm, reboot_and_wait
from winbox.config import Config
from winbox.defender import DefenderError
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM


def _step(msg: str) -> None:
    """Progress callback handed to the shared defender operations."""
    console.print(f"[blue][*][/] {msg}")


@click.group()
def av() -> None:
    """Toggle Windows Defender and AMSI on the VM."""
    pass


@av.command("enable")
@needs_vm()
def av_enable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Re-enable Defender real-time protection and AMSI.

    Persists across reboots. Adds exclusions for the QEMU guest agent
    and VirtIO-FS share so winbox commands keep working.
    Undo with: winbox av disable
    """
    def _enable() -> bool:
        try:
            return defender.enable(ga, progress=_step)
        except DefenderError as e:
            console.print(f"[red][-][/] {e}:")
            if e.result is not None:
                console.print(
                    f"    {e.result.stdout.strip()}", markup=False, highlight=False
                )
            raise SystemExit(1)

    if _enable():
        # A Win11 image built with the offline Defender disable has WinDefend
        # marked disabled in the SCM for the life of this boot, so the start
        # types we just corrected only take effect after a restart.
        #
        # That restart is also the one chance to clear Tamper Protection while
        # Defender still isn't running to defend it. Without this, enabling
        # Defender on a client SKU is one-way: TP arms as soon as WinDefend
        # starts and every later `av disable` needs its own power cycle. So on
        # client SKUs the warm reboot becomes a power cycle that clears TP on
        # the way through — same number of restarts, one less trap.
        if cfg.profile.client_sku:
            _restart_clearing_tamper_protection(cfg, vm, ga)
        else:
            reboot_and_wait(
                cfg, ga,
                msg="Rebooting so the SCM picks up the restored service start types...",
            )
        if _enable():
            console.print(
                "[red][-][/] WinDefend is still disabled after a reboot.\n"
                "    Check [bold]HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\Start[/] "
                "(2 = automatic); Tamper Protection may be reverting it."
            )
            raise SystemExit(1)

    # WdFilter is a boot-start driver. If it was disabled when this boot
    # began, real-time protection cannot come up until the next one — so
    # "enabled" was being claimed while RealTimeProtection was still False.
    # Reboot once to make the claim true rather than merely optimistic.
    if not _defender_fully_on(ga):
        reboot_and_wait(
            cfg, ga,
            msg="Rebooting so the boot-start filter driver loads...",
        )

    status = _status_text(ga)
    if "Defender: ON" in status:
        console.print("[green][+][/] Defender enabled (real-time, AMSI, behavior monitoring)")
    else:
        console.print(
            "[yellow][!][/] Defender enabled, but not every protection is active:"
        )
        if status:
            console.print(status, markup=False, highlight=False)
    console.print("    QEMU GA and Z:\\ excluded — winbox commands still work")
    console.print("    Undo with: [bold]winbox av disable[/]")


def _status_text(ga: GuestAgent) -> str:
    """Defender's own status summary, or "" if the guest won't answer."""
    try:
        return (defender.status(ga, timeout=60).stdout or "").strip()
    except GuestAgentError:
        return ""


def _defender_fully_on(ga: GuestAgent) -> bool:
    return "Defender: ON" in _status_text(ga)


def _power_off_or_refuse(vm: VM, ga: GuestAgent) -> None:
    """Shut the VM down for an offline hive edit, or exit rather than risk it.

    Both offline paths (`av disable` and the enable-side power cycle) hand the
    disk to guestfish --rw. Editing a disk a live QEMU still has open scrambles
    the SYSTEM hive — an unbootable VM with no in-guest recovery — so a VM that
    will not power off is a hard stop, never a "probably fine". This lives in
    one place because the enable path once checked and the disable path didn't;
    the two must not be able to drift again.
    """
    try:
        ga.shutdown()
    except GuestAgentError:
        pass
    if vm.wait_shutdown(timeout=300):
        return
    vm.force_stop()
    if vm.wait_shutdown(timeout=60):
        return
    console.print(
        "[red][-][/] VM would not shut down; refusing to edit a disk "
        "that may still be in use."
    )
    raise SystemExit(1)


def _disable_via_offline_hive(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Shut the VM down, disable Defender in its SYSTEM hive, boot it back.

    Tamper Protection is enforced by Defender's own kernel components, so the
    guest has to be off for this to land. Costs a power cycle — `av disable`
    already reboots, so the extra is the shutdown, not the boot.
    """
    from winbox import offlinereg

    missing = offlinereg.tools_available()
    if missing is not None:
        console.print(
            f"[red][-][/] {missing} not found — install libguestfs-tools.\n"
            "    An offline hive edit is the only way to disable Defender on "
            "this guest once Tamper Protection has armed."
        )
        raise SystemExit(1)

    console.print("[blue][*][/] Shutting VM down for the offline edit...")
    _power_off_or_refuse(vm, ga)

    try:
        defender.disable_offline(cfg, progress=_step)
    except offlinereg.OfflineRegistryError as e:
        console.print(f"[red][-][/] Offline disable failed: {e}")
        console.print("    The VM is shut down; bring it back with [bold]winbox up[/].")
        raise SystemExit(1)

    console.print("[blue][*][/] Booting VM...")
    vm.start()
    try:
        ga.wait(timeout=420)
    except GuestAgentError as e:
        console.print(f"[yellow][!][/] VM booted but the guest agent is quiet: {e}")
        raise SystemExit(1)

    # Say what actually happened rather than assuming it worked.
    try:
        out = (defender.status(ga, timeout=30).stdout or "").strip()
    except GuestAgentError:
        out = ""
    if "Defender: off" in out or "Defender: OFF" in out:
        console.print("[green][+][/] Defender disabled (services off at boot)")
    else:
        console.print(
            "[yellow][!][/] Offline edit applied, but Defender still reports active:"
        )
        if out:
            console.print(out, markup=False, highlight=False)


def _restart_clearing_tamper_protection(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Power-cycle the VM, fixing up Defender state in the offline hives.

    Two edits, with different stakes. Restoring the service start types is
    required — they are ACL-protected against in-guest writes, so this is the
    only way back from an offline disable. Clearing Tamper Protection is
    best-effort: if it doesn't take, Defender still comes up and `av disable`
    just falls back to its own power cycle.
    """
    from winbox import offlinereg

    console.print("[blue][*][/] Shutting VM down (restart also clears Tamper Protection)...")
    _power_off_or_refuse(vm, ga)

    # Restoring the service start types is not optional: Defender's
    # Services\*\Start values are ACL-protected, so reg.exe cannot undo an
    # offline disable from inside the guest. Without this the offline disable
    # would be one-way.
    try:
        defender.enable_offline(cfg, progress=_step)
    except offlinereg.OfflineRegistryError as e:
        console.print(f"[red][-][/] Could not restore Defender services offline: {e}")
        console.print("    The VM is shut down; bring it back with [bold]winbox up[/].")
        raise SystemExit(1)

    # Clearing Tamper Protection is best-effort by comparison — if it doesn't
    # take, Defender still comes up and `av disable` falls back to its own
    # power cycle.
    try:
        defender.clear_tamper_protection_offline(cfg, progress=_step)
        console.print("[green][+][/] Tamper Protection cleared offline")
    except offlinereg.OfflineRegistryError as e:
        console.print(
            f"[yellow][!][/] Could not clear Tamper Protection offline: {e}\n"
            "    Continuing — Defender will still come up, but a later "
            "`winbox av disable` will need its own power cycle."
        )

    console.print("[blue][*][/] Booting VM...")
    vm.start()
    ga.wait(timeout=420)


@av.command("disable")
@needs_vm()
def av_disable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Disable Defender completely — service stopped, all protections off.

    Sets GP registry keys then reboots the VM. WinDefend is a protected process
    (PPL) that cannot be stopped by any user-mode process including SYSTEM —
    only a reboot with the right registry keys will actually kill it.

    On Win11 client, Tamper Protection gates this: while TP is on, the GP keys
    are silently ignored. We check TP first and refuse rather than falsely
    report success. `winbox setup --os win11` clears TP offline during
    provisioning; if it's back on, disable it in the Windows Security UI.
    """
    # Step 0: On a client SKU, Tamper Protection makes every in-guest disable
    # a no-op. Rather than refuse — which left the VM in a state only a
    # rebuild escaped — power the VM down and edit the hive offline, where
    # nothing is enforcing TP. This is the same operation `winbox setup`
    # applies before the guest's first boot.
    if cfg.profile.client_sku and defender.tamper_protection_on(ga):
        console.print(
            "[blue][*][/] Tamper Protection is ON — disabling offline instead "
            "(the VM will be shut down and restarted)."
        )
        _disable_via_offline_hive(cfg, vm, ga)
        return

    # Step 1: Set GP registry keys (only way to kill WinDefend — it's PPL)
    try:
        defender.set_disable_regkeys(ga, progress=_step)
    except DefenderError as e:
        console.print(f"[red][-][/] Failed: {e}")
        if e.result is not None:
            console.print(f"    {e.result.stderr.strip()}", markup=False)
        raise SystemExit(1)

    # Step 2: Reboot — the only way to actually stop the WinDefend service
    reboot_and_wait(cfg, ga, msg="Rebooting VM...")

    # Step 3: Verify the disable actually took (Win11 can ignore keys even
    # with TP off; don't claim success we didn't achieve).
    try:
        result = defender.status(ga, timeout=20)
        out = (result.stdout or "").strip()
    except GuestAgentError:
        out = ""
    if "Defender: OFF" in out or "Defender: off" in out:
        console.print("[green][+][/] Defender disabled")
    else:
        console.print(
            "[yellow][!][/] Registry keys set and VM rebooted, but Defender still "
            "reports active:"
        )
        if out:
            console.print(out, markup=False, highlight=False)
        console.print(
            "    On Win11 the GP `DisableAntiSpyware` key is ignored on client SKUs; "
            "real-time may still be off — check `winbox av status`."
        )


@av.command("status")
@needs_vm()
def av_status(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Show current Defender and AMSI status."""
    result = defender.status(ga)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to query status: {result.stderr.strip()}")
        raise SystemExit(1)

    console.print(result.stdout.strip(), markup=False, highlight=False)


# Auto-discovery hook for cli/__init__.py.
REGISTER = ("Target", [av])
