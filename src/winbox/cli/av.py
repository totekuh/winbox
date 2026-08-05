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

    console.print("[green][+][/] Defender enabled (real-time, AMSI, behavior monitoring)")
    console.print("    QEMU GA and Z:\\ excluded — winbox commands still work")
    console.print("    Undo with: [bold]winbox av disable[/]")


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
    # Step 0: On Win11, Tamper Protection makes the whole disable a no-op.
    # Detect and refuse rather than reboot into a still-protected VM.
    if defender.tamper_protection_on(ga):
        console.print(
            "[red][-][/] Tamper Protection is ON — Defender cannot be disabled "
            "from the running OS."
        )
        console.print(
            "    It should have been cleared offline by `winbox setup --os win11`.\n"
            "    Turn it off in Windows Security ▸ Virus & threat protection ▸\n"
            "    Manage settings ▸ Tamper Protection, then re-run `winbox av disable`."
        )
        raise SystemExit(1)

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
