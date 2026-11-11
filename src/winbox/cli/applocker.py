"""AppLocker commands — enable/disable/status with default rules."""

from __future__ import annotations

import click

from winbox import applocker
from winbox.applocker import AppLockerError
from winbox.cli import console, needs_vm, reboot_and_wait
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM


@click.group()
def applocker_group() -> None:
    """Toggle AppLocker on the VM (default rules, no DLLs)."""
    pass


@applocker_group.command("enable")
@needs_vm()
def applocker_enable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Enable AppLocker with default rules (Exe, Script, MSI, Appx).

    Standard corporate/exam config: allow C:\\Windows\\* and C:\\Program Files\\*
    for Everyone, Administrators can run anything. No DLL rules.
    Undo with: winbox applocker disable
    """
    console.print("[blue][*][/] Applying default AppLocker policy...")
    try:
        applocker.enable(ga, cfg.shared_dir)
    except AppLockerError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)

    console.print("[green][+][/] AppLocker enforced (Exe, Script, MSI, Appx)")
    console.print("    Allowed: %WINDIR%\\*, %PROGRAMFILES%\\*, Admins everywhere")
    console.print("    Blocked: everything else (e.g. Z:\\tools for non-admin)")
    console.print("    Undo with: [bold]winbox applocker disable[/]")


@applocker_group.command("disable")
@needs_vm()
def applocker_disable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Disable AppLocker — clear policy, stop stack, reboot.

    Reboot is required because appid.sys caches rules in kernel memory
    and continues enforcing even after AppIDSvc is stopped.
    """
    console.print("[blue][*][/] Clearing AppLocker policies...")
    try:
        applocker.disable_apply(ga, cfg.shared_dir)
    except AppLockerError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)

    reboot_and_wait(
        cfg, ga,
        msg="Rebooting VM (kernel caches enforcement)...",
    )

    try:
        result = applocker.status(ga)
    except AppLockerError as exc:
        console.print(f"[yellow][!][/] Policy cleared, but could not verify state:")
        console.print(f"    {exc}", markup=False, highlight=False)
        return

    if not result.active:
        console.print("[green][+][/] AppLocker disabled")
        return

    console.print("[red][-][/] AppLocker still active after disable:")
    console.print(result.raw_stdout, markup=False, highlight=False)
    raise SystemExit(1)


@applocker_group.command("status")
@needs_vm()
def applocker_status(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Show current AppLocker enforcement status."""
    try:
        result = applocker.status(ga)
    except AppLockerError as exc:
        console.print("[red][-][/] Failed to query status:")
        console.print(f"    {exc}", markup=False, highlight=False)
        raise SystemExit(1)

    console.print(result.raw_stdout, markup=False, highlight=False)


REGISTER = ("Target", [applocker_group])
