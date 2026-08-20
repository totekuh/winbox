"""HVCI commands — enable/disable/status for HVCI and VBS."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm, reboot_and_wait
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM


@click.group()
def hvci() -> None:
    """Toggle HVCI / Virtualization Based Security on the VM."""
    pass


@hvci.command("status")
@needs_vm()
def hvci_status(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Show HVCI and VBS state."""
    from winbox import hvci as _hvci

    s = _hvci.status(ga)
    console.print(f"  VBS:  {'[green]on[/]' if s.vbs_enabled else '[red]off[/]'}")
    console.print(f"  HVCI: {'[green]on[/]' if s.hvci_enabled else '[red]off[/]'}")
    if s.hypervisor_off:
        console.print("  [dim]hypervisorlaunchtype: off[/]")
    if s.hvci_enabled:
        console.print(
            "[yellow][!][/] Kernel breakpoints (kdbg) will not work while HVCI is on"
        )


@hvci.command("disable")
@needs_vm()
def hvci_disable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Disable HVCI and VBS. Reboots the VM."""
    from winbox import hvci as _hvci

    s = _hvci.status(ga)
    if not s.hvci_enabled and not s.vbs_enabled:
        console.print("[green][+][/] HVCI/VBS already disabled")
        return

    _hvci.disable(ga)
    console.print("[blue][*][/] HVCI/VBS disabled in registry + bcdedit. Rebooting...")
    reboot_and_wait(cfg, ga)

    s = _hvci.status(ga)
    if not s.hvci_enabled:
        console.print("[green][+][/] HVCI disabled")
    else:
        console.print(
            "[red][-][/] HVCI still on after reboot — may need a second reboot "
            "or Secure Boot change"
        )


@hvci.command("enable")
@needs_vm()
def hvci_enable(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Enable HVCI and VBS. Reboots the VM."""
    from winbox import hvci as _hvci

    s = _hvci.status(ga)
    if s.hvci_enabled and s.vbs_enabled:
        console.print("[green][+][/] HVCI/VBS already enabled")
        return

    _hvci.enable(ga)
    console.print("[blue][*][/] HVCI/VBS enabled in registry + bcdedit. Rebooting...")
    reboot_and_wait(cfg, ga)

    s = _hvci.status(ga)
    if s.hvci_enabled:
        console.print("[green][+][/] HVCI enabled")
    else:
        console.print(
            "[yellow][!][/] HVCI not active yet — may need Secure Boot enabled "
            "in UEFI"
        )


# Auto-discovery hook for cli/__init__.py.
REGISTER = ("Target", [hvci])
