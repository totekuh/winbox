"""Network connectivity commands — isolate, unplug, connect, status."""

from __future__ import annotations

import time

import click

from winbox import nwfilter
from winbox.cli import console, _ensure_z_drive
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM, VMState


@click.group()
def net() -> None:
    """Control VM network connectivity."""
    pass


@net.command("isolate")
@click.pass_context
def net_isolate(ctx: click.Context) -> None:
    """Block internet via libvirt nwfilter (guest-proof).

    Attaches a host-side bridge filter that only permits intra-subnet
    (192.168.122.0/24) IPv4 plus ARP and DHCPv4. Enforcement happens
    below the VM, so DHCP renewals, route changes, or anything else
    the guest does cannot defeat it. Kali <-> VM traffic (guest agent,
    VirtIO-FS, SSH, 192.168.122.x targets) stays up.
    For a full air-gap use `winbox net unplug` instead.
    Undo with: winbox net connect
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    try:
        nwfilter.ensure_filter_defined(cfg)
        changed = nwfilter.attach_filter(vm.name)
    except RuntimeError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    live = vm.net_link_state()
    boot = vm.net_link_state(config=True)
    if "down" in (live, boot):
        try:
            vm.net_set_link("up")
        except RuntimeError as e:
            console.print(
                "[red][-][/] nwfilter attached, but the NIC link could not be "
                "brought up:"
            )
            console.print(f"    {e}", markup=False, highlight=False)
            console.print(
                "    Isolation is not active yet, and the VM may boot with no NIC."
            )
            raise SystemExit(1)
        if live == "down":
            console.print(
                "[yellow][!][/] NIC was air-gapped — link brought up "
                "(live + next boot) for filtered access"
            )

    if changed:
        console.print("[green][+][/] Internet isolated — nwfilter enforced at host bridge")
    else:
        console.print("[green][+][/] Already isolated — nwfilter already attached")
    console.print("    Guest-proof: DHCP renewals and route changes cannot defeat it.")
    console.print("    Undo with: [bold]winbox net connect[/]")


@net.command("unplug")
@click.pass_context
def net_unplug(ctx: click.Context) -> None:
    """Unplug the VM's virtual NIC entirely (full air-gap).

    Kills all IP traffic including Kali <-> VM. Guest agent and VirtIO-FS
    stay up because they run over virtio-serial, not the NIC. The link is
    set down both live and in the persistent domain config, so the air-gap
    survives a guest reboot, a BSOD, and `winbox down` / `winbox up`. For
    internet-only isolation that keeps Kali <-> VM working, use
    `winbox net isolate` instead.
    Undo with: winbox net connect
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    try:
        vm.net_set_link("down")
    except RuntimeError as e:
        console.print("[red][-][/] NOT air-gapped — the link change failed:")
        console.print(f"    {e}", markup=False, highlight=False)
        console.print(
            "    Retry, or use [bold]winbox net isolate[/] (nwfilter) if this "
            "virsh lacks `domif-setlink --config`."
        )
        raise SystemExit(1)

    console.print(
        "[green][+][/] NIC unplugged — VM is fully air-gapped (live + next boot)"
    )
    console.print("    Undo with: [bold]winbox net connect[/]")


@net.command("connect")
@click.pass_context
def net_connect(ctx: click.Context) -> None:
    """Restore full network access (undo isolate or unplug).

    Clears the link-down state in both the live domain and the persistent
    config, so the NIC is back now and after the next boot.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    try:
        if nwfilter.detach_filter(vm.name):
            console.print("[blue][*][/] Detaching nwfilter 'winbox-isolate'...")
    except Exception as e:
        console.print(f"[yellow][!][/] Could not detach nwfilter: {e}")

    live = vm.net_link_state()
    boot = vm.net_link_state(config=True)
    if "down" in (live, boot):
        console.print("[blue][*][/] Plugging NIC back in (live + next boot)...")
        try:
            vm.net_set_link("up")
        except RuntimeError as e:
            console.print("[red][-][/] Failed to set link up:")
            console.print(f"    {e}", markup=False, highlight=False)
            raise SystemExit(1)
    if live == "down":
        try:
            ga.exec_powershell(
                "Restart-NetAdapter -Name (Get-NetAdapter | Select -First 1).Name "
                "-Confirm:$false",
                timeout=30,
            )
        except GuestAgentError as e:
            console.print(f"[yellow][!][/] Could not restart adapter: {e}")

    console.print("[blue][*][/] Renewing DHCP lease...")
    try:
        ga.exec("ipconfig /release", timeout=15)
    except GuestAgentError:
        pass
    try:
        ga.exec("ipconfig /renew", timeout=30)
    except GuestAgentError as e:
        console.print(f"[yellow][!][/] DHCP renew did not complete cleanly: {e}")

    ip = None
    for _ in range(15):
        ip = vm.ip()
        if ip:
            break
        time.sleep(1)

    if ip:
        console.print(f"[green][+][/] Network connected — IP: {ip}")
    else:
        console.print("[green][+][/] Network connected (DHCP pending)")


@net.command("status")
@click.pass_context
def net_status(ctx: click.Context) -> None:
    """Show VM network state — link, filter and internet reachability.

    Reports the link both live and as it will be on the next boot, because
    `virsh domif-setlink` writes the two scopes separately and a live-only
    link-down is undone by any power cycle. Works with the VM off, where
    only the next-boot state exists.
    """
    from winbox.netstatus import net_status as _net_status

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ns = _net_status(vm, ga)

    if not ns.vm_running:
        console.print(
            f"[yellow][!][/] VM is not running (state: {ns.vm_state}) — "
            "showing next-boot state"
        )

    def _color(link: str) -> str:
        return "green" if link == "up" else "red"

    if not ns.vm_running:
        if ns.link_boot is None:
            console.print("Link:     [yellow]unknown[/] (next boot)")
        else:
            console.print(f"Link:     [{_color(ns.link_boot)}]{ns.link_boot}[/] (next boot)")
    elif ns.link_live is None:
        console.print("Link:     [yellow]unknown[/]")
    elif ns.link_boot is None:
        console.print(f"Link:     [{_color(ns.link_live)}]{ns.link_live}[/] (next boot: unknown)")
    elif ns.link_live == ns.link_boot:
        suffix = "" if ns.link_live == "up" else " (next boot: down)"
        console.print(f"Link:     [{_color(ns.link_live)}]{ns.link_live}[/]{suffix}")
    elif ns.link_live == "down":
        console.print(
            "Link:     [yellow]down (next boot: up — a power cycle restores the "
            "network; re-run winbox net unplug)[/]"
        )
    else:
        console.print(
            "Link:     [yellow]up (next boot: down — a power cycle leaves the VM "
            "with no NIC; run winbox net connect)[/]"
        )

    if ns.vm_state == VMState.SAVED.value:
        console.print(
            "    Saved state present — resuming restores the link state captured "
            "at suspend time, not the next-boot state above."
        )

    scope = "" if ns.vm_running else " (next boot)"
    if ns.filter_active:
        console.print(f"Filter:   [red]{nwfilter.FILTER_NAME}[/] (isolated){scope}")
    else:
        console.print(f"Filter:   [green]none[/]{scope}")

    _INET_COLORS = {"reachable": "green", "isolated": "red", "blocked": "red", "unknown": "yellow"}
    color = _INET_COLORS.get(ns.internet, "yellow")
    detail = f" ({ns.internet_detail})" if ns.internet_detail else ""
    console.print(f"Internet: [{color}]{ns.internet}[/]{detail}")


REGISTER = ("Network", [net])
