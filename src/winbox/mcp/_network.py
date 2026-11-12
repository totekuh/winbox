"""Network isolation and connectivity MCP tools."""

from __future__ import annotations

import json as _json

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (
    _get_state,
    _guest_errors,
    GuestAgentError,
    VMState,
)


@mcp.tool()
def net_isolate() -> str:
    """Block internet on the VM via libvirt nwfilter (guest-proof).

    Attaches the 'winbox-isolate' nwfilter to the VM's interface so only
    intra-192.168.122.0/24 IPv4, ARP, and DHCPv4 traffic is allowed.
    Enforcement is at the host bridge -- DHCP renewals or in-guest route
    changes cannot defeat it. Kali <-> VM (guest agent, VirtIO-FS, SSH)
    stays up. For a full NIC disconnect, use net_unplug(). Also clears any
    persistent (next-boot) link-down left by net_unplug(), so the VM does
    not boot with no NIC at all. Undo with net_connect().
    """
    from winbox import nwfilter

    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    try:
        nwfilter.ensure_filter_defined(cfg)
        changed = nwfilter.attach_filter(vm.name)
    except Exception as e:
        return f"Failed to attach nwfilter: {e}"

    downgrade_note = ""
    live = vm.net_link_state()
    if "down" in (live, vm.net_link_state(config=True)):
        try:
            vm.net_set_link("up")
        except RuntimeError as e:
            return (
                f"nwfilter attached, but failed to bring the NIC link up: {e} — "
                "internet-isolation is not yet active, and the VM may boot with "
                "no NIC."
            )
        if live == "down":
            downgrade_note = (
                " (note: the NIC was unplugged/air-gapped; brought the link up "
                "(live + next boot) for filtered access — Kali<->VM is reachable "
                "again, internet stays blocked)"
            )

    if changed:
        return "Internet isolated — nwfilter enforced at host bridge" + downgrade_note
    return "Already isolated — nwfilter already attached" + downgrade_note


@mcp.tool()
def net_unplug() -> str:
    """Unplug the VM's virtual NIC entirely (full air-gap).

    Kills all IP traffic including Kali <-> VM. GA and VirtIO-FS stay
    up over virtio-serial. The link goes down both live and in the
    persistent domain config, so the air-gap survives a guest reboot, a
    BSOD and a VM power cycle. For internet-only isolation that keeps
    Kali <-> VM working, use net_isolate(). Undo with net_connect().
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    try:
        vm.net_set_link("down")
    except RuntimeError as e:
        return (
            f"error: NOT air-gapped — the link change failed: {e}. The guest may "
            "still be on the network. Retry net_unplug(), or use net_isolate() "
            "if this libvirt lacks `domif-setlink --config`."
        )
    return "NIC unplugged — VM is fully air-gapped (live + next boot)"


@mcp.tool()
def net_connect() -> str:
    """Restore full network access (undo net_isolate or net_unplug).

    Detaches the 'winbox-isolate' nwfilter (idempotent), brings the NIC
    link up if needed -- in both the live and the persistent domain config
    -- then runs a full DHCP cycle (release + renew) to re-add the default
    gateway.
    """
    import time
    from winbox import nwfilter

    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"

    try:
        nwfilter.detach_filter(vm.name)
    except Exception as e:
        return (
            f"error: nwfilter detach FAILED — the VM is STILL internet-isolated: "
            f"{e}. Retry, or inspect the domain XML / `virsh nwfilter-list`."
        )

    live = vm.net_link_state()
    if "down" in (live, vm.net_link_state(config=True)):
        try:
            vm.net_set_link("up")
        except RuntimeError as e:
            return f"error: failed to bring the NIC link up: {e}"
    if live == "down":
        try:
            ga.exec_powershell(
                "Restart-NetAdapter -Name (Get-NetAdapter | Select -First 1).Name "
                "-Confirm:$false",
                timeout=30,
            )
        except GuestAgentError:
            pass

    try:
        ga.exec("ipconfig /release", timeout=15)
    except GuestAgentError:
        pass
    try:
        ga.exec("ipconfig /renew", timeout=30)
    except GuestAgentError:
        pass

    for _ in range(15):
        ip = vm.ip()
        if ip:
            return f"Network connected — IP: {ip}"
        time.sleep(1)
    return "Network connected (DHCP pending)"


@mcp.tool()
def net_status() -> str:
    """Report VM network state — link, filter, and internet reachability.

    Returns a JSON object with link state (live and next-boot), nwfilter
    status, and internet reachability.  Works whether the VM is running
    or off.
    """
    from winbox.netstatus import net_status as _net_status

    cfg, vm, ga = _get_state()
    ns = _net_status(vm, ga)

    return _json.dumps({
        "vm_running": ns.vm_running,
        "link_live": ns.link_live,
        "link_boot": ns.link_boot,
        "filter_active": ns.filter_active,
        "internet": ns.internet,
        "internet_detail": ns.internet_detail,
        "vm_state": ns.vm_state,
    })
