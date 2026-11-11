"""Network status probe, shared by the CLI and MCP server."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from winbox import nwfilter
from winbox.vm.lifecycle import VMState

if TYPE_CHECKING:
    from winbox.vm import GuestAgent
    from winbox.vm.lifecycle import VM


@dataclass(frozen=True)
class NetStatus:
    """Structured network status across three layers."""

    vm_running: bool
    link_live: str | None
    link_boot: str | None
    filter_active: bool
    internet: str
    internet_detail: str | None
    vm_state: str


def net_status(vm: VM, ga: GuestAgent) -> NetStatus:
    """Probe VM network state across link, filter, and internet layers."""
    state = vm.state()
    running = state == VMState.RUNNING

    live = vm.net_link_state() if running else None
    boot = vm.net_link_state(config=True)

    filter_active = nwfilter.has_filter(vm.name)

    internet = "unknown"
    internet_detail = None

    if not running:
        internet = "unknown"
        internet_detail = "VM not running"
    elif live != "up":
        internet = "blocked"
        internet_detail = "link down"
    elif filter_active:
        internet = "isolated"
        internet_detail = "nwfilter active"
    elif not ga.ping():
        internet = "unknown"
        internet_detail = "GA unreachable"
    else:
        try:
            from winbox.vm import GuestAgentError
            try:
                result = ga.exec_powershell(
                    "@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                    "-ErrorAction SilentlyContinue).Count",
                    timeout=10,
                )
            except GuestAgentError:
                internet = "unknown"
                internet_detail = "guest probe timed out"
                result = None

            if result is not None:
                if result.exitcode != 0 or not result.stdout.strip().isdigit():
                    internet = "unknown"
                    internet_detail = None
                elif int(result.stdout.strip()) > 0:
                    internet = "reachable"
                    internet_detail = None
                else:
                    internet = "isolated"
                    internet_detail = "no default route"
        except Exception:
            internet = "unknown"
            internet_detail = "probe error"

    return NetStatus(
        vm_running=running,
        link_live=live,
        link_boot=boot,
        filter_active=filter_active,
        internet=internet,
        internet_detail=internet_detail,
        vm_state=state.value,
    )
