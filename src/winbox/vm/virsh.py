"""Libvirt/virsh plumbing shared by VM lifecycle and networking."""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from enum import Enum


_GUEST_AGENT_CHANNEL = "org.qemu.guest_agent.0"

_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def _parse_domiflist(stdout: str) -> list[tuple[str | None, str]]:
    """Parse ``virsh domiflist`` output into ``[(host tap name, MAC)]``."""
    nics: list[tuple[str | None, str]] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or not _MAC_RE.match(parts[-1]):
            continue
        tap = parts[0]
        nics.append((None if tap == "-" else tap, parts[-1]))
    return nics


def _virsh_err(result: subprocess.CompletedProcess[str]) -> str:
    """The stderr-or-stdout-or-exit-code detail reported when virsh fails."""
    return (
        result.stderr.strip()
        or result.stdout.strip()
        or f"virsh exit {result.returncode}"
    )


def agent_channel_connected(vm_name: str) -> bool:
    """Whether libvirt currently sees the guest-agent channel as connected."""
    result = virsh_run("dumpxml", vm_name, check=False)
    if result.returncode != 0:
        return False
    try:
        domain = ET.fromstring(result.stdout)
    except ET.ParseError:
        return False
    target = domain.find(
        f"devices/channel/target[@name='{_GUEST_AGENT_CHANNEL}']"
    )
    return target is not None and target.get("state") == "connected"


class VMState(Enum):
    RUNNING = "running"
    SHUTOFF = "shut off"
    PAUSED = "paused"
    SAVED = "saved"
    NOT_FOUND = "not found"
    UNKNOWN = "unknown"


def virsh_run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``virsh -c qemu:///system <args>`` and return the result."""
    result = subprocess.run(
        ["virsh", "-c", "qemu:///system", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"virsh {' '.join(args)} failed: {_virsh_err(result)}")
    return result
