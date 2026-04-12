"""VM lifecycle management via libvirt/virsh."""

from __future__ import annotations

import subprocess
import time
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from winbox.config import Config


class VMState(Enum):
    RUNNING = "running"
    SHUTOFF = "shut off"
    PAUSED = "paused"
    SAVED = "saved"
    NOT_FOUND = "not found"
    UNKNOWN = "unknown"


def _virsh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a virsh command and return the result."""
    return subprocess.run(
        ["virsh", "-c", "qemu:///system", *args],
        capture_output=True,
        text=True,
        check=check,
    )


class VM:
    """Manages the winbox VM lifecycle via virsh."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.name = cfg.vm_name

    def state(self) -> VMState:
        result = _virsh("domstate", self.name, check=False)
        if result.returncode != 0:
            return VMState.NOT_FOUND
        raw = result.stdout.strip().lower()
        # Handle managedsave indicator
        if "saved" in raw:
            return VMState.SAVED
        for s in VMState:
            if s.value == raw:
                return s
        return VMState.UNKNOWN

    def exists(self) -> bool:
        return self.state() != VMState.NOT_FOUND

    def is_running(self) -> bool:
        return self.state() == VMState.RUNNING

    def start(self) -> None:
        _virsh("start", self.name)

    def shutdown(self) -> None:
        _virsh("shutdown", self.name, check=False)

    def force_stop(self) -> None:
        _virsh("destroy", self.name, check=False)

    def resume(self) -> None:
        _virsh("resume", self.name)

    def suspend(self) -> None:
        """Save VM state to disk (managedsave) for instant resume."""
        _virsh("managedsave", self.name)

    def destroy(self) -> None:
        """Completely remove the VM, snapshots, NVRAM, and disk (but not ISOs)."""
        # Stop if running
        if self.state() in (VMState.RUNNING, VMState.PAUSED):
            self.force_stop()

        # Undefine without --remove-all-storage (that deletes attached ISOs too)
        undefine_ok = False
        for flags in [
            ["--managed-save", "--snapshots-metadata", "--nvram"],
            ["--managed-save", "--snapshots-metadata"],
            [],
        ]:
            result = _virsh("undefine", self.name, *flags, check=False)
            if result.returncode == 0:
                undefine_ok = True
                break

        if not undefine_ok:
            raise RuntimeError(
                f"Failed to undefine VM '{self.name}'. "
                f"Manual cleanup: virsh undefine {self.name} && rm {self.cfg.disk_path}"
            )

        # Clean up disk only
        if self.cfg.disk_path.exists():
            try:
                self.cfg.disk_path.unlink()
            except OSError as e:
                raise RuntimeError(
                    f"VM undefined but disk deletion failed: {e}\n"
                    f"    Manual cleanup: rm {self.cfg.disk_path}"
                ) from e

    def ip(self) -> str | None:
        result = _virsh("domifaddr", self.name, check=False)
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if "ipv4" in line:
                parts = line.split()
                for part in parts:
                    if "/" in part and "." in part:
                        return part.split("/")[0]
        return None

    def interface(self) -> str | None:
        """Get the VM's network interface name (e.g. 'vnet0')."""
        result = _virsh("domiflist", self.name, check=False)
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("Interface") and not line.startswith("-"):
                return line.split()[0]
        return None

    def net_set_link(self, state: str) -> bool:
        """Set network interface link state ('up' or 'down')."""
        iface = self.interface()
        if not iface:
            return False
        result = _virsh("domif-setlink", self.name, iface, state, check=False)
        return result.returncode == 0

    def net_link_state(self) -> str | None:
        """Get current network link state ('up' or 'down')."""
        iface = self.interface()
        if not iface:
            return None
        result = _virsh("domif-getlink", self.name, iface, check=False)
        if result.returncode != 0:
            return None
        # Output like: "vnet0 up" or "vnet0 down"
        for word in result.stdout.strip().split():
            if word in ("up", "down"):
                return word
        return None

    def snapshot_create(self, name: str) -> None:
        _virsh(
            "snapshot-create-as", self.name, name,
            "--description", f"winbox snapshot: {name}",
        )

    def snapshot_revert(self, name: str) -> None:
        _virsh("snapshot-revert", self.name, name)

    def snapshot_list(self) -> list[str]:
        result = _virsh("snapshot-list", self.name, "--name", check=False)
        if result.returncode != 0:
            return []
        return [s.strip() for s in result.stdout.splitlines() if s.strip()]

    def wait_shutdown(self, timeout: int = 600, poll: int = 5) -> bool:
        """Wait for the VM to reach SHUTOFF state. Returns True if shut down within timeout."""
        deadline = time.monotonic() + timeout
        while self.state() != VMState.SHUTOFF:
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll)
        return True

    def disk_usage(self) -> str | None:
        if not self.cfg.disk_path.exists():
            return None
        from winbox.utils import human_size
        return human_size(self.cfg.disk_path.stat().st_size)
