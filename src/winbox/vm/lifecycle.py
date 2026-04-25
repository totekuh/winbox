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


def virsh_run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``virsh -c qemu:///system <args>`` and return the result.

    Always returns a :class:`subprocess.CompletedProcess`. With
    ``check=True``, raises :class:`RuntimeError` (with stderr) on a
    non-zero exit instead of the stdlib's :class:`CalledProcessError` —
    the rest of the codebase already raises ``RuntimeError`` for virsh
    failures (e.g. ``snapshot_create``), so a single error type avoids
    callers having to ``except (RuntimeError, CalledProcessError)``.
    """
    result = subprocess.run(
        ["virsh", "-c", "qemu:///system", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        msg = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"virsh exit {result.returncode}"
        )
        raise RuntimeError(f"virsh {' '.join(args)} failed: {msg}")
    return result


# Backward-compat alias. New code should use ``virsh_run``.
_virsh = virsh_run


class VM:
    """Manages the winbox VM lifecycle via virsh."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.name = cfg.vm_name

    def state(self) -> VMState:
        result = virsh_run("domstate", self.name, check=False)
        if result.returncode != 0:
            return VMState.NOT_FOUND
        raw = result.stdout.strip().lower()
        # virsh emits 8 well-known states; map the transient ones to the
        # nearest stable one rather than collapsing them all to UNKNOWN
        # (which callers like _ensure_vm_ready treat as fatal). "saved"
        # comes from managedsave indicator on running VMs.
        if "saved" in raw:
            return VMState.SAVED
        # Direct match against canonical values first.
        for s in VMState:
            if s.value == raw:
                return s
        # Transient / nearby states virsh can emit:
        #   "in shutdown" — heading to SHUTOFF, not interesting to most callers
        #   "dying"       — heading to SHUTOFF
        #   "crashed"     — VM died; treat as off so callers offer winbox up
        #   "pmsuspended" — ACPI-suspended, equivalent to a saved state
        #   "idle"        — defined-but-not-running on some libvirt builds
        if raw in ("in shutdown", "dying", "crashed", "idle"):
            return VMState.SHUTOFF
        if raw == "pmsuspended":
            return VMState.SAVED
        return VMState.UNKNOWN

    def exists(self) -> bool:
        return self.state() != VMState.NOT_FOUND

    def is_running(self) -> bool:
        return self.state() == VMState.RUNNING

    def start(self) -> None:
        virsh_run("start", self.name)

    def shutdown(self) -> None:
        virsh_run("shutdown", self.name, check=False)

    def force_stop(self) -> None:
        virsh_run("destroy", self.name, check=False)

    def resume(self) -> None:
        virsh_run("resume", self.name)

    def suspend(self) -> None:
        """Save VM state to disk (managedsave) for instant resume."""
        virsh_run("managedsave", self.name)

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
            result = virsh_run("undefine", self.name, *flags, check=False)
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
        result = virsh_run("domifaddr", self.name, check=False)
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
        result = virsh_run("domiflist", self.name, check=False)
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
        result = virsh_run("domif-setlink", self.name, iface, state, check=False)
        return result.returncode == 0

    def net_link_state(self) -> str | None:
        """Get current network link state ('up' or 'down')."""
        iface = self.interface()
        if not iface:
            return None
        result = virsh_run("domif-getlink", self.name, iface, check=False)
        if result.returncode != 0:
            return None
        # Output like: "vnet0 up" or "vnet0 down"
        for word in result.stdout.strip().split():
            if word in ("up", "down"):
                return word
        return None

    def snapshot_create(self, name: str) -> None:
        result = virsh_run(
            "snapshot-create-as", self.name, name,
            "--description", f"winbox snapshot: {name}",
            check=False,
        )
        if result.returncode != 0:
            msg = result.stderr.strip() or result.stdout.strip() or f"virsh exit {result.returncode}"
            raise RuntimeError(msg)

    def snapshot_revert(self, name: str) -> None:
        virsh_run("snapshot-revert", self.name, name)

    def snapshot_list(self) -> list[str]:
        result = virsh_run("snapshot-list", self.name, "--name", check=False)
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
