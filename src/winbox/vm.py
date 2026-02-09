"""VM lifecycle management via libvirt/virsh."""

from __future__ import annotations

import subprocess
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
        ["virsh", *args],
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
        """Completely remove the VM, storage, snapshots, NVRAM."""
        # Stop if running
        if self.state() in (VMState.RUNNING, VMState.PAUSED):
            self.force_stop()

        # Try progressively less aggressive undefine
        for flags in [
            ["--remove-all-storage", "--managed-save", "--snapshots-metadata", "--nvram"],
            ["--remove-all-storage", "--managed-save", "--snapshots-metadata"],
            ["--remove-all-storage"],
        ]:
            result = _virsh("undefine", self.name, *flags, check=False)
            if result.returncode == 0:
                break

        # Clean up leftover disk
        if self.cfg.disk_path.exists():
            self.cfg.disk_path.unlink()

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

    def disk_usage(self) -> str | None:
        if not self.cfg.disk_path.exists():
            return None
        size = self.cfg.disk_path.stat().st_size
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
