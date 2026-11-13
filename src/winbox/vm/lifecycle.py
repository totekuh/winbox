"""VM lifecycle management — state queries, power control, snapshots."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import TYPE_CHECKING

from winbox.vm.net import VMNetMixin
from winbox.vm.virsh import (  # noqa: F401 — re-exported
    VMState, agent_channel_connected, virsh_run,
)

if TYPE_CHECKING:
    from winbox.config import Config


class VM(VMNetMixin):
    """Manages the winbox VM lifecycle via virsh."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.name = cfg.vm_name

    def _domstate_raw(self) -> str | None:
        """Raw, lowercased ``virsh domstate --reason`` text — or None."""
        result = virsh_run("domstate", self.name, "--reason", check=False)
        if result.returncode != 0:
            return None
        return result.stdout.strip().lower()

    def state(self) -> VMState:
        raw = self._domstate_raw()
        if raw is None:
            return VMState.NOT_FOUND
        if "saved" in raw:
            return VMState.SAVED
        canonical = raw.partition(" (")[0]
        for s in VMState:
            if s.value == canonical:
                return s
        if canonical in ("in shutdown", "dying", "crashed", "idle"):
            return VMState.SHUTOFF
        if canonical == "pmsuspended":
            return VMState.SAVED
        return VMState.UNKNOWN

    def is_off(self) -> bool:
        """True only when libvirt reports the domain as genuinely "shut off"."""
        raw = self._domstate_raw()
        if raw is None:
            return False
        canonical, _, reason = raw.partition(" (")
        return canonical == "shut off" and "saved" not in reason

    def exists(self) -> bool:
        return self.state() != VMState.NOT_FOUND

    def is_running(self) -> bool:
        return self.state() == VMState.RUNNING

    def agent_connected(self) -> bool:
        """Whether libvirt sees the guest-agent channel as connected."""
        return agent_channel_connected(self.name)

    @staticmethod
    def _ensure_libvirt_traversal(winbox_dir: Path) -> None:
        """Ensure libvirt-qemu can traverse to winbox_dir."""
        for ancestor in [*reversed(winbox_dir.parents), winbox_dir]:
            try:
                mode = ancestor.stat().st_mode
                if not (mode & stat.S_IXOTH):
                    ancestor.chmod(mode | stat.S_IXOTH)
            except (PermissionError, OSError):
                break

    def start(self) -> None:
        """Start the domain, tolerating one that is still winding down."""
        self._ensure_libvirt_traversal(self.cfg.winbox_dir)

        raw = self._domstate_raw()
        if raw is not None and "pmsuspended" in raw:
            result = virsh_run("dompmwakeup", self.name, check=False)
            if result.returncode != 0:
                msg = result.stderr.strip() or f"virsh exit {result.returncode}"
                raise RuntimeError(f"virsh dompmwakeup {self.name} failed: {msg}")
            return

        result = virsh_run("start", self.name, check=False)
        if result.returncode == 0:
            return

        stderr = (result.stderr or "").lower()
        if "already active" not in stderr:
            msg = result.stderr.strip() or f"virsh exit {result.returncode}"
            raise RuntimeError(f"virsh start {self.name} failed: {msg}")

        if self.wait_shutdown(timeout=120, poll=2):
            virsh_run("start", self.name)
            return

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
        if self.exists() and not self.is_off():
            self.force_stop()

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

        if self.cfg.disk_path.exists():
            try:
                self.cfg.disk_path.unlink()
            except OSError as e:
                raise RuntimeError(
                    f"VM undefined but disk deletion failed: {e}\n"
                    f"    Manual cleanup: rm {self.cfg.disk_path}"
                ) from e

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
        """Wait for the VM to be genuinely shut off. False on timeout."""
        deadline = time.monotonic() + timeout
        while not self.is_off():
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll)
        return True

    def disk_usage(self) -> int | None:
        """Return disk image size in bytes, or None if the image doesn't exist."""
        if not self.cfg.disk_path.exists():
            return None
        return self.cfg.disk_path.stat().st_size
