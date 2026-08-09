"""VM lifecycle management via libvirt/virsh."""

from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from winbox.config import Config

# The virtio-serial channel qemu-ga speaks over. libvirt stamps a live
# ``state`` attribute on this target and keeps it current as the agent
# connects and drops — see ``agent_channel_connected``.
_GUEST_AGENT_CHANNEL = "org.qemu.guest_agent.0"


def agent_channel_connected(vm_name: str) -> bool:
    """Whether libvirt currently sees the guest-agent channel as connected.

    This is the authoritative readiness signal, and the cause of the
    post-reboot flake it guards against: the agent comes up, answers once, and
    the channel drops again for a few seconds before it settles. A
    ``guest-ping`` only sees that indirectly; libvirt tracks the channel state
    directly and exposes it in ``virsh dumpxml`` as::

        <target type='virtio' name='org.qemu.guest_agent.0' state='connected'/>

    Reads that attribute and nothing else. Returns ``False`` — never raises —
    when the domain is off, absent, unqueryable, or the channel/attribute is
    missing, matching how :meth:`VM.state` degrades an unusable domain: a
    "not connected" answer has to be a value callers can gate on, not an
    exception.
    """
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
    # `state` is only present on a live domain; absent on a shut-off one.
    return target is not None and target.get("state") == "connected"


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




class VM:
    """Manages the winbox VM lifecycle via virsh."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.name = cfg.vm_name

    def _domstate_raw(self) -> str | None:
        """Raw, lowercased ``virsh domstate --reason`` text — or None if
        unqueryable.

        ``--reason`` is what makes a managed-saved domain read as
        ``"shut off (saved)"`` instead of a bare ``"shut off"`` indistinguishable
        from any other shutoff cause; without it ``state()`` can never see
        SAVED and ``is_off()`` can never exclude it.

        Kept separate from :meth:`state` because two callers want two
        different questions answered from the same output: "roughly, what is
        this domain doing" (``state``, which folds transient states onto the
        nearest stable one) and "has QEMU actually let go of the disk"
        (``is_off``, which must not fold anything).
        """
        result = virsh_run("domstate", self.name, "--reason", check=False)
        if result.returncode != 0:
            return None
        return result.stdout.strip().lower()

    def state(self) -> VMState:
        raw = self._domstate_raw()
        if raw is None:
            return VMState.NOT_FOUND
        # virsh emits 8 well-known states; map the transient ones to the
        # nearest stable one rather than collapsing them all to UNKNOWN
        # (which callers like _ensure_vm_ready treat as fatal). "saved"
        # comes from managedsave indicator on running VMs.
        if "saved" in raw:
            return VMState.SAVED
        # --reason appends " (<reason>)" to the state; strip it before
        # matching against the bare canonical values below.
        canonical = raw.partition(" (")[0]
        # Direct match against canonical values first.
        for s in VMState:
            if s.value == canonical:
                return s
        # Transient / nearby states virsh can emit:
        #   "in shutdown" — heading to SHUTOFF, not interesting to most callers
        #   "dying"       — heading to SHUTOFF
        #   "crashed"     — VM died; treat as off so callers offer winbox up
        #   "pmsuspended" — ACPI-suspended, equivalent to a saved state
        #   "idle"        — defined-but-not-running on some libvirt builds
        if canonical in ("in shutdown", "dying", "crashed", "idle"):
            return VMState.SHUTOFF
        if canonical == "pmsuspended":
            return VMState.SAVED
        return VMState.UNKNOWN

    def is_off(self) -> bool:
        """True only when libvirt reports the domain as genuinely "shut off".

        Deliberately *not* ``state() == VMState.SHUTOFF``. ``state()`` folds
        "in shutdown", "dying", "crashed" and "idle" onto SHUTOFF so callers
        like ``ensure_running`` don't treat them as a fatal UNKNOWN — but in
        every one of those states the domain is still active and the QEMU
        process still holds the qcow2 open read-write. "crashed" is the worst
        of them: it is not transient, it persists until someone destroys the
        domain.

        This is the predicate for "QEMU has released the disk, so guestfish
        may open it read-write" (offline provisioning, the offline Defender
        hive edits). A false "yes" costs a corrupted disk image; a false "no"
        costs a caller some waiting. So anything we cannot positively confirm
        as off — including a domain we failed to query at all, since a dead
        libvirtd is not evidence that QEMU exited — answers False.

        "shut off (saved)" is excluded on purpose too: the disk is free, but
        the next ``start`` restores RAM captured before whatever edit we are
        about to make, and a hive edited underneath a saved memory image is
        its own kind of corruption.
        """
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
        """Whether libvirt sees the guest-agent channel as connected.

        The authoritative readiness signal — see
        :func:`agent_channel_connected`. A method here so callers read it the
        conventional ``vm.*`` way and tests can mock it like ``state``.
        """
        return agent_channel_connected(self.name)

    def start(self) -> None:
        """Start the domain, tolerating one that is still winding down.

        ``state()`` folds "in shutdown" into SHUTOFF — right for callers
        asking "is it usable", wrong for callers asking "can I start it".
        A `winbox down` immediately followed by `winbox up` therefore hit
        ``virsh start`` while the domain was still active, and libvirt
        refused with "Domain is already active".

        Rather than leak that distinction into every caller, settle it here:
        wait for the shutdown to finish and start once more. If it never
        settles, the domain is genuinely running and the goal is already met.
        """
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
        # Still up after two minutes: it was not shutting down at all, it was
        # simply running. Nothing to do.

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
        """Return the VM's IPv4 address on the libvirt default network.

        ``virsh domifaddr`` can list multiple NICs / leases; if the user has
        added a second network for testing, the first IPv4 line is no longer
        guaranteed to be the libvirt-default-network address. Filter to
        leases on the interface returned by ``self.interface()`` so the
        ConPTY listener doesn't reject "the wrong" IP later.
        """
        result = virsh_run("domifaddr", self.name, check=False)
        if result.returncode != 0:
            return None
        target_iface = self.interface()
        # `domifaddr` output (Linux/libvirt) looks like:
        #   Name       MAC address       Protocol   Address
        #   ----------------------------------------------------
        #   vnet0      52:54:00:aa:bb    ipv4       192.168.122.10/24
        # The Name field is set on the row that introduces an interface
        # and blank on subsequent rows belonging to the same iface.
        current_iface: str | None = None
        first_seen_ip: str | None = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("Name") or stripped.startswith("-"):
                continue
            parts = stripped.split()
            # 4-column row: NEW interface; 3-column row: continuation.
            if len(parts) >= 4 and not parts[0].startswith("0x") and "ipv4" in parts:
                current_iface = parts[0]
            if "ipv4" in parts:
                for part in parts:
                    if "/" in part and "." in part:
                        ip_addr = part.split("/")[0]
                        if first_seen_ip is None:
                            first_seen_ip = ip_addr
                        if target_iface and current_iface == target_iface:
                            return ip_addr
        # Fall back to the first IPv4 we saw if interface filtering didn't
        # pin one (single-NIC case, or if we couldn't determine the iface).
        return first_seen_ip

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
        """Wait for the VM to be genuinely shut off. False on timeout.

        Gated on :meth:`is_off`, not on ``state()``: every caller of this
        method uses a True return as permission to open the qcow2 read-write
        from the host (``winbox setup`` phase 2, ``winbox av enable/disable``).
        Under ``state()``'s lenient mapping a domain that had crashed — QEMU
        still running, image still open — reported SHUTOFF on the very first
        poll, and provisioning went on to write to a live disk.
        """
        deadline = time.monotonic() + timeout
        while not self.is_off():
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll)
        return True

    def disk_usage(self) -> str | None:
        if not self.cfg.disk_path.exists():
            return None
        from winbox.utils import human_size
        return human_size(self.cfg.disk_path.stat().st_size)
