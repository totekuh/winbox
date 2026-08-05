"""Tests for winbox.vm.lifecycle — VM state mapping and virsh plumbing.

Everything that decides "can this command run right now" flows through
``VM.state()``, and every ``winbox`` command that touches the guest calls it
first. A state libvirt emits that we map wrongly turns into a command that
either refuses to run on a healthy VM or charges ahead against a dead one.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from winbox.config import Config
from winbox.vm.lifecycle import VM, VMState, virsh_run


def _proc(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


@pytest.fixture
def vm(tmp_path):
    return VM(Config(winbox_dir=tmp_path / ".winbox"))


class TestVirshRun:
    def test_returns_completed_process(self):
        with patch("subprocess.run", return_value=_proc("ok")) as run:
            assert virsh_run("domstate", "x").stdout == "ok"
        assert run.call_args[0][0][:3] == ["virsh", "-c", "qemu:///system"]

    def test_raises_runtime_error_with_stderr(self):
        """One error type across the codebase: callers should not have to
        catch both RuntimeError and CalledProcessError."""
        with patch("subprocess.run", return_value=_proc(returncode=1, stderr="boom")):
            with pytest.raises(RuntimeError, match="boom"):
                virsh_run("start", "x")

    def test_falls_back_to_stdout_then_exit_code(self):
        with patch("subprocess.run", return_value=_proc("detail", returncode=1)):
            with pytest.raises(RuntimeError, match="detail"):
                virsh_run("start", "x")
        with patch("subprocess.run", return_value=_proc(returncode=3)):
            with pytest.raises(RuntimeError, match="virsh exit 3"):
                virsh_run("start", "x")

    def test_check_false_never_raises(self):
        with patch("subprocess.run", return_value=_proc(returncode=1, stderr="boom")):
            assert virsh_run("domstate", "x", check=False).returncode == 1


class TestStateMapping:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("running", VMState.RUNNING),
            ("shut off", VMState.SHUTOFF),
            ("paused", VMState.PAUSED),
            # Transient states map to the nearest stable one rather than
            # UNKNOWN, which callers treat as fatal.
            ("in shutdown", VMState.SHUTOFF),
            ("dying", VMState.SHUTOFF),
            ("crashed", VMState.SHUTOFF),
            ("idle", VMState.SHUTOFF),
            ("pmsuspended", VMState.SAVED),
            ("something new", VMState.UNKNOWN),
        ],
    )
    def test_maps_virsh_output(self, vm, raw, expected):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(raw + "\n")):
            assert vm.state() is expected

    def test_case_and_whitespace_insensitive(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc("  RUNNING \n")):
            assert vm.state() is VMState.RUNNING

    def test_saved_wins_over_everything(self, vm):
        """managedsave shows up alongside another word; SAVED is the one that
        determines whether `up` resumes or cold-boots."""
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc("shut off (saved)")):
            assert vm.state() is VMState.SAVED

    def test_nonzero_exit_means_not_found(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(returncode=1)):
            assert vm.state() is VMState.NOT_FOUND

    def test_exists_and_is_running(self, vm):
        with patch.object(VM, "state", return_value=VMState.NOT_FOUND):
            assert vm.exists() is False
            assert vm.is_running() is False
        with patch.object(VM, "state", return_value=VMState.RUNNING):
            assert vm.exists() is True
            assert vm.is_running() is True
        with patch.object(VM, "state", return_value=VMState.SHUTOFF):
            assert vm.exists() is True
            assert vm.is_running() is False


class TestPowerCommands:
    @pytest.mark.parametrize(
        "method,expected_verb,checked",
        [
            ("start", "start", True),
            ("shutdown", "shutdown", False),
            ("force_stop", "destroy", False),
            ("resume", "resume", True),
            ("suspend", "managedsave", True),
        ],
    )
    def test_dispatches_the_right_virsh_verb(self, vm, method, expected_verb, checked):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()) as run:
            getattr(vm, method)()
        args, kwargs = run.call_args
        assert args[0] == expected_verb
        assert args[1] == vm.name
        # shutdown/force_stop are best-effort: a VM that is already off must
        # not turn a stop request into an error.
        assert kwargs.get("check", True) is checked


class TestIpDiscovery:
    SINGLE_NIC = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.10/24
"""

    MULTI_NIC = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet1      52:54:00:11:22:33    ipv4         10.9.9.5/24
 vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.10/24
"""

    def test_single_nic(self, vm):
        with (
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(self.SINGLE_NIC)),
            patch.object(VM, "interface", return_value="vnet0"),
        ):
            assert vm.ip() == "192.168.122.10"

    def test_picks_the_lease_on_the_vms_own_interface(self, vm):
        """With a second test network attached, the first IPv4 line is no
        longer necessarily the libvirt-default-network address."""
        with (
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(self.MULTI_NIC)),
            patch.object(VM, "interface", return_value="vnet0"),
        ):
            assert vm.ip() == "192.168.122.10"

    def test_falls_back_to_first_ip_when_interface_is_unknown(self, vm):
        with (
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(self.MULTI_NIC)),
            patch.object(VM, "interface", return_value=None),
        ):
            assert vm.ip() == "10.9.9.5"

    def test_no_lease_returns_none(self, vm):
        header = self.SINGLE_NIC.split("\n")[0] + "\n"
        with (
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(header)),
            patch.object(VM, "interface", return_value="vnet0"),
        ):
            assert vm.ip() is None

    def test_virsh_failure_returns_none(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(returncode=1)):
            assert vm.ip() is None


class TestInterfaceAndLink:
    IFLIST = """\
 Interface   Type      Source    Model    MAC
-------------------------------------------------------
 vnet0       network   default   virtio   52:54:00:aa:bb:cc
"""

    def test_interface_parses_the_name(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(self.IFLIST)):
            assert vm.interface() == "vnet0"

    def test_interface_none_on_failure(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(returncode=1)):
            assert vm.interface() is None

    def test_set_link_requires_an_interface(self, vm):
        with patch.object(VM, "interface", return_value=None):
            assert vm.net_set_link("down") is False

    def test_set_link_reports_success(self, vm):
        with (
            patch.object(VM, "interface", return_value="vnet0"),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()) as run,
        ):
            assert vm.net_set_link("down") is True
        assert run.call_args[0] == ("domif-setlink", vm.name, "vnet0", "down")

    @pytest.mark.parametrize("out,expected", [("vnet0 up", "up"), ("vnet0 down", "down")])
    def test_link_state(self, vm, out, expected):
        with (
            patch.object(VM, "interface", return_value="vnet0"),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(out)),
        ):
            assert vm.net_link_state() == expected

    def test_link_state_none_on_failure(self, vm):
        with (
            patch.object(VM, "interface", return_value="vnet0"),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(returncode=1)),
        ):
            assert vm.net_link_state() is None


class TestSnapshots:
    def test_create_raises_with_virsh_detail(self, vm):
        with patch(
            "winbox.vm.lifecycle.virsh_run",
            return_value=_proc(returncode=1, stderr="disk is in use"),
        ):
            with pytest.raises(RuntimeError, match="disk is in use"):
                vm.snapshot_create("snap")

    def test_list_parses_names(self, vm):
        with patch(
            "winbox.vm.lifecycle.virsh_run", return_value=_proc("clean\n\n testsnap \n")
        ):
            assert vm.snapshot_list() == ["clean", "testsnap"]

    def test_list_is_empty_on_failure(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(returncode=1)):
            assert vm.snapshot_list() == []


class TestWaitShutdown:
    def test_returns_true_once_shut_off(self, vm):
        raws = ["running", "running", "shut off"]
        with (
            patch("winbox.vm.lifecycle.virsh_run", side_effect=[_proc(r) for r in raws]),
            patch("time.sleep"),
        ):
            assert vm.wait_shutdown(timeout=60, poll=0) is True

    def test_returns_false_on_timeout(self, vm):
        with (
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc("running")),
            patch("time.sleep"),
            patch("time.monotonic", side_effect=[0.0, 100.0]),
        ):
            assert vm.wait_shutdown(timeout=10, poll=0) is False


class TestDiskIsFreePredicate:
    """`wait_shutdown` is the *only* gate the offline-disk operations use to
    decide that QEMU has released the qcow2 and guestfish may open it
    read-write: `winbox setup` phase 2, `winbox av enable/disable`.

    `state()` deliberately folds "in shutdown"/"dying"/"crashed"/"idle" onto
    SHUTOFF so `ensure_running` doesn't treat them as fatal — but in all of
    them the domain is still active and QEMU still holds the image open.
    "crashed" is the dangerous one: it is not transient, so the old
    `state() != SHUTOFF` loop returned True on its first poll and phase 2 then
    wrote to a live disk.
    """

    @pytest.mark.parametrize("raw", ["in shutdown", "dying", "crashed", "idle"])
    def test_active_domain_is_not_off_even_though_state_says_shutoff(self, vm, raw):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(raw + "\n")):
            assert vm.state() is VMState.SHUTOFF  # unchanged, on purpose
            assert vm.is_off() is False

    @pytest.mark.parametrize("raw", ["in shutdown", "dying", "crashed", "idle"])
    def test_wait_shutdown_does_not_report_success_for_an_active_domain(self, vm, raw):
        with (
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(raw + "\n")),
            patch("time.sleep"),
            patch("time.monotonic", side_effect=[0.0, 100.0]),
        ):
            assert vm.wait_shutdown(timeout=10, poll=0) is False

    def test_shut_off_is_off(self, vm):
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc("  Shut off \n")):
            assert vm.is_off() is True

    def test_unqueryable_domain_is_not_off(self, vm):
        """A dead libvirtd is not evidence that QEMU exited."""
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc(returncode=1)):
            assert vm.is_off() is False

    def test_saved_domain_is_not_treated_as_free(self, vm):
        """The disk is free, but the next start restores RAM captured before
        whatever edit we are about to make — a hive edited underneath a saved
        memory image is its own corruption."""
        with patch("winbox.vm.lifecycle.virsh_run", return_value=_proc("shut off (saved)")):
            assert vm.is_off() is False


class TestDiskUsage:
    def test_none_when_disk_is_absent(self, vm):
        assert vm.disk_usage() is None

    def test_human_readable_size(self, vm):
        vm.cfg.winbox_dir.mkdir(parents=True, exist_ok=True)
        vm.cfg.disk_path.write_bytes(b"\x00" * 2048)
        assert "KB" in vm.disk_usage() or "B" in vm.disk_usage()


class TestDestroy:
    """`destroy` removes the domain, its snapshots, NVRAM, and disk — but must
    never take the shared ISOs with it, and must not report success when the
    domain is still defined."""

    def test_running_vm_is_forced_off_first(self, vm):
        with (
            patch.object(VM, "state", return_value=VMState.RUNNING),
            patch.object(VM, "force_stop") as force_stop,
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()),
        ):
            vm.destroy()
        force_stop.assert_called_once()

    def test_shutoff_vm_is_not_force_stopped(self, vm):
        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch.object(VM, "force_stop") as force_stop,
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()),
        ):
            vm.destroy()
        force_stop.assert_not_called()

    def test_undefine_never_uses_remove_all_storage(self, vm):
        """--remove-all-storage would delete the attached install ISOs, which
        are multi-GB downloads shared across rebuilds."""
        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()) as run,
        ):
            vm.destroy()
        for call in run.call_args_list:
            assert "--remove-all-storage" not in call[0]

    def test_falls_back_through_less_capable_undefine_flags(self, vm):
        """Older libvirt rejects --nvram; the VM must still get removed."""
        attempts: list[tuple] = []

        def fake_virsh(*args, check=True):
            attempts.append(args)
            # Only the flagless form succeeds.
            return _proc() if len(args) == 2 else _proc(returncode=1, stderr="unsupported")

        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch("winbox.vm.lifecycle.virsh_run", side_effect=fake_virsh),
        ):
            vm.destroy()

        assert len(attempts) == 3
        assert attempts[-1] == ("undefine", vm.name)

    def test_raises_with_manual_cleanup_when_every_undefine_fails(self, vm):
        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch(
                "winbox.vm.lifecycle.virsh_run",
                return_value=_proc(returncode=1, stderr="in use"),
            ),
        ):
            with pytest.raises(RuntimeError, match="Manual cleanup"):
                vm.destroy()

    def test_disk_is_deleted(self, vm):
        vm.cfg.winbox_dir.mkdir(parents=True, exist_ok=True)
        vm.cfg.disk_path.write_bytes(b"disk")

        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()),
        ):
            vm.destroy()

        assert not vm.cfg.disk_path.exists()

    def test_missing_disk_is_not_an_error(self, vm):
        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()),
        ):
            vm.destroy()  # must not raise

    def test_undeletable_disk_reports_manual_cleanup(self, vm):
        vm.cfg.winbox_dir.mkdir(parents=True, exist_ok=True)
        vm.cfg.disk_path.write_bytes(b"disk")

        with (
            patch.object(VM, "state", return_value=VMState.SHUTOFF),
            patch("winbox.vm.lifecycle.virsh_run", return_value=_proc()),
            patch(
                "pathlib.Path.unlink",
                side_effect=OSError("Permission denied"),
            ),
        ):
            with pytest.raises(RuntimeError, match="Manual cleanup"):
                vm.destroy()
