"""Tests for winbox snapshot command — auto-shutdown and error surfacing."""

from unittest.mock import patch

import pytest

from winbox.cli import cli
from winbox.vm import VMState


class TestSnapshotAutoShutdown:
    """The snapshot command should shut a running VM down before snapshotting.

    virsh refuses to snapshot a live VM that uses UEFI/pflash, and the user
    shouldn't have to run `winbox down` manually every time.
    """

    def test_running_vm_shuts_down_first(self, runner, mock_env):
        """RUNNING VM → graceful shutdown → snapshot."""
        # state() is called: (1) in snapshot cmd, (2) at top of _graceful_shutdown,
        # (3+) in the shutdown poll loop. RUNNING twice, then SHUTOFF stops the loop.
        mock_env._vm.state.side_effect = [
            VMState.RUNNING,
            VMState.RUNNING,
            VMState.SHUTOFF,
        ]
        mock_env._vm.exists.return_value = True
        mock_env.ping.return_value = True

        with patch("winbox.cli.vm.time.sleep"):
            result = runner.invoke(cli, ["snapshot", "before-install"])

        assert result.exit_code == 0
        assert "VM is running — shutting down" in result.output
        assert "Snapshot 'before-install' created" in result.output
        mock_env.shutdown.assert_called_once()
        mock_env._vm.snapshot_create.assert_called_once_with("before-install")

    def test_already_off_vm_goes_straight_to_snapshot(self, runner, mock_env):
        """SHUTOFF VM → no shutdown message → straight to snapshot."""
        mock_env._vm.state.return_value = VMState.SHUTOFF
        mock_env._vm.exists.return_value = True

        result = runner.invoke(cli, ["snapshot", "clean"])
        assert result.exit_code == 0
        assert "shutting down" not in result.output
        assert "Snapshot 'clean' created" in result.output
        mock_env.shutdown.assert_not_called()
        mock_env._vm.snapshot_create.assert_called_once_with("clean")

    def test_force_stop_on_shutdown_timeout(self, runner, mock_env):
        """If the graceful shutdown times out, force_stop fires."""
        # state() returns RUNNING repeatedly so the loop hits timeout.
        mock_env._vm.state.return_value = VMState.RUNNING
        mock_env._vm.exists.return_value = True
        mock_env.ping.return_value = True

        with patch("winbox.cli.vm.time.sleep"):
            result = runner.invoke(cli, ["snapshot", "test"])

        # Timeout is 60s at 2s poll → 30 iterations → force_stop called
        mock_env._vm.force_stop.assert_called_once()
        assert "forcing" in result.output

    def test_ga_down_path_uses_virsh_shutdown(self, runner, mock_env):
        """If guest agent isn't responding, fall back to virsh shutdown."""
        mock_env._vm.state.side_effect = [
            VMState.RUNNING,
            VMState.RUNNING,
            VMState.SHUTOFF,
        ]
        mock_env._vm.exists.return_value = True
        mock_env.ping.return_value = False  # GA dead

        with patch("winbox.cli.vm.time.sleep"):
            result = runner.invoke(cli, ["snapshot", "test"])

        assert result.exit_code == 0
        mock_env.shutdown.assert_not_called()  # GA shutdown NOT used
        mock_env._vm.shutdown.assert_called_once()  # virsh shutdown IS


class TestSnapshotErrorSurfacing:
    """Failures in virsh snapshot-create-as must surface the real stderr,
    not a raw CalledProcessError repr."""

    def test_snapshot_create_raises_with_stderr_message(self):
        """lifecycle.VM.snapshot_create() includes virsh stderr in the error."""
        from winbox.vm.lifecycle import VM
        from winbox.config import Config

        cfg = Config()
        vm = VM(cfg)

        fake_result = type("R", (), {
            "returncode": 1,
            "stdout": "",
            "stderr": "error: unsupported configuration: internal snapshot for "
                      "disk vda unsupported for storage type raw",
        })()

        with patch("winbox.vm.lifecycle._virsh", return_value=fake_result):
            with pytest.raises(RuntimeError, match="internal snapshot.*unsupported"):
                vm.snapshot_create("bad")

    def test_snapshot_cli_surfaces_error(self, runner, mock_env):
        """The CLI prints the error message — not just 'Command returned 1'."""
        mock_env._vm.state.return_value = VMState.SHUTOFF
        mock_env._vm.exists.return_value = True
        mock_env._vm.snapshot_create.side_effect = RuntimeError(
            "error: unsupported configuration: snapshot for disk vda unsupported"
        )

        result = runner.invoke(cli, ["snapshot", "broken"])
        assert result.exit_code == 1
        assert "Failed to create snapshot 'broken'" in result.output
        assert "unsupported configuration" in result.output

    def test_snapshot_nonexistent_vm(self, runner, mock_env):
        """No VM → clean error, no attempt to snapshot."""
        mock_env._vm.exists.return_value = False

        result = runner.invoke(cli, ["snapshot", "test"])
        assert result.exit_code == 1
        assert "VM not found" in result.output
        mock_env._vm.snapshot_create.assert_not_called()


class TestSnapshotList:
    """Bare `winbox snapshot` with no name should list existing snapshots."""

    def test_bare_command_lists_snapshots(self, runner, mock_env):
        mock_env._vm.exists.return_value = True
        mock_env._vm.snapshot_list.return_value = ["clean", "before-av", "post-install"]

        result = runner.invoke(cli, ["snapshot"])
        assert result.exit_code == 0
        assert "Snapshots (3):" in result.output
        assert "clean" in result.output
        assert "before-av" in result.output
        assert "post-install" in result.output
        # Must NOT attempt to create anything
        mock_env._vm.snapshot_create.assert_not_called()

    def test_empty_snapshot_list(self, runner, mock_env):
        mock_env._vm.exists.return_value = True
        mock_env._vm.snapshot_list.return_value = []

        result = runner.invoke(cli, ["snapshot"])
        assert result.exit_code == 0
        assert "No snapshots" in result.output
        mock_env._vm.snapshot_create.assert_not_called()

    def test_list_does_not_shutdown_running_vm(self, runner, mock_env):
        """Listing must never touch a running VM."""
        mock_env._vm.exists.return_value = True
        mock_env._vm.state.return_value = VMState.RUNNING
        mock_env._vm.snapshot_list.return_value = ["clean"]

        result = runner.invoke(cli, ["snapshot"])
        assert result.exit_code == 0
        mock_env._vm.force_stop.assert_not_called()
        mock_env.shutdown.assert_not_called()
        mock_env._vm.shutdown.assert_not_called()
