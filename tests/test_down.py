"""Tests for `winbox down`, including the --force hard power-off."""

from unittest.mock import patch

from winbox.cli import cli
from winbox.vm import VMState


class TestDownGraceful:
    def test_running_vm_shuts_down_gracefully(self, runner, mock_env):
        # down cmd reads state once (RUNNING), then _graceful_shutdown reads it:
        # RUNNING at the guard, SHUTOFF ends the poll loop.
        mock_env._vm.state.side_effect = [
            VMState.RUNNING,
            VMState.RUNNING,
            VMState.SHUTOFF,
        ]
        mock_env.ping.return_value = True

        with patch("winbox.cli.vm.time.sleep"):
            result = runner.invoke(cli, ["down"])

        assert result.exit_code == 0
        assert "Shutting down VM" in result.output
        assert "VM stopped" in result.output
        mock_env.shutdown.assert_called_once()
        mock_env._vm.force_stop.assert_not_called()

    def test_paused_vm_points_at_force(self, runner, mock_env):
        """Graceful down can't act on a paused guest — it must name the escape
        hatch rather than silently doing nothing."""
        mock_env._vm.state.return_value = VMState.PAUSED

        result = runner.invoke(cli, ["down"])

        assert result.exit_code == 0
        assert "not running" in result.output
        assert "--force" in result.output
        mock_env._vm.force_stop.assert_not_called()
        mock_env.shutdown.assert_not_called()

    def test_shutoff_vm_is_a_noop(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.SHUTOFF

        result = runner.invoke(cli, ["down"])

        assert result.exit_code == 0
        assert "not running" in result.output
        mock_env._vm.force_stop.assert_not_called()


class TestDownForce:
    def test_force_kills_a_running_vm(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.RUNNING

        result = runner.invoke(cli, ["down", "--force"])

        assert result.exit_code == 0
        assert "powered off" in result.output
        mock_env._vm.force_stop.assert_called_once()
        # Force must not go through the guest — that's the whole point of it
        # working on a wedged VM.
        mock_env.shutdown.assert_not_called()

    def test_force_kills_a_paused_vm(self, runner, mock_env):
        """The case that started this: a paused VM `down` alone won't touch."""
        mock_env._vm.state.return_value = VMState.PAUSED

        result = runner.invoke(cli, ["down", "-f"])

        assert result.exit_code == 0
        assert "powered off" in result.output
        mock_env._vm.force_stop.assert_called_once()

    def test_force_on_shutoff_is_a_noop(self, runner, mock_env):
        """Nothing to destroy when there's no live QEMU process."""
        mock_env._vm.state.return_value = VMState.SHUTOFF

        result = runner.invoke(cli, ["down", "--force"])

        assert result.exit_code == 0
        assert "not running" in result.output
        mock_env._vm.force_stop.assert_not_called()
