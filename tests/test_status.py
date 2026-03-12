"""Tests for winbox status and vnc commands."""

from unittest.mock import patch, MagicMock

from winbox.cli import cli
from winbox.vm import VMState


class TestStatusRunning:
    def test_shows_vm_name(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "winbox" in result.output

    def test_shows_running_state(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "running" in result.output

    def test_shows_ip(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "192.168.122.203" in result.output

    def test_shows_agent_responding(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "responding" in result.output

    def test_shows_disk_usage(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "6.5 GB" in result.output

    def test_shows_snapshot_count(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "1" in result.output

    def test_shows_tool_count(self, runner, mock_env, cfg):
        # Create some tool files (all non-hidden files counted)
        (cfg.tools_dir / "SharpHound.exe").touch()
        (cfg.tools_dir / "PsExec64.exe").touch()
        (cfg.tools_dir / "Invoke-Kerberoast.ps1").touch()
        (cfg.tools_dir / ".ssh_pubkey").touch()  # hidden, not counted
        result = runner.invoke(cli, ["status"])
        assert "3 files" in result.output

    def test_shows_loot_count(self, runner, mock_env, cfg):
        (cfg.loot_dir / "creds.txt").write_text("data")
        (cfg.loot_dir / "hashes.ntds").write_text("data")
        result = runner.invoke(cli, ["status"])
        assert "2 files" in result.output

    def test_zero_tools(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "0 files" in result.output

    def test_zero_loot(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "0 files" in result.output

    def test_loot_excludes_job_logs(self, runner, mock_env, cfg):
        """Job log files in .jobs/ should not inflate the loot count."""
        (cfg.loot_dir / "creds.txt").write_text("data")
        (cfg.jobs_log_dir / "1.stdout").write_text("output")
        (cfg.jobs_log_dir / "1.stderr").write_text("")
        result = runner.invoke(cli, ["status"])
        assert "1 files" in result.output


class TestStatusAgent:
    def test_agent_not_responding(self, runner, mock_env):
        mock_env.ping.return_value = False
        result = runner.invoke(cli, ["status"])
        assert "not responding" in result.output

    def test_agent_responding(self, runner, mock_env):
        result = runner.invoke(cli, ["status"])
        assert "responding" in result.output


class TestStatusStopped:
    def test_shutoff_state(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["status"])
        assert "shut off" in result.output

    def test_no_ip_when_stopped(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["status"])
        assert "192.168.122.203" not in result.output

    def test_no_agent_when_stopped(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["status"])
        assert "responding" not in result.output

    def test_disk_shown_when_stopped(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["status"])
        assert "6.5 GB" in result.output


class TestStatusOtherStates:
    def test_paused(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.PAUSED
        result = runner.invoke(cli, ["status"])
        assert "paused" in result.output

    def test_saved(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.SAVED
        result = runner.invoke(cli, ["status"])
        assert "saved" in result.output

    def test_not_found(self, runner, mock_env):
        mock_env._vm.state.return_value = VMState.NOT_FOUND
        mock_env._vm.disk_usage.return_value = None
        mock_env._vm.snapshot_list.return_value = []
        result = runner.invoke(cli, ["status"])
        assert "not found" in result.output

    def test_no_disk(self, runner, mock_env):
        mock_env._vm.disk_usage.return_value = None
        result = runner.invoke(cli, ["status"])
        assert "Disk" not in result.output

    def test_multiple_snapshots(self, runner, mock_env):
        mock_env._vm.snapshot_list.return_value = ["clean", "pre-attack", "post-pivot"]
        result = runner.invoke(cli, ["status"])
        assert "3" in result.output

    def test_no_ip(self, runner, mock_env):
        mock_env._vm.ip.return_value = None
        result = runner.invoke(cli, ["status"])
        assert "IP" not in result.output


# ─── VNC command ─────────────────────────────────────────────────────────────


class TestVnc:
    @patch("winbox.cli.vm.subprocess.Popen")
    @patch("winbox.cli.vm.shutil.which", return_value="/usr/bin/virt-manager")
    def test_launches_virt_manager(self, mock_which, mock_popen, runner, mock_env):
        result = runner.invoke(cli, ["vnc"])
        assert result.exit_code == 0
        assert "virt-manager launched" in result.output
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        assert args[0] == "virt-manager"
        assert "--connect" in args
        assert "qemu:///system" in args
        assert "--show-domain-console" in args
        assert "winbox" in args

    @patch("winbox.cli.vm.shutil.which", return_value=None)
    def test_not_installed(self, mock_which, runner, mock_env):
        result = runner.invoke(cli, ["vnc"])
        assert result.exit_code != 0
        assert "virt-manager not found" in result.output
        assert "apt install virt-manager" in result.output
