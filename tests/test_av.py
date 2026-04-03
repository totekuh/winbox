"""Tests for winbox.cli.av — enable/disable/status commands."""

from unittest.mock import patch

from winbox.cli import cli
from winbox.cli.av import (
    _DISABLE_REG_ARGS,
    _ENABLE_SCRIPT,
    _EXCLUSION_SCRIPT,
    _GP_DEFENDER,
    _GP_DEFENDER_REG,
    _GP_RTP,
    _GP_RTP_REG,
    _MS_RTP,
    _MS_RTP_REG,
    _PREFS_ENABLE_SCRIPT,
    _STATUS_SCRIPT,
)
from winbox.vm.guest import ExecResult


# ─── enable ──────────────────────────────────────────────────────────────────


class TestAvEnable:
    def test_enable_success(self, runner, mock_env):
        """Full enable flow: registry, sc.exe start, exclusions, preferences."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry cleanup
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="START_PENDING", stderr=""
        )

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

        # Verify registry cleanup script was called
        reg_script = mock_env.exec_powershell.call_args_list[0][0][0]
        assert "Remove-ItemProperty" in reg_script
        assert "DisableAntiSpyware" in reg_script

        # Verify sc.exe start was called
        mock_env.exec.assert_called_once()
        assert "sc.exe start WinDefend" in mock_env.exec.call_args[0][0]

        # Verify exclusions script (QEMU GA + VirtIO-FS)
        excl_script = mock_env.exec_powershell.call_args_list[1][0][0]
        assert "Qemu-ga" in excl_script
        assert "Z:\\" in excl_script

        # Verify preferences script
        prefs_script = mock_env.exec_powershell.call_args_list[2][0][0]
        assert "DisableRealtimeMonitoring $false" in prefs_script

    def test_enable_service_already_running(self, runner, mock_env):
        """sc.exe returns 1056 when already running — should succeed."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(
            exitcode=1056, stdout="already running", stderr=""
        )

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

    def test_enable_registry_cleanup_is_best_effort(self, runner, mock_env):
        """Registry cleanup failing should not block the rest of the flow."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=1, stdout="", stderr=""),  # registry (ignored)
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

    def test_enable_exclusions_are_best_effort(self, runner, mock_env):
        """Exclusion failures should not block the rest of the flow."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry
            ExecResult(exitcode=1, stdout="", stderr="failed"),  # exclusions (ignored)
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

    def test_enable_service_start_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=5, stdout="Access is denied", stderr=""
        )

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code != 0
        assert "Failed to start WinDefend" in result.output

    def test_enable_prefs_fail_is_best_effort(self, runner, mock_env):
        """Pref failures don't abort — defaults are already 'enabled'."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry ok
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions ok
            ExecResult(exitcode=1, stdout="", stderr="0x800106ba"),  # prefs fail
        ]
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output


# ─── disable ─────────────────────────────────────────────────────────────────


class TestAvDisable:
    def test_disable_success(self, runner, mock_env):
        """Disable sets reg keys then reboots."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        with patch("winbox.cli.av.time.sleep"), \
             patch("winbox.cli.av._ensure_z_drive"):
            result = runner.invoke(cli, ["av", "disable"])

        assert result.exit_code == 0
        assert "Defender disabled" in result.output

        # Verify reg.exe was called for each key
        assert mock_env.exec_argv.call_count == len(_DISABLE_REG_ARGS)
        for i, args in enumerate(_DISABLE_REG_ARGS):
            call_args = mock_env.exec_argv.call_args_list[i]
            assert call_args[0][0] == "reg.exe"
            assert call_args[0][1] == args

        # Verify reboot was triggered
        reboot_calls = [
            c for c in mock_env.exec.call_args_list
            if "shutdown" in c[0][0]
        ]
        assert len(reboot_calls) == 1
        assert "shutdown /r" in reboot_calls[0][0][0]

    def test_disable_reg_failure(self, runner, mock_env):
        """Reg.exe failure should abort before reboot."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )

        result = runner.invoke(cli, ["av", "disable"])
        assert result.exit_code != 0
        assert "Failed" in result.output
        # Should NOT have rebooted
        mock_env.exec.assert_not_called()

    def test_disable_reboot_wait_failure(self, runner, mock_env):
        """GuestAgentError during reboot wait should exit cleanly."""
        from winbox.vm.guest import GuestAgentError

        mock_env.exec_argv.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.wait.side_effect = GuestAgentError("timeout")

        with patch("winbox.cli.av.time.sleep"), \
             patch("winbox.cli.av._ensure_z_drive"):
            result = runner.invoke(cli, ["av", "disable"])

        assert result.exit_code != 0
        assert "not responding" in result.output

    def test_disable_uses_no_encoded_powershell(self, runner, mock_env):
        """AMSI blocks encoded PowerShell — disable uses reg.exe only."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        with patch("winbox.cli.av.time.sleep"), \
             patch("winbox.cli.av._ensure_z_drive"):
            runner.invoke(cli, ["av", "disable"])

        mock_env.exec_powershell.assert_not_called()


# ─── status ──────────────────────────────────────────────────────────────────


class TestAvStatus:
    def test_status_enabled(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=(
                "Defender: ON\n"
                "  RealTimeProtection: True\n"
                "  AMSI/ScriptScanning: True\n"
                "  BehaviorMonitoring: True\n"
                "  IOAVProtection: True\n"
            ),
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "ON" in result.output
        assert "RealTimeProtection: True" in result.output

    def test_status_disabled(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: OFF (service running but all protections disabled)\n",
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "OFF" in result.output

    def test_status_service_stopped(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: off (service stopped)\n",
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "off" in result.output

    def test_status_not_installed(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: not installed\n",
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "not installed" in result.output

    def test_status_partial(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=(
                "Defender: partial\n"
                "  RealTimeProtection: True\n"
                "  AMSI/ScriptScanning: False\n"
                "  BehaviorMonitoring: False\n"
                "  IOAVProtection: False\n"
            ),
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "partial" in result.output

    def test_status_query_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Service error"
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code != 0
        assert "Failed to query" in result.output


# ─── scripts ─────────────────────────────────────────────────────────────────


class TestScriptContent:
    """Verify the PowerShell scripts reference the right registry paths."""

    def test_enable_script_removes_gp_keys(self):
        assert "DisableAntiSpyware" in _ENABLE_SCRIPT
        assert _GP_DEFENDER in _ENABLE_SCRIPT
        assert _GP_RTP in _ENABLE_SCRIPT
        assert _MS_RTP in _ENABLE_SCRIPT

    def test_prefs_enable_all_five(self):
        assert "DisableRealtimeMonitoring $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableIOAVProtection $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableBehaviorMonitoring $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableBlockAtFirstSeen $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableScriptScanning $false" in _PREFS_ENABLE_SCRIPT

    def test_exclusion_script_covers_ga_and_virtiofs(self):
        assert "Qemu-ga" in _EXCLUSION_SCRIPT
        assert "Z:\\" in _EXCLUSION_SCRIPT
        assert "Add-MpPreference" in _EXCLUSION_SCRIPT

    def test_disable_reg_args_cover_all_keys(self):
        combined = " ".join(arg for args in _DISABLE_REG_ARGS for arg in args)
        assert "DisableAntiSpyware" in combined
        assert "DisableRealtimeMonitoring" in combined
        assert "DisableIOAVProtection" in combined
        assert "DisableBehaviorMonitoring" in combined
        assert "DisableScriptScanning" in combined
        # Uses GP keys only (non-policy keys are ACL-protected by Defender)
        assert _GP_DEFENDER_REG in combined
        assert _GP_RTP_REG in combined
        # All arg lists start with "add"
        for args in _DISABLE_REG_ARGS:
            assert args[0] == "add"

    def test_registry_paths_are_consistent(self):
        """PS paths (HKLM:) must match reg.exe paths (HKLM) after colon strip."""
        assert _GP_DEFENDER == _GP_DEFENDER_REG.replace("HKLM", "HKLM:", 1)
        assert _GP_RTP == _GP_RTP_REG.replace("HKLM", "HKLM:", 1)
        assert _MS_RTP == _MS_RTP_REG.replace("HKLM", "HKLM:", 1)

    def test_status_script_checks_service_and_prefs(self):
        assert "Get-Service WinDefend" in _STATUS_SCRIPT
        assert "Get-MpPreference" in _STATUS_SCRIPT
        assert "Get-MpComputerStatus" in _STATUS_SCRIPT
        assert "RealTimeProtection" in _STATUS_SCRIPT
        assert "AMSI" in _STATUS_SCRIPT
        assert "BehaviorMonitor" in _STATUS_SCRIPT
