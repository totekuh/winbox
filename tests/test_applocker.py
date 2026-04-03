"""Tests for winbox.cli.applocker — enable/disable/status commands."""

from unittest.mock import patch

from winbox.cli import cli
from winbox.cli.applocker import (
    _CLEAR_POLICY_XML,
    _DEFAULT_POLICY_XML,
    _STATUS_SCRIPT,
)
from winbox.vm.guest import ExecResult


# ─── enable ──────────────────────────────────────────────────────────────────


class TestAppLockerEnable:
    def test_enable_success(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        with patch("winbox.cli.applocker.time.sleep"):
            result = runner.invoke(cli, ["applocker", "enable"])

        assert result.exit_code == 0
        assert "AppLocker enforced" in result.output

        # Verify Set-AppLockerPolicy was called
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Set-AppLockerPolicy" in script

        # Verify appidtel, converter, gpupdate were called as separate GA calls
        exec_cmds = [c[0][0] for c in mock_env.exec.call_args_list]
        assert any("appidtel" in cmd for cmd in exec_cmds)
        assert any("AppIdPolicyConverter" in cmd for cmd in exec_cmds)
        assert any("gpupdate" in cmd for cmd in exec_cmds)

    def test_enable_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )

        result = runner.invoke(cli, ["applocker", "enable"])
        assert result.exit_code != 0
        assert "Failed" in result.output


# ─── disable ─────────────────────────────────────────────────────────────────


class TestAppLockerDisable:
    def test_disable_success(self, runner, mock_env):
        """Disable clears policy, nukes caches, reboots VM."""
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        with patch("winbox.cli.applocker.time.sleep"), \
             patch("winbox.cli.applocker._ensure_z_drive"):
            result = runner.invoke(cli, ["applocker", "disable"])

        assert result.exit_code == 0
        assert "AppLocker disabled" in result.output

        # Verify Set-AppLockerPolicy was called via exec_powershell
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Set-AppLockerPolicy" in script
        assert "Stop-Service" in script
        assert ".AppLocker" in script  # cache deletion

        # Verify reboot was triggered
        shutdown_calls = [
            c for c in mock_env.exec.call_args_list
            if "shutdown" in c[0][0]
        ]
        assert len(shutdown_calls) == 1


# ─── status ──────────────────────────────────────────────────────────────────


class TestAppLockerStatus:
    def test_status_enforced(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=(
                "AppLocker: ENFORCED\n"
                "  Appx: Enabled (1 rules)\n"
                "  Exe: Enabled (3 rules)\n"
                "  Msi: Enabled (3 rules)\n"
                "  Script: Enabled (3 rules)\n"
            ),
            stderr="",
        )

        result = runner.invoke(cli, ["applocker", "status"])
        assert result.exit_code == 0
        assert "ENFORCED" in result.output
        assert "Exe" in result.output

    def test_status_off_service_stopped(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="AppLocker: off (AppIDSvc Stopped)\n",
            stderr="",
        )

        result = runner.invoke(cli, ["applocker", "status"])
        assert result.exit_code == 0
        assert "off" in result.output

    def test_status_off_no_rules(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="AppLocker: off (no rules configured)\n",
            stderr="",
        )

        result = runner.invoke(cli, ["applocker", "status"])
        assert result.exit_code == 0
        assert "no rules" in result.output

    def test_status_not_available(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="AppLocker: not available\n",
            stderr="",
        )

        result = runner.invoke(cli, ["applocker", "status"])
        assert result.exit_code == 0
        assert "not available" in result.output

    def test_status_query_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="WMI error"
        )

        result = runner.invoke(cli, ["applocker", "status"])
        assert result.exit_code != 0
        assert "Failed to query" in result.output


# ─── policy content ──────────────────────────────────────────────────────────


class TestPolicyContent:
    def test_default_policy_has_exe_rules(self):
        assert 'Type="Exe"' in _DEFAULT_POLICY_XML
        assert 'EnforcementMode="Enabled"' in _DEFAULT_POLICY_XML
        assert "%WINDIR%" in _DEFAULT_POLICY_XML
        assert "%PROGRAMFILES%" in _DEFAULT_POLICY_XML

    def test_default_policy_has_script_rules(self):
        assert 'Type="Script"' in _DEFAULT_POLICY_XML

    def test_default_policy_has_msi_rules(self):
        assert 'Type="Msi"' in _DEFAULT_POLICY_XML

    def test_default_policy_has_appx_rules(self):
        assert 'Type="Appx"' in _DEFAULT_POLICY_XML

    def test_default_policy_has_no_dll_rules(self):
        assert 'Type="Dll"' not in _DEFAULT_POLICY_XML

    def test_default_policy_allows_admins_everywhere(self):
        assert "S-1-5-32-544" in _DEFAULT_POLICY_XML

    def test_default_policy_allows_everyone_in_safe_paths(self):
        assert "S-1-1-0" in _DEFAULT_POLICY_XML

    def test_clear_policy_sets_not_configured(self):
        assert 'EnforcementMode="NotConfigured"' in _CLEAR_POLICY_XML

    def test_status_script_checks_enforcement(self):
        assert "Get-AppLockerPolicy" in _STATUS_SCRIPT
        assert "AppIDSvc" in _STATUS_SCRIPT
        assert "EnforcementMode" in _STATUS_SCRIPT
