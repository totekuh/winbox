"""Tests for winbox.cli.applocker — enable/disable/status commands."""

from unittest.mock import patch

from winbox.cli import cli
from winbox.cli.applocker import (
    _clear_policy_xml,
    _default_policy_xml,
    _STATUS_SCRIPT,
)

# Module-level constants the tests assert against — reading from disk once.
_DEFAULT_POLICY_XML = _default_policy_xml()
_CLEAR_POLICY_XML = _clear_policy_xml()
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


_OFF = ExecResult(exitcode=0, stdout="AppLocker: off (AppIDSvc Stopped)\n", stderr="")
_ENFORCED = ExecResult(
    exitcode=0,
    stdout="AppLocker: ENFORCED\n  Exe: Enabled (3 rules)\n",
    stderr="",
)


def _run_disable(runner, mock_env, *powershell_results):
    """Invoke `applocker disable` with a scripted exec_powershell sequence.

    Call order is: clear script, then the post-reboot status re-query.
    """
    mock_env.exec_powershell.side_effect = list(powershell_results)
    mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
    with patch("winbox.cli.applocker.time.sleep"), \
         patch("winbox.cli.applocker._ensure_z_drive"):
        return runner.invoke(cli, ["applocker", "disable"])


class TestAppLockerDisable:
    def test_disable_success(self, runner, mock_env):
        """Disable clears policy, nukes caches, reboots VM."""
        result = _run_disable(
            runner, mock_env,
            ExecResult(exitcode=0, stdout="", stderr=""),
            _OFF,
        )

        assert result.exit_code == 0
        assert "AppLocker disabled" in result.output

        # Verify Set-AppLockerPolicy was called via exec_powershell
        script = mock_env.exec_powershell.call_args_list[0][0][0]
        assert "Set-AppLockerPolicy" in script
        assert "Stop-Service" in script
        assert ".AppLocker" in script  # cache deletion

        # Verify reboot was triggered
        shutdown_calls = [
            c for c in mock_env.exec.call_args_list
            if "shutdown" in c[0][0]
        ]
        assert len(shutdown_calls) == 1

    def test_disable_aborts_when_clear_script_fails(self, runner, mock_env):
        """Regression: the clear result was discarded, so a failed
        Set-AppLockerPolicy (e.g. Z: not mounted, script exits 1) still
        rebooted and printed "AppLocker disabled" with exit 0 while the
        guest went on enforcing."""
        result = _run_disable(
            runner, mock_env,
            ExecResult(
                exitcode=1, stdout="",
                stderr="Policy file not found: Z:\\.applocker-policy.xml",
            ),
        )

        assert result.exit_code == 1
        assert "AppLocker disabled" not in result.output
        assert "Failed to clear" in result.output
        assert "Policy file not found" in result.output
        # And it must not have rebooted on the strength of a failed clear.
        assert not [
            c for c in mock_env.exec.call_args_list if "shutdown" in c[0][0]
        ]

    def test_disable_reports_failure_when_still_enforcing(self, runner, mock_env):
        """Exit code 0 from the clear script is not proof the guest stopped
        enforcing — the post-reboot status query is."""
        result = _run_disable(
            runner, mock_env,
            ExecResult(exitcode=0, stdout="", stderr=""),
            _ENFORCED,
        )

        assert result.exit_code == 1
        assert "AppLocker disabled" not in result.output
        assert "still active" in result.output
        assert "ENFORCED" in result.output

    def test_disable_warns_but_succeeds_when_status_unreadable(self, runner, mock_env):
        """A flaky verification query must not be reported as a failed
        disable — the clear itself did succeed."""
        result = _run_disable(
            runner, mock_env,
            ExecResult(exitcode=0, stdout="", stderr=""),
            ExecResult(exitcode=1, stdout="", stderr="WinRM hiccup"),
        )

        assert result.exit_code == 0
        assert "could not verify" in result.output


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

    def test_status_query_fails_with_markup_chars_in_stderr(self, runner, mock_env):
        # Guest-controlled PowerShell stderr can contain rich markup
        # metacharacters (bracketed .NET type names, a stray `[/]`). It is
        # echoed verbatim and must not be parsed as markup and crash.
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1,
            stdout="",
            stderr="Cannot convert [System.String] to type [/] boom",
        )

        result = runner.invoke(cli, ["applocker", "status"])
        assert result.exit_code != 0, result.output
        assert "Failed to query" in result.output
        assert "[System.String]" in result.output


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


class TestClearScriptExitCodeIsMeaningful:
    """The clear script's teardown is all best-effort, and it ends with
    `appidtel.exe stop` — telemetry, which returns non-zero routinely because
    the service is already going away. Without an explicit `exit 0`,
    PowerShell hands the caller that native exit code, so a perfectly good
    clear reads as a failure. Whether the policy actually went away is
    decided by the post-reboot status check, not by this exit code."""

    def test_script_ends_with_an_explicit_success_exit(self):
        from winbox.cli.applocker import _DISABLE_APPLY_SCRIPT

        assert _DISABLE_APPLY_SCRIPT.rstrip().endswith("exit 0"), (
            "clear script must not leak appidtel.exe's exit code to the caller"
        )

    def test_appidtel_stop_is_not_the_last_statement(self):
        from winbox.cli.applocker import _DISABLE_APPLY_SCRIPT

        body = _DISABLE_APPLY_SCRIPT.rstrip()
        assert not body.endswith("appidtel.exe stop")
        assert "appidtel.exe stop" in body  # still performed, just not last
