"""Tests for winbox.cli.autologin — enable/disable/status commands."""

from winbox.cli import cli
from winbox.cli.autologin import (
    _DISABLE_ARGV,
    _PWDLESS_REG,
    _STATUS_SCRIPT,
    _WINLOGON_REG,
    _enable_argv,
)
from winbox.vm.guest import ExecResult


# ─── enable ──────────────────────────────────────────────────────────────────


class TestAutologinEnable:
    def test_enable_success(self, runner, mock_env, cfg):
        """Enable writes all 6 registry values."""
        mock_env.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["autologin", "enable"])
        assert result.exit_code == 0
        assert "Autologin enabled" in result.output
        assert cfg.vm_user in result.output

        expected = _enable_argv(cfg.vm_user, cfg.vm_password)
        assert mock_env.exec_argv.call_count == len(expected)
        for i, args in enumerate(expected):
            call = mock_env.exec_argv.call_args_list[i]
            assert call[0][0] == "reg.exe"
            assert call[0][1] == args

    def test_enable_argv_contents(self, cfg):
        """Verify the six keys we're actually setting."""
        argv = _enable_argv(cfg.vm_user, cfg.vm_password)
        flat = [" ".join(args) for args in argv]

        assert any("AutoAdminLogon" in s and "/d 1" in s for s in flat)
        assert any("DefaultUserName" in s and cfg.vm_user in s for s in flat)
        assert any("DefaultDomainName" in s and "/d ." in s for s in flat)
        assert any("DefaultPassword" in s and cfg.vm_password in s for s in flat)
        assert any("ForceAutoLogon" in s and "/d 1" in s for s in flat)
        assert any(
            "DevicePasswordLessBuildVersion" in s
            and _PWDLESS_REG in s
            and "REG_DWORD" in s
            and "/d 0" in s
            for s in flat
        )

    def test_enable_all_keys_target_correct_hives(self, cfg):
        """5 keys go under Winlogon, 1 under PasswordLess\\Device."""
        argv = _enable_argv(cfg.vm_user, cfg.vm_password)
        winlogon_entries = [a for a in argv if a[1] == _WINLOGON_REG]
        pwdless_entries = [a for a in argv if a[1] == _PWDLESS_REG]
        assert len(winlogon_entries) == 5
        assert len(pwdless_entries) == 1

    def test_enable_fails_on_reg_error(self, runner, mock_env):
        """A reg.exe failure aborts with a non-zero exit code."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=1, stdout="", stderr="ERROR: Access denied"
        )

        result = runner.invoke(cli, ["autologin", "enable"])
        assert result.exit_code != 0
        assert "Failed" in result.output


# ─── disable ─────────────────────────────────────────────────────────────────


class TestAutologinDisable:
    def test_disable_success(self, runner, mock_env):
        """Disable sets AutoAdminLogon=0 and deletes DefaultPassword + ForceAutoLogon."""
        mock_env.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["autologin", "disable"])
        assert result.exit_code == 0
        assert "Autologin disabled" in result.output

        assert mock_env.exec_argv.call_count == len(_DISABLE_ARGV)
        for i, args in enumerate(_DISABLE_ARGV):
            call = mock_env.exec_argv.call_args_list[i]
            assert call[0][0] == "reg.exe"
            assert call[0][1] == args

    def test_disable_argv_contents(self):
        """Disable targets only the three credential-bearing values."""
        flat = [" ".join(args) for args in _DISABLE_ARGV]
        assert any("add" in s and "AutoAdminLogon" in s and "/d 0" in s for s in flat)
        assert any("delete" in s and "DefaultPassword" in s for s in flat)
        assert any("delete" in s and "ForceAutoLogon" in s for s in flat)
        # Don't touch DefaultUserName/DefaultDomainName — they're harmless.
        assert not any("DefaultUserName" in s for s in flat)
        assert not any("DefaultDomainName" in s for s in flat)
        # Don't touch PasswordLess gate on disable.
        assert not any("DevicePasswordLessBuildVersion" in s for s in flat)

    def test_disable_tolerates_missing_delete_target(self, runner, mock_env):
        """reg delete returning non-zero (value already absent) is not fatal."""
        def fake_exec_argv(path, args, **kwargs):
            if args[0] == "delete":
                return ExecResult(exitcode=1, stdout="", stderr="not found")
            return ExecResult(exitcode=0, stdout="", stderr="")

        mock_env.exec_argv.side_effect = fake_exec_argv
        result = runner.invoke(cli, ["autologin", "disable"])
        assert result.exit_code == 0
        assert "Autologin disabled" in result.output

    def test_disable_fails_on_add_error(self, runner, mock_env):
        """A reg add failure (AutoAdminLogon=0) is fatal."""
        def fake_exec_argv(path, args, **kwargs):
            if args[0] == "add":
                return ExecResult(exitcode=1, stdout="", stderr="ERROR")
            return ExecResult(exitcode=0, stdout="", stderr="")

        mock_env.exec_argv.side_effect = fake_exec_argv
        result = runner.invoke(cli, ["autologin", "disable"])
        assert result.exit_code != 0
        assert "Failed" in result.output


# ─── status ──────────────────────────────────────────────────────────────────


class TestAutologinStatus:
    def test_status_on(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Autologin: ON\n  AutoAdminLogon: 1\n  DefaultUserName: Administrator\n",
            stderr="",
        )

        result = runner.invoke(cli, ["autologin", "status"])
        assert result.exit_code == 0
        assert "Autologin: ON" in result.output
        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "AutoAdminLogon" in script
        assert "DevicePasswordLessBuildVersion" in script

    def test_status_off(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="Autologin: OFF\n", stderr=""
        )

        result = runner.invoke(cli, ["autologin", "status"])
        assert result.exit_code == 0
        assert "Autologin: OFF" in result.output

    def test_status_query_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="ERROR: registry unreachable"
        )

        result = runner.invoke(cli, ["autologin", "status"])
        assert result.exit_code != 0
        assert "Failed to query status" in result.output


# ─── constants ───────────────────────────────────────────────────────────────


class TestConstants:
    def test_winlogon_path(self):
        assert _WINLOGON_REG == r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    def test_passwordless_path(self):
        assert _PWDLESS_REG == r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device"

    def test_status_script_reports_all_fields(self):
        """Status script must surface every field we care about."""
        for field in (
            "AutoAdminLogon",
            "DefaultUserName",
            "DefaultDomainName",
            "DefaultPassword",
            "ForceAutoLogon",
            "DevicePasswordLessBuildVersion",
        ):
            assert field in _STATUS_SCRIPT
