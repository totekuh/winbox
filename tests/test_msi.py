"""Tests for winbox.cli.msi — MSI install command."""

from winbox.cli import cli
from winbox.cli.msi import _STAGING_SUBDIR, _SUCCESS_EXITCODES
from winbox.vm.guest import ExecResult


def _make_msi(cfg, name="test.msi", size=1024):
    msi_path = cfg.winbox_dir / name
    msi_path.write_bytes(b"\x00" * size)
    return msi_path


def _ok(*, stdout="", stderr="", exitcode=0):
    return ExecResult(exitcode=exitcode, stdout=stdout, stderr=stderr)


# ─── success ─────────────────────────────────────────────────────────────────


class TestMsiSuccess:
    def test_install_success(self, runner, mock_env, cfg):
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.side_effect = [
            _ok(),  # cmd.exe copy into C:\Windows\Temp
            _ok(stdout="install ok"),  # msiexec
            _ok(),  # cmd.exe del cleanup
        ]

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code == 0
        assert "MSI installed" in result.output

        calls = mock_env.exec_argv.call_args_list
        assert len(calls) == 3

        # 1) copy from Z:\.msi\test.msi to C:\Windows\Temp\test.msi
        assert calls[0][0][0] == "cmd.exe"
        assert calls[0][0][1][0] == "/c"
        assert calls[0][0][1][1] == "copy"
        assert calls[0][0][1][3] == f"Z:\\{_STAGING_SUBDIR}\\test.msi"
        assert calls[0][0][1][4] == "C:\\Windows\\Temp\\test.msi"

        # 2) msiexec /i <path> /qn
        assert calls[1][0][0] == "msiexec.exe"
        assert calls[1][0][1] == ["/i", "C:\\Windows\\Temp\\test.msi", "/qn"]

        # 3) del C:\Windows\Temp\test.msi
        assert calls[2][0][0] == "cmd.exe"
        assert calls[2][0][1][:2] == ["/c", "del"]
        assert "C:\\Windows\\Temp\\test.msi" in calls[2][0][1]

    def test_staging_dir_gets_cleaned_up(self, runner, mock_env, cfg):
        """After a successful install the staged file is removed."""
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.return_value = _ok()

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code == 0

        staged = cfg.shared_dir / _STAGING_SUBDIR / "test.msi"
        assert not staged.exists()

    def test_reboot_required_is_success(self, runner, mock_env, cfg):
        """msiexec exit 3010 (reboot required) is treated as success."""
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.side_effect = [
            _ok(),  # copy
            _ok(exitcode=3010),  # msiexec
            _ok(),  # cleanup
        ]

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code == 0
        assert "reboot required" in result.output


# ─── passthrough ─────────────────────────────────────────────────────────────


class TestMsiPassthrough:
    def test_property_passthrough(self, runner, mock_env, cfg):
        """PROPERTY=VALUE style args pass through to msiexec verbatim."""
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.return_value = _ok()

        result = runner.invoke(
            cli,
            ["msi", str(msi_path), "INSTALLDIR=C:\\Foo", "ALLUSERS=1"],
        )
        assert result.exit_code == 0

        msiexec_call = mock_env.exec_argv.call_args_list[1]
        args = msiexec_call[0][1]
        assert args == [
            "/i",
            "C:\\Windows\\Temp\\test.msi",
            "/qn",
            "INSTALLDIR=C:\\Foo",
            "ALLUSERS=1",
        ]

    def test_slash_flag_passthrough(self, runner, mock_env, cfg):
        """Unknown /flags pass through without being eaten by Click."""
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.return_value = _ok()

        result = runner.invoke(
            cli,
            ["msi", str(msi_path), "/norestart", "/log", "C:\\install.log"],
        )
        assert result.exit_code == 0

        args = mock_env.exec_argv.call_args_list[1][0][1]
        assert args[-3:] == ["/norestart", "/log", "C:\\install.log"]


# ─── failure & cleanup ───────────────────────────────────────────────────────


class TestMsiFailure:
    def test_missing_msi_file(self, runner, mock_env):
        """Click's exists=True rejects nonexistent paths before we run."""
        result = runner.invoke(cli, ["msi", "/tmp/does-not-exist.msi"])
        assert result.exit_code != 0
        mock_env.exec_argv.assert_not_called()

    def test_copy_failure_exits_nonzero(self, runner, mock_env, cfg):
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.side_effect = [
            _ok(exitcode=1, stderr="The system cannot find the file specified."),  # copy fails
            _ok(),  # cleanup still runs via finally
        ]

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code != 0
        assert "Failed to copy" in result.output

    def test_msiexec_failure_exits_with_its_code(self, runner, mock_env, cfg):
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.side_effect = [
            _ok(),  # copy ok
            _ok(exitcode=1603, stderr="Fatal error during installation."),  # msiexec fails
            _ok(),  # cleanup
        ]

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code == 1603
        assert "msiexec failed" in result.output

    def test_staging_cleaned_up_on_failure(self, runner, mock_env, cfg):
        """The local staged copy is removed even when msiexec fails."""
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.side_effect = [
            _ok(),  # copy
            _ok(exitcode=1603),  # msiexec fails
            _ok(),  # cleanup
        ]

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code == 1603

        staged = cfg.shared_dir / _STAGING_SUBDIR / "test.msi"
        assert not staged.exists()

    def test_guest_cleanup_is_best_effort(self, runner, mock_env, cfg):
        """Cleanup del failing doesn't mask the real install result."""
        msi_path = _make_msi(cfg)
        mock_env.exec_argv.side_effect = [
            _ok(),  # copy
            _ok(stdout="ok"),  # msiexec success
            _ok(exitcode=1, stderr="access denied"),  # cleanup fails (ignored)
        ]

        result = runner.invoke(cli, ["msi", str(msi_path)])
        assert result.exit_code == 0
        assert "MSI installed" in result.output


# ─── constants ───────────────────────────────────────────────────────────────


class TestConstants:
    def test_staging_subdir_is_hidden(self):
        """Leading dot keeps the subdir out of tool/loot counts."""
        assert _STAGING_SUBDIR.startswith(".")

    def test_reboot_code_is_success(self):
        assert 0 in _SUCCESS_EXITCODES
        assert 3010 in _SUCCESS_EXITCODES
        assert 1603 not in _SUCCESS_EXITCODES
