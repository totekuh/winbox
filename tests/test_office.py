"""Tests for winbox.cli.office — Office installation command."""

from unittest.mock import MagicMock, patch
import subprocess

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.vm.guest import ExecResult


@pytest.fixture
def office_env(cfg):
    """Patch VM/GA/ensure_running for the office command."""
    ga = MagicMock()
    ga.ping.return_value = True

    vm = MagicMock()

    with (
        patch("winbox.cli.office.ensure_running"),
        patch("winbox.cli.office.GuestAgent", return_value=ga),
        patch("winbox.cli.office.VM", return_value=vm),
        patch("winbox.cli.Config.load", return_value=cfg),
    ):
        ga._vm = vm
        yield ga


class TestOffice:
    def test_office_success(self, runner, office_env, cfg):
        """Happy path: desktop check passes, download OK, install OK, macros OK."""
        office_env.exec.side_effect = [
            ExecResult(exitcode=0, stdout="C:\\Windows\\explorer.exe\n", stderr=""),  # where explorer.exe
            ExecResult(exitcode=0, stdout="", stderr=""),  # setup.exe /configure
        ]
        office_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        with patch("winbox.cli.office.subprocess") as mock_sub:
            mock_sub.run.return_value = MagicMock(returncode=0)
            result = runner.invoke(cli, ["office"])

        assert result.exit_code == 0
        assert "Office installed" in result.output
        assert "Macros enabled" in result.output

    def test_office_no_desktop_experience(self, runner, office_env, cfg):
        """Fails when Desktop Experience is not installed."""
        office_env.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="not recognized"
        )
        result = runner.invoke(cli, ["office"])
        assert result.exit_code != 0
        assert "Desktop Experience" in result.output

    def test_office_download_fails(self, runner, office_env, cfg):
        """Fails gracefully when ODT download fails."""
        office_env.exec.return_value = ExecResult(
            exitcode=0, stdout="C:\\Windows\\explorer.exe\n", stderr=""
        )
        with patch("winbox.cli.office.subprocess") as mock_sub:
            mock_sub.run.side_effect = subprocess.CalledProcessError(1, "wget")
            mock_sub.CalledProcessError = subprocess.CalledProcessError
            result = runner.invoke(cli, ["office"])

        assert result.exit_code != 0
        assert "Failed to download" in result.output

    def test_office_install_fails(self, runner, office_env, cfg):
        """Fails when Office setup.exe returns non-zero."""
        office_env.exec.side_effect = [
            ExecResult(exitcode=0, stdout="C:\\Windows\\explorer.exe\n", stderr=""),
            ExecResult(exitcode=1, stdout="", stderr="Installation error"),
        ]
        with patch("winbox.cli.office.subprocess") as mock_sub:
            mock_sub.run.return_value = MagicMock(returncode=0)
            result = runner.invoke(cli, ["office"])

        assert result.exit_code != 0
        assert "failed" in result.output.lower()

    def test_office_copies_config_xml(self, runner, office_env, cfg):
        """Config XML is copied to shared dir before install."""
        office_env.exec.side_effect = [
            ExecResult(exitcode=0, stdout="C:\\Windows\\explorer.exe\n", stderr=""),
            ExecResult(exitcode=0, stdout="", stderr=""),
        ]
        office_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        with patch("winbox.cli.office.subprocess") as mock_sub:
            mock_sub.run.return_value = MagicMock(returncode=0)
            # The config should exist during the command
            result = runner.invoke(cli, ["office"])

        assert result.exit_code == 0
        # After cleanup, config should be removed
        assert not (cfg.shared_dir / "office-config.xml").exists()

    def test_office_cleanup_on_failure(self, runner, office_env, cfg):
        """Cleanup runs even when install fails."""
        office_env.exec.side_effect = [
            ExecResult(exitcode=0, stdout="C:\\Windows\\explorer.exe\n", stderr=""),
            ExecResult(exitcode=1, stdout="", stderr="fail"),
        ]
        with patch("winbox.cli.office.subprocess") as mock_sub:
            mock_sub.run.return_value = MagicMock(returncode=0)
            result = runner.invoke(cli, ["office"])

        # Files should be cleaned up regardless
        assert not (cfg.shared_dir / "setup.exe").exists()
        assert not (cfg.shared_dir / "office-config.xml").exists()

    def test_office_macro_warning(self, runner, office_env, cfg):
        """Warning shown if macro registry keys fail."""
        office_env.exec.side_effect = [
            ExecResult(exitcode=0, stdout="C:\\Windows\\explorer.exe\n", stderr=""),
            ExecResult(exitcode=0, stdout="", stderr=""),
        ]
        office_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="registry error"
        )
        with patch("winbox.cli.office.subprocess") as mock_sub:
            mock_sub.run.return_value = MagicMock(returncode=0)
            result = runner.invoke(cli, ["office"])

        assert result.exit_code == 0
        assert "Warning" in result.output or "may not have been set" in result.output
