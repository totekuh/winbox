"""Tests for winbox.cli.network — dns and hosts commands."""

from pathlib import Path
from unittest.mock import patch

from winbox.cli import cli
from winbox.vm import VMState
from winbox.vm.guest import ExecResult


# ─── dns set ──────────────────────────────────────────────────────────────────


class TestDnsSet:
    def test_set_success(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        result = runner.invoke(cli, ["dns", "set", "10.0.0.1"])
        assert result.exit_code == 0
        assert "10.0.0.1" in result.output

        script = mock_env.exec_powershell.call_args[0][0]
        assert "10.0.0.1" in script
        assert "Set-DnsClientServerAddress" in script
        assert "Clear-DnsClientCache" in script

    def test_set_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )
        result = runner.invoke(cli, ["dns", "set", "10.0.0.1"])
        assert result.exit_code != 0
        assert "Failed" in result.output


# ─── dns sync ─────────────────────────────────────────────────────────────────


class TestDnsSync:
    def test_sync_single_ns(self, runner, mock_env, tmp_path):
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver 10.0.0.1\n")

        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        with patch("winbox.cli.network.Path") as mock_path:
            mock_path.side_effect = lambda p: resolv if p == "/etc/resolv.conf" else Path(p)
            mock_path.return_value.exists.return_value = True
            result = runner.invoke(cli, ["dns", "sync"])

        assert result.exit_code == 0
        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "10.0.0.1" in script
        assert "Set-DnsClientServerAddress" in script

    def test_sync_no_resolv(self, runner, mock_env):
        with patch("winbox.cli.network.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            result = runner.invoke(cli, ["dns", "sync"])
        assert result.exit_code != 0

    def test_sync_multiple_ns(self, runner, mock_env, tmp_path):
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver 10.0.0.1\nnameserver 10.0.0.2\n")

        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        with patch("winbox.cli.network.Path") as mock_path:
            mock_path.side_effect = lambda p: resolv if p == "/etc/resolv.conf" else Path(p)
            mock_path.return_value.exists.return_value = True
            result = runner.invoke(cli, ["dns", "sync"])

        assert result.exit_code == 0
        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "10.0.0.1" in script
        assert "10.0.0.2" in script


# ─── dns view ─────────────────────────────────────────────────────────────────


class TestDnsView:
    def test_view_with_dns(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="192.168.122.1\n", stderr=""
        )
        result = runner.invoke(cli, ["dns", "view"])
        assert "192.168.122.1" in result.output

    def test_view_no_dns(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        result = runner.invoke(cli, ["dns", "view"])
        assert "no DNS" in result.output

    def test_view_vm_not_running(self, runner, mock_env):
        mock_env.ping.return_value = False
        mock_env._vm.state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["dns", "view"])
        assert "not running" in result.output

    def test_view_multiple_servers(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="10.0.0.1\n10.0.0.2\n", stderr=""
        )
        result = runner.invoke(cli, ["dns", "view"])
        assert "10.0.0.1" in result.output
        assert "10.0.0.2" in result.output


# ─── hosts view ───────────────────────────────────────────────────────────────


SAMPLE_HOSTS = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
    "#\r\n"
    "# localhost name resolution is handled within DNS itself.\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n"
    "10.0.0.5\tdc01.corp.local\r\n"
    "10.0.0.6\tfs01.corp.local\r\n"
)

EMPTY_HOSTS = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# localhost name resolution is handled within DNS itself.\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n"
)


class TestHostsView:
    def test_view_entries(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout=SAMPLE_HOSTS, stderr=""
        )
        result = runner.invoke(cli, ["hosts", "view"])
        assert result.exit_code == 0
        assert "dc01.corp.local" in result.output
        assert "fs01.corp.local" in result.output
        assert "10.0.0.5" in result.output
        assert "Copyright" not in result.output
        assert "localhost" not in result.output

    def test_view_empty(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout=EMPTY_HOSTS, stderr=""
        )
        result = runner.invoke(cli, ["hosts", "view"])
        assert result.exit_code == 0
        assert "No entries" in result.output

    def test_view_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )
        result = runner.invoke(cli, ["hosts", "view"])
        assert result.exit_code != 0


# ─── hosts add ────────────────────────────────────────────────────────────────


class TestHostsAdd:
    def test_add_entry(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        result = runner.invoke(cli, ["hosts", "add", "10.0.0.5", "dc01.corp.local"])
        assert result.exit_code == 0
        assert "10.0.0.5" in result.output
        assert "dc01.corp.local" in result.output

        script = mock_env.exec_powershell.call_args[0][0]
        assert "Add-Content" in script
        assert "10.0.0.5" in script
        assert "dc01.corp.local" in script

    def test_add_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )
        result = runner.invoke(cli, ["hosts", "add", "10.0.0.5", "dc01.corp.local"])
        assert result.exit_code != 0

    def test_add_missing_args(self, runner, mock_env):
        result = runner.invoke(cli, ["hosts", "add", "10.0.0.5"])
        assert result.exit_code != 0


# ─── hosts set ────────────────────────────────────────────────────────────────


class TestHostsSet:
    def test_set_entry(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        result = runner.invoke(cli, ["hosts", "set", "10.0.0.5", "dc01.corp.local"])
        assert result.exit_code == 0
        assert "10.0.0.5" in result.output
        assert "dc01.corp.local" in result.output

        script = mock_env.exec_powershell.call_args[0][0]
        assert "notmatch" in script
        assert r"dc01\.corp\.local" in script
        assert "Set-Content" in script

    def test_set_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Permission denied"
        )
        result = runner.invoke(cli, ["hosts", "set", "10.0.0.5", "dc01.corp.local"])
        assert result.exit_code != 0


# ─── hosts delete ─────────────────────────────────────────────────────────────


class TestHostsDelete:
    def test_delete_entry(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        result = runner.invoke(cli, ["hosts", "delete", "dc01.corp.local"])
        assert result.exit_code == 0
        assert "Removed" in result.output
        assert "dc01.corp.local" in result.output

        script = mock_env.exec_powershell.call_args[0][0]
        assert "notmatch" in script
        assert r"dc01\.corp\.local" in script
        assert "Set-Content" in script

    def test_delete_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="File not found"
        )
        result = runner.invoke(cli, ["hosts", "delete", "dc01.corp.local"])
        assert result.exit_code != 0

    def test_delete_missing_arg(self, runner, mock_env):
        result = runner.invoke(cli, ["hosts", "delete"])
        assert result.exit_code != 0
