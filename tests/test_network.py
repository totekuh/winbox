"""Tests for winbox.cli.network — net, dns, and hosts commands."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from winbox.cli import cli
from winbox.vm import VMState
from winbox.vm.guest import ExecResult


@pytest.fixture
def mock_nwfilter():
    """Patch winbox.cli.network.nwfilter with sensible defaults."""
    with patch("winbox.cli.network.nwfilter") as m:
        m.FILTER_NAME = "winbox-isolate"
        m.ensure_filter_defined.return_value = None
        m.attach_filter.return_value = True
        m.detach_filter.return_value = False
        m.has_filter.return_value = False
        yield m


# ─── net isolate ──────────────────────────────────────────────────────────────


class TestNetIsolate:
    def test_isolate_attaches_filter(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_link_state.return_value = "up"
        mock_env._vm.name = "winbox"
        result = runner.invoke(cli, ["net", "isolate"])

        assert result.exit_code == 0, result.output
        mock_nwfilter.ensure_filter_defined.assert_called_once()
        mock_nwfilter.attach_filter.assert_called_once_with("winbox")
        assert "nwfilter" in result.output.lower()
        # Old PS route removal must not be invoked anymore.
        mock_env.exec_powershell.assert_not_called()

    def test_isolate_brings_link_up_when_unplugged(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_link_state.return_value = "down"
        mock_env._vm.name = "winbox"
        result = runner.invoke(cli, ["net", "isolate"])

        assert result.exit_code == 0, result.output
        mock_env._vm.net_set_link.assert_called_with("up")
        mock_nwfilter.attach_filter.assert_called_once()

    def test_isolate_idempotent_when_already_attached(
        self, runner, mock_env, mock_nwfilter,
    ):
        mock_nwfilter.attach_filter.return_value = False
        mock_env._vm.net_link_state.return_value = "up"
        result = runner.invoke(cli, ["net", "isolate"])

        assert result.exit_code == 0
        assert "already" in result.output.lower()

    def test_isolate_surfaces_nwfilter_error(self, runner, mock_env, mock_nwfilter):
        mock_nwfilter.attach_filter.side_effect = RuntimeError("libvirt refused")
        result = runner.invoke(cli, ["net", "isolate"])

        assert result.exit_code != 0
        assert "libvirt refused" in result.output

    def test_isolate_vm_not_running(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["net", "isolate"])

        assert result.exit_code != 0
        assert "not running" in result.output
        mock_nwfilter.attach_filter.assert_not_called()


# ─── net connect ──────────────────────────────────────────────────────────────


class TestNetConnect:
    def test_connect_detaches_filter(self, runner, mock_env, mock_nwfilter):
        mock_nwfilter.detach_filter.return_value = True
        mock_env._vm.net_link_state.return_value = "up"
        mock_env._vm.ip.return_value = "192.168.122.203"
        mock_env._vm.name = "winbox"
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        mock_env.exec.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["net", "connect"])

        assert result.exit_code == 0, result.output
        mock_nwfilter.detach_filter.assert_called_once_with("winbox")

    def test_connect_also_brings_link_up(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_link_state.return_value = "down"
        mock_env._vm.ip.return_value = "192.168.122.203"
        mock_env._vm.name = "winbox"
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        mock_env.exec.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["net", "connect"])

        assert result.exit_code == 0
        mock_env._vm.net_set_link.assert_any_call("up")
        mock_nwfilter.detach_filter.assert_called_once()

    def test_connect_tolerates_detach_failure(self, runner, mock_env, mock_nwfilter):
        """Detach failure is a warning, not a hard error — connect should still run."""
        mock_nwfilter.detach_filter.side_effect = RuntimeError("busted")
        mock_env._vm.net_link_state.return_value = "up"
        mock_env._vm.name = "winbox"
        mock_env.exec.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["net", "connect"])

        assert result.exit_code == 0
        assert "busted" in result.output


# ─── net status ───────────────────────────────────────────────────────────────


class TestNetStatus:
    def test_status_connected(self, runner, mock_env, mock_nwfilter):
        mock_nwfilter.has_filter.return_value = False
        mock_env._vm.net_link_state.return_value = "up"
        mock_env._vm.name = "winbox"
        mock_env.exec_powershell.return_value = ExecResult(0, "1\n", "")
        result = runner.invoke(cli, ["net", "status"])

        assert result.exit_code == 0
        assert "Filter:" in result.output
        assert "none" in result.output
        assert "reachable" in result.output

    def test_status_isolated_by_filter(self, runner, mock_env, mock_nwfilter):
        mock_nwfilter.has_filter.return_value = True
        mock_env._vm.net_link_state.return_value = "up"
        mock_env._vm.name = "winbox"
        result = runner.invoke(cli, ["net", "status"])

        assert result.exit_code == 0
        assert "winbox-isolate" in result.output
        assert "nwfilter active" in result.output
        # Must NOT probe Get-NetRoute when filter is attached.
        mock_env.exec_powershell.assert_not_called()

    def test_status_unplugged(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_link_state.return_value = "down"
        mock_env._vm.name = "winbox"
        result = runner.invoke(cli, ["net", "status"])

        assert result.exit_code == 0
        assert "link down" in result.output


# ─── net unplug (sanity — unchanged semantics) ────────────────────────────────


class TestNetUnplug:
    def test_unplug_calls_set_link_down(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_set_link.return_value = True
        result = runner.invoke(cli, ["net", "unplug"])

        assert result.exit_code == 0
        mock_env._vm.net_set_link.assert_called_with("down")
        # unplug leaves filter state alone.
        mock_nwfilter.attach_filter.assert_not_called()
        mock_nwfilter.detach_filter.assert_not_called()

    def test_unplug_fails_when_set_link_fails(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_set_link.return_value = False
        result = runner.invoke(cli, ["net", "unplug"])

        assert result.exit_code != 0
        assert "Failed" in result.output or "no interface" in result.output


# ─── net connect (set-link failure branch) ────────────────────────────────────


class TestNetConnectLinkFailure:
    def test_connect_fails_when_set_link_up_fails(self, runner, mock_env, mock_nwfilter):
        mock_env._vm.net_link_state.return_value = "down"
        mock_env._vm.net_set_link.return_value = False
        mock_env._vm.name = "winbox"
        result = runner.invoke(cli, ["net", "connect"])

        assert result.exit_code != 0
        assert "Failed" in result.output or "no interface" in result.output


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
