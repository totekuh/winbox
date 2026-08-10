"""Tests for winbox.cli.detonate — the detonation preflight gate."""

from pathlib import Path
from unittest.mock import patch

from winbox.cli import cli
from winbox.vm.guest import ExecResult


def _dns_result(servers: str) -> ExecResult:
    return ExecResult(exitcode=0, stdout=servers, stderr="")


def _defender_result(value: str) -> ExecResult:
    return ExecResult(exitcode=0, stdout=value, stderr="")


class TestDetonateCheck:
    def test_fails_when_internet_reachable(self, runner, mock_env):
        """The hard gate: guest can route out -> FAIL, non-zero exit."""
        mock_env._vm.net_link_state.return_value = "up"
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=False):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exit_code == 1
        assert "Internet REACHABLE" in result.output
        assert "NOT safe to detonate" in result.output

    def test_passes_gate_when_nwfilter_attached(self, runner, mock_env):
        """nwfilter attached satisfies the internet gate -> exit 0."""
        mock_env._vm.net_link_state.return_value = "up"
        mock_env.exec_powershell.side_effect = [
            _dns_result("192.168.122.1"),
            _defender_result("False"),
        ]
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=True), \
             patch("winbox.cli.detonate._cap_read_pidfile", return_value=(123, Path("/t/x.pcap"))), \
             patch("winbox.cli.detonate._cap_pid_alive", return_value=True), \
             patch("winbox.cli.detonate.sk.is_running", return_value=999), \
             patch("winbox.cli.detonate.sk.query_log_path", return_value=Path("/t/q.log")):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exit_code == 0
        assert "Internet blocked" in result.output
        assert "nwfilter attached" in result.output
        assert "Safe to detonate" in result.output

    def test_markup_chars_in_pcap_path_do_not_crash(self, runner, mock_env):
        """A pcap path from the capture pidfile can contain rich markup
        metacharacters (e.g. `[/]`); the preflight must escape it, not crash
        with MarkupError."""
        mock_env._vm.net_link_state.return_value = "up"
        mock_env.exec_powershell.side_effect = [
            _dns_result("192.168.122.1"),
            _defender_result("False"),
        ]
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=True), \
             patch("winbox.cli.detonate._cap_read_pidfile",
                   return_value=(123, Path("/tmp/weird[/].pcap"))), \
             patch("winbox.cli.detonate._cap_pid_alive", return_value=True), \
             patch("winbox.cli.detonate.sk.is_running", return_value=999), \
             patch("winbox.cli.detonate.sk.query_log_path",
                   return_value=Path("/tmp/q[/].log")):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exception is None, result.exception
        assert result.exit_code == 0
        assert "Capture running" in result.output
        assert "weird" in result.output

    def test_passes_gate_when_nic_unplugged(self, runner, mock_env):
        """Link down (air-gap) also satisfies the gate."""
        mock_env._vm.net_link_state.return_value = "down"
        mock_env.exec_powershell.side_effect = [
            _dns_result("192.168.122.1"),
            _defender_result("False"),
        ]
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=False), \
             patch("winbox.cli.detonate._cap_read_pidfile", return_value=None), \
             patch("winbox.cli.detonate.sk.is_running", return_value=None):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exit_code == 0
        assert "air-gap" in result.output

    def test_warns_but_safe_when_helpers_down(self, runner, mock_env):
        """Gate satisfied but capture/sinkhole/DNS/AV not ready -> warnings, exit 0."""
        mock_env._vm.net_link_state.return_value = "up"
        mock_env._vm.snapshot_list.return_value = []
        mock_env.exec_powershell.side_effect = [
            _dns_result("8.8.8.8"),       # guest DNS not pointed at sink
            _defender_result("True"),     # Defender still on
        ]
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=True), \
             patch("winbox.cli.detonate._cap_read_pidfile", return_value=None), \
             patch("winbox.cli.detonate.sk.is_running", return_value=None):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exit_code == 0
        assert "Capture not running" in result.output
        assert "Sinkhole not running" in result.output
        assert "Guest DNS not pointed at sink" in result.output
        assert "Defender real-time ON" in result.output
        assert "No snapshot" in result.output
        assert "Safe to detonate" in result.output

    def test_warns_when_sinkhole_on_nonstandard_port(self, runner, mock_env):
        """Sinkhole alive + guest DNS -> host IP look fine individually, but if
        the sinkhole bound a non-53 port (e.g. the documented unprivileged
        `--port 5353` path), the guest's queries land nowhere. Must WARN, not
        PASS -- this is the case detonate check previously missed."""
        mock_env._vm.net_link_state.return_value = "up"
        mock_env.exec_powershell.side_effect = [
            _dns_result("192.168.122.1"),  # guest DNS points at the sink IP
            _defender_result("False"),
        ]
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=True), \
             patch("winbox.cli.detonate._cap_read_pidfile", return_value=None), \
             patch("winbox.cli.detonate.sk.is_running", return_value=999), \
             patch("winbox.cli.detonate.sk.read_port", return_value=5353), \
             patch("winbox.cli.detonate.sk.query_log_path", return_value=Path("/t/q.log")):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exit_code == 0
        assert "non-standard port" in result.output
        assert ":5353" in result.output
        assert "PASS  Guest DNS → sink" not in result.output

    def test_dns_query_failure_warns_unknown(self, runner, mock_env):
        """If the guest DNS query fails, report unknown rather than crashing."""
        mock_env._vm.net_link_state.return_value = "up"
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=1, stdout="", stderr="boom"),  # DNS query failed
            _defender_result("False"),
        ]
        with patch("winbox.cli.detonate.nwfilter.has_filter", return_value=True), \
             patch("winbox.cli.detonate._cap_read_pidfile", return_value=None), \
             patch("winbox.cli.detonate.sk.is_running", return_value=None):
            result = runner.invoke(cli, ["detonate", "check"])
        assert result.exit_code == 0
        assert "Guest DNS unknown" in result.output
