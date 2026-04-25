"""Tests for the `winbox kdbg` command group."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from winbox.vm import VMState


@pytest.fixture
def kdbg_env(cfg):
    """Mock VM + virsh/socket so kdbg commands run without a live VM.

    The HMP subprocess call lives in ``winbox.kdbg.hmp`` — the CLI module
    imports a thin wrapper around it — so that's where we patch.
    """
    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING

    with patch("winbox.cli.kdbg.VM", return_value=vm), \
         patch("winbox.cli.Config.load", return_value=cfg), \
         patch("winbox.kdbg.hmp.subprocess.run") as mock_run, \
         patch("winbox.cli.kdbg.probe_port", return_value=False) as mock_probe:
        # Default: virsh succeeds and the HMP output looks like a real start
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Waiting for gdb connection on device 'tcp:127.0.0.1:1234'",
            stderr="",
        )
        yield {
            "vm": vm,
            "run": mock_run,
            "probe": mock_probe,
        }


class TestKdbgStart:
    def test_defaults_to_localhost(self, runner, kdbg_env):
        from winbox.cli import cli
        result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 0
        assert "listening on 127.0.0.1:1234" in result.output

        # virsh qemu-monitor-command was called with the right HMP string
        args = kdbg_env["run"].call_args[0][0]
        assert args[:3] == ["virsh", "-c", "qemu:///system"]
        assert "qemu-monitor-command" in args
        assert "--hmp" in args
        hmp = args[args.index("--hmp") + 1]
        assert hmp == "gdbserver tcp:127.0.0.1:1234"

    def test_custom_port(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["run"].return_value.stdout = (
            "Waiting for gdb connection on device 'tcp:127.0.0.1:9999'"
        )
        result = runner.invoke(cli, ["kdbg", "start", "--port", "9999"])
        assert result.exit_code == 0
        assert "127.0.0.1:9999" in result.output
        hmp = kdbg_env["run"].call_args[0][0]
        assert hmp[hmp.index("--hmp") + 1] == "gdbserver tcp:127.0.0.1:9999"

    def test_any_interface_opt_in(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["run"].return_value.stdout = (
            "Waiting for gdb connection on device 'tcp:0.0.0.0:1234'"
        )
        result = runner.invoke(cli, ["kdbg", "start", "--any-interface"])
        assert result.exit_code == 0
        assert "Bound to 0.0.0.0:1234" in result.output
        assert "anyone on this LAN" in result.output
        hmp = kdbg_env["run"].call_args[0][0]
        assert hmp[hmp.index("--hmp") + 1] == "gdbserver tcp:0.0.0.0:1234"

    def test_refuses_when_port_already_in_use(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["probe"].return_value = True  # something already listening
        result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 1
        assert "already listening" in result.output
        kdbg_env["run"].assert_not_called()

    def test_refuses_when_vm_not_running(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 1
        assert "not running" in result.output
        kdbg_env["run"].assert_not_called()

    def test_virsh_failure_surfaces_error(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["run"].return_value = MagicMock(
            returncode=1, stdout="", stderr="qemu agent not connected"
        )
        result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 1
        assert "Failed to start" in result.output
        assert "qemu agent not connected" in result.output

    def test_unexpected_hmp_response_fails(self, runner, kdbg_env):
        """If HMP returns 0 but the message isn't the expected one, bail —
        silent success on a weird response would hide real problems."""
        from winbox.cli import cli
        kdbg_env["run"].return_value = MagicMock(
            returncode=0, stdout="Unknown command", stderr=""
        )
        result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 1
        assert "Unexpected HMP response" in result.output

    def test_prints_cheat_sheet(self, runner, kdbg_env):
        from winbox.cli import cli
        result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 0
        # The cheat sheet mentions the key gdb incantations
        assert "target remote :1234" in result.output
        assert "hbreak" in result.output
        assert "detach" in result.output


class TestKdbgStop:
    def test_stop_sends_gdbserver_none(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["run"].return_value = MagicMock(
            returncode=0, stdout="Disabled gdbserver", stderr=""
        )
        result = runner.invoke(cli, ["kdbg", "stop"])
        assert result.exit_code == 0
        assert "gdb stub stopped" in result.output
        hmp = kdbg_env["run"].call_args[0][0]
        assert hmp[hmp.index("--hmp") + 1] == "gdbserver none"

    def test_stop_refuses_when_vm_not_running(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["kdbg", "stop"])
        assert result.exit_code == 1
        assert "not running" in result.output

    def test_stop_virsh_failure(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["run"].return_value = MagicMock(
            returncode=1, stdout="", stderr="monitor error"
        )
        result = runner.invoke(cli, ["kdbg", "stop"])
        assert result.exit_code == 1
        assert "Failed to stop" in result.output


class TestKdbgStatus:
    def test_status_listening(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["probe"].return_value = True
        result = runner.invoke(cli, ["kdbg", "status"])
        assert result.exit_code == 0
        assert "listening" in result.output
        assert "127.0.0.1:1234" in result.output

    def test_status_not_running(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["probe"].return_value = False
        result = runner.invoke(cli, ["kdbg", "status"])
        assert result.exit_code == 0
        assert "not running" in result.output

    def test_status_custom_port(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["probe"].return_value = True
        result = runner.invoke(cli, ["kdbg", "status", "--port", "4321"])
        assert result.exit_code == 0
        assert "127.0.0.1:4321" in result.output
        kdbg_env["probe"].assert_called_once_with("127.0.0.1", 4321)

    def test_status_vm_not_running(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["kdbg", "status"])
        assert result.exit_code == 0
        assert "not running" in result.output
        kdbg_env["probe"].assert_not_called()


class TestProbePortHelper:
    """Direct unit test for _probe_port since everything else mocks it out."""

    def test_probe_returns_true_when_port_open(self):
        import socket as _socket
        from winbox.kdbg.hmp import probe_port as _probe_port

        # Open a real listener on an ephemeral port
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            assert _probe_port("127.0.0.1", port) is True
        finally:
            srv.close()

    def test_probe_returns_false_when_port_closed(self):
        from winbox.kdbg.hmp import probe_port as _probe_port

        # Ephemeral port that's definitely not bound
        assert _probe_port("127.0.0.1", 1, timeout=0.1) is False
