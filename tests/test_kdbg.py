"""Tests for the `winbox kdbg` command group."""

from __future__ import annotations

import importlib
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from winbox.vm import VMState

hmp_module = importlib.import_module("winbox.kdbg.hmp")


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
         patch("winbox.kdbg.hmp._qmp_socket_paths", return_value=[]), \
         patch(
             "winbox.kdbg.hmp._libvirt_hmp",
             side_effect=hmp_module._QmpUnavailable("disabled for subprocess tests"),
         ), \
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

    def test_refuses_when_persistent_reader_owns_stub(self, runner, kdbg_env):
        from winbox.cli import cli
        with patch("winbox.cli.kdbg.reader_info", return_value={"port": 4321}):
            result = runner.invoke(cli, ["kdbg", "start"])
        assert result.exit_code == 1
        assert "reader already owns" in result.output
        assert "4321" in result.output
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

    def test_status_reports_connected_reader_without_probe(self, runner, kdbg_env):
        from winbox.cli import cli
        with patch("winbox.cli.kdbg.reader_info", return_value={"port": 1234}):
            result = runner.invoke(cli, ["kdbg", "status"])
        assert result.exit_code == 0
        assert "persistent reader owns it" in result.output
        kdbg_env["probe"].assert_not_called()


class TestKdbgCetSafety:
    def test_status_reports_safe_boot(self, runner, kdbg_env):
        from types import SimpleNamespace
        from winbox.cli import cli

        with patch("winbox.cli.VM", return_value=kdbg_env["vm"]), patch(
            "winbox.cli.GuestAgent",
        ), patch("winbox.cli.ensure_running"), patch(
            "winbox.cli.kdbg.query_cet_status",
            return_value=SimpleNamespace(
                safe_for_debug=True, user_shadow_stack="OFF", strict_mode="OFF",
            ),
        ):
            result = runner.invoke(cli, ["kdbg", "cet-status"])
        assert result.exit_code == 0
        assert "SAFE" in result.output
        assert "UserShadowStack=OFF" in result.output

    def test_prepare_requires_explicit_confirmation(self, runner, kdbg_env):
        from winbox.cli import cli

        with patch("winbox.cli.VM", return_value=kdbg_env["vm"]), patch(
            "winbox.cli.GuestAgent",
        ), patch("winbox.cli.ensure_running"), patch(
            "winbox.cli.kdbg.prepare_cet",
        ) as prepare:
            result = runner.invoke(cli, ["kdbg", "prepare"])
        assert result.exit_code == 1
        assert "--confirm" in result.output
        prepare.assert_not_called()

    def test_prepare_stops_reader_and_preserves_backup(self, runner, kdbg_env, tmp_path):
        from winbox.cli import cli

        backup = tmp_path / "kdbg-cet-backup.json"
        with patch("winbox.cli.VM", return_value=kdbg_env["vm"]), patch(
            "winbox.cli.GuestAgent",
        ), patch("winbox.cli.ensure_running"), patch(
            "winbox.cli.kdbg.stop_reader",
        ) as stop, patch(
            "winbox.cli.kdbg.prepare_cet", return_value=backup,
        ):
            result = runner.invoke(cli, ["kdbg", "prepare", "--confirm"])
        assert result.exit_code == 0
        compact_output = "".join(result.output.split())
        assert "kdbg-cet-backup.json" in compact_output
        assert "Reboot" in result.output
        stop.assert_called_once()

    def test_restore_requires_explicit_confirmation(self, runner, kdbg_env):
        from winbox.cli import cli

        with patch("winbox.cli.VM", return_value=kdbg_env["vm"]), patch(
            "winbox.cli.GuestAgent",
        ), patch("winbox.cli.ensure_running"), patch(
            "winbox.cli.kdbg.restore_cet_policy",
        ) as restore:
            result = runner.invoke(cli, ["kdbg", "restore-cet"])
        assert result.exit_code == 1
        restore.assert_not_called()


class TestKdbgUserBreakpointOwnership:
    def test_hands_persistent_reader_to_foreground_rsp_client(self, runner, kdbg_env):
        from winbox.cli import cli
        from winbox.kdbg.walk import ProcessRecord

        cfg_store = MagicMock()
        target = ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xFFFF0000,
            directory_table_base=0x123000,
        )
        rsp = MagicMock()
        events = []
        with patch("winbox.cli.kdbg.reader_info", return_value={"port": 1234}), \
             patch("winbox.cli.kdbg.debug_snapshot", return_value=nullcontext()), \
             patch("winbox.cli.kdbg._get_store", return_value=cfg_store), \
             patch("winbox.cli.kdbg.find_process", return_value=target), \
             patch(
                 "winbox.cli.kdbg.stop_reader",
                 side_effect=lambda cfg: events.append("stop"),
             ), patch("winbox.cli.kdbg.RspClient") as rsp_cls, patch(
                 "winbox.cli.kdbg.install_user_breakpoint",
                 return_value=SimpleNamespace(elapsed=0.001, target_dtb=0x123000),
             ):
            rsp_cls.connect.side_effect = lambda *a, **kw: events.append("connect") or rsp
            result = runner.invoke(
                cli, ["kdbg", "user-bp", "1234", "0x7ff600001000", "--max-hits", "0"],
            )

        assert result.exit_code == 0, result.output
        assert events == ["stop", "connect"]
        kdbg_env["probe"].assert_not_called()
        rsp.close.assert_called_once()


class TestKdbgResume:
    """`kdbg resume` had zero unit coverage before this — only the live e2e
    suite touched it, which is why a dead conditional (state == RUNNING
    checked after the two guards above it already made that impossible)
    went unnoticed through more than one prior audit pass."""

    def test_running_vm_is_a_clean_noop(self, runner, kdbg_env):
        from winbox.cli import cli
        result = runner.invoke(cli, ["kdbg", "resume"])
        assert result.exit_code == 0
        assert "already running" in result.output.lower()

    def test_shutoff_vm_has_nothing_to_do(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.return_value = VMState.SHUTOFF
        result = runner.invoke(cli, ["kdbg", "resume"])
        assert result.exit_code == 0
        assert "nothing to do" in result.output.lower()

    def test_no_gdbstub_listening_errors(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.return_value = VMState.PAUSED
        kdbg_env["probe"].return_value = False
        result = runner.invoke(cli, ["kdbg", "resume"])
        assert result.exit_code == 1
        assert "not listening" in result.output.lower()

    def test_active_daemon_session_defers_to_detach(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.return_value = VMState.PAUSED
        kdbg_env["probe"].return_value = True
        daemon = MagicMock()
        daemon.session_alive.return_value = True
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon):
            result = runner.invoke(cli, ["kdbg", "resume"])
        assert result.exit_code == 1
        assert "kdbg detach" in result.output

    def test_successful_resume_reports_success_and_never_prints_the_dead_message(
        self, runner, kdbg_env
    ):
        """The removed conditional's message ("gdb halted it on attach")
        could never fire even before removal -- state is always PAUSED by
        this point, never RUNNING -- so it must not reappear."""
        from winbox.cli import cli
        kdbg_env["vm"].state.side_effect = [VMState.PAUSED, VMState.RUNNING]
        kdbg_env["probe"].return_value = True
        daemon = MagicMock()
        daemon.session_alive.return_value = False
        rsp_client = MagicMock()
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon), \
             patch("winbox.cli.kdbg.RspClient") as rsp_cls, \
             patch("time.sleep"):
            rsp_cls.connect.return_value = rsp_client
            result = runner.invoke(cli, ["kdbg", "resume"])
        assert result.exit_code == 0
        assert "VM resumed" in result.output
        assert "halted it on attach" not in result.output
        rsp_client.cont.assert_called_once()
        rsp_client.close.assert_called_once()

    def test_reports_the_real_state_when_release_leaves_it_paused(self, runner, kdbg_env):
        from winbox.cli import cli
        kdbg_env["vm"].state.side_effect = [VMState.PAUSED, VMState.PAUSED]
        kdbg_env["probe"].return_value = True
        daemon = MagicMock()
        daemon.session_alive.return_value = False
        rsp_client = MagicMock()
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon), \
             patch("winbox.cli.kdbg.RspClient") as rsp_cls, \
             patch("time.sleep"):
            rsp_cls.connect.return_value = rsp_client
            result = runner.invoke(cli, ["kdbg", "resume"])
        assert result.exit_code == 0
        assert "VM resumed" not in result.output
        assert "paused" in result.output.lower()


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
