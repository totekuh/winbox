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


class TestKdbgAttachPolicies:
    def test_preflight_forwards_policy_without_forking(self, runner, kdbg_env):
        import json
        from winbox.cli import cli

        daemon = MagicMock()
        daemon.session_alive.return_value = False
        plan = {
            "schema": "winbox.kdbg-staging-preflight/1",
            "staging_policy": "cached-only", "dry_run": True,
        }
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon), \
             patch(
                 "winbox.kdbg.staging.preflight_user_module_staging",
                 return_value=plan,
             ) as preflight, \
             patch("winbox.cli.kdbg.fork_daemon") as fork:
            result = runner.invoke(cli, [
                "kdbg", "attach", "4584", "--staging-policy", "cached-only",
                "--preflight", "--prewarm",
            ])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["dry_run"] is True
        assert json.loads(result.output)["prewarm_requested"] is True
        assert preflight.call_args.kwargs["policy"] == "cached-only"
        fork.assert_not_called()

    def test_invalid_policy_is_rejected_by_click(self, runner, kdbg_env):
        from winbox.cli import cli
        result = runner.invoke(cli, [
            "kdbg", "attach", "4584", "--staging-policy", "guess",
        ])
        assert result.exit_code == 2
        assert "Invalid value" in result.output


class TestKdbgThreads:
    def _target_and_threads(self):
        from winbox.kdbg.walk import ProcessRecord, ThreadRecord, ThreadWalkResult

        target = ProcessRecord(
            pid=4712, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000, create_time=0x11223344,
        )
        result = ThreadWalkResult(
            threads=[ThreadRecord(
                tid=4816, ethread=0xffffae0012345000, state=5,
                state_name="Waiting", wait_reason=6, wait_reason_name="UserRequest",
                priority=13, base_priority=8, context_switches=927,
                teb=0x7ffde000, kernel_stack=0xfffff80001234000,
                stack_limit=0xfffff80001230000, stack_base=0xfffff80001238000,
                start_address=0xfffff80010001000,
                win32_start_address=0x7ff740001000, create_time=0x1234,
                exit_status=259,
            )],
            complete=False,
            truncated_reason="cycle detected at ETHREAD list entry 0xffffae0012345578",
        )
        return target, result

    def test_renders_thread_metadata_and_partial_walk_warning(self, runner, kdbg_env):
        from winbox.cli import cli

        target, walked = self._target_and_threads()
        with patch("winbox.cli.kdbg.debug_snapshot", return_value=nullcontext()), \
             patch("winbox.cli.kdbg._get_store"), \
             patch("winbox.cli.kdbg.find_process", return_value=target), \
             patch("winbox.cli.kdbg.list_threads", return_value=walked):
            result = runner.invoke(cli, ["kdbg", "threads", "4712"])

        assert result.exit_code == 0, result.output
        assert "4816" in result.output
        assert "Waiting" in result.output
        assert "UserRequest" in result.output
        assert "incomplete thread walk" in result.output
        assert "cycle detected at ETHREAD list entry" in result.output
        assert "0xffffae0012345578" in result.output

    def test_emits_machine_safe_thread_json(self, runner, kdbg_env):
        import json
        from winbox.cli import cli

        target, walked = self._target_and_threads()
        with patch("winbox.cli.kdbg.debug_snapshot", return_value=nullcontext()), \
             patch("winbox.cli.kdbg._get_store"), \
             patch("winbox.cli.kdbg.find_process", return_value=target), \
             patch("winbox.cli.kdbg.list_threads", return_value=walked):
            result = runner.invoke(cli, ["kdbg", "threads", "4712", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["pid"] == 4712
        assert payload["complete"] is False
        assert payload["threads"][0]["ethread"] == "0xffffae0012345000"
        assert payload["threads"][0]["state"] == {"raw": 5, "name": "Waiting"}
        assert payload["threads"][0]["wait_reason"] == {
            "raw": 6, "name": "UserRequest",
        }

    def test_bounds_rows_and_emits_resolution_and_current_vcpu(self, runner, kdbg_env):
        import json
        from winbox.cli import cli
        from winbox.kdbg.walk import (
            CurrentVcpuRecord,
            ThreadAddressAttribution,
            ThreadStartAttribution,
        )

        target, walked = self._target_and_threads()
        thread = walked.threads[0]
        attribution = ThreadStartAttribution(
            start_address=ThreadAddressAttribution(
                address=thread.start_address, mapping="kernel_module",
                module="ntoskrnl.exe", module_base=0xfffff80010000000,
                module_size=0x4000, rva=0x1000,
                symbol="PspSystemThreadStartup", symbol_offset=0,
            ),
            win32_start_address=ThreadAddressAttribution(
                address=thread.win32_start_address, mapping="user_module",
                module="target.exe", module_base=0x7ff740000000,
                module_size=0x4000, rva=0x1000, architecture="x64",
            ),
        )
        current = CurrentVcpuRecord(
            vcpu=2, status="current", ethread=thread.ethread,
            eprocess=target.eprocess, pid=target.pid, process_name=target.name,
            tid=thread.tid, in_target_process=True,
        )
        with patch("winbox.cli.kdbg.debug_snapshot", return_value=nullcontext()), \
             patch("winbox.cli.kdbg._get_store"), \
             patch("winbox.cli.kdbg.find_process", return_value=target), \
             patch("winbox.cli.kdbg.list_threads", return_value=walked), \
             patch("winbox.cli.kdbg.resolve_thread_start_addresses", return_value=({thread.ethread: attribution}, ())), \
             patch("winbox.cli.kdbg.list_current_vcpu_threads", return_value=[current]):
            result = runner.invoke(cli, [
                "kdbg", "threads", "4712", "--json", "--resolve",
                "--state", "Waiting", "--limit", "1",
            ])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert (payload["total_count"], payload["matched_count"], payload["returned"]) == (1, 1, 1)
        assert payload["walk_complete"] is False
        assert payload["threads"][0]["running_on_vcpus"] == [2]
        assert payload["threads"][0]["start_attribution"]["start_address"] == {
            "address": "0xfffff80010001000", "mapping": "kernel_module",
            "module": "ntoskrnl.exe", "module_base": "0xfffff80010000000",
            "module_size": "0x4000", "rva": "0x1000", "architecture": None,
            "symbol": "PspSystemThreadStartup", "symbol_offset": "0x0",
        }
        assert payload["current_vcpus"][0]["tid"] == 4816

    def test_summary_omits_rows_without_claiming_walk_truncation(self, runner, kdbg_env):
        import json
        from winbox.cli import cli

        target, walked = self._target_and_threads()
        with patch("winbox.cli.kdbg.debug_snapshot", return_value=nullcontext()), \
             patch("winbox.cli.kdbg._get_store"), \
             patch("winbox.cli.kdbg.find_process", return_value=target), \
             patch("winbox.cli.kdbg.list_threads", return_value=walked), \
             patch("winbox.cli.kdbg.list_current_vcpu_threads", return_value=[]):
            result = runner.invoke(cli, ["kdbg", "threads", "4712", "--json", "--detail", "summary"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["threads"] == []
        assert payload["detail_rows_omitted"] is True
        assert payload["output_truncated"] is False
        assert payload["walk_complete"] is False

    def test_missing_pid_never_walks_threads(self, runner, kdbg_env):
        from winbox.cli import cli

        with patch("winbox.cli.kdbg.debug_snapshot", return_value=nullcontext()), \
             patch("winbox.cli.kdbg._get_store"), \
             patch("winbox.cli.kdbg.find_process", return_value=None), \
             patch("winbox.cli.kdbg.list_threads") as listed:
            result = runner.invoke(cli, ["kdbg", "threads", "9999"])

        assert result.exit_code == 1
        assert "pid 9999 not found" in result.output
        listed.assert_not_called()

    def test_triage_emits_one_snapshot_bounded_machine_safe_view(self, runner, kdbg_env):
        import json
        from winbox.cli import cli
        from winbox.kdbg.walk import (
            CurrentVcpuRecord, ModuleRecord, ThreadAddressAttribution,
            ThreadStartAttribution, UserModuleRecord,
        )

        target, walked = self._target_and_threads()
        thread = walked.threads[0]
        attribution = ThreadStartAttribution(
            start_address=ThreadAddressAttribution(
                address=thread.start_address, mapping="kernel_unmapped",
            ),
            win32_start_address=ThreadAddressAttribution(
                address=thread.win32_start_address, mapping="user_module", module="target.exe",
                module_base=0x7ff740000000, module_size=0x4000, rva=0x1000,
            ),
        )
        current = CurrentVcpuRecord(
            vcpu=2, status="current", ethread=thread.ethread,
            eprocess=target.eprocess, pid=target.pid, process_name=target.name,
            tid=thread.tid, in_target_process=True,
        )
        snapshot = MagicMock(return_value=nullcontext())
        with patch("winbox.cli.kdbg.debug_snapshot", snapshot), \
             patch("winbox.cli.kdbg._get_store"), \
             patch("winbox.cli.kdbg.find_process", return_value=target), \
             patch("winbox.cli.kdbg.list_threads", return_value=walked), \
             patch("winbox.cli.kdbg.list_modules", return_value=[ModuleRecord("ntoskrnl.exe", 0xfffff80010000000, 0x4000, 0)]), \
             patch("winbox.cli.kdbg.ensure_types_loaded"), \
             patch("winbox.cli.kdbg.list_user_modules", return_value=[UserModuleRecord("target.exe", 0x7ff740000000, 0x4000, "C:\\target.exe", 0)]), \
             patch("winbox.cli.kdbg.resolve_thread_start_addresses", return_value=({thread.ethread: attribution}, ())), \
             patch("winbox.cli.kdbg.list_current_vcpu_threads", return_value=[current]):
            result = runner.invoke(cli, ["kdbg", "triage", "4712", "--json", "--thread-limit", "1"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert snapshot.call_count == 1
        assert payload["snapshot"] == "single_rsp_stop"
        assert payload["process"]["pid"] == 4712
        assert payload["threads"][0]["running_on_vcpus"] == [2]
        assert payload["user_modules"]["count"] == 1
        assert payload["unmapped_starts"][0]["mapping"] == "kernel_unmapped"

    def test_triage_bounds_limit_in_click(self, runner, kdbg_env):
        from winbox.cli import cli

        result = runner.invoke(cli, ["kdbg", "triage", "4712", "--thread-limit", "65"])
        assert result.exit_code == 2
        assert "1<=x<=64" in result.output


class TestKdbgDoctor:
    def test_doctor_json_uses_shared_non_disruptive_report(self, runner, kdbg_env):
        import json
        from winbox.cli import cli

        report = {
            "ready": True,
            "vm": {"name": "winbox", "state": "running", "running": True},
            "guest_agent": {"responding": True, "error": None},
            "cet": {"safe_for_debug": True, "summary": "safe", "error": None},
            "symbols": {"nt": {"available": True, "identity": "cached_unverified", "live_base": "not_checked", "build": "build"}},
            "debugger": {"state": "stopped", "owner": None},
            "mcp": {"version": "test", "catalog_revision": "test", "tool_count": 83},
            "notes": [],
        }
        with patch("winbox.cli.kdbg.collect_doctor", return_value=report) as doctor:
            result = runner.invoke(cli, ["kdbg", "doctor", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == report
        assert doctor.call_args.kwargs["tool_count"] == 83


class TestKdbgTargetStatus:
    def test_emits_machine_safe_liveness_json(self, runner, kdbg_env):
        import json
        from winbox.cli import cli
        daemon = MagicMock()
        daemon.call.return_value = {
            "state": "gone", "reason": "pid_reused", "advisory": True,
        }
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon):
            result = runner.invoke(cli, ["kdbg", "target-status"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["state"] == "gone"
        daemon.call.assert_called_once_with("target_status")


def test_ghidra_cancel_forwards_exact_background_token(runner, kdbg_env):
    import json
    from winbox.cli import cli

    with patch(
        "winbox.kdbg.decomp.cancel_decomp",
        return_value={"schema": "winbox.decomp-prepare-cancel/1", "cancel_requested": True},
    ) as cancel:
        result = runner.invoke(cli, [
            "kdbg", "ghidra", "cancel", "--token", "a" * 32,
        ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["cancel_requested"] is True
    assert cancel.call_args.kwargs == {"request_id": "", "token": "a" * 32}


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
                enabled_processes=(), unqueryable_processes=(),
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


class TestKdbgBreakpointCliParity:
    def test_watchpoint_and_repeated_actions_forward_exact_contract(
        self, runner, kdbg_env,
    ):
        from winbox.cli import cli

        client = MagicMock()
        client.call.return_value = {
            "id": 3, "va": "0x1000", "user_mode": True, "hw": True,
            "wp_type": "access", "wp_size": 8,
            "condition": "rcx == 4", "actions": ["rax", "bytes(rdx,16)"],
            "elapsed_ms": 1.25,
        }
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, [
                "kdbg", "bp", "0x1000", "--watch", "access", "--size", "8",
                "--condition", "rcx == 4", "--action", "rax",
                "--action", "bytes(rdx,16)",
            ])

        assert result.exit_code == 0, result.output
        client.call.assert_called_once_with(
            "bp_add", target="0x1000", mode="hw", condition="rcx == 4",
            wp_type="access", wp_size=8, actions=["rax", "bytes(rdx,16)"],
        )
        assert "watch-access/8" in result.output
        assert "actions=2" in result.output

    @pytest.mark.parametrize("size", ["0", "3", "16"])
    def test_watchpoint_size_rejects_unsupported_width_before_daemon(
        self, runner, kdbg_env, size,
    ):
        from winbox.cli import cli

        client = MagicMock()
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, [
                "kdbg", "bp", "0x1000", "--watch", "write", "--size", size,
            ])
        assert result.exit_code == 2
        client.call.assert_not_called()

    def test_size_without_watch_is_not_forwarded(self, runner, kdbg_env):
        from winbox.cli import cli

        client = MagicMock()
        client.call.return_value = {
            "id": 1, "va": "0x1000", "user_mode": False, "hw": True,
            "condition": None, "elapsed_ms": 1.0,
        }
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, ["kdbg", "bp", "0x1000", "--size", "8"])
        assert result.exit_code == 0, result.output
        client.call.assert_called_once_with(
            "bp_add", target="0x1000", mode="hw", condition=None,
        )

    def test_bp_trace_forwards_all_query_options_and_renders_compact_rows(
        self, runner, kdbg_env,
    ):
        from winbox.cli import cli

        client = MagicMock()
        client.call.return_value = {
            "id": 3,
            "entries": [{
                "hit": 40, "rip": "0x1234", "values": {"rax": "0x22"},
            }],
            "total": 100, "returned": 1, "truncated": True, "next_hit": 41,
            "summary": {"rax": {"distinct": 1}},
        }
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, [
                "kdbg", "bp-trace", "3", "--from-hit", "40", "--limit", "50",
                "--expression", "rax", "--value", "34", "--errors-only",
                "--summary", "--top", "7",
            ])

        assert result.exit_code == 0, result.output
        client.call.assert_called_once_with(
            "bp_trace", id=3, tail=20, from_hit=40, limit=50,
            expression="rax", value="34", errors_only=True, summary=True, top=7,
        )
        assert "#40" in result.output
        assert "rax=0x22" in result.output
        assert "next_hit=41" in result.output
        assert "truncated" in result.output

    def test_bp_trace_json_is_machine_safe(self, runner, kdbg_env):
        import json
        from winbox.cli import cli

        payload = {
            "id": 1, "entries": [], "total": 0, "returned": 0,
            "truncated": False,
        }
        client = MagicMock()
        client.call.return_value = payload
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, ["kdbg", "bp-trace", "1", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == payload

    @pytest.mark.parametrize(
        "arguments",
        [
            ["--tail", "0"], ["--tail", "201"],
            ["--limit", "0"], ["--top", "21"], ["--from-hit", "-1"],
        ],
    )
    def test_bp_trace_bounds_fail_before_daemon(
        self, runner, kdbg_env, arguments,
    ):
        from winbox.cli import cli

        client = MagicMock()
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, ["kdbg", "bp-trace", "1", *arguments])
        assert result.exit_code == 2
        client.call.assert_not_called()

    def test_bps_renders_watchpoint_kind(self, runner, kdbg_env):
        from winbox.cli import cli

        client = MagicMock()
        client.call.return_value = {"bps": [{
            "id": 1, "va": "0x1000", "hw": True, "wp_type": "write",
            "wp_size": 4, "hits": 2, "age_s": 1.0, "target": "buffer",
        }]}
        with patch("winbox.cli.kdbg._client", return_value=client):
            result = runner.invoke(cli, ["kdbg", "bps"])
        assert result.exit_code == 0, result.output
        assert "write/4" in result.output


class TestKdbgDetach:
    def test_clean_detach_uses_resume_guard_only_with_certificate(
        self, runner, kdbg_env
    ):
        from winbox.cli import cli

        daemon = MagicMock()
        daemon.session_alive.side_effect = [True, False]
        daemon.call.return_value = {
            "shutting_down": True,
            "resume_safe": True,
            "cr3_poisoned": False,
        }
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon), \
             patch(
                 "winbox.kdbg.debugger.continue_job.poll_continue",
                 return_value={"state": "idle"},
             ), \
             patch("winbox.cli.kdbg.ensure_not_paused", return_value=None) as guard:
            result = runner.invoke(cli, ["kdbg", "detach"])

        assert result.exit_code == 0, result.output
        assert "detached" in result.output
        guard.assert_called_once()

    def test_poisoned_detach_skips_resume_guard_and_prints_recovery(
        self, runner, kdbg_env
    ):
        from winbox.cli import cli

        daemon = MagicMock()
        daemon.session_alive.side_effect = [True, False]
        daemon.call.return_value = {
            "shutting_down": True,
            "resume_safe": False,
            "cr3_poisoned": True,
            "recovery": "restore snapshot before resuming",
        }
        with patch("winbox.cli.kdbg.DaemonClient", return_value=daemon), \
             patch(
                 "winbox.kdbg.debugger.continue_job.poll_continue",
                 return_value={"state": "idle"},
             ), \
             patch("winbox.cli.kdbg.ensure_not_paused") as guard:
            result = runner.invoke(cli, ["kdbg", "detach"])

        assert result.exit_code == 0, result.output
        assert "restore snapshot" in result.output
        guard.assert_not_called()


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
