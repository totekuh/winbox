"""Tests for winbox.cli.av — enable/disable/status commands."""

from unittest.mock import MagicMock, patch

import pytest

from winbox.cli import cli
from winbox.defender import EnableOutcome

# enable() reports two facts now; these are the two shapes the tests use.
_OUT_REBOOT = EnableOutcome(reboot_required=True)
_OUT_DONE = EnableOutcome(reboot_required=False)
from winbox.defender import (
    DISABLE_REG_ARGS as _DISABLE_REG_ARGS,
    ENABLE_SCRIPT as _ENABLE_SCRIPT,
    EXCLUSION_SCRIPT as _EXCLUSION_SCRIPT,
    GP_DEFENDER as _GP_DEFENDER,
    GP_DEFENDER_REG as _GP_DEFENDER_REG,
    GP_RTP as _GP_RTP,
    GP_RTP_REG as _GP_RTP_REG,
    MS_RTP as _MS_RTP,
    MS_RTP_REG as _MS_RTP_REG,
    PREFS_ENABLE_SCRIPT as _PREFS_ENABLE_SCRIPT,
    STATUS_SCRIPT as _STATUS_SCRIPT,
)
from winbox.vm.guest import ExecResult


# ─── enable ──────────────────────────────────────────────────────────────────


class TestAvEnable:
    @pytest.fixture(autouse=True)
    def _already_fully_on(self):
        """These tests are about the enable *steps*, not the verification.

        `av enable` now checks Defender's real state afterwards and reboots
        once if the boot-start filter driver hasn't loaded; pinning that to
        "already on" keeps these focused on what they name.
        """
        with patch("winbox.cli.av._status_text", return_value="Defender: ON"):
            yield

    def test_enable_success(self, runner, mock_env):
        """Full enable flow: registry, sc.exe start, exclusions, preferences."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry cleanup
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="START_PENDING", stderr=""
        )

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

        # Verify registry cleanup script was called
        reg_script = mock_env.exec_powershell.call_args_list[0][0][0]
        assert "Remove-ItemProperty" in reg_script
        assert "DisableAntiSpyware" in reg_script

        # Verify sc.exe start was called
        mock_env.exec.assert_called_once()
        assert "sc.exe start WinDefend" in mock_env.exec.call_args[0][0]

        # Verify exclusions script (QEMU GA + VirtIO-FS)
        excl_script = mock_env.exec_powershell.call_args_list[1][0][0]
        assert "Qemu-ga" in excl_script
        assert "Z:\\" in excl_script

        # Verify preferences script
        prefs_script = mock_env.exec_powershell.call_args_list[2][0][0]
        assert "DisableRealtimeMonitoring $false" in prefs_script

    def test_enable_service_already_running(self, runner, mock_env):
        """sc.exe returns 1056 when already running — should succeed."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(
            exitcode=1056, stdout="already running", stderr=""
        )

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

    def test_enable_registry_cleanup_is_best_effort(self, runner, mock_env):
        """Registry cleanup failing should not block the rest of the flow."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=1, stdout="", stderr=""),  # registry (ignored)
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

    def test_enable_exclusions_are_best_effort(self, runner, mock_env):
        """Exclusion failures should not block the rest of the flow."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry
            ExecResult(exitcode=1, stdout="", stderr="failed"),  # exclusions (ignored)
            ExecResult(exitcode=0, stdout="", stderr=""),  # prefs
        ]
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output

    def test_enable_service_start_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=5, stdout="Access is denied", stderr=""
        )

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code != 0
        assert "Failed to start WinDefend" in result.output

    def test_enable_prefs_fail_is_best_effort(self, runner, mock_env):
        """Pref failures don't abort — defaults are already 'enabled'."""
        mock_env.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),  # registry ok
            ExecResult(exitcode=0, stdout="", stderr=""),  # exclusions ok
            ExecResult(exitcode=1, stdout="", stderr="0x800106ba"),  # prefs fail
        ]
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["av", "enable"])
        assert result.exit_code == 0
        assert "Defender enabled" in result.output


# ─── disable ─────────────────────────────────────────────────────────────────


class TestAvDisable:
    def test_disable_success(self, runner, mock_env):
        """Disable sets reg keys then reboots."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        # Benign reads: TP off (no TAMPER_ON) before disable, and Defender
        # reports OFF on the post-reboot verification.
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="TAMPER_OFF\nDefender: OFF (all protections disabled)\n",
            stderr="",
        )

        with patch("winbox.cli.time.sleep"), \
             patch("winbox.cli._ensure_z_drive"):
            result = runner.invoke(cli, ["av", "disable"])

        assert result.exit_code == 0
        assert "Defender disabled" in result.output

        # Verify reg.exe was called for each key
        assert mock_env.exec_argv.call_count == len(_DISABLE_REG_ARGS)
        for i, args in enumerate(_DISABLE_REG_ARGS):
            call_args = mock_env.exec_argv.call_args_list[i]
            assert call_args[0][0] == "reg.exe"
            assert call_args[0][1] == args

        # Verify reboot was triggered
        reboot_calls = [
            c for c in mock_env.exec.call_args_list
            if "shutdown" in c[0][0]
        ]
        assert len(reboot_calls) == 1
        assert "shutdown /r" in reboot_calls[0][0][0]

    def test_disable_reg_failure(self, runner, mock_env):
        """Reg.exe failure should abort before reboot."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )

        result = runner.invoke(cli, ["av", "disable"])
        assert result.exit_code != 0
        assert "Failed" in result.output
        # Should NOT have rebooted
        mock_env.exec.assert_not_called()

    def test_disable_reboot_wait_failure(self, runner, mock_env):
        """GuestAgentError during reboot wait should exit cleanly."""
        from winbox.vm.guest import GuestAgentError

        mock_env.exec_argv.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.wait.side_effect = GuestAgentError("timeout")

        with patch("winbox.cli.time.sleep"), \
             patch("winbox.cli._ensure_z_drive"):
            result = runner.invoke(cli, ["av", "disable"])

        assert result.exit_code != 0
        assert "not responding" in result.output

    def test_disable_mutation_uses_no_encoded_powershell(self, runner, mock_env):
        """AMSI flags `Set-MpPreference -Disable* $true` inside encoded PS, so the
        disable *mutation* must go through reg.exe (exec_argv). Benign reads
        (Tamper-Protection / status) via exec_powershell are allowed — the same
        reads `av status` already does while Defender is live."""
        mock_env.exec_argv.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="TAMPER_OFF\nDefender: OFF (all protections disabled)\n",
            stderr="",
        )

        with patch("winbox.cli.time.sleep"), \
             patch("winbox.cli._ensure_z_drive"):
            runner.invoke(cli, ["av", "disable"])

        # No exec_powershell call may carry a mutating Set-MpPreference payload
        # (that's what AMSI blocks); only benign reads are allowed. Ignore
        # comment lines, which may mention the cmdlet in prose.
        for call in mock_env.exec_powershell.call_args_list:
            script = call[0][0] if call[0] else ""
            code = "\n".join(
                ln for ln in script.splitlines() if not ln.lstrip().startswith("#")
            )
            assert "Set-MpPreference" not in code


# ─── status ──────────────────────────────────────────────────────────────────


class TestAvStatus:
    def test_status_enabled(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=(
                "Defender: ON\n"
                "  RealTimeProtection: True\n"
                "  AMSI/ScriptScanning: True\n"
                "  BehaviorMonitoring: True\n"
                "  IOAVProtection: True\n"
            ),
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "ON" in result.output
        assert "RealTimeProtection: True" in result.output

    def test_status_disabled(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: OFF (service running but all protections disabled)\n",
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "OFF" in result.output

    def test_status_service_stopped(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: off (service stopped)\n",
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "off" in result.output

    def test_status_not_installed(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: not installed\n",
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "not installed" in result.output

    def test_status_partial(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=(
                "Defender: partial\n"
                "  RealTimeProtection: True\n"
                "  AMSI/ScriptScanning: False\n"
                "  BehaviorMonitoring: False\n"
                "  IOAVProtection: False\n"
            ),
            stderr="",
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code == 0
        assert "partial" in result.output

    def test_status_query_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Service error"
        )

        result = runner.invoke(cli, ["av", "status"])
        assert result.exit_code != 0
        assert "Failed to query" in result.output


# ─── scripts ─────────────────────────────────────────────────────────────────


class TestScriptContent:
    """Verify the PowerShell scripts reference the right registry paths."""

    def test_enable_script_removes_gp_keys(self):
        assert "DisableAntiSpyware" in _ENABLE_SCRIPT
        assert _GP_DEFENDER in _ENABLE_SCRIPT
        assert _GP_RTP in _ENABLE_SCRIPT
        assert _MS_RTP in _ENABLE_SCRIPT

    def test_prefs_enable_all_five(self):
        assert "DisableRealtimeMonitoring $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableIOAVProtection $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableBehaviorMonitoring $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableBlockAtFirstSeen $false" in _PREFS_ENABLE_SCRIPT
        assert "DisableScriptScanning $false" in _PREFS_ENABLE_SCRIPT

    def test_exclusion_script_covers_ga_and_virtiofs(self):
        assert "Qemu-ga" in _EXCLUSION_SCRIPT
        assert "Z:\\" in _EXCLUSION_SCRIPT
        assert "Add-MpPreference" in _EXCLUSION_SCRIPT

    def test_disable_reg_args_cover_all_keys(self):
        combined = " ".join(arg for args in _DISABLE_REG_ARGS for arg in args)
        assert "DisableAntiSpyware" in combined
        assert "DisableRealtimeMonitoring" in combined
        assert "DisableIOAVProtection" in combined
        assert "DisableBehaviorMonitoring" in combined
        assert "DisableScriptScanning" in combined
        # Uses GP keys only (non-policy keys are ACL-protected by Defender)
        assert _GP_DEFENDER_REG in combined
        assert _GP_RTP_REG in combined
        # All arg lists start with "add"
        for args in _DISABLE_REG_ARGS:
            assert args[0] == "add"

    def test_registry_paths_are_consistent(self):
        """PS paths (HKLM:) must match reg.exe paths (HKLM) after colon strip."""
        assert _GP_DEFENDER == _GP_DEFENDER_REG.replace("HKLM", "HKLM:", 1)
        assert _GP_RTP == _GP_RTP_REG.replace("HKLM", "HKLM:", 1)
        assert _MS_RTP == _MS_RTP_REG.replace("HKLM", "HKLM:", 1)

    def test_status_script_checks_service_and_prefs(self):
        assert "Get-Service WinDefend" in _STATUS_SCRIPT
        assert "Get-MpPreference" in _STATUS_SCRIPT
        assert "Get-MpComputerStatus" in _STATUS_SCRIPT
        assert "RealTimeProtection" in _STATUS_SCRIPT
        assert "AMSI" in _STATUS_SCRIPT
        assert "BehaviorMonitor" in _STATUS_SCRIPT


class TestEnableNeedsRebootWhenServiceDisabled:
    """A Win11 image built with the offline Defender disable has WinDefend
    marked disabled in the SCM for the whole boot. The start types get
    corrected, but `sc start` still returns 1058 (ERROR_SERVICE_DISABLED) —
    and treating that as fatal meant `av enable` could never re-enable
    Defender on Win11 at all.
    """

    def _ga(self, start_exitcodes):
        from winbox.vm.guest import ExecResult

        ga = MagicMock()
        codes = list(start_exitcodes)

        def fake_exec(cmd, **kw):
            if "sc.exe start WinDefend" in cmd:
                return ExecResult(exitcode=codes.pop(0), stdout="", stderr="")
            return ExecResult(exitcode=0, stdout="", stderr="")

        ga.exec.side_effect = fake_exec
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        ga.exec_argv.return_value = ExecResult(0, "", "")
        return ga

    def test_1058_reports_reboot_required_instead_of_raising(self):
        from winbox import defender

        assert defender.enable(self._ga([1058])).reboot_required is True

    @pytest.mark.parametrize("code", [0, 1056])
    def test_started_or_already_running_completes(self, code):
        from winbox import defender

        assert defender.enable(self._ga([code])).reboot_required is False

    def test_other_failures_still_raise(self):
        from winbox import defender

        with pytest.raises(defender.DefenderError, match="Failed to start WinDefend"):
            defender.enable(self._ga([5]))

    def test_1058_skips_the_steps_that_need_a_running_service(self):
        """Setting preferences against a stopped WinDefend just errors."""
        from winbox import defender

        ga = self._ga([1058])
        defender.enable(ga)
        scripts = [c[0][0] for c in ga.exec_powershell.call_args_list]
        assert not any("Set-MpPreference" in s for s in scripts)

    def test_cli_reboots_and_retries(self, runner, mock_env):
        from winbox.vm.guest import ExecResult

        mock_env.exec_powershell.return_value = ExecResult(
            0, "TAMPER_OFF\nDefender: ON\n", ""
        )
        with (
            patch("winbox.cli.av.defender.enable", side_effect=[_OUT_REBOOT, _OUT_DONE]) as enable,
            patch("winbox.cli.av.reboot_and_wait") as reboot,
        ):
            result = runner.invoke(cli, ["av", "enable"])

        assert result.exit_code == 0
        reboot.assert_called_once()
        assert enable.call_count == 2
        assert "Defender enabled" in result.output

    def test_cli_gives_up_after_one_reboot(self, runner, mock_env):
        with (
            patch("winbox.cli.av.defender.enable", side_effect=[_OUT_REBOOT, _OUT_REBOOT]),
            patch("winbox.cli.av.reboot_and_wait"),
        ):
            result = runner.invoke(cli, ["av", "enable"])

        assert result.exit_code != 0
        assert "still disabled after a reboot" in result.output

    def _mcp_enable(self, ga, unwritten=()):
        """Drive the MCP tool with a real `ga` behind the readback.

        `enable()` performs the readback itself now, so the outcome is what
        carries the answer to the frontend.
        """
        import winbox.mcp as m

        fn = m.av_enable.fn if hasattr(m.av_enable, "fn") else m.av_enable
        outcome = EnableOutcome(
            reboot_required=True, start_types_unwritten=tuple(unwritten)
        )
        with (
            patch.object(m, "_ensure_vm_ready", return_value=(MagicMock(), MagicMock(), ga)),
            patch("winbox.defender.enable", return_value=outcome),
        ):
            return fn()

    def _start_readback(self, values: dict[str, int]):
        """A ga whose `reg.exe query ... /v Start` reports `values`."""
        from winbox.vm.guest import ExecResult

        ga = MagicMock()

        def fake_argv(exe, args, **kw):
            key = args[1]
            svc = key.rsplit("\\", 1)[-1]
            if svc not in values:
                return ExecResult(exitcode=1, stdout="", stderr="not found")
            return ExecResult(
                exitcode=0,
                stdout=f"    Start    REG_DWORD    0x{values[svc]:x}\n",
                stderr="",
            )

        ga.exec_argv.side_effect = fake_argv
        return ga

    def test_mcp_reports_the_reboot_requirement(self):
        """When the start types really did land, a reboot is the right advice."""
        ga = self._start_readback(
            {"WinDefend": 2, "WdFilter": 0, "WdNisSvc": 3, "WdNisDrv": 3}
        )
        out = self._mcp_enable(ga)

        assert "Reboot the VM" in out
        assert "av_enable" in out

    def test_mcp_does_not_claim_a_restore_that_did_not_happen(self):
        """Services\\*\\Start is ACL-protected: on a guest built with the
        offline disable, defender.enable()'s reg.exe writes silently fail. The
        tool used to report them restored and ask for a reboot — an
        unbreakable loop, since the reboot changes nothing."""
        ga = self._start_readback({"WinDefend": 4, "WdFilter": 4, "WdNisSvc": 4, "WdNisDrv": 4})
        out = self._mcp_enable(
            ga, unwritten=("WinDefend", "WdFilter", "WdNisSvc", "WdNisDrv")
        )

        assert "restored" not in out or "could NOT be restored" in out
        assert "WinDefend" in out
        # Must point at the only thing that actually works: the host-side
        # offline hive edit.
        assert "winbox av enable" in out
        assert "Reboot the VM and call av_enable again to finish" not in out


class TestOfflineDisableOnClientSku:
    """Once Defender has run on a client SKU, Tamper Protection is enforced by
    its own kernel components and every in-guest disable is ignored. Refusing
    was honest but left the VM in a state only a rebuild escaped. The disable
    now happens with the VM powered off, where nothing enforces TP."""

    def test_client_with_tp_on_goes_offline(self, runner, mock_env, cfg):
        cfg.vm_os = "win11"
        with (
            patch("winbox.cli.av.defender.tamper_protection_on", return_value=True),
            patch("winbox.cli.av._disable_via_offline_hive") as offline,
            patch("winbox.cli.av.defender.set_disable_regkeys") as gp_keys,
        ):
            result = runner.invoke(cli, ["av", "disable"])

        assert result.exit_code == 0
        offline.assert_called_once()
        # The in-guest path cannot work here; it must not even be attempted.
        gp_keys.assert_not_called()

    def test_client_without_tp_uses_the_fast_in_guest_path(self, runner, mock_env, cfg):
        """Clearing TP during enable is what makes this reachable."""
        cfg.vm_os = "win11"
        with (
            patch("winbox.cli.av.defender.tamper_protection_on", return_value=False),
            patch("winbox.cli.av._disable_via_offline_hive") as offline,
            patch("winbox.cli.av.defender.set_disable_regkeys"),
            patch("winbox.cli.av.reboot_and_wait"),
        ):
            runner.invoke(cli, ["av", "disable"])

        offline.assert_not_called()

    def test_server_never_takes_the_offline_path(self, runner, mock_env, cfg):
        """Server 2022 has no Tamper Protection; its proven path is untouched."""
        cfg.vm_os = "server2022"
        with (
            patch("winbox.cli.av.defender.tamper_protection_on", return_value=True),
            patch("winbox.cli.av._disable_via_offline_hive") as offline,
            patch("winbox.cli.av.defender.set_disable_regkeys"),
            patch("winbox.cli.av.reboot_and_wait"),
        ):
            runner.invoke(cli, ["av", "disable"])

        offline.assert_not_called()

    def test_offline_edit_refuses_while_the_disk_may_be_in_use(self, cfg):
        """guestfish opens the disk read-write; running it against a live VM
        risks corruption."""
        from winbox.cli.av import _disable_via_offline_hive

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = False  # never shuts down

        with (
            patch("winbox.offlinereg.tools_available", return_value=None),
            patch("winbox.cli.av.defender.disable_offline") as edit,
            pytest.raises(SystemExit),
        ):
            _disable_via_offline_hive(cfg, vm, ga)

        edit.assert_not_called()
        vm.force_stop.assert_called_once()

    def test_missing_libguestfs_fails_with_guidance(self, cfg):
        from winbox.cli.av import _disable_via_offline_hive

        with (
            patch("winbox.offlinereg.tools_available", return_value="hivexregedit"),
            patch("winbox.cli.av.defender.disable_offline") as edit,
            pytest.raises(SystemExit),
        ):
            _disable_via_offline_hive(cfg, MagicMock(), MagicMock())

        edit.assert_not_called()


class TestEnableClearsTamperProtection:
    @pytest.fixture(autouse=True)
    def _already_fully_on(self):
        with patch("winbox.cli.av._status_text", return_value="Defender: ON"):
            yield

    """Enabling Defender on a client SKU used to be one-way: TP armed the
    moment WinDefend started. The restart the SCM already forces is the one
    window where TP can still be cleared."""

    def test_client_restart_clears_tp_instead_of_warm_rebooting(
        self, runner, mock_env, cfg
    ):
        cfg.vm_os = "win11"
        with (
            patch("winbox.cli.av.defender.enable", side_effect=[_OUT_REBOOT, _OUT_DONE]),
            patch("winbox.cli.av._restart_clearing_tamper_protection") as restart,
            patch("winbox.cli.av.reboot_and_wait") as warm,
        ):
            result = runner.invoke(cli, ["av", "enable"])

        assert result.exit_code == 0
        restart.assert_called_once()
        warm.assert_not_called()

    def test_server_still_warm_reboots(self, runner, mock_env, cfg):
        cfg.vm_os = "server2022"
        with (
            patch("winbox.cli.av.defender.enable", side_effect=[_OUT_REBOOT, _OUT_DONE]),
            patch("winbox.cli.av._restart_clearing_tamper_protection") as restart,
            patch("winbox.cli.av.reboot_and_wait") as warm,
        ):
            runner.invoke(cli, ["av", "enable"])

        warm.assert_called_once()
        restart.assert_not_called()

    def test_a_failed_tp_clear_does_not_fail_the_enable(self, cfg):
        """Defender still comes up; av disable just falls back to its own
        power cycle. Failing here would trade a working outcome for a tidy one."""
        from winbox.cli.av import _restart_clearing_tamper_protection
        from winbox.offlinereg import OfflineRegistryError

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = True

        with (
            patch("winbox.cli.av.defender.enable_offline"),
            patch(
                "winbox.cli.av.defender.clear_tamper_protection_offline",
                side_effect=OfflineRegistryError("hive locked"),
            ),
        ):
            _restart_clearing_tamper_protection(cfg, vm, ga)  # must not raise

        vm.start.assert_called_once()

    def test_a_failed_service_restore_does_fail_the_enable(self, cfg):
        """Unlike the TP clear, this one is load-bearing: Defender's
        Services\\*\\Start values are ACL-protected, so if the offline restore
        does not land there is no in-guest way back."""
        from winbox.cli.av import _restart_clearing_tamper_protection
        from winbox.offlinereg import OfflineRegistryError

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = True

        with (
            patch(
                "winbox.cli.av.defender.enable_offline",
                side_effect=OfflineRegistryError("hive locked"),
            ),
            pytest.raises(SystemExit),
        ):
            _restart_clearing_tamper_protection(cfg, vm, ga)

        vm.start.assert_not_called()

    def test_a_quiet_guest_agent_after_boot_exits_cleanly(self, cfg):
        """Mirrors _disable_via_offline_hive's handling of the same wait — a
        slow/unhealthy guest boot must not crash `av enable` with a raw
        GuestAgentError traceback."""
        from winbox.cli.av import _restart_clearing_tamper_protection
        from winbox.vm import GuestAgentError

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = True
        ga.wait.side_effect = GuestAgentError("timeout")

        with (
            patch("winbox.cli.av.defender.enable_offline"),
            patch("winbox.cli.av.defender.clear_tamper_protection_offline"),
            pytest.raises(SystemExit),
        ):
            _restart_clearing_tamper_protection(cfg, vm, ga)

    def test_service_restore_happens_before_the_tp_clear(self, cfg):
        from winbox.cli.av import _restart_clearing_tamper_protection

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = True
        order = []

        with (
            patch("winbox.cli.av.defender.enable_offline",
                  side_effect=lambda *a, **k: order.append("services")),
            patch("winbox.cli.av.defender.clear_tamper_protection_offline",
                  side_effect=lambda *a, **k: order.append("tamper")),
        ):
            _restart_clearing_tamper_protection(cfg, vm, ga)

        assert order == ["services", "tamper"]


class TestEnableVerifiesWhatItClaims:
    """WdFilter is a boot-start driver. If it was disabled when the current
    boot began, real-time protection cannot come up until the next one — so
    `av enable` was reporting "real-time, AMSI, behavior monitoring" while
    RealTimeProtection was still False."""

    def _run(self, runner, statuses):
        with (
            patch("winbox.cli.av.defender.enable", return_value=_OUT_DONE),
            patch("winbox.cli.av._status_text", side_effect=statuses),
            patch("winbox.cli.av.reboot_and_wait") as reboot,
        ):
            result = runner.invoke(cli, ["av", "enable"])
        return result, reboot

    def test_reboots_when_protections_are_not_all_up(self, runner, mock_env):
        result, reboot = self._run(
            runner, ["Defender: partial", "Defender: ON"]
        )
        assert result.exit_code == 0
        reboot.assert_called_once()
        assert "Defender enabled" in result.output

    def test_no_reboot_when_already_fully_on(self, runner, mock_env):
        result, reboot = self._run(runner, ["Defender: ON", "Defender: ON"])
        reboot.assert_not_called()

    def test_reports_honestly_when_a_reboot_did_not_fix_it(self, runner, mock_env):
        """Claiming success we didn't achieve is the failure mode this whole
        verification exists to prevent."""
        result, _ = self._run(
            runner,
            ["Defender: partial",
             "Defender: partial\n  RealTimeProtection: False"],
        )
        assert "not every protection is active" in result.output
        assert "RealTimeProtection: False" in result.output

    def test_status_text_survives_an_unreachable_guest(self):
        from winbox.cli.av import _status_text
        from winbox.vm import GuestAgentError

        ga = MagicMock()
        ga.exec_powershell.side_effect = GuestAgentError("gone")
        assert _status_text(ga) == ""


class TestOfflineEditNeverTouchesALiveDisk:
    """Both offline paths hand cfg.disk_path to `guestfish --rw`. Editing a
    disk a live QEMU still has open scrambles the SYSTEM hive — an unbootable
    VM with no in-guest recovery. The disable path checked; the enable-side
    power cycle discarded the second wait_shutdown result and edited anyway."""

    def test_enable_power_cycle_refuses_while_the_disk_may_be_in_use(self, cfg):
        from winbox.cli.av import _restart_clearing_tamper_protection

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = False  # never shuts down, even after destroy

        with (
            patch("winbox.cli.av.defender.enable_offline") as services,
            patch("winbox.cli.av.defender.clear_tamper_protection_offline") as tamper,
            pytest.raises(SystemExit),
        ):
            _restart_clearing_tamper_protection(cfg, vm, ga)

        services.assert_not_called()
        tamper.assert_not_called()
        vm.force_stop.assert_called_once()
        vm.start.assert_not_called()

    def test_enable_power_cycle_proceeds_once_the_force_stop_lands(self, cfg):
        """A graceful shutdown that fails but a `virsh destroy` that works is
        still a safe disk — don't turn that into a hard failure."""
        from winbox.cli.av import _restart_clearing_tamper_protection

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.side_effect = [False, True]

        with (
            patch("winbox.cli.av.defender.enable_offline") as services,
            patch("winbox.cli.av.defender.clear_tamper_protection_offline"),
        ):
            _restart_clearing_tamper_protection(cfg, vm, ga)

        services.assert_called_once()
        vm.start.assert_called_once()

    def test_disable_path_still_refuses_too(self, cfg):
        """The contract both paths must share, pinned from the other side."""
        from winbox.cli.av import _disable_via_offline_hive

        vm, ga = MagicMock(), MagicMock()
        vm.wait_shutdown.return_value = False

        with (
            patch("winbox.offlinereg.tools_available", return_value=None),
            patch("winbox.cli.av.defender.disable_offline") as edit,
            pytest.raises(SystemExit),
        ):
            _disable_via_offline_hive(cfg, vm, ga)

        edit.assert_not_called()


class TestEnableChecksItsOwnWrites:
    """`Services\\*\\Start` is ACL-protected. `enable()` wrote those four
    values and discarded every exit code, so on a guest built with the offline
    Defender disable it reported a restore that never happened — and the
    caller then asked for a reboot that could not possibly help."""

    def _ga(self, *, write_rc=0, readback):
        from winbox.vm.guest import ExecResult

        ga = MagicMock()

        def fake_argv(exe, args, **kw):
            svc = args[1].rsplit("\\", 1)[-1]
            if args[0] == "add":
                return ExecResult(exitcode=write_rc, stdout="", stderr="Access is denied.")
            return ExecResult(
                exitcode=0,
                stdout=f"    Start    REG_DWORD    0x{readback[svc]:x}\n",
                stderr="",
            )

        ga.exec_argv.side_effect = fake_argv
        ga.exec.return_value = ExecResult(exitcode=1058, stdout="", stderr="")
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        return ga

    SHIPPED = {"WinDefend": 2, "WdFilter": 0, "WdNisSvc": 3, "WdNisDrv": 3}
    DISABLED = {"WinDefend": 4, "WdFilter": 4, "WdNisSvc": 4, "WdNisDrv": 4}

    def test_reports_every_service_it_could_not_write(self):
        from winbox import defender

        outcome = defender.enable(self._ga(write_rc=1, readback=self.DISABLED))

        assert outcome.reboot_required is True
        assert set(outcome.start_types_unwritten) == set(self.SHIPPED)

    def test_reports_nothing_unwritten_when_the_values_did_land(self):
        from winbox import defender

        outcome = defender.enable(self._ga(readback=self.SHIPPED))

        assert outcome.reboot_required is True
        assert outcome.start_types_unwritten == ()

    def test_verifies_by_reading_back_not_by_trusting_the_exit_code(self):
        """reg.exe has been seen returning 0 while changing nothing."""
        from winbox import defender

        outcome = defender.enable(self._ga(write_rc=0, readback=self.DISABLED))

        assert set(outcome.start_types_unwritten) == set(self.SHIPPED)

    def test_a_service_that_cannot_be_read_counts_as_unwritten(self):
        """Failing closed only ever downgrades a success claim."""
        from winbox import defender
        from winbox.vm.guest import ExecResult

        ga = MagicMock()
        ga.exec_argv.side_effect = lambda *a, **kw: ExecResult(1, "", "boom")
        ga.exec.return_value = ExecResult(exitcode=1058, stdout="", stderr="")
        ga.exec_powershell.return_value = ExecResult(0, "", "")

        assert set(defender.enable(ga).start_types_unwritten) == set(self.SHIPPED)

    def test_cli_refuses_to_send_the_user_round_a_pointless_reboot(
        self, runner, mock_env
    ):
        from winbox.defender import EnableOutcome

        with (
            patch(
                "winbox.cli.av.defender.enable",
                return_value=EnableOutcome(
                    reboot_required=True,
                    start_types_unwritten=("WinDefend", "WdFilter"),
                ),
            ),
            patch("winbox.cli.av.reboot_and_wait") as reboot,
            patch("winbox.cli.av._restart_clearing_tamper_protection") as restart,
        ):
            result = runner.invoke(cli, ["av", "enable"])

        assert result.exit_code != 0
        assert "ACL-protected" in result.output
        assert "WinDefend" in result.output
        reboot.assert_not_called()
        restart.assert_not_called()

    def test_the_start_type_table_has_one_definition(self):
        """Two hardcoded copies, in the module whose job is verifying the
        other one wrote them, is how they drift."""
        import inspect

        import winbox.mcp as mcp_mod
        from winbox import defender

        assert not hasattr(mcp_mod, "_DEFENDER_DEFAULT_START")
        assert defender._DEFENDER_DEFAULT_START == {
            "WinDefend": 2, "WdFilter": 0, "WdNisSvc": 3, "WdNisDrv": 3
        }
        # enable() must drive its writes from that table, not its own literal.
        assert "_DEFENDER_DEFAULT_START.items()" in inspect.getsource(defender.enable)
