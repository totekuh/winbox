"""Tests for winbox.hvci — HVCI/VBS status, enable, disable."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from winbox.hvci import HvciStatus, disable, enable, status
from winbox.vm.guest import ExecResult


class TestHvciStatus:
    def test_on(self):
        """When both registry keys are 1 and hypervisor is auto, report on."""
        ga = MagicMock()
        ga.exec.side_effect = [
            # VBS query
            ExecResult(
                exitcode=0,
                stdout=(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\n"
                    "    EnableVirtualizationBasedSecurity    REG_DWORD    0x1\n"
                ),
                stderr="",
            ),
            # HVCI query
            ExecResult(
                exitcode=0,
                stdout=(
                    "HKEY_LOCAL_MACHINE\\...\\HypervisorEnforcedCodeIntegrity\n"
                    "    Enabled    REG_DWORD    0x1\n"
                ),
                stderr="",
            ),
            # bcdedit
            ExecResult(
                exitcode=0,
                stdout="hypervisorlaunchtype    Auto\n",
                stderr="",
            ),
        ]

        s = status(ga)
        assert s.vbs_enabled is True
        assert s.hvci_enabled is True
        assert s.hypervisor_off is False

    def test_off(self):
        """When both registry keys are 0 and hypervisor is off, report off."""
        ga = MagicMock()
        ga.exec.side_effect = [
            # VBS query
            ExecResult(
                exitcode=0,
                stdout=(
                    "HKEY_LOCAL_MACHINE\\...\\DeviceGuard\n"
                    "    EnableVirtualizationBasedSecurity    REG_DWORD    0x0\n"
                ),
                stderr="",
            ),
            # HVCI query
            ExecResult(
                exitcode=0,
                stdout=(
                    "HKEY_LOCAL_MACHINE\\...\\HypervisorEnforcedCodeIntegrity\n"
                    "    Enabled    REG_DWORD    0x0\n"
                ),
                stderr="",
            ),
            # bcdedit
            ExecResult(
                exitcode=0,
                stdout="hypervisorlaunchtype    Off\n",
                stderr="",
            ),
        ]

        s = status(ga)
        assert s.vbs_enabled is False
        assert s.hvci_enabled is False
        assert s.hypervisor_off is True

    def test_key_missing(self):
        """When the registry keys don't exist, treat as disabled."""
        ga = MagicMock()
        ga.exec.side_effect = [
            # VBS query — key not found
            ExecResult(
                exitcode=1,
                stdout="ERROR: The system was unable to find the specified registry key or value.\n",
                stderr="",
            ),
            # HVCI query — key not found
            ExecResult(
                exitcode=1,
                stdout="ERROR: The system was unable to find the specified registry key or value.\n",
                stderr="",
            ),
            # bcdedit — no hypervisorlaunchtype entry
            ExecResult(
                exitcode=0,
                stdout="identifier              {current}\ndevice                  partition=C:\n",
                stderr="",
            ),
        ]

        s = status(ga)
        assert s.vbs_enabled is False
        assert s.hvci_enabled is False
        assert s.hypervisor_off is False


class TestHvciDisable:
    def test_sets_keys_and_bcdedit(self):
        ga = MagicMock()
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        disable(ga)

        calls = [str(c) for c in ga.exec.call_args_list]
        assert any(
            "EnableVirtualizationBasedSecurity" in c and "/d 0" in c
            for c in calls
        )
        assert any(
            "HypervisorEnforcedCodeIntegrity" in c and "/d 0" in c
            for c in calls
        )
        assert any("hypervisorlaunchtype off" in c for c in calls)


class TestHvciEnable:
    def test_sets_keys_and_bcdedit(self):
        ga = MagicMock()
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        enable(ga)

        calls = [str(c) for c in ga.exec.call_args_list]
        assert any(
            "EnableVirtualizationBasedSecurity" in c and "/d 1" in c
            for c in calls
        )
        assert any(
            "HypervisorEnforcedCodeIntegrity" in c and "/d 1" in c
            for c in calls
        )
        assert any("hypervisorlaunchtype auto" in c for c in calls)
