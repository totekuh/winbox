"""Opt-in live smoke coverage for the persistent RSP walker transport."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.vm import VM, GuestAgent, VMState


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def cfg(bootstrapped_vm):
    return Config.load()


@pytest.fixture(scope="module")
def vm(cfg):
    return VM(cfg)


@pytest.fixture(scope="module")
def ga(cfg):
    return GuestAgent(cfg)


@pytest.fixture(scope="module", autouse=True)
def _require_safe(vm, ga, cfg):
    if vm.state() != VMState.RUNNING:
        pytest.skip("VM is not running")
    try:
        require_safe(cfg, ga)
    except CetSafetyError:
        pytest.skip("CET not safe for QEMU debugging")


def test_live_installed_cli_can_reuse_reader_for_kernel_module_walks():
    runner = CliRunner()
    for _ in range(2):
        result = runner.invoke(cli, ["kdbg", "lm"])
        assert result.exit_code == 0, result.output
        assert "ntoskrnl.exe" in result.output
        assert " modules)" in result.output
