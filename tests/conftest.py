"""Shared test fixtures for winbox CLI tests."""

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from winbox.config import Config
from winbox.vm import VMState


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.iso_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    c.tools_dir.mkdir(parents=True)
    c.loot_dir.mkdir(parents=True)
    c.jobs_log_dir.mkdir(parents=True)
    return c


# CLI modules that need VM/GA/ensure_running patched
_CLI_MODULES = ["vm", "network", "exec", "jobs", "av", "applocker"]


@pytest.fixture
def mock_env(cfg):
    """Patch VM/GA/ensure_running so CLI commands run without a real VM.

    Yields the mocked GuestAgent instance. Also exposes:
      - mock_env._vm: the mocked VM instance
      - mock_env._vm.state defaults to RUNNING
      - mock_env._vm.ip defaults to "192.168.122.203"
      - mock_env.ping defaults to True
    """
    ga = MagicMock()
    ga.ping.return_value = True

    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING
    vm.ip.return_value = "192.168.122.203"
    vm.exists.return_value = True
    vm.disk_usage.return_value = "6.5 GB"
    vm.snapshot_list.return_value = ["clean"]

    with ExitStack() as stack:
        for mod in _CLI_MODULES:
            stack.enter_context(patch(f"winbox.cli.{mod}.ensure_running"))
            stack.enter_context(patch(f"winbox.cli.{mod}.GuestAgent", return_value=ga))
            stack.enter_context(patch(f"winbox.cli.{mod}.VM", return_value=vm))

        stack.enter_context(patch("winbox.cli.network.VMState", VMState))
        stack.enter_context(patch("winbox.cli.setup.VM", return_value=vm))
        stack.enter_context(patch("winbox.cli.Config.load", return_value=cfg))

        ga._vm = vm
        yield ga
