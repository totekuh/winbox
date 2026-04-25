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


# CLI modules that need VM/GA/ensure_running patched. Derived from the
# REGISTER auto-discovery introduced for `cli` so adding a new command
# stops requiring a manual edit here. Modules without REGISTER (the
# private _ps helper, mcp, kdbg) are correctly skipped because either
# they don't talk to VM/GA or have their own bespoke fixtures.
def _discover_cli_modules() -> list[str]:
    import importlib
    import pkgutil

    import winbox.cli as cli_pkg

    found: list[str] = []
    for _finder, mod_name, ispkg in pkgutil.iter_modules(cli_pkg.__path__):
        if ispkg or mod_name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"winbox.cli.{mod_name}")
        except Exception:
            continue
        if not hasattr(module, "REGISTER"):
            continue
        # Only patch modules that actually import VM / GuestAgent /
        # ensure_running -- the names referenced by mock_env. Modules like
        # `mcp` and `binfmt` whose CLI side doesn't talk to GA are skipped.
        for attr in ("VM", "GuestAgent", "ensure_running"):
            if hasattr(module, attr):
                found.append(mod_name)
                break
    return found


_CLI_MODULES = _discover_cli_modules()


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

    import importlib

    with ExitStack() as stack:
        for mod in _CLI_MODULES:
            module = importlib.import_module(f"winbox.cli.{mod}")
            # ensure_running is only re-imported by modules that still call it
            # directly (vm, jobs, kdbg, eventlogs after the @needs_vm migration).
            # Skip the patch for modules that delegate fully to @needs_vm.
            if hasattr(module, "ensure_running"):
                stack.enter_context(patch(f"winbox.cli.{mod}.ensure_running"))
            if hasattr(module, "GuestAgent"):
                stack.enter_context(patch(f"winbox.cli.{mod}.GuestAgent", return_value=ga))
            if hasattr(module, "VM"):
                stack.enter_context(patch(f"winbox.cli.{mod}.VM", return_value=vm))

        # The @needs_vm decorator (in cli/__init__.py) resolves VM /
        # GuestAgent / ensure_running through its own module namespace,
        # so commands using @needs_vm need this patched too.
        stack.enter_context(patch("winbox.cli.ensure_running"))
        stack.enter_context(patch("winbox.cli.GuestAgent", return_value=ga))
        stack.enter_context(patch("winbox.cli.VM", return_value=vm))

        stack.enter_context(patch("winbox.cli.network.VMState", VMState))
        stack.enter_context(patch("winbox.cli.setup.VM", return_value=vm))
        stack.enter_context(patch("winbox.cli.Config.load", return_value=cfg))

        ga._vm = vm
        yield ga
