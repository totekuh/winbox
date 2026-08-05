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


# ─── Guest-agent test doubles ───────────────────────────────────────────────
# `GuestAgent.exec` tags each command with an identity nonce and rejects a
# completed result that doesn't carry it, because the guest agent keys
# buffered results by a Windows PID it readily recycles. Test doubles have to
# model that or every canned "exited" response looks like another process's
# leftovers.

import base64 as _base64
import re as _re

NONCE_RE = _re.compile(r"__wbx[0-9a-f]{16}__")


def extract_nonce(payload) -> str | None:
    """Pull the identity nonce out of a ``guest-exec`` payload, if present."""
    for arg in payload.get("arguments", {}).get("arg") or []:
        m = NONCE_RE.search(str(arg))
        if m:
            return m.group(0)
    return None


def nonce_aware(responses):
    """Wrap a canned ``_raw_command`` response sequence for ``GuestAgent.exec``.

    Replays ``responses`` in order (an ``Exception`` element is raised), but
    rewrites any ``exited`` result so its stdout is prefixed with the nonce
    the call under test actually generated — which is what the real guest
    does, since ``exec`` prepends an ``echo`` of it to the command line.
    """
    seq = iter(responses)
    state: dict[str, str | None] = {"nonce": None}

    def fake(payload, **kwargs):
        if payload.get("execute") == "guest-exec":
            found = extract_nonce(payload)
            if found:
                state["nonce"] = found
        r = next(seq)
        if isinstance(r, Exception):
            raise r
        ret = r.get("return", {})
        if ret.get("exited") and state["nonce"]:
            prior = ret.get("out-data") or ""
            decoded = _base64.b64decode(prior).decode() if prior else ""
            tagged = f"{state['nonce']}\r\n{decoded}"
            r = {
                **r,
                "return": {
                    **ret,
                    "out-data": _base64.b64encode(tagged.encode()).decode(),
                },
            }
        return r

    return fake


class FakeQemuGA:
    """A faithful-enough model of qemu-ga's guest-exec slot table.

    The behavior that matters, mirroring ``qga/commands.c``:

    * results live in one flat list keyed by the guest's **OS PID**;
    * a lookup returns the **first** entry matching that PID, so an older
      abandoned entry shadows a newer one;
    * an entry is freed only when a status read reports it as exited, so a
      result nobody reads is retained indefinitely.

    Together those let a recycled PID hand one command another command's
    output — the contamination this models.
    """

    def __init__(self, output: str = "", exitcode: int = 0):
        self.slots: list[dict] = []
        self.output = output
        self.exitcode = exitcode
        self.pids: list[int] = []
        self._next_pid = 1000

    def seed_abandoned(self, pid: int, output: str, exitcode: int = 1) -> None:
        """Park a completed result nobody ever read on ``pid``."""
        self.slots.append(
            {"pid": pid, "exited": True, "out": output, "exitcode": exitcode}
        )

    def force_next_pid(self, pid: int) -> None:
        """Make the next ``guest-exec`` return ``pid`` (simulates recycling)."""
        self.pids.append(pid)

    def __call__(self, payload, **kwargs):
        cmd = payload.get("execute")
        if cmd == "guest-exec":
            pid = self.pids.pop(0) if self.pids else self._next_pid
            self._next_pid += 1
            nonce = extract_nonce(payload)
            out = f"{nonce}\r\n{self.output}" if nonce else self.output
            self.slots.append(
                {"pid": pid, "exited": True, "out": out, "exitcode": self.exitcode}
            )
            return {"return": {"pid": pid}}
        if cmd == "guest-exec-status":
            want = payload["arguments"]["pid"]
            for i, slot in enumerate(self.slots):
                if slot["pid"] != want:
                    continue
                if slot["exited"]:
                    self.slots.pop(i)  # freed on read, like qemu-ga
                return {
                    "return": {
                        "exited": slot["exited"],
                        "exitcode": slot["exitcode"],
                        "out-data": _base64.b64encode(
                            slot["out"].encode()
                        ).decode(),
                        "err-data": "",
                    }
                }
            return {"return": {"exited": False}}
        return {"return": {}}
