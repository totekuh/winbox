"""Opt-in end-to-end mixed WoW64 unwind through the real daemon/QEMU."""

from __future__ import annotations

import time

import pytest

from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.kdbg.debugger.client import DaemonClient
from winbox.kdbg.debugger.daemon import fork_daemon
from winbox.kdbg.debugger.reader import debug_snapshot, stop_reader
from winbox.kdbg.hmp import ensure_not_paused, probe_port
from winbox.kdbg.staging import prepare_user_module_manifest
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.walk import list_processes
from winbox.vm import GuestAgent


pytestmark = pytest.mark.integration


def test_live_attach_manifest_and_mixed_wow64_transition_trace():
    cfg = Config.load()
    ga = GuestAgent(cfg)
    try:
        require_safe(cfg, ga)
    except CetSafetyError as exc:
        pytest.skip(f"live mixed WoW64 test requires prepared CET state: {exc}")
    if not probe_port("127.0.0.1", 1234):
        pytest.skip("gdbstub is not listening")
    store = SymbolStore(cfg.symbols_dir)
    with debug_snapshot(cfg):
        target = next(
            (process for process in list_processes(cfg.vm_name, store)
             if process.name.casefold() == "ping.exe"),
            None,
        )
    if target is None:
        pytest.skip("no persistent SysWOW64 PING.EXE target")

    manifest = prepare_user_module_manifest(cfg, ga, store, target.pid)
    assert manifest.failures == ()
    assert any(
        item.name.casefold() == "wow64cpu.dll" and item.store_build
        for item in manifest.modules
    )
    stop_reader(cfg)
    client = DaemonClient(cfg)
    try:
        fork_daemon(
            cfg, target.pid, gdbstub_port=1234, module_manifest=manifest,
        )
        client.call("bp_add", target="wow64cpu!CpupSyscallStub", mode="hw")
        hit = client.call("cont", timeout=15, sock_timeout=25)
        assert hit["reason"] == "bp"
        first = client.call("bt", depth=24)
        second = client.call("bt", depth=24)
        assert first["method"] == "windows-wow64-mixed"
        assert first["transition"]["layout"] == "exact-wow64cpu-instructions"
        assert first["transition"]["x86_frame_count"] >= 1
        assert any(frame["architecture"] == "x64" for frame in first["frames"])
        assert any(frame["architecture"] == "x86" for frame in first["frames"])
        assert [frame["addr"] for frame in first["frames"]] == [
            frame["addr"] for frame in second["frames"]
        ]
    finally:
        if client.session_alive():
            try:
                client.call("detach")
            except Exception:
                pass
            deadline = time.monotonic() + 5
            while client.session_alive() and time.monotonic() < deadline:
                time.sleep(0.1)
        ensure_not_paused(cfg.vm_name)
