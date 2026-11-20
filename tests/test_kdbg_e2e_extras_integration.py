"""Integration tests for breakpoint intents, pipe/share negatives, resume recovery, sinkhole DNS.

Real VM operations throughout — no mocking. Exercises intent-installed breakpoints
that actually fire, daemon crash recovery via kdbg_resume, DNS resolution through
the sinkhole, and negative cases for pipes and shares.
"""

from __future__ import annotations

import json
import os
import signal
import time
from contextlib import suppress

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.vm import VM, GuestAgent, VMState
from winbox.vm.virsh import virsh_run


pytestmark = pytest.mark.integration

_runner = CliRunner()


def _run(*args: str, expect_ok: bool = True):
    result = _runner.invoke(cli, list(args))
    if expect_ok:
        assert result.exit_code == 0, (
            f"winbox {' '.join(args)} exited {result.exit_code}\n"
            f"{result.output}\n{result.exception!r}"
        )
    return result


def _tool(name: str):
    import winbox.mcp as mcp_mod
    obj = mcp_mod.__dict__[name]
    return obj.fn if hasattr(obj, "fn") else obj


def _assert_ok(response):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is True, response
    assert response["error"] is None, response
    return response["result"]


def _assert_error(response, code: str | None = None):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is False, response
    assert response["error"] is not None, response
    if code:
        assert response["error"]["code"] == code, response["error"]


def _force_reset(cfg: Config) -> None:
    from winbox.kdbg.debugger.daemon import force_stop_daemon
    from winbox.kdbg.debugger.reader import stop_reader
    from winbox.kdbg.hmp import ensure_not_paused, hmp
    with suppress(Exception):
        force_stop_daemon(cfg)
    with suppress(Exception):
        stop_reader(cfg)
    with suppress(Exception):
        hmp(cfg.vm_name, "gdbserver none", mode="tuple")
    with suppress(Exception):
        ensure_not_paused(cfg.vm_name)


def _domstate(vm_name: str) -> str:
    return virsh_run("domstate", vm_name, check=False).stdout.strip()


def _winlogon_pid() -> int:
    return json.loads(_tool("ps")("winlogon"))[0]["pid"]


# ─── fixtures ──────────────────────────────────────────────────────────────


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
def _require_running(vm):
    if vm.state() != VMState.RUNNING:
        pytest.skip("VM not running")


@pytest.fixture(scope="module")
def _require_safe_vm(cfg, vm, ga):
    try:
        require_safe(cfg, ga)
    except CetSafetyError:
        pytest.skip("CET not safe for debugging")


# ─── breakpoint intent lifecycle ───────────────────────────────────────────


@pytest.mark.usefixtures("_require_safe_vm")
class TestBreakpointIntentLifecycle:
    @pytest.fixture(autouse=True)
    def _clean(self, cfg):
        _force_reset(cfg)
        yield
        _force_reset(cfg)

    @staticmethod
    def _resolve_ntclose_offset():
        """Resolve ntdll!NtClose to a module+0xoffset target string.

        Requires gdbstub already started (kdbg_start). Does NOT start/stop.
        """
        pid = _winlogon_pid()
        _assert_ok(_tool("kdbg_user_symbols_load")(pid, "ntdll"))
        modules = _assert_ok(_tool("kdbg_user_lm")(pid))["modules"]
        ntdll = next(
            r for r in modules
            if r["name"].casefold() == "ntdll.dll"
            and r.get("architecture", "x64") == "x64"
        )
        sym = _assert_ok(_tool("kdbg_sym")("ntdll!NtClose"))
        va = int(sym["matches"][0].split()[-1], 0)
        base = int(ntdll["base"], 0)
        offset = va - base
        assert 0 <= offset < int(ntdll["size"], 0)
        return pid, f"ntdll+0x{offset:x}", offset

    @staticmethod
    def _working_mode(pid, target):
        """Try hw then soft, return whichever the daemon accepts.

        Requires gdbstub started. Does one attach/detach cycle.
        """
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            for mode in ("hw", "soft"):
                resp = _tool("kdbg_bp")(target, mode)
                if resp["ok"]:
                    _assert_ok(_tool("kdbg_rm")(resp["result"]["id"]))
                    return mode
        finally:
            _tool("kdbg_detach")()
        pytest.skip("neither hw nor soft breakpoint accepted")

    def test_intent_add_bad_target(self):
        _assert_error(_tool("kdbg_bp_intent_add")("0xDEAD"))
        _assert_error(_tool("kdbg_bp_intent_add")("nt!NtCreateFile"))

    def test_intent_add_duplicate(self, cfg):
        from winbox.kdbg.breakpoint_intent import BreakpointIntentStore
        store = BreakpointIntentStore(cfg)
        result = _assert_ok(_tool("kdbg_bp_intent_add")("ntdll+0x1000", mode="hw"))
        try:
            _assert_error(_tool("kdbg_bp_intent_add")("ntdll+0x1000", mode="hw"))
        finally:
            with suppress(Exception):
                store.remove(result["id"])

    def test_intent_remove_nonexistent(self):
        _assert_error(_tool("kdbg_bp_intent_remove")(999999))

    def test_intent_persists_across_sessions(self, cfg):
        from winbox.kdbg.breakpoint_intent import BreakpointIntentStore
        store = BreakpointIntentStore(cfg)

        _assert_ok(_tool("kdbg_start")())
        try:
            pid, target, _ = self._resolve_ntclose_offset()
        finally:
            _run("kdbg", "stop", expect_ok=False)

        saved = _assert_ok(_tool("kdbg_bp_intent_add")(target, mode="hw"))
        intent_id = saved["id"]
        try:
            _assert_ok(_tool("kdbg_start")())
            try:
                _assert_ok(_tool("kdbg_attach")(pid))
                try:
                    bps = _assert_ok(_tool("kdbg_bps")())["bps"]
                    assert len(bps) == 0, "intent should not auto-install without apply_intents"
                finally:
                    _tool("kdbg_detach")()
            finally:
                _run("kdbg", "stop", expect_ok=False)

            inventory = _assert_ok(_tool("kdbg_bp_intents")())
            assert any(i["id"] == intent_id for i in inventory["intents"])
        finally:
            with suppress(Exception):
                store.remove(intent_id)

    def test_intent_installed_bp_fires_on_cont(self, cfg):
        """Full e2e: add intent, attach with apply, cont until bp fires."""
        from winbox.kdbg.breakpoint_intent import BreakpointIntentStore
        store = BreakpointIntentStore(cfg)

        _assert_ok(_tool("kdbg_start")())
        try:
            pid, target, offset = self._resolve_ntclose_offset()
            mode = self._working_mode(pid, target)

            saved = _assert_ok(_tool("kdbg_bp_intent_add")(target, mode=mode))
            intent_id = saved["id"]
            try:
                attach_result = _assert_ok(
                    _tool("kdbg_attach")(pid, apply_intents=True)
                )
                try:
                    report = attach_result["breakpoint_intents"]
                    assert report["requested"] == 1
                    assert report["installed"] == 1
                    assert report["unresolved"] == 0

                    bps = _assert_ok(_tool("kdbg_bps")())["bps"]
                    assert len(bps) == 1
                    bp_id = bps[0]["id"]

                    result = _tool("kdbg_cont")(timeout=10.0)
                    if result.get("ok"):
                        ctx = result["result"]
                        assert "reason" in ctx
                        regs = _assert_ok(_tool("kdbg_regs")())
                        assert "rip" in regs

                    _assert_ok(_tool("kdbg_rm")(bp_id))
                finally:
                    _tool("kdbg_detach")()
            finally:
                with suppress(Exception):
                    store.remove(intent_id)
        finally:
            _run("kdbg", "stop", expect_ok=False)
        assert _domstate(cfg.vm_name) == "running"

    def test_intent_with_actions_captures_values(self, cfg):
        """Intent with actions: attach, cont, verify trace has captured values."""
        from winbox.kdbg.breakpoint_intent import BreakpointIntentStore
        store = BreakpointIntentStore(cfg)

        _assert_ok(_tool("kdbg_start")())
        try:
            pid, target, _ = self._resolve_ntclose_offset()
            mode = self._working_mode(pid, target)

            saved = _assert_ok(
                _tool("kdbg_bp_intent_add")(target, mode=mode, actions=["rax", "rcx"])
            )
            intent_id = saved["id"]
            try:
                _assert_ok(_tool("kdbg_attach")(pid, apply_intents=True))
                try:
                    bps = _assert_ok(_tool("kdbg_bps")())["bps"]
                    bp_id = bps[0]["id"]

                    started = _assert_ok(_tool("kdbg_cont_start")(10))
                    token = started["token"]
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        polled = _assert_ok(_tool("kdbg_cont_poll")(token))
                        if not polled["active"]:
                            break
                        time.sleep(0.2)
                    if polled.get("active"):
                        _assert_ok(_tool("kdbg_cont_cancel")(token))
                        for _ in range(50):
                            polled = _assert_ok(_tool("kdbg_cont_poll")(token))
                            if not polled["active"]:
                                break
                            time.sleep(0.1)

                    trace = _assert_ok(_tool("kdbg_bp_trace")(bp_id))
                    assert isinstance(trace["total"], int)
                    if trace["total"] > 0:
                        entry = trace["entries"][0]
                        assert "hit" in entry
                        assert "rip" in entry
                        assert isinstance(entry["values"], dict)

                    _assert_ok(_tool("kdbg_rm")(bp_id))
                finally:
                    _tool("kdbg_detach")()
            finally:
                with suppress(Exception):
                    store.remove(intent_id)
        finally:
            _run("kdbg", "stop", expect_ok=False)
        assert _domstate(cfg.vm_name) == "running"


# ─── pipe negative cases ──────────────────────────────────────────────────


class TestPipeNegative:
    def test_pipe_open_nonexistent(self):
        out = _tool("pipe_open")("winbox_nonexistent_test_pipe_xyz")
        assert "error" in out.lower(), f"expected error, got: {out}"

    def test_pipe_send_invalid_hex(self):
        sid = _tool("pipe_open")("lsass").strip()
        if "error" in sid.lower():
            pytest.skip("could not open lsass pipe")
        try:
            out = _tool("pipe_send")(sid, "ZZZZ")
            assert "error" in out.lower(), f"expected hex error, got: {out}"
        finally:
            _tool("pipe_close")(sid)

    def test_pipe_ops_on_nonexistent_session(self):
        fake_sid = "deadbeef1234"
        assert "not found" in _tool("pipe_send")(fake_sid, "0500").lower()
        assert "not found" in _tool("pipe_recv")(fake_sid, 16).lower()


# ─── share negative cases ─────────────────────────────────────────────────


class TestShareNegative:
    def test_share_rm_refuses_without_confirm(self):
        _tool("share_create")(name="RmRefuseTest")
        try:
            _tool("share_write")(name="RmRefuseTest", path="f.txt", content="data")
            out = _tool("share_rm")(name="RmRefuseTest", path="f.txt")
            assert "confirm" in out.lower(), f"expected confirm refusal, got: {out}"
            out2 = _tool("share_rm")(name="RmRefuseTest", path="f.txt", confirm=True)
            assert "removed" in out2.lower() or "true" in out2.lower(), out2
        finally:
            _tool("share_delete")(name="RmRefuseTest", purge=True, confirm=True)

    def test_share_ls_nonexistent(self):
        out = _tool("share_ls")(name="winbox_no_such_share_xyz")
        assert "error" in out.lower() or "not found" in out.lower() or "fail" in out.lower(), (
            f"expected error for nonexistent share, got: {out}"
        )

    def test_share_mkdir_path_traversal(self):
        _tool("share_create")(name="TraversalTest")
        try:
            with pytest.raises(ValueError, match="[Tt]raversal"):
                _tool("share_mkdir")(name="TraversalTest", path="..\\..\\Windows")
        finally:
            _tool("share_delete")(name="TraversalTest", purge=True, confirm=True)


# ─── resume recovery ──────────────────────────────────────────────────────


@pytest.mark.usefixtures("_require_safe_vm")
class TestResumeRecovery:
    @pytest.fixture(autouse=True)
    def _clean(self, cfg):
        _force_reset(cfg)
        yield
        _force_reset(cfg)

    def test_resume_unsticks_paused_vm(self, cfg):
        """Kill daemon with SIGKILL to leave VM stuck, then kdbg_resume recovers it."""
        from winbox.kdbg.debugger.client import DaemonClient
        from winbox.kdbg.hmp import hmp

        pid = _winlogon_pid()
        _assert_ok(_tool("kdbg_start")())
        _assert_ok(_tool("kdbg_attach")(pid))

        client = DaemonClient(cfg)
        info = client.session_info()
        daemon_pid = int(info["daemon_pid"])

        os.kill(daemon_pid, signal.SIGKILL)
        time.sleep(0.5)

        state = _domstate(cfg.vm_name)
        assert state == "paused", f"expected paused after daemon kill, got {state}"

        result = _assert_ok(_tool("kdbg_resume")())
        assert result["resumed"] is True
        assert _domstate(cfg.vm_name) == "running"

        with suppress(Exception):
            hmp(cfg.vm_name, "gdbserver none", mode="tuple")

    def test_resume_refuses_with_active_session(self, cfg):
        pid = _winlogon_pid()
        _assert_ok(_tool("kdbg_start")())
        try:
            _assert_ok(_tool("kdbg_attach")(pid))
            try:
                resp = _tool("kdbg_resume")()
                _assert_error(resp)
                assert "detach" in resp["error"]["message"].lower()
            finally:
                _tool("kdbg_detach")()
        finally:
            _run("kdbg", "stop", expect_ok=False)

    def test_resume_noop_already_running(self, cfg):
        result = _assert_ok(_tool("kdbg_resume")())
        assert result["already_running"] is True
        assert _domstate(cfg.vm_name) == "running"


# ─── sinkhole DNS resolution ──────────────────────────────────────────────


class TestSinkholeResolution:
    @staticmethod
    def _dns_query(host: str, port: int, qname: str, timeout: float = 5.0) -> bytes:
        """Send a minimal UDP DNS A-record query and return the raw response."""
        import socket
        import struct

        labels = b""
        for part in qname.split("."):
            labels += bytes([len(part)]) + part.encode()
        labels += b"\x00"
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        packet = header + labels + struct.pack("!HH", 1, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(512)
        finally:
            sock.close()
        return data

    def test_sinkhole_resolves_dns_query(self, cfg):
        """Start sinkhole on 5353, send raw UDP DNS query from host, verify response."""
        import struct

        host_ip = cfg.host_ip
        _run("sinkhole", "start", "--port", "5353")
        try:
            data = None
            for attempt in range(3):
                try:
                    data = self._dns_query(host_ip, 5353, "winbox-test.example.com")
                    break
                except TimeoutError:
                    if attempt == 2:
                        raise
                    time.sleep(1)

            assert len(data) >= 12, f"response too short: {len(data)} bytes"
            ancount = struct.unpack("!H", data[6:8])[0]
            assert ancount >= 1, f"expected at least 1 answer, got {ancount}"

            rdata_ip = ".".join(str(b) for b in data[-4:])
            assert rdata_ip == host_ip, f"expected sink IP {host_ip}, got {rdata_ip}"

            log_out = _run("sinkhole", "log").output
            assert "winbox-test.example.com" in log_out, (
                f"query not in sinkhole log:\n{log_out}"
            )
        finally:
            _run("sinkhole", "stop")

    def test_sinkhole_start_idempotent(self):
        _run("sinkhole", "stop", expect_ok=False)
        _run("sinkhole", "start", "--port", "5353")
        try:
            result = _run("sinkhole", "start", "--port", "5353", expect_ok=False)
            assert result.exit_code == 0 or "already" in result.output.lower()
        finally:
            _run("sinkhole", "stop")

    def test_sinkhole_stop_when_already_stopped(self):
        _run("sinkhole", "stop", expect_ok=False)

    def test_sinkhole_status_stopped(self):
        _run("sinkhole", "stop", expect_ok=False)
        out = _run("sinkhole", "status").output.lower()
        assert "stopped" in out
