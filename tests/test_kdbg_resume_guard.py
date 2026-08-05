"""Tests for the detach-time guard against a VM left paused.

Attaching a debugger stops the guest CPU; detaching is what resumes it.
But that only happens when the daemon shuts down cleanly — when it doesn't,
the CPU stays stopped and the only trace is a "daemon didn't exit within 5s"
warning. Every winbox command afterwards then sees a VM that looks down, and
recovery required knowing about the separate ``kdbg resume`` valve.
"""

from __future__ import annotations

import importlib
import subprocess
from unittest.mock import patch

from winbox.kdbg.hmp import ensure_not_paused


def _proc(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class TestEnsureNotPaused:
    def test_running_vm_is_left_alone(self):
        with patch("winbox.kdbg.hmp.subprocess.run", return_value=_proc("running")) as run:
            assert ensure_not_paused("winbox") is None
        # Only the domstate probe — no resume attempted.
        assert run.call_count == 1

    def test_paused_vm_is_resumed_via_gdbstub_when_listening(self):
        calls = []

        class FakeRsp:
            @classmethod
            def connect(cls, host, port, timeout=5):
                calls.append(("connect", host, port))
                return cls()

            def handshake(self):
                calls.append(("handshake",))

            def cont(self):
                calls.append(("cont",))

            def close(self):
                calls.append(("close",))

        with (
            patch("winbox.kdbg.hmp.subprocess.run", return_value=_proc("paused")),
            patch("winbox.kdbg.hmp.probe_port", return_value=True),
            patch("winbox.kdbg.debugger.RspClient", FakeRsp),
        ):
            note = ensure_not_paused("winbox")

        assert note is not None and "resumed via gdbstub" in note
        assert ("cont",) in calls
        assert ("close",) in calls

    def test_falls_back_to_virsh_when_stub_is_gone(self):
        def fake_run(cmd, **kw):
            if "domstate" in cmd:
                return _proc("paused")
            return _proc("", returncode=0)  # virsh resume

        with (
            patch("winbox.kdbg.hmp.subprocess.run", side_effect=fake_run),
            patch("winbox.kdbg.hmp.probe_port", return_value=False),
        ):
            note = ensure_not_paused("winbox")

        assert note is not None and "resumed via virsh" in note

    def test_reports_actionable_message_when_resume_fails(self):
        def fake_run(cmd, **kw):
            if "domstate" in cmd:
                return _proc("paused")
            return _proc("", returncode=1)

        with (
            patch("winbox.kdbg.hmp.subprocess.run", side_effect=fake_run),
            patch("winbox.kdbg.hmp.probe_port", return_value=False),
        ):
            note = ensure_not_paused("winbox")

        assert note is not None
        assert "left PAUSED" in note
        assert "virsh -c qemu:///system resume winbox" in note

    def test_never_raises(self):
        """It runs during teardown; masking the real failure would be worse."""
        with patch("winbox.kdbg.hmp.subprocess.run", side_effect=OSError("virsh gone")):
            assert ensure_not_paused("winbox") is None

    def test_shutoff_vm_is_not_touched(self):
        with patch("winbox.kdbg.hmp.subprocess.run", return_value=_proc("shut off")) as run:
            assert ensure_not_paused("winbox") is None
        assert run.call_count == 1


class TestProbePortIsPassive:
    """`kdbg status` must not disturb the guest.

    QEMU's gdbstub halts the CPU the moment a client attaches, so probing it
    with socket.create_connection paused the VM — and `kdbg stop` then
    refused ("VM is not running"), wedging the guest behind a read-only
    status check until someone found `kdbg resume`.
    """

    def test_probe_does_not_open_a_connection(self, monkeypatch):
        import socket as socket_mod

        hmp = importlib.import_module("winbox.kdbg.hmp")

        def forbidden(*a, **kw):
            raise AssertionError("probe_port must not connect to the gdbstub")

        monkeypatch.setattr(socket_mod, "create_connection", forbidden)
        monkeypatch.setattr(hmp, "_listening_sockets", lambda: {("127.0.0.1", 1234)})

        assert hmp.probe_port("127.0.0.1", 1234) is True
        assert hmp.probe_port("127.0.0.1", 4321) is False

    def test_reads_listen_sockets_from_proc(self, monkeypatch, tmp_path):
        hmp = importlib.import_module("winbox.kdbg.hmp")

        # state 0A is TCP_LISTEN; 01 is ESTABLISHED and must be ignored.
        proc_tcp = tmp_path / "tcp"
        proc_tcp.write_text(
            "  sl  local_address rem_address   st ...\n"
            "   0: 0100007F:04D2 00000000:0000 0A 0 0 0\n"
            "   1: 0100007F:1F90 0100007F:C000 01 0 0 0\n"
        )
        real_open = open

        def fake_open(path, *a, **kw):
            if path == "/proc/net/tcp":
                return real_open(proc_tcp, *a, **kw)
            raise OSError("no tcp6 here")

        monkeypatch.setattr("builtins.open", fake_open)

        socks = hmp._listening_sockets()
        assert ("127.0.0.1", 0x04D2) in socks   # 1234, listening
        assert not any(p == 0x1F90 for _, p in socks)  # established, not LISTEN

    def test_falls_back_to_connect_when_proc_is_unavailable(self, monkeypatch):
        import socket as socket_mod

        hmp = importlib.import_module("winbox.kdbg.hmp")

        monkeypatch.setattr(hmp, "_listening_sockets", lambda: None)

        class FakeConn:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(
            socket_mod, "create_connection", lambda *a, **kw: FakeConn()
        )
        assert hmp.probe_port("127.0.0.1", 1234) is True

        def refuse(*a, **kw):
            raise OSError("refused")

        monkeypatch.setattr(socket_mod, "create_connection", refuse)
        assert hmp.probe_port("127.0.0.1", 1234) is False


class TestProbePortAddressMatching:
    """Matching on port alone would let an unrelated service on the same port
    read as "the gdbstub is up", which makes `kdbg start` refuse to run."""

    def _probe(self, monkeypatch, sockets, host="127.0.0.1", port=1234):
        hmp = importlib.import_module("winbox.kdbg.hmp")
        monkeypatch.setattr(hmp, "_listening_sockets", lambda: sockets)
        return hmp.probe_port(host, port)

    def test_exact_host_matches(self, monkeypatch):
        assert self._probe(monkeypatch, {("127.0.0.1", 1234)}) is True

    def test_wildcard_bind_matches(self, monkeypatch):
        """`--any-interface` binds 0.0.0.0; that still serves 127.0.0.1."""
        assert self._probe(monkeypatch, {("0.0.0.0", 1234)}) is True

    def test_ipv6_or_unparsed_address_matches(self, monkeypatch):
        """Better to accept than to report a live stub as absent."""
        assert self._probe(monkeypatch, {(None, 1234)}) is True

    def test_a_different_host_on_the_same_port_does_not_match(self, monkeypatch):
        assert self._probe(monkeypatch, {("10.1.2.3", 1234)}) is False

    def test_a_different_port_does_not_match(self, monkeypatch):
        assert self._probe(monkeypatch, {("127.0.0.1", 4321)}) is False

    def test_no_listeners_at_all(self, monkeypatch):
        assert self._probe(monkeypatch, set()) is False


class TestHexToIpv4:
    """/proc stores IPv4 little-endian, so a naive decode reverses the octets."""

    def test_loopback(self):
        hmp = importlib.import_module("winbox.kdbg.hmp")
        assert hmp._hex_to_ipv4("0100007F") == "127.0.0.1"

    def test_wildcard(self):
        hmp = importlib.import_module("winbox.kdbg.hmp")
        assert hmp._hex_to_ipv4("00000000") == "0.0.0.0"

    def test_libvirt_bridge(self):
        hmp = importlib.import_module("winbox.kdbg.hmp")
        assert hmp._hex_to_ipv4("017AA8C0") == "192.168.122.1"

    def test_rejects_malformed_input(self):
        hmp = importlib.import_module("winbox.kdbg.hmp")
        assert hmp._hex_to_ipv4("00FF") is None
        assert hmp._hex_to_ipv4("ZZZZZZZZ") is None


class TestResumeIsSafeOnARunningVm:
    """`kdbg resume` documents itself as a no-op when the VM is already
    running. It wasn't: it connected to the gdbstub and issued `continue`,
    which blocks waiting for a stop reply that never arrives, and surfaced as
    `RspError('empty stop reply')`. A recovery valve that errors on a healthy
    VM is one people learn not to trust."""

    def _invoke(self, state):
        from click.testing import CliRunner

        from winbox.cli import cli
        from winbox.vm import VMState

        with (
            patch("winbox.cli.kdbg.VM") as vm_cls,
            patch("winbox.cli.kdbg.probe_port") as probe,
            patch("winbox.cli.kdbg.RspClient") as rsp,
        ):
            vm_cls.return_value.state.return_value = state
            result = CliRunner().invoke(cli, ["kdbg", "resume"])
        return result, probe, rsp

    def test_running_vm_is_a_clean_no_op(self):
        from winbox.vm import VMState

        result, probe, rsp = self._invoke(VMState.RUNNING)

        assert result.exit_code == 0, result.output
        assert "already running" in result.output
        # It must not even look at the stub, let alone connect to it.
        probe.assert_not_called()
        rsp.connect.assert_not_called()

    def test_shutoff_vm_reports_nothing_to_do(self):
        from winbox.vm import VMState

        result, _, rsp = self._invoke(VMState.SHUTOFF)

        assert result.exit_code == 0
        assert "nothing to do" in result.output
        rsp.connect.assert_not_called()

    def test_paused_vm_still_goes_to_the_stub(self):
        """The actual recovery path must not be short-circuited away."""
        from winbox.vm import VMState

        _, probe, _ = self._invoke(VMState.PAUSED)

        probe.assert_called_once()
