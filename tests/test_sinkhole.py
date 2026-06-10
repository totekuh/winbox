"""Tests for the DNS sinkhole (packet codec + process mgmt + CLI)."""

from __future__ import annotations

import ipaddress
import os
import struct
from unittest.mock import MagicMock, patch

import pytest

from winbox import sinkhole as sk
from winbox.cli.sinkhole import sinkhole
from winbox.config import Config


# ─── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    return c


def _build_query_packet(qname: str, qtype: int = sk.QTYPE_A, txid: int = 0x1234) -> bytes:
    """Hand-build a minimal DNS request packet for ``qname``."""
    header = struct.pack(
        "!HHHHHH",
        txid,
        0x0100,  # flags: standard query, RD=1
        1,       # qdcount
        0, 0, 0,
    )
    return header + sk._encode_name(qname) + struct.pack("!HH", qtype, sk.QCLASS_IN)


def _parse_a_rdata(resp: bytes, query: sk.DNSQuery) -> str:
    """Extract the A-record RDATA (the sink IP) from a response packet."""
    # header(12) + question(len) -> answer starts here.
    ans = resp[12 + len(query.question):]
    # name pointer(2) + type(2) + class(2) + ttl(4) + rdlen(2) = 12 bytes
    rdlen = struct.unpack_from("!H", ans, 10)[0]
    rdata = ans[12 : 12 + rdlen]
    assert rdlen == 4
    return str(ipaddress.IPv4Address(rdata))


# ─── DNS codec ──────────────────────────────────────────────────────────────


class TestDNSCodec:
    def test_a_response_points_at_sink_and_echoes_qname(self):
        pkt = _build_query_packet("c2.evil.example", txid=0xABCD)
        query = sk.parse_query(pkt)
        assert query.qname == "c2.evil.example"
        assert query.qtype == sk.QTYPE_A
        assert query.txid == 0xABCD

        resp = sk.build_response(query, "192.168.122.1", ttl=60)

        # Header: same txid, QR bit set, ancount == 1.
        rxid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", resp, 0)
        assert rxid == 0xABCD
        assert flags & 0x8000  # QR
        assert qd == 1
        assert an == 1

        # RDATA is the sink IP; question (qname) round-trips verbatim.
        assert _parse_a_rdata(resp, query) == "192.168.122.1"
        assert resp[12 : 12 + len(query.question)] == query.question

    def test_a_response_uses_configured_ttl(self):
        pkt = _build_query_packet("x.test")
        query = sk.parse_query(pkt)
        resp = sk.build_response(query, "10.0.0.5", ttl=42)
        ans = resp[12 + len(query.question):]
        ttl = struct.unpack_from("!I", ans, 6)[0]
        assert ttl == 42

    def test_arbitrary_qname_resolves_to_sink(self):
        for name in ("a.b.c.d.example", "single", "very-long-subdomain.attacker.tld"):
            query = sk.parse_query(_build_query_packet(name))
            resp = sk.build_response(query, "192.168.122.1")
            assert _parse_a_rdata(resp, query) == "192.168.122.1"
            assert query.qname == name

    def test_aaaa_is_nodata_not_a_record(self):
        pkt = _build_query_packet("ipv6.evil.example", qtype=sk.QTYPE_AAAA)
        query = sk.parse_query(pkt)
        resp = sk.build_response(query, "192.168.122.1")
        _, flags, _, an, _, _ = struct.unpack_from("!HHHHHH", resp, 0)
        assert an == 0           # NODATA
        assert flags & 0xF == 0  # RCODE NOERROR

    def test_parse_rejects_short_packet(self):
        with pytest.raises(ValueError):
            sk.parse_query(b"\x00\x01")

    def test_parse_rejects_no_question(self):
        bad = struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0)
        with pytest.raises(ValueError):
            sk.parse_query(bad)


# ─── query logging ────────────────────────────────────────────────────────────


class TestQueryLog:
    def test_log_line_is_greppable(self):
        from datetime import datetime
        line = sk.format_log_line(
            "c2.evil.example", sk.QTYPE_A, "192.168.122.203",
            when=datetime(2026, 6, 10, 14, 3, 11),
        )
        parts = line.split("\t")
        assert parts == ["2026-06-10T14:03:11", "c2.evil.example", "A", "192.168.122.203"]

    def test_append_log_writes_line(self, cfg):
        path = sk.query_log_path(cfg)
        sk.append_log(path, "line one")
        sk.append_log(path, "line two")
        assert path.read_text().splitlines() == ["line one", "line two"]
        assert sk.line_count(path) == 2

    def test_aaaa_qtype_renders_in_log(self):
        line = sk.format_log_line("x.test", sk.QTYPE_AAAA, "1.2.3.4")
        assert "\tAAAA\t" in line


# ─── process / pidfile management ──────────────────────────────────────────────


class TestProcessMgmt:
    def test_write_then_read_pidfile(self, cfg):
        sk.write_pidfile(cfg, 4242)
        assert sk.read_pidfile(cfg) == 4242
        assert sk.read_port(cfg) == sk.DNS_PORT  # no port token -> default

    def test_write_pidfile_with_port_roundtrips(self, cfg):
        sk.write_pidfile(cfg, 4242, 5353)
        assert sk.read_pidfile(cfg) == 4242
        assert sk.read_port(cfg) == 5353

    def test_wait_ready_true_when_marker_present(self, tmp_path):
        log = tmp_path / "server.log"
        log.write_text(f"{sk.READY_MARKER} on 192.168.122.1:53\n")
        proc = MagicMock()
        proc.poll.return_value = None
        assert sk.wait_ready(log, proc, timeout=1.0) is True

    def test_wait_ready_false_when_proc_exits(self, tmp_path):
        log = tmp_path / "server.log"  # never gets the marker
        proc = MagicMock()
        proc.poll.return_value = 1  # process already exited
        assert sk.wait_ready(log, proc, timeout=1.0) is False

    def test_read_pidfile_missing(self, cfg):
        assert sk.read_pidfile(cfg) is None

    def test_read_pidfile_garbage(self, cfg):
        sk.pidfile_path(cfg).parent.mkdir(parents=True, exist_ok=True)
        sk.pidfile_path(cfg).write_text("not-a-pid")
        assert sk.read_pidfile(cfg) is None

    def test_is_running_cleans_stale_pidfile(self, cfg):
        # A PID that's almost certainly dead.
        sk.write_pidfile(cfg, 999999)
        with patch.object(sk, "pid_alive", return_value=False):
            assert sk.is_running(cfg) is None
        assert not sk.pidfile_path(cfg).exists()

    def test_is_running_reports_live_pid(self, cfg):
        sk.write_pidfile(cfg, os.getpid())
        assert sk.is_running(cfg) == os.getpid()

    def test_stop_signals_and_clears_pidfile(self, cfg):
        sk.write_pidfile(cfg, 5555)
        with patch.object(sk, "pid_alive", side_effect=[True, False]), \
             patch.object(sk.os, "kill") as mock_kill:
            assert sk.stop(cfg) is True
            mock_kill.assert_called_once()
        assert not sk.pidfile_path(cfg).exists()

    def test_stop_when_not_running(self, cfg):
        assert sk.stop(cfg) is False


# ─── port-in-use detection ──────────────────────────────────────────────────────


class TestPortInUse:
    def test_ephemeral_loopback_roundtrip(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        try:
            assert sk.port_in_use("127.0.0.1", port) is True
        finally:
            s.close()
        # Once freed it should report available.
        assert sk.port_in_use("127.0.0.1", port) is False


# ─── CLI ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def ctx_obj(cfg):
    return {"cfg": cfg}


class TestCLIStart:
    def test_start_permission_denied_errors(self, runner, ctx_obj):
        """Privileged-port bind denied -> actionable error, not 'needs root'."""
        with patch.object(sk, "is_running", return_value=None), \
             patch.object(sk, "try_bind", return_value="denied"):
            result = runner.invoke(sinkhole, ["start"], obj=ctx_obj)
        assert result.exit_code == 1
        assert "permission denied" in result.output.lower()
        # Offers the non-root paths, not just "use sudo".
        assert "ip_unprivileged_port_start" in result.output
        assert "--port" in result.output

    def test_start_port_in_use_errors(self, runner, ctx_obj):
        with patch.object(sk, "is_running", return_value=None), \
             patch.object(sk, "try_bind", return_value="in_use"):
            result = runner.invoke(sinkhole, ["start"], obj=ctx_obj)
        assert result.exit_code == 1
        assert "udp/53" in result.output

    def test_start_already_running_errors(self, runner, ctx_obj):
        with patch.object(sk, "is_running", return_value=1234):
            result = runner.invoke(sinkhole, ["start"], obj=ctx_obj)
        assert result.exit_code == 1
        assert "already running" in result.output.lower()

    def test_start_launches_detached_and_writes_pidfile(self, runner, ctx_obj, cfg):
        fake_proc = MagicMock()
        fake_proc.pid = 7777
        with patch.object(sk, "is_running", return_value=None), \
             patch.object(sk, "try_bind", return_value="ok"), \
             patch.object(sk, "wait_ready", return_value=True), \
             patch("winbox.cli.sinkhole.subprocess.Popen", return_value=fake_proc) as popen:
            result = runner.invoke(sinkhole, ["start"], obj=ctx_obj)
        assert result.exit_code == 0
        # Re-invokes itself as `-m winbox sinkhole _serve`.
        cmd = popen.call_args[0][0]
        assert cmd[1:4] == ["-m", "winbox", "sinkhole"]
        assert "_serve" in cmd
        assert popen.call_args.kwargs.get("start_new_session") is True
        assert sk.read_pidfile(cfg) == 7777

    def test_start_high_port_runs_unprivileged(self, runner, ctx_obj, cfg):
        """--port lets it bind a high port without privilege."""
        fake_proc = MagicMock()
        fake_proc.pid = 8888
        with patch.object(sk, "is_running", return_value=None), \
             patch.object(sk, "try_bind", return_value="ok") as tb, \
             patch.object(sk, "wait_ready", return_value=True), \
             patch("winbox.cli.sinkhole.subprocess.Popen", return_value=fake_proc) as popen:
            result = runner.invoke(sinkhole, ["start", "--port", "5353"], obj=ctx_obj)
        assert result.exit_code == 0
        # Probed the high port, and threaded it into the detached server.
        assert tb.call_args_list[0][0][1] == 5353
        cmd = popen.call_args[0][0]
        assert "--port" in cmd and "5353" in cmd
        assert "redirect" in result.output.lower()
        # The bound port is persisted so `status` reports it accurately.
        assert sk.read_port(cfg) == 5353


class TestCLIStop:
    def test_stop_running(self, runner, ctx_obj):
        with patch.object(sk, "stop", return_value=True):
            result = runner.invoke(sinkhole, ["stop"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_stop_not_running(self, runner, ctx_obj):
        with patch.object(sk, "stop", return_value=False):
            result = runner.invoke(sinkhole, ["stop"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "not running" in result.output.lower()


class TestCLIStatus:
    def test_status_stopped(self, runner, ctx_obj):
        with patch.object(sk, "is_running", return_value=None):
            result = runner.invoke(sinkhole, ["status"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_status_running_with_count(self, runner, ctx_obj, cfg):
        sk.append_log(sk.query_log_path(cfg), "a")
        sk.append_log(sk.query_log_path(cfg), "b")
        with patch.object(sk, "is_running", return_value=4321):
            result = runner.invoke(sinkhole, ["status"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "running" in result.output.lower()
        assert "4321" in result.output
        assert "2 logged" in result.output


class TestCLILog:
    def test_log_empty(self, runner, ctx_obj):
        result = runner.invoke(sinkhole, ["log"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "no queries" in result.output.lower()

    def test_log_prints_lines(self, runner, ctx_obj, cfg):
        sk.append_log(sk.query_log_path(cfg), "2026-06-10T00:00:00\tc2.evil\tA\t1.2.3.4")
        result = runner.invoke(sinkhole, ["log"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "c2.evil" in result.output

    def test_log_tail_n(self, runner, ctx_obj, cfg):
        for i in range(5):
            sk.append_log(sk.query_log_path(cfg), f"line{i}")
        result = runner.invoke(sinkhole, ["log", "-n", "2"], obj=ctx_obj)
        assert result.exit_code == 0
        assert "line3" in result.output and "line4" in result.output
        assert "line0" not in result.output


class TestCLIInetsim:
    def test_inetsim_not_installed(self, runner, ctx_obj):
        with patch.object(sk, "inetsim_installed", return_value=None):
            result = runner.invoke(sinkhole, ["inetsim"], obj=ctx_obj)
        assert result.exit_code == 1
        assert "apt install inetsim" in result.output

    def test_inetsim_installed_writes_conf(self, runner, ctx_obj, cfg):
        with patch.object(sk, "inetsim_installed", return_value="/usr/bin/inetsim"):
            result = runner.invoke(sinkhole, ["inetsim"], obj=ctx_obj)
        assert result.exit_code == 0
        conf = sk.inetsim_conf_path(cfg)
        assert conf.exists()
        text = conf.read_text()
        # DNS must be left to our own sinkhole (commented out).
        assert "# start_service dns" in text
        assert "start_service http" in text
        assert cfg.host_ip in text


# ─── shutil.which detection ────────────────────────────────────────────────────


class TestInetsimDetection:
    def test_detected_via_which(self):
        with patch("shutil.which", return_value="/usr/bin/inetsim"):
            assert sk.inetsim_installed() == "/usr/bin/inetsim"

    def test_not_detected(self):
        with patch("shutil.which", return_value=None), \
             patch("winbox.sinkhole.Path.exists", return_value=False):
            assert sk.inetsim_installed() is None
