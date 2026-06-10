"""Tests for winbox.cli.capture — host-side pcap capture for C2 extraction."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbox.cli import capture as cap


# ─── bridge discovery ──────────────────────────────────────────────────────


def _completed(returncode=0, stdout=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    return proc


class TestDiscoverBridge:
    def test_parses_bridge_line(self):
        out = (
            "Name:           default\n"
            "Active:         yes\n"
            "Bridge:         virbr5\n"
        )
        with patch.object(cap, "virsh_run", return_value=_completed(0, out)):
            assert cap.discover_bridge() == "virbr5"

    def test_falls_back_on_missing_line(self):
        out = "Name:           default\nActive:         yes\n"
        with patch.object(cap, "virsh_run", return_value=_completed(0, out)):
            assert cap.discover_bridge() == "virbr0"

    def test_falls_back_on_virsh_failure(self):
        with patch.object(cap, "virsh_run", return_value=_completed(1, "")):
            assert cap.discover_bridge() == "virbr0"

    def test_falls_back_on_virsh_exception(self):
        with patch.object(cap, "virsh_run", side_effect=RuntimeError("boom")):
            assert cap.discover_bridge() == "virbr0"


# ─── pidfile helpers ────────────────────────────────────────────────────────


class TestPidfile:
    def test_read_missing(self, cfg):
        assert cap.read_pidfile(cfg) is None

    def test_round_trip(self, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        pcap = cap.captures_dir(cfg) / "x.pcap"
        cap.pidfile_path(cfg).write_text(f"4321\n{pcap}\n")
        pid, path = cap.read_pidfile(cfg)
        assert pid == 4321
        assert path == pcap

    def test_malformed(self, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        cap.pidfile_path(cfg).write_text("not-a-pid\n")
        assert cap.read_pidfile(cfg) is None


# ─── start ──────────────────────────────────────────────────────────────────


class TestStart:
    def _invoke(self, runner, cfg, args=()):
        return runner.invoke(cap.capture_start, list(args), obj={"cfg": cfg})

    def test_writes_pidfile_and_records_pcap(self, runner, cfg):
        proc = MagicMock()
        proc.pid = 9999
        with patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap.os, "geteuid", return_value=0), \
                patch.object(cap, "discover_bridge", return_value="virbr0"), \
                patch.object(cap.subprocess, "Popen", return_value=proc) as popen:
            result = self._invoke(runner, cfg)

        assert result.exit_code == 0, result.output
        state = cap.read_pidfile(cfg)
        assert state is not None
        pid, pcap = state
        assert pid == 9999
        # pcap path is under the captures dir with a timestamped name.
        assert pcap.parent == cap.captures_dir(cfg)
        assert pcap.suffix == ".pcap"
        # tcpdump invoked on the bridge writing to that pcap.
        cmd = popen.call_args[0][0]
        assert cmd[0] == "tcpdump"
        assert "virbr0" in cmd
        assert str(pcap) in cmd

    def test_filter_passthrough_and_output_override(self, runner, cfg, tmp_path):
        proc = MagicMock()
        proc.pid = 100
        out = tmp_path / "custom" / "my.pcap"
        with patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap.os, "geteuid", return_value=0), \
                patch.object(cap, "discover_bridge", return_value="virbr0"), \
                patch.object(cap.subprocess, "Popen", return_value=proc) as popen:
            result = self._invoke(
                runner, cfg, ["--filter", "not port 22", "-o", str(out)]
            )

        assert result.exit_code == 0, result.output
        cmd = popen.call_args[0][0]
        assert "not port 22" in cmd
        assert str(out) in cmd
        _, pcap = cap.read_pidfile(cfg)
        assert pcap == out
        assert out.parent.exists()

    def test_missing_tcpdump(self, runner, cfg):
        with patch.object(cap.shutil, "which", return_value=None):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "tcpdump not found" in result.output

    def test_non_root(self, runner, cfg):
        with patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap.os, "geteuid", return_value=1000):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "root" in result.output.lower()
        assert "sudo" in result.output.lower()

    def test_already_running(self, runner, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        cap.pidfile_path(cfg).write_text("1234\n/tmp/old.pcap\n")
        with patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap.os, "geteuid", return_value=0), \
                patch.object(cap, "pid_alive", return_value=True), \
                patch.object(cap.subprocess, "Popen") as popen:
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "already running" in result.output.lower()
        popen.assert_not_called()


# ─── stop ─────────────────────────────────────────────────────────────────


class TestStop:
    def _invoke(self, runner, cfg):
        return runner.invoke(cap.capture_stop, [], obj={"cfg": cfg})

    def test_signals_and_cleans_up(self, runner, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        pcap = cap.captures_dir(cfg) / "c.pcap"
        pcap.write_bytes(b"\x00" * 2048)
        cap.pidfile_path(cfg).write_text(f"5555\n{pcap}\n")

        with patch.object(cap, "pid_alive", return_value=True), \
                patch.object(cap.os, "kill") as kill:
            result = self._invoke(runner, cfg)

        assert result.exit_code == 0, result.output
        kill.assert_called_once()
        assert kill.call_args[0][0] == 5555
        assert not cap.pidfile_path(cfg).exists()
        # rich may wrap the path across lines in a narrow test terminal;
        # collapse whitespace before matching.
        flat = "".join(result.output.split())
        assert "".join(str(pcap).split()) in flat
        assert "pcap saved" in result.output

    def test_no_pidfile(self, runner, cfg):
        result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "no capture running" in result.output.lower()

    def test_stale_pid_still_cleans_up(self, runner, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        cap.pidfile_path(cfg).write_text("7777\n/tmp/gone.pcap\n")
        with patch.object(cap, "pid_alive", return_value=False), \
                patch.object(cap.os, "kill") as kill:
            result = self._invoke(runner, cfg)
        assert result.exit_code == 0
        kill.assert_not_called()
        assert not cap.pidfile_path(cfg).exists()


# ─── status ─────────────────────────────────────────────────────────────────


class TestStatus:
    def _invoke(self, runner, cfg):
        with patch.object(cap, "discover_bridge", return_value="virbr0"):
            return runner.invoke(cap.capture_status, [], obj={"cfg": cfg})

    def test_stopped_when_no_pidfile(self, runner, cfg):
        result = self._invoke(runner, cfg)
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()
        assert "virbr0" in result.output

    def test_running(self, runner, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        pcap = cap.captures_dir(cfg) / "c.pcap"
        pcap.write_bytes(b"\x00" * 1024)
        cap.pidfile_path(cfg).write_text(f"8888\n{pcap}\n")
        with patch.object(cap, "pid_alive", return_value=True):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 0
        assert "running" in result.output.lower()
        assert "8888" in result.output

    def test_stale(self, runner, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        cap.pidfile_path(cfg).write_text("9999\n/tmp/x.pcap\n")
        with patch.object(cap, "pid_alive", return_value=False):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 0
        assert "stale" in result.output.lower()
