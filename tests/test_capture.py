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


# ─── backend selection ──────────────────────────────────────────────────────


class TestPickBackend:
    def test_prefers_dumpcap(self):
        with patch.object(cap.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"):
            assert cap.pick_backend() == "dumpcap"

    def test_falls_back_to_tcpdump(self):
        with patch.object(
            cap.shutil, "which",
            side_effect=lambda n: None if n == "dumpcap" else f"/usr/bin/{n}",
        ):
            assert cap.pick_backend() == "tcpdump"

    def test_none_when_neither_installed(self):
        with patch.object(cap.shutil, "which", return_value=None):
            assert cap.pick_backend() is None


class TestCanCaptureUnprivileged:
    def test_root_always_can(self):
        with patch.object(cap.os, "geteuid", return_value=0):
            assert cap.can_capture_unprivileged("/usr/bin/anything") is True

    def test_not_executable_by_us(self):
        with patch.object(cap.os, "geteuid", return_value=1000), \
                patch.object(cap.os, "access", return_value=False):
            assert cap.can_capture_unprivileged("/usr/bin/dumpcap") is False

    def test_executable_but_no_cap_net_raw(self):
        with patch.object(cap.os, "geteuid", return_value=1000), \
                patch.object(cap.os, "access", return_value=True), \
                patch.object(cap.subprocess, "run",
                             return_value=MagicMock(stdout="")):
            assert cap.can_capture_unprivileged("/usr/bin/tcpdump") is False

    def test_executable_with_cap_net_raw(self):
        with patch.object(cap.os, "geteuid", return_value=1000), \
                patch.object(cap.os, "access", return_value=True), \
                patch.object(
                    cap.subprocess, "run",
                    return_value=MagicMock(
                        stdout="/usr/bin/dumpcap cap_net_admin,cap_net_raw=eip\n"
                    ),
                ):
            assert cap.can_capture_unprivileged("/usr/bin/dumpcap") is True

    def test_getcap_missing_is_not_fatal(self):
        with patch.object(cap.os, "geteuid", return_value=1000), \
                patch.object(cap.os, "access", return_value=True), \
                patch.object(cap.subprocess, "run", side_effect=OSError("no getcap")):
            assert cap.can_capture_unprivileged("/usr/bin/dumpcap") is False


class TestBuildCaptureCmd:
    def test_tcpdump_uses_positional_filter_and_dash_capital_u(self, tmp_path):
        pcap = tmp_path / "x.pcap"
        cmd = cap.build_capture_cmd("tcpdump", "virbr0", pcap, "not port 22")
        assert cmd == ["tcpdump", "-i", "virbr0", "-U", "-w", str(pcap), "not port 22"]

    def test_dumpcap_uses_dash_f_for_filter(self, tmp_path):
        pcap = tmp_path / "x.pcap"
        cmd = cap.build_capture_cmd("dumpcap", "virbr0", pcap, "not port 22")
        assert cmd == ["dumpcap", "-i", "virbr0", "-w", str(pcap), "-f", "not port 22"]

    def test_no_filter_omits_the_flag(self, tmp_path):
        pcap = tmp_path / "x.pcap"
        assert cap.build_capture_cmd("dumpcap", "virbr0", pcap, None) == [
            "dumpcap", "-i", "virbr0", "-w", str(pcap),
        ]


# ─── start ──────────────────────────────────────────────────────────────────


class TestStart:
    def _invoke(self, runner, cfg, args=()):
        return runner.invoke(cap.capture_start, list(args), obj={"cfg": cfg})

    def _still_running_proc(self, pid=9999):
        proc = MagicMock()
        proc.pid = pid
        proc.poll.return_value = None  # still alive past the startup check
        return proc

    def test_writes_pidfile_and_records_pcap(self, runner, cfg):
        proc = self._still_running_proc(9999)
        with patch.object(cap, "pick_backend", return_value="tcpdump"), \
                patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap, "can_capture_unprivileged", return_value=True), \
                patch.object(cap, "discover_bridge", return_value="virbr0"), \
                patch.object(cap.time, "sleep"), \
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
        proc = self._still_running_proc(100)
        out = tmp_path / "custom" / "my.pcap"
        with patch.object(cap, "pick_backend", return_value="tcpdump"), \
                patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap, "can_capture_unprivileged", return_value=True), \
                patch.object(cap, "discover_bridge", return_value="virbr0"), \
                patch.object(cap.time, "sleep"), \
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

    def test_missing_backend(self, runner, cfg):
        with patch.object(cap, "pick_backend", return_value=None):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "neither dumpcap nor tcpdump" in result.output.lower()

    def test_needs_root_when_backend_cannot_capture_unprivileged(self, runner, cfg):
        with patch.object(cap, "pick_backend", return_value="tcpdump"), \
                patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap, "can_capture_unprivileged", return_value=False):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "elevated privileges" in result.output.lower()
        assert "sudo" in result.output.lower()

    def test_dumpcap_without_privilege_suggests_the_wireshark_group(self, runner, cfg):
        with patch.object(cap, "pick_backend", return_value="dumpcap"), \
                patch.object(cap.shutil, "which", return_value="/usr/bin/dumpcap"), \
                patch.object(cap, "can_capture_unprivileged", return_value=False):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "wireshark" in result.output.lower()

    def test_already_running(self, runner, cfg):
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        cap.pidfile_path(cfg).write_text("1234\n/tmp/old.pcap\n")
        with patch.object(cap, "pick_backend", return_value="tcpdump"), \
                patch.object(cap.shutil, "which", return_value="/usr/sbin/tcpdump"), \
                patch.object(cap, "can_capture_unprivileged", return_value=True), \
                patch.object(cap, "pid_alive", return_value=True), \
                patch.object(cap.subprocess, "Popen") as popen:
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "already running" in result.output.lower()
        popen.assert_not_called()

    def test_reports_and_cleans_up_when_backend_dies_immediately(self, runner, cfg):
        proc = MagicMock()
        proc.pid = 4242
        proc.poll.return_value = 1  # already exited by the time we check
        proc.returncode = 1
        with patch.object(cap, "pick_backend", return_value="dumpcap"), \
                patch.object(cap.shutil, "which", return_value="/usr/bin/dumpcap"), \
                patch.object(cap, "can_capture_unprivileged", return_value=True), \
                patch.object(cap, "discover_bridge", return_value="virbr0"), \
                patch.object(cap.time, "sleep"), \
                patch.object(cap.subprocess, "Popen", return_value=proc):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 1
        assert "exited immediately" in result.output.lower()
        assert cap.read_pidfile(cfg) is None
        # the stderr logfile is cleaned up, not left behind on failure
        assert list(cap.captures_dir(cfg).glob("*.log")) == []


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

    def test_pcap_path_with_markup_chars_does_not_crash(self, runner, cfg):
        # A user-chosen -o path can contain rich markup metacharacters; the
        # path is echoed back verbatim and must not be parsed as markup.
        # `[/]` is a stray closing tag that raises MarkupError unescaped,
        # which would crash status after the capture child is already up.
        cap.captures_dir(cfg).mkdir(parents=True, exist_ok=True)
        cap.pidfile_path(cfg).write_text("8888\n/tmp/weird[/].pcap\n")
        with patch.object(cap, "pid_alive", return_value=True):
            result = self._invoke(runner, cfg)
        assert result.exit_code == 0, result.output
        assert "/tmp/weird[/].pcap" in result.output
