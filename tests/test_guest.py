"""Tests for winbox.guest — base64 decoding and ExecResult."""

import base64

import pytest

from winbox.vm.guest import ExecResult, _decode_b64


class TestDecodeB64:
    def test_normal_string(self):
        encoded = base64.b64encode(b"hello world").decode()
        assert _decode_b64(encoded) == "hello world"

    def test_empty_string(self):
        assert _decode_b64("") == ""

    def test_none_like_falsy(self):
        # The function checks `if not data`, so empty/falsy => ""
        assert _decode_b64("") == ""

    def test_multiline_output(self):
        text = "line one\nline two\nline three\n"
        encoded = base64.b64encode(text.encode()).decode()
        assert _decode_b64(encoded) == text

    def test_unicode_content(self):
        text = "hello \u2603 snowman"
        encoded = base64.b64encode(text.encode("utf-8")).decode()
        assert _decode_b64(encoded) == text

    def test_invalid_base64_returns_empty(self):
        assert _decode_b64("!!!not-base64!!!") == ""

    def test_windows_line_endings(self):
        text = "line one\r\nline two\r\n"
        encoded = base64.b64encode(text.encode()).decode()
        assert _decode_b64(encoded) == text

    def test_binary_with_replacement(self):
        # Invalid UTF-8 bytes should be replaced, not crash
        raw = b"\x80\x81\x82"
        encoded = base64.b64encode(raw).decode()
        result = _decode_b64(encoded)
        assert isinstance(result, str)
        assert len(result) > 0  # replacement chars

    def test_large_output(self):
        text = "A" * 100_000
        encoded = base64.b64encode(text.encode()).decode()
        assert _decode_b64(encoded) == text


class TestExecResult:
    def test_creation(self):
        r = ExecResult(exitcode=0, stdout="out", stderr="err")
        assert r.exitcode == 0
        assert r.stdout == "out"
        assert r.stderr == "err"

    def test_equality(self):
        r1 = ExecResult(exitcode=0, stdout="a", stderr="b")
        r2 = ExecResult(exitcode=0, stdout="a", stderr="b")
        assert r1 == r2

    def test_nonzero_exit(self):
        r = ExecResult(exitcode=1, stdout="", stderr="error msg")
        assert r.exitcode == 1
        assert r.stderr == "error msg"


class TestExecPollTolerance:
    """Audit fix: ga.exec used to die on a single transient mid-poll error.
    Now it tolerates up to 5 consecutive errors before giving up."""

    def _make_ga(self):
        from winbox.vm.guest import GuestAgent
        from winbox.config import Config
        ga = GuestAgent(Config())
        return ga

    def test_tolerates_single_transient_error(self, monkeypatch):
        from winbox.vm.guest import GuestAgentError

        ga = self._make_ga()

        # Sequence:
        #   1. guest-exec  -> {return: {pid: 42}}
        #   2. guest-exec-status -> raise (transient)
        #   3. guest-exec-status -> {return: {exited: True, exitcode: 0}}
        from tests.conftest import nonce_aware

        fake_raw = nonce_aware([
            {"return": {"pid": 42}},
            GuestAgentError("transient"),
            {"return": {"exited": True, "exitcode": 0}},
        ])

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        # poll_interval=0 so the test doesn't actually sleep on retry
        result = ga.exec("whoami", timeout=10, poll_interval=0)
        assert result.exitcode == 0

    def test_gives_up_after_too_many_transient_errors(self, monkeypatch):
        from winbox.vm.guest import GuestAgentError
        import pytest

        ga = self._make_ga()

        call_count = [0]

        def fake_raw(payload, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"return": {"pid": 99}}
            raise GuestAgentError("persistent")

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        with pytest.raises(GuestAgentError, match="persistent"):
            ga.exec("whoami", timeout=10, poll_interval=0)
        # Initial guest-exec + 6 status polls (5 tolerated, 6th raises)
        assert call_count[0] >= 6


class TestPowershellStderrHygiene:
    """With stderr redirected, PowerShell serializes its *progress* stream as
    a CLIXML document onto stderr. Callers then saw hundreds of bytes of XML
    on every Defender query and had to treat it as if it were an error."""

    def test_progress_preference_is_disabled_in_the_script(self, monkeypatch):
        import base64

        from winbox.config import Config
        from winbox.vm.guest import ExecResult, GuestAgent

        ga = GuestAgent(Config())
        seen = {}

        def fake_exec(cmd, *, timeout=300):
            encoded = cmd.split("-EncodedCommand ")[1]
            seen["script"] = base64.b64decode(encoded).decode("utf-16-le")
            return ExecResult(exitcode=0, stdout="", stderr="")

        monkeypatch.setattr(ga, "exec", fake_exec)
        ga.exec_powershell("Get-MpComputerStatus")

        assert seen["script"].startswith("$ProgressPreference = 'SilentlyContinue'")
        assert "Get-MpComputerStatus" in seen["script"]

    def test_progress_only_clixml_is_dropped(self):
        from winbox.vm.guest import _strip_clixml_progress

        noise = (
            '#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft'
            '.com/powershell/2004/04"><Obj S="progress" RefId="0"><MS><PR N="Record">'
            "<AV>Preparing modules for first use.</AV></PR></MS></Obj></Objs>"
        )
        assert _strip_clixml_progress(noise) == ""

    def test_real_errors_are_preserved(self):
        """Losing a genuine PowerShell error to cosmetics would be worse."""
        from winbox.vm.guest import _strip_clixml_progress

        err = (
            '#< CLIXML\r\n<Objs Version="1.1.0.1"><S S="Error">'
            "Set-MpPreference : Access denied</S></Objs>"
        )
        assert _strip_clixml_progress(err) == err

    def test_warnings_are_preserved(self):
        from winbox.vm.guest import _strip_clixml_progress

        warn = '#< CLIXML\r\n<Objs><S S="Warning">deprecated</S></Objs>'
        assert _strip_clixml_progress(warn) == warn

    def test_plain_stderr_untouched(self):
        from winbox.vm.guest import _strip_clixml_progress

        assert _strip_clixml_progress("boom\r\n") == "boom\r\n"
        assert _strip_clixml_progress("") == ""

    def test_exec_powershell_returns_cleaned_stderr(self, monkeypatch):
        from winbox.config import Config
        from winbox.vm.guest import ExecResult, GuestAgent

        ga = GuestAgent(Config())
        monkeypatch.setattr(
            ga, "exec",
            lambda cmd, *, timeout=300: ExecResult(
                exitcode=0,
                stdout="Defender: ON\n",
                stderr='#< CLIXML\r\n<Objs><Obj S="progress"/></Objs>',
            ),
        )

        result = ga.exec_powershell("x")

        assert result.stdout == "Defender: ON\n"
        assert result.stderr == ""


class TestExecPowershellFile:
    """Script paths must never traverse cmd.exe.

    The guest agent escapes embedded quotes as \\" when it builds the Windows
    command line, and cmd.exe has no backslash-escape rule — so it forwarded
    them verbatim and PowerShell got a path with literal quote characters,
    failing every `winbox provision` with "Illegal characters in path".
    """

    def _ga(self, monkeypatch):
        from winbox.config import Config
        from winbox.vm.guest import ExecResult, GuestAgent

        ga = GuestAgent(Config())
        seen = {}

        def fake_exec_argv(path, args, *, timeout=300, poll_interval=0.5):
            seen["path"] = path
            seen["args"] = args
            return ExecResult(exitcode=0, stdout="", stderr="")

        def fail_exec(*a, **kw):
            raise AssertionError("must not route a script path through cmd.exe")

        monkeypatch.setattr(ga, "exec_argv", fake_exec_argv)
        monkeypatch.setattr(ga, "exec", fail_exec)
        return ga, seen

    def test_path_is_passed_as_argv_not_a_shell_string(self, monkeypatch):
        ga, seen = self._ga(monkeypatch)

        ga.exec_powershell_file(r"Z:\tools\provision.ps1")

        assert seen["path"] == "powershell.exe"
        assert seen["args"] == [
            "-ExecutionPolicy", "Bypass", "-File", r"Z:\tools\provision.ps1",
        ]

    def test_path_is_not_wrapped_in_quotes(self, monkeypatch):
        ga, seen = self._ga(monkeypatch)

        ga.exec_powershell_file(r"Z:\tools\provision.ps1")

        assert '"' not in seen["args"][-1]

    def test_path_with_spaces_needs_no_escaping(self, monkeypatch):
        ga, seen = self._ga(monkeypatch)

        ga.exec_powershell_file(r"C:\Program Files\x\s.ps1")

        assert seen["args"][-1] == r"C:\Program Files\x\s.ps1"

    def test_timeout_is_forwarded(self, monkeypatch):
        from winbox.config import Config
        from winbox.vm.guest import ExecResult, GuestAgent

        ga = GuestAgent(Config())
        seen = {}
        monkeypatch.setattr(
            ga, "exec_argv",
            lambda p, a, *, timeout=300, poll_interval=0.5: (
                seen.update(timeout=timeout) or ExecResult(0, "", "")
            ),
        )
        ga.exec_powershell_file("x.ps1", timeout=42)
        assert seen["timeout"] == 42


class TestPingIsChannelFirst:
    """ping() consults libvirt's channel state before spending a round-trip.

    The post-reboot flake is the channel dropping; firing a guest-ping into a
    dead pipe only learns that the slow way. So: channel down -> False with no
    round-trip; channel up -> confirm with the ping so a wedged-but-connected
    agent still reads not-ready.
    """

    def _ga(self, monkeypatch, *, connected, raw=None):
        from winbox.config import Config
        from winbox.vm.guest import GuestAgent

        ga = GuestAgent(Config())
        monkeypatch.setattr(
            "winbox.vm.guest.agent_channel_connected", lambda vm_name: connected
        )
        calls = []

        def fake_raw(payload, **kw):
            calls.append(payload)
            if raw is None:
                raise AssertionError("guest-ping must not run when channel is down")
            if isinstance(raw, Exception):
                raise raw
            return raw

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        return ga, calls

    def test_channel_down_returns_false_without_a_round_trip(self, monkeypatch):
        ga, calls = self._ga(monkeypatch, connected=False)
        assert ga.ping() is False
        assert calls == [], "no guest-ping should be attempted on a dead channel"

    def test_channel_up_and_agent_answers(self, monkeypatch):
        ga, calls = self._ga(monkeypatch, connected=True, raw={"return": {}})
        assert ga.ping() is True
        assert len(calls) == 1  # the confirming guest-ping ran

    def test_channel_up_but_agent_wedged(self, monkeypatch):
        from winbox.vm.guest import GuestAgentError

        ga, _ = self._ga(
            monkeypatch, connected=True, raw=GuestAgentError("no answer")
        )
        assert ga.ping() is False

    def test_wait_loops_on_the_channel_state(self, monkeypatch):
        """wait() inherits the channel gate through ping(), so it blocks until
        the channel is up — which is the whole point post-reboot."""
        from winbox.config import Config
        from winbox.vm.guest import GuestAgent

        ga = GuestAgent(Config())
        states = iter([False, False, True])
        monkeypatch.setattr(
            "winbox.vm.guest.agent_channel_connected", lambda vm_name: next(states)
        )
        monkeypatch.setattr(ga, "_raw_command", lambda p, **kw: {"return": {}})
        monkeypatch.setattr("time.sleep", lambda *_: None)

        ga.wait(timeout=5, interval=0)  # must return, not raise


class TestStartGuestExecLaunchRetry:
    """The launch-transport retry lives at the guest layer, so every entry point
    (exec, exec_argv, exec_background, exec_detached) inherits it — not just the
    CLI `run_command`. It is deliberately narrow: only GuestAgentUnreachable (the
    agent was never reached, so guest-exec never executed) is retried. A plain
    GuestAgentError — which a reply lost *after* the process spawned also looks
    like — is raised immediately, because re-sending it could double-run a
    non-idempotent command. See _start_guest_exec's docstring."""

    def _make_ga(self):
        from winbox.config import Config
        from winbox.vm.guest import GuestAgent
        return GuestAgent(Config())

    @pytest.fixture(autouse=True)
    def _no_launch_sleep(self, monkeypatch):
        # Don't actually sleep between launch retries.
        monkeypatch.setattr("winbox.vm.guest.time.sleep", lambda *_: None)

    def test_retries_unreachable_launch_then_succeeds(self, monkeypatch):
        from winbox.vm.guest import GuestAgentUnreachable

        ga = self._make_ga()
        calls = [0]

        def fake_raw(payload, **kw):
            calls[0] += 1
            if calls[0] == 1:
                # Agent never reached — nothing spawned, so retry is safe.
                raise GuestAgentUnreachable(
                    "Guest agent command failed: agent is not responding"
                )
            return {"return": {"pid": 4242}}

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        assert ga._start_guest_exec({"execute": "guest-exec"}) == 4242
        assert calls[0] == 2

    def test_plain_agent_error_is_not_retried(self, monkeypatch):
        """A plain GuestAgentError (the agent answered, or a reply lost after
        the process already spawned) must not be re-sent — double-run hazard."""
        from winbox.vm.guest import GuestAgentError

        ga = self._make_ga()
        calls = [0]

        def fake_raw(payload, **kw):
            calls[0] += 1
            raise GuestAgentError("guest-exec failed: some agent-side error")

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        with pytest.raises(GuestAgentError, match="agent-side error"):
            ga._start_guest_exec({"execute": "guest-exec"})
        assert calls[0] == 1

    def test_missing_pid_raises_immediately(self, monkeypatch):
        """No PID on a successful response is a degenerate result; re-sending it
        has the same double-run hazard, so it raises without retry."""
        ga = self._make_ga()
        calls = [0]

        def fake_raw(payload, **kw):
            calls[0] += 1
            return {"return": {}}

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        with pytest.raises(Exception, match="no PID"):
            ga._start_guest_exec({"execute": "guest-exec"})
        assert calls[0] == 1

    def test_persistent_unreachable_raises_after_retries(self, monkeypatch):
        from winbox.vm.guest import GuestAgentUnreachable, _LAUNCH_RETRIES

        ga = self._make_ga()
        calls = [0]

        def fake_raw(payload, **kw):
            calls[0] += 1
            raise GuestAgentUnreachable("persistent unreachable")

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        with pytest.raises(GuestAgentUnreachable, match="persistent"):
            ga._start_guest_exec({"execute": "guest-exec"})
        assert calls[0] == _LAUNCH_RETRIES

    def test_exec_background_inherits_retry(self, monkeypatch):
        from winbox.vm.guest import GuestAgentUnreachable

        ga = self._make_ga()
        calls = [0]

        def fake_raw(payload, **kw):
            calls[0] += 1
            if calls[0] == 1:
                raise GuestAgentUnreachable("agent not responding")
            return {"return": {"pid": 55}}

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        assert ga.exec_background("whoami") == 55
        assert calls[0] == 2

    def test_exec_detached_inherits_retry(self, monkeypatch):
        from winbox.vm.guest import GuestAgentUnreachable

        ga = self._make_ga()
        calls = [0]

        def fake_raw(payload, **kw):
            calls[0] += 1
            if calls[0] == 1:
                raise GuestAgentUnreachable("agent not responding")
            return {"return": {"pid": 88}}

        monkeypatch.setattr(ga, "_raw_command", fake_raw)
        assert ga.exec_detached("whoami") == 88
        assert calls[0] == 2

    def test_happy_path_launches_exactly_once(self, monkeypatch):
        """A successful exec must not fire the launch retry — otherwise it would
        consume an extra _raw_command and desync a canned response sequence."""
        from tests.conftest import nonce_aware

        ga = self._make_ga()
        launches = [0]
        base = nonce_aware([
            {"return": {"pid": 42}},
            {"return": {"exited": True, "exitcode": 0}},
        ])

        def counting(payload, **kw):
            if payload.get("execute") == "guest-exec":
                launches[0] += 1
            return base(payload, **kw)

        monkeypatch.setattr(ga, "_raw_command", counting)
        result = ga.exec("whoami", timeout=10, poll_interval=0)
        assert result.exitcode == 0
        assert launches[0] == 1
