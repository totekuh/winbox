"""Regression tests for cross-call output contamination in GuestAgent.exec.

The guest agent buffers each ``guest-exec`` result in a flat list keyed by the
guest's Windows PID, returns the *first* entry matching a requested PID, and
frees an entry only when a status read reports it exited. A result nobody
reads is therefore kept forever — and Windows recycles PIDs aggressively,
especially the short-lived ``cmd.exe`` PIDs every exec here burns.

That combination let one command receive another command's output and exit
code. It was observed live: an MCP ``python`` call returned 120 lines of
``ping`` output with exit code 1, from a background job the test suite had
started and killed minutes earlier. The same mechanism explains a ``file_copy``
that returned exit 1 with completely empty streams — the orphan it collided
with was started ``capture-output: false``, so it had no output to give.

The fix makes results self-identifying: ``exec`` prefixes each command with an
echo of a per-call nonce and discards any completed result that lacks it.
"""

from __future__ import annotations

import pytest

from tests.conftest import FakeQemuGA
from winbox.config import Config
from winbox.vm.guest import GuestAgent, GuestAgentError


def _ga(monkeypatch, fake) -> GuestAgent:
    ga = GuestAgent(Config())
    monkeypatch.setattr(ga, "_raw_command", fake)
    return ga


class TestStaleSlotRejection:
    def test_does_not_return_another_commands_output(self, monkeypatch):
        """The live failure: a recycled PID carrying a killed job's output."""
        fake = FakeQemuGA(output="nt authority\\system\r\n", exitcode=0)
        ping_output = "\r\n".join(
            f"Reply from 127.0.0.1: bytes=32 time<1ms TTL=128" for _ in range(120)
        )
        fake.seed_abandoned(4242, ping_output, exitcode=1)
        fake.force_next_pid(4242)

        result = _ga(monkeypatch, fake).exec("whoami", poll_interval=0)

        assert "Reply from 127.0.0.1" not in result.stdout
        assert result.stdout == "nt authority\\system\r\n"
        assert result.exitcode == 0

    def test_does_not_return_empty_result_of_uncaptured_orphan(self, monkeypatch):
        """The `file_copy` shape: orphan started with capture-output false.

        It has no stdout and no stderr, so inheriting it looked exactly like
        "the command failed and told us nothing".
        """
        fake = FakeQemuGA(output="Copied 360448 bytes\r\n", exitcode=0)
        fake.seed_abandoned(777, "", exitcode=1)
        fake.force_next_pid(777)

        result = _ga(monkeypatch, fake).exec("copy", poll_interval=0)

        assert result.exitcode == 0
        assert "Copied 360448 bytes" in result.stdout

    def test_nonce_is_stripped_from_returned_stdout(self, monkeypatch):
        """Callers must see their command's output and nothing else."""
        fake = FakeQemuGA(output="line1\r\nline2\r\n")

        result = _ga(monkeypatch, fake).exec("whoami", poll_interval=0)

        assert result.stdout == "line1\r\nline2\r\n"
        assert "__wbx" not in result.stdout

    def test_command_with_no_output_returns_empty_string(self, monkeypatch):
        """Stripping the nonce must not leave a stray newline behind."""
        fake = FakeQemuGA(output="")

        assert _ga(monkeypatch, fake).exec("rem", poll_interval=0).stdout == ""

    def test_gives_up_rather_than_looping_on_persistent_foreign_results(
        self, monkeypatch
    ):
        """A PID that keeps yielding foreign results must raise, not spin."""
        fake = FakeQemuGA(output="ours\r\n")
        for _ in range(6):
            fake.seed_abandoned(31337, "not ours", exitcode=9)
        fake.force_next_pid(31337)

        with pytest.raises(GuestAgentError, match="foreign results"):
            _ga(monkeypatch, fake).exec("whoami", poll_interval=0)

    def test_normal_path_unaffected_by_unrelated_stale_slots(self, monkeypatch):
        """Orphans on *other* PIDs must not perturb a healthy call."""
        fake = FakeQemuGA(output="fine\r\n")
        fake.seed_abandoned(1, "junk")
        fake.seed_abandoned(2, "junk")

        assert _ga(monkeypatch, fake).exec("whoami", poll_interval=0).stdout == "fine\r\n"


class TestCommandTagging:
    def test_command_is_wrapped_so_the_nonce_precedes_its_output(self, monkeypatch):
        """`&&` (not `&`) so the echo completes before the command starts."""
        seen: list[list[str]] = []
        fake = FakeQemuGA(output="")

        def combined(payload, **kwargs):
            if payload.get("execute") == "guest-exec":
                seen.append(payload["arguments"]["arg"])
            return fake(payload, **kwargs)

        _ga(monkeypatch, combined).exec("whoami", poll_interval=0)

        assert seen[0][0] == "/c"
        assert seen[0][1].startswith("echo __wbx")
        assert seen[0][1].endswith("&&whoami")
        # No space before `&&` — `echo x && y` would emit a trailing space.
        assert "__&&whoami" in seen[0][1]

    def test_each_call_gets_a_distinct_nonce(self, monkeypatch):
        seen: list[str] = []
        fake = FakeQemuGA(output="")

        def combined(payload, **kwargs):
            if payload.get("execute") == "guest-exec":
                seen.append(payload["arguments"]["arg"][1])
            return fake(payload, **kwargs)

        ga = _ga(monkeypatch, combined)
        ga.exec("a", poll_interval=0)
        ga.exec("b", poll_interval=0)

        assert seen[0].split("&&")[0] != seen[1].split("&&")[0]


class TestReap:
    def test_reap_frees_the_slot(self, monkeypatch):
        fake = FakeQemuGA(output="")
        fake.seed_abandoned(5150, "orphaned output")
        assert len(fake.slots) == 1

        _ga(monkeypatch, fake).reap(5150)

        assert fake.slots == []

    def test_reap_never_raises(self, monkeypatch):
        def boom(payload, **kwargs):
            raise RuntimeError("agent gone")

        # Must not mask whatever error the caller is already handling.
        _ga(monkeypatch, boom).reap(1234, attempts=1, interval=0)

    def test_timeout_kills_the_process_tree_and_reaps(self, monkeypatch):
        """Killing only the outer cmd.exe left children holding the pipe open,
        so the agent kept buffering their output into the orphaned slot."""
        calls: list[dict] = []

        def never_exits(payload, **kwargs):
            calls.append(payload)
            if payload.get("execute") == "guest-exec":
                return {"return": {"pid": 42}}
            return {"return": {"exited": False}}

        monkeypatch.setattr("time.sleep", lambda *_: None)
        with pytest.raises(GuestAgentError, match="timed out"):
            _ga(monkeypatch, never_exits).exec("hang", timeout=0, poll_interval=0)

        kills = [
            c for c in calls
            if c.get("arguments", {}).get("path") == "taskkill"
        ]
        assert kills, "timeout should kill the runaway process"
        assert "/T" in kills[0]["arguments"]["arg"]
        # A status read after the kill is what actually frees the slot.
        assert any(
            c.get("execute") == "guest-exec-status"
            for c in calls[calls.index(kills[0]):]
        )


class _QgaAgent:
    """A model of qemu-ga's slot table for the ``exec_argv`` path.

    Same rules as ``tests.conftest.FakeQemuGA`` (flat list keyed by Windows
    PID, oldest matching entry wins, an entry is freed only when a status read
    reports it exited) plus the one behaviour that decides whether an
    ``exec_argv`` result can be identified at all: a status read for a PID the
    agent has no entry for is an **error**, not a polite "not exited yet".
    That is what ``qmp_guest_exec_status`` does, and it is how "the result I
    just read was the only one" is told apart from "there is another entry
    behind it".

    ``lenient_unknown_pid=True`` models an agent that answers
    ``exited: false`` instead — the assumption the orphan check leans on,
    inverted, so the fallback path can be tested.
    """

    def __init__(self, *, output="", exitcode=0, polls_before_exit=0,
                 lenient_unknown_pid=False):
        self.slots: list[dict] = []
        self.output = output
        self.exitcode = exitcode
        self.polls_before_exit = polls_before_exit
        self.lenient_unknown_pid = lenient_unknown_pid
        self.forced_pids: list[int] = []
        self.payloads: list[dict] = []
        self._next_pid = 2000

    def seed_abandoned(self, pid: int, output: str, exitcode: int = 1) -> None:
        self.slots.append(
            {"pid": pid, "polls_left": 0, "out": output, "exitcode": exitcode}
        )

    def force_next_pid(self, pid: int) -> None:
        self.forced_pids.append(pid)

    def __call__(self, payload, **kwargs):
        self.payloads.append(payload)
        cmd = payload.get("execute")
        if cmd == "guest-exec":
            pid = self.forced_pids.pop(0) if self.forced_pids else self._next_pid
            self._next_pid += 1
            # taskkill is fire-and-forget; give it its own instant slot.
            is_kill = payload["arguments"]["path"] == "taskkill"
            self.slots.append({
                "pid": pid,
                "polls_left": 0 if is_kill else self.polls_before_exit,
                "out": "" if is_kill else self.output,
                "exitcode": 0 if is_kill else self.exitcode,
            })
            return {"return": {"pid": pid}}
        if cmd == "guest-exec-status":
            want = payload["arguments"]["pid"]
            for i, slot in enumerate(self.slots):
                if slot["pid"] != want:
                    continue
                if slot["polls_left"] > 0:
                    slot["polls_left"] -= 1
                    return {"return": {"exited": False}}
                self.slots.pop(i)  # freed on read, like qemu-ga
                return {"return": {
                    "exited": True,
                    "exitcode": slot["exitcode"],
                    "out-data": _b64(slot["out"]),
                    "err-data": "",
                }}
            if self.lenient_unknown_pid:
                return {"return": {"exited": False}}
            raise GuestAgentError(f"PID {want} does not exist")
        return {"return": {}}


def _b64(text: str) -> str:
    import base64
    return base64.b64encode(text.encode()).decode()


class TestExecArgvIdentity:
    """``exec_argv`` cannot carry ``exec``'s echoed nonce — bypassing cmd.exe
    is the whole point of it — so it establishes identity out of band. Without
    that, `winbox msi install` and `winbox av status` could report an orphan's
    exit code as their own."""

    def test_does_not_return_an_orphans_result(self, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_: None)
        # Ours takes two polls to finish; the orphan is already sitting there.
        fake = _QgaAgent(output="ours\r\n", exitcode=0, polls_before_exit=2)
        fake.seed_abandoned(4242, "someone else's output\r\n", exitcode=1)
        fake.force_next_pid(4242)

        result = _ga(monkeypatch, fake).exec_argv("msiexec.exe", ["/i", "x.msi"])

        assert result.stdout == "ours\r\n"
        assert result.exitcode == 0

    def test_plain_fast_command_is_unaffected(self, monkeypatch):
        """reg.exe finishes long before the first poll — no orphan involved,
        and the identity check must not turn that into a failure or a wait."""
        fake = _QgaAgent(output="value\r\n", exitcode=0)

        result = _ga(monkeypatch, fake).exec_argv("reg.exe", ["query", "HKLM"], timeout=15)

        assert result.stdout == "value\r\n"
        assert result.exitcode == 0

    def test_does_not_discard_a_result_against_a_lenient_agent(self, monkeypatch):
        """The check reads "not exited" as proof that a second entry exists.
        Against an agent that answers "not exited" for PIDs it holds nothing
        for, that inference is backwards — and acting on it would throw away
        the command's real output. It must detect that and keep the result."""
        monkeypatch.setattr("time.sleep", lambda *_: None)
        fake = _QgaAgent(output="value\r\n", exitcode=0, lenient_unknown_pid=True)

        result = _ga(monkeypatch, fake).exec_argv("reg.exe", ["query", "HKLM"], timeout=15)

        assert result.stdout == "value\r\n"
        assert result.exitcode == 0
        assert not any(
            p.get("arguments", {}).get("path") == "taskkill" for p in fake.payloads
        ), "a completed command must not be killed"


class TestExecArgvPollResilience:
    """``exec`` has tolerated brief virtio-serial hiccups since the poll-loop
    audit; ``exec_argv`` did not, and `winbox provision` runs a 30-minute
    script through it."""

    def test_tolerates_a_transient_error_mid_poll(self, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_: None)
        fake = _QgaAgent(output="done\r\n", polls_before_exit=1)
        real = fake.__call__
        state = {"n": 0}

        def flaky(payload, **kwargs):
            if payload.get("execute") == "guest-exec-status":
                state["n"] += 1
                if state["n"] == 1:
                    raise GuestAgentError("Guest agent command failed: hiccup")
            return real(payload, **kwargs)

        result = _ga(monkeypatch, flaky).exec_argv(
            "powershell.exe", ["-File", "C:\\bootstrap.ps1"], timeout=1800
        )

        assert result.stdout == "done\r\n"

    def test_abandoning_a_pid_kills_and_reaps_it(self, monkeypatch):
        """An abandoned PID's entry lives in the agent forever and becomes the
        orphan the next command to land on that PID inherits."""
        monkeypatch.setattr("time.sleep", lambda *_: None)
        calls: list[dict] = []

        def dead_agent(payload, **kwargs):
            calls.append(payload)
            if payload.get("execute") == "guest-exec":
                return {"return": {"pid": 4242}}
            raise GuestAgentError("Guest agent command failed: agent gone")

        with pytest.raises(GuestAgentError):
            _ga(monkeypatch, dead_agent).exec_argv("msiexec.exe", ["/i", "x.msi"])

        kills = [
            c for c in calls
            if c.get("arguments", {}).get("path") == "taskkill"
        ]
        assert kills, "a PID we stop polling must not be left running and unreaped"
        assert "/T" in kills[0]["arguments"]["arg"]

    def test_timeout_still_kills_and_reaps(self, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_: None)
        fake = _QgaAgent(output="", polls_before_exit=10_000)

        with pytest.raises(GuestAgentError, match="timed out"):
            _ga(monkeypatch, fake).exec_argv("hang.exe", [], timeout=0)

        assert any(
            p.get("arguments", {}).get("path") == "taskkill" for p in fake.payloads
        )
