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
