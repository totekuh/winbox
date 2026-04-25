"""Tests for background job execution and management."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.jobs import Job, JobMode, JobStatus, JobStore
from winbox.vm.guest import ExecResult


# ─── JobStore ─────────────────────────────────────────────────────────────────


class TestJobStore:
    def test_empty_store(self, cfg):
        store = JobStore(cfg)
        assert store.all() == []

    def test_next_id_empty(self, cfg):
        store = JobStore(cfg)
        assert store.next_id() == 1

    def test_add_and_get(self, cfg):
        store = JobStore(cfg)
        job = Job(id=1, pid=100, command="foo.exe", mode=JobMode.BUFFERED)
        store.add(job)
        got = store.get(1)
        assert got is not None
        assert got.pid == 100
        assert got.command == "foo.exe"

    def test_next_id_increments(self, cfg):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="a", mode=JobMode.BUFFERED))
        store.add(Job(id=2, pid=200, command="b", mode=JobMode.LOG))
        assert store.next_id() == 3

    def test_persistence(self, cfg):
        store1 = JobStore(cfg)
        store1.add(Job(id=1, pid=100, command="foo.exe", mode=JobMode.BUFFERED))
        # Load from disk in a new instance
        store2 = JobStore(cfg)
        assert len(store2.all()) == 1
        assert store2.get(1).command == "foo.exe"

    def test_update(self, cfg):
        store = JobStore(cfg)
        job = Job(id=1, pid=100, command="foo.exe", mode=JobMode.BUFFERED)
        store.add(job)
        job.status = JobStatus.DONE
        job.exitcode = 0
        job.stdout = "hello"
        store.update(job)
        reloaded = JobStore(cfg)
        got = reloaded.get(1)
        assert got.status == JobStatus.DONE
        assert got.stdout == "hello"

    def test_get_nonexistent(self, cfg):
        store = JobStore(cfg)
        assert store.get(999) is None

    def test_corrupt_json(self, cfg):
        cfg.jobs_file.write_text("not json!!!")
        store = JobStore(cfg)
        assert store.all() == []

    def test_log_path(self, cfg):
        store = JobStore(cfg)
        path = store.log_path(1, "stdout")
        assert path == cfg.jobs_log_dir / "1.stdout"

    def test_vm_log_path(self, cfg):
        store = JobStore(cfg)
        assert store.vm_log_path(1, "stderr") == "Z:\\loot\\.jobs\\1.stderr"

    def test_corrupt_json_is_backed_up(self, cfg):
        """Corrupt jobs.json must be preserved as `.bad-<ts>` for forensics
        rather than silently overwritten."""
        cfg.jobs_file.write_text("not json!!!")
        JobStore(cfg)
        backups = list(cfg.jobs_file.parent.glob("jobs.json.bad-*"))
        assert len(backups) == 1
        assert backups[0].read_text() == "not json!!!"

    def test_claim_atomically_allocates_unique_ids(self, cfg):
        """The race we're guarding against: two callers claim() at the same
        time. With locking + re-load each must see the other's reservation
        and pick a fresh ID."""
        store_a = JobStore(cfg)
        store_b = JobStore(cfg)

        job_a = store_a.claim(
            lambda jid: Job(id=jid, pid=100, command="a", mode=JobMode.BUFFERED)
        )
        # store_b's in-memory view is stale (loaded at __init__ time, before
        # store_a wrote). claim() must re-read inside the lock.
        job_b = store_b.claim(
            lambda jid: Job(id=jid, pid=200, command="b", mode=JobMode.BUFFERED)
        )

        assert job_a.id == 1
        assert job_b.id == 2
        # Both jobs persisted, neither overwrote the other.
        reloaded = JobStore(cfg)
        assert {j.id for j in reloaded.all()} == {1, 2}

    def test_claim_rejects_mismatched_id(self, cfg):
        import pytest
        store = JobStore(cfg)
        with pytest.raises(ValueError, match="must return Job with id"):
            store.claim(
                lambda jid: Job(id=999, pid=1, command="x", mode=JobMode.BUFFERED)
            )
        # Failed claim must not leave any junk in the store.
        assert store.all() == []


# ─── Job dataclass ────────────────────────────────────────────────────────────


class TestJob:
    def test_to_dict(self):
        job = Job(id=1, pid=100, command="foo.exe", mode=JobMode.BUFFERED, started=1000.0)
        d = job.to_dict()
        assert d["id"] == 1
        assert d["pid"] == 100
        assert d["mode"] == "buffered"
        assert d["status"] == "running"

    def test_from_dict(self):
        d = {
            "id": 2, "pid": 200, "command": "bar.exe",
            "mode": "log", "status": "done", "exitcode": 0,
            "started": 1000.0, "stdout": "out", "stderr": "err",
        }
        job = Job.from_dict(d)
        assert job.id == 2
        assert job.mode == JobMode.LOG
        assert job.status == JobStatus.DONE

    def test_roundtrip(self):
        original = Job(
            id=3, pid=300, command="baz.exe -c All",
            mode=JobMode.LOG, status=JobStatus.FAILED,
            exitcode=1, started=1234.5, stdout="x", stderr="y",
        )
        restored = Job.from_dict(original.to_dict())
        assert restored.id == original.id
        assert restored.pid == original.pid
        assert restored.mode == original.mode
        assert restored.status == original.status
        assert restored.exitcode == original.exitcode

    def test_from_dict_extra_keys(self):
        d = {
            "id": 1, "pid": 100, "command": "a", "mode": "buffered",
            "status": "running", "future_field": "ignored",
        }
        job = Job.from_dict(d)
        assert job.id == 1

    def test_defaults(self):
        job = Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED)
        assert job.status == JobStatus.RUNNING
        assert job.exitcode is None
        assert job.stdout == ""
        assert job.stderr == ""


# ─── exec --bg ────────────────────────────────────────────────────────────────


class TestExecBg:
    def test_bg_buffered(self, runner, cfg, mock_env):
        mock_env.exec_background.return_value = 4532
        result = runner.invoke(cli, ["exec", "--bg", "SharpHound.exe", "-c", "All"])
        assert result.exit_code == 0
        assert "Job 1 started" in result.output
        assert "PID 4532" in result.output
        assert "winbox jobs output 1" in result.output

    def test_bg_log(self, runner, cfg, mock_env):
        mock_env._vm.state.return_value = MagicMock(value="running")
        mock_env.exec_detached.return_value = 4533
        result = runner.invoke(cli, ["exec", "--bg", "--log", "Rubeus.exe", "kerberoast"])
        assert result.exit_code == 0
        assert "Job 1 started" in result.output
        assert "PID 4533" in result.output
        # Rich wraps long paths — check without newlines
        flat = result.output.replace("\n", "")
        assert ".jobs/1.stdout" in flat

    def test_bg_increments_id(self, runner, cfg, mock_env):
        mock_env.exec_background.return_value = 100
        runner.invoke(cli, ["exec", "--bg", "a.exe"])
        mock_env.exec_background.return_value = 200
        result = runner.invoke(cli, ["exec", "--bg", "b.exe"])
        assert "Job 2 started" in result.output

    def test_log_without_bg_errors(self, runner, cfg, mock_env):
        """--log without --bg now errors via Click's UsageError -- silently
        ignoring the user's explicit flag was a footgun."""
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="ok\n", stderr="")
        result = runner.invoke(cli, ["exec", "--log", "cmd.exe", "/c", "echo", "hi"])
        assert result.exit_code != 0
        assert "--log requires --bg" in result.output


# ─── jobs list ────────────────────────────────────────────────────────────────


class TestJobsList:
    def test_empty(self, runner, cfg, mock_env):
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "No jobs" in result.output

    def test_with_jobs(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="foo.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.DONE, exitcode=0, started=time.time()))
        store.add(Job(id=2, pid=200, command="bar.exe -x", mode=JobMode.LOG,
                       status=JobStatus.RUNNING, started=time.time()))
        mock_env.exec_status.return_value = {"exited": False, "exitcode": -1, "stdout": "", "stderr": ""}
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "foo.exe" in result.output
        assert "bar.exe" in result.output

    def test_marks_finished(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="done.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING, started=time.time()))
        mock_env.exec_status.return_value = {
            "exited": True, "exitcode": 0, "stdout": "out", "stderr": "",
        }
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "done" in result.output
        # Verify it was persisted
        reloaded = JobStore(cfg)
        assert reloaded.get(1).status == JobStatus.DONE


# ─── jobs output ──────────────────────────────────────────────────────────────


class TestJobsOutput:
    def test_nonexistent(self, runner, cfg, mock_env):
        result = runner.invoke(cli, ["jobs", "output", "99"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_buffered_cached(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.DONE, stdout="cached output\n", stderr=""))
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "cached output" in result.output

    def test_log_file(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.LOG,
                       status=JobStatus.DONE))
        store.log_path(1, "stdout").write_text("log content\n")
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "log content" in result.output

    def test_log_no_files_yet(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.LOG,
                       status=JobStatus.RUNNING))
        # Remove the log files if they exist
        for stream in ("stdout", "stderr"):
            p = store.log_path(1, stream)
            if p.exists():
                p.unlink()
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert "No output files yet" in result.output

    def test_lost_job(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.LOST))
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 1
        assert "lost" in result.output.lower()

    def test_buffered_fetches_from_ga(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": "fetched output\n", "stderr": "",
        }
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "fetched output" in result.output
        # Should be cached now
        reloaded = JobStore(cfg)
        assert reloaded.get(1).stdout == "fetched output\n"


# ─── jobs kill ────────────────────────────────────────────────────────────────


class TestJobsKill:
    def test_kill_running(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        result = runner.invoke(cli, ["jobs", "kill", "1"])
        assert result.exit_code == 0
        assert "killed" in result.output.lower()
        reloaded = JobStore(cfg)
        assert reloaded.get(1).status == JobStatus.FAILED

    def test_kill_not_running(self, runner, cfg, mock_env):
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.DONE))
        result = runner.invoke(cli, ["jobs", "kill", "1"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    def test_kill_nonexistent(self, runner, cfg, mock_env):
        result = runner.invoke(cli, ["jobs", "kill", "99"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_kill_ga_error(self, runner, cfg, mock_env):
        """Kill fails when taskkill GA exec raises GuestAgentError."""
        from winbox.vm.guest import GuestAgentError
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec.side_effect = GuestAgentError("connection lost")
        result = runner.invoke(cli, ["jobs", "kill", "1"])
        assert result.exit_code == 1
        assert "Kill failed" in result.output


# ─── jobs list edge cases ────────────────────────────────────────────────────


class TestJobsListEdge:
    def test_ga_unavailable_keeps_running(self, runner, cfg, mock_env):
        """Running jobs stay RUNNING when GA is unreachable (not permanently LOST)."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="slow.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING, started=time.time()))
        mock_env.ping.return_value = False
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "running" in result.output
        reloaded = JobStore(cfg)
        assert reloaded.get(1).status == JobStatus.RUNNING

    def test_ga_init_exception_keeps_running(self, runner, cfg):
        """Running jobs stay RUNNING when GA constructor throws."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING, started=time.time()))
        with (
            patch("winbox.cli.jobs.VM") as mock_vm_cls,
            patch("winbox.cli.jobs.GuestAgent", side_effect=Exception("no socket")),
            patch("winbox.cli.Config.load", return_value=cfg),
        ):
            mock_vm_cls.return_value.state.return_value.value = "running"
            result = CliRunner().invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "running" in result.output

    def test_exec_status_error_marks_lost(self, runner, cfg, mock_env):
        """Running job marked LOST when exec_status raises GuestAgentError."""
        from winbox.vm.guest import GuestAgentError
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="crash.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING, started=time.time()))
        mock_env.exec_status.side_effect = GuestAgentError("pid expired")
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "lost" in result.output
        reloaded = JobStore(cfg)
        assert reloaded.get(1).status == JobStatus.LOST

    def test_lost_job_repolled_when_vm_back(self, runner, cfg, mock_env):
        """LOST jobs are re-polled when VM comes back online."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="recovered.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.LOST, started=time.time()))
        mock_env.exec_status.return_value = {
            "exited": True, "exitcode": 0, "stdout": "done", "stderr": "",
        }
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "done" in result.output
        reloaded = JobStore(cfg)
        assert reloaded.get(1).status == JobStatus.DONE

    def test_age_minutes(self, runner, cfg, mock_env):
        """Jobs between 1-59 minutes display as Xm."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="mid.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.DONE, exitcode=0,
                       started=time.time() - 300))  # 5 minutes ago
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "5m" in result.output

    def test_age_hours(self, runner, cfg, mock_env):
        """Jobs older than 1 hour display as XhYm."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="long.exe", mode=JobMode.BUFFERED,
                       status=JobStatus.DONE, exitcode=0,
                       started=time.time() - 7200))  # 2 hours ago
        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "2h0m" in result.output


# ─── jobs output edge cases ──────────────────────────────────────────────────


class TestJobsOutputEdge:
    def test_log_stderr(self, runner, cfg, mock_env):
        """LOG mode prints stderr from file."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.LOG,
                       status=JobStatus.DONE))
        store.log_path(1, "stdout").write_text("out\n")
        store.log_path(1, "stderr").write_text("err msg\n")
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "out" in result.output
        assert "err msg" in result.output

    def test_buffered_cached_stderr(self, runner, cfg, mock_env):
        """Buffered mode prints cached stderr."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.DONE, stdout="", stderr="error line\n"))
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "error line" in result.output

    def test_ga_fetch_error(self, runner, cfg, mock_env):
        """GA exec_status failure when fetching output."""
        from winbox.vm.guest import GuestAgentError
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec_status.side_effect = GuestAgentError("gone")
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 1
        assert "Cannot fetch output" in result.output

    def test_ga_returns_stderr(self, runner, cfg, mock_env):
        """GA status returns stderr content."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec_status.return_value = {
            "exited": True, "exitcode": 1,
            "stdout": "", "stderr": "fatal error\n",
        }
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "fatal error" in result.output

    def test_no_output_exited(self, runner, cfg, mock_env):
        """Job finished with no stdout or stderr."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": "", "stderr": "",
        }
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "finished with no output" in result.output

    def test_no_output_still_running(self, runner, cfg, mock_env):
        """Job still running with no output yet."""
        store = JobStore(cfg)
        store.add(Job(id=1, pid=100, command="x", mode=JobMode.BUFFERED,
                       status=JobStatus.RUNNING))
        mock_env.exec_status.return_value = {
            "exited": False, "exitcode": -1,
            "stdout": "", "stderr": "",
        }
        result = runner.invoke(cli, ["jobs", "output", "1"])
        assert result.exit_code == 0
        assert "still running" in result.output
