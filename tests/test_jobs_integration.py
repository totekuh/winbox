"""End-to-end integration tests for background jobs.

Requires a running winbox VM with guest agent responding.
Run with:  pytest -m integration
Skip with: pytest -m 'not integration'
"""

from __future__ import annotations

import re
import time

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.jobs import JobMode, JobStatus, JobStore
from winbox.vm import VM, VMState, GuestAgent, GuestAgentError


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def live_cfg():
    return Config.load()


@pytest.fixture(scope="session")
def live_vm(live_cfg):
    vm = VM(live_cfg)
    if vm.state() != VMState.RUNNING:
        pytest.skip("VM not running")
    return vm


@pytest.fixture(scope="session")
def live_ga(live_cfg, live_vm):
    ga = GuestAgent(live_cfg)
    if not ga.ping():
        pytest.skip("Guest agent not responding")
    return ga


@pytest.fixture()
def clean_jobs(live_cfg):
    """Ensure a clean jobs.json and log dir before each test."""
    if live_cfg.jobs_file.exists():
        live_cfg.jobs_file.unlink()
    # Clean log files
    if live_cfg.jobs_log_dir.exists():
        for f in live_cfg.jobs_log_dir.iterdir():
            if f.is_file():
                f.unlink()
    yield
    if live_cfg.jobs_file.exists():
        live_cfg.jobs_file.unlink()
    if live_cfg.jobs_log_dir.exists():
        for f in live_cfg.jobs_log_dir.iterdir():
            if f.is_file():
                f.unlink()


@pytest.fixture()
def runner():
    return CliRunner()


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _parse_job_id(output: str) -> int:
    """Extract job ID from 'Job N started' output."""
    m = re.search(r"Job (\d+) started", output)
    assert m, f"Could not parse job ID from: {output}"
    return int(m.group(1))


def _poll_job_done(store: JobStore, ga: GuestAgent, job_id: int, timeout: int = 30) -> None:
    """Poll until a job finishes or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = store.get(job_id)
        if job is None:
            pytest.fail(f"Job {job_id} not found in store")
        if job.status != JobStatus.RUNNING:
            return
        try:
            status = ga.exec_status(job.pid)
            if status["exited"]:
                job.exitcode = status["exitcode"]
                job.stdout = status["stdout"]
                job.stderr = status["stderr"]
                job.status = JobStatus.DONE if job.exitcode == 0 else JobStatus.FAILED
                store.update(job)
                return
        except GuestAgentError:
            pass
        time.sleep(1)
    pytest.fail(f"Job {job_id} did not finish within {timeout}s")


def _wait_for_file(path, timeout: int = 30) -> None:
    """Wait for a file to appear and have content."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(1)
    pytest.fail(f"File not created within {timeout}s: {path}")


# ─── Tests ────────────────────────────────────────────────────────────────────


pytestmark = pytest.mark.integration


class TestExecBgBuffered:
    """exec --bg with GA-buffered output (default mode)."""

    def test_simple_echo(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "hello_bg"])
        assert result.exit_code == 0
        assert "PID" in result.output

        job_id = _parse_job_id(result.output)
        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, job_id)

        job = store.get(job_id)
        assert job.status == JobStatus.DONE
        assert job.exitcode == 0

    def test_output_retrieval(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "retrieve_me"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, job_id)

        result = runner.invoke(cli, ["jobs", "output", str(job_id)])
        assert result.exit_code == 0
        assert "retrieve_me" in result.output

    def test_multiword_output(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "multi word output 12345"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, job_id)

        job = store.get(job_id)
        assert job.status == JobStatus.DONE
        assert "multi word output 12345" in job.stdout

    def test_stderr_captured(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "err_msg", "1>&2"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, job_id)

        job = store.get(job_id)
        assert "err_msg" in job.stderr


class TestExecBgLog:
    """exec --bg --log with file-redirect output."""

    def test_log_creates_files(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "--log", "cmd.exe", "/c", "echo", "logged_output"])
        assert result.exit_code == 0

        job_id = _parse_job_id(result.output)
        store = JobStore(live_cfg)
        stdout_path = store.log_path(job_id, "stdout")

        _wait_for_file(stdout_path)
        assert "logged_output" in stdout_path.read_text()

    def test_log_output_command(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "--log", "cmd.exe", "/c", "echo", "via_output_cmd"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        stdout_path = store.log_path(job_id, "stdout")
        _wait_for_file(stdout_path)

        result = runner.invoke(cli, ["jobs", "output", str(job_id)])
        assert result.exit_code == 0
        assert "via_output_cmd" in result.output

    def test_log_stderr_file(self, runner, live_cfg, live_ga, clean_jobs):
        # Use a command that naturally writes to stderr (dir of nonexistent path)
        result = runner.invoke(cli, ["exec", "--bg", "--log", "cmd.exe", "/c", "dir", "C:\\nonexistent_path_12345"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        stderr_path = store.log_path(job_id, "stderr")

        _wait_for_file(stderr_path)
        assert "file not found" in stderr_path.read_text().lower()


class TestJobsList:
    """jobs list with real GA polling."""

    def test_list_shows_jobs(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "listed"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, job_id)

        result = runner.invoke(cli, ["jobs", "list"])
        assert result.exit_code == 0
        assert "cmd.exe" in result.output

    def test_list_updates_status(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "status_check"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, job_id)

        result = runner.invoke(cli, ["jobs", "list"])
        assert "done" in result.output

    def test_multiple_jobs(self, runner, live_cfg, live_ga, clean_jobs):
        r1 = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "first"])
        r2 = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "second"])
        id1 = _parse_job_id(r1.output)
        id2 = _parse_job_id(r2.output)

        store = JobStore(live_cfg)
        _poll_job_done(store, live_ga, id1)
        _poll_job_done(store, live_ga, id2)

        result = runner.invoke(cli, ["jobs", "list"])
        flat = result.output.replace("\n", "")
        assert str(id1) in flat
        assert str(id2) in flat


class TestJobsKill:
    """jobs kill with a real long-running process."""

    def test_kill_running_process(self, runner, live_cfg, live_ga, clean_jobs):
        result = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "ping", "-n", "120", "127.0.0.1"])
        job_id = _parse_job_id(result.output)

        store = JobStore(live_cfg)
        job = store.get(job_id)
        assert job is not None
        assert job.status == JobStatus.RUNNING

        time.sleep(2)

        result = runner.invoke(cli, ["jobs", "kill", str(job_id)])
        assert result.exit_code == 0
        assert "killed" in result.output.lower()

        reloaded = JobStore(live_cfg)
        assert reloaded.get(job_id).status == JobStatus.FAILED


class TestJobIdIncrement:
    """Job IDs increment across commands."""

    def test_ids_sequential(self, runner, live_cfg, live_ga, clean_jobs):
        r1 = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "a"])
        r2 = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "b"])
        r3 = runner.invoke(cli, ["exec", "--bg", "cmd.exe", "/c", "echo", "c"])

        id1 = _parse_job_id(r1.output)
        id2 = _parse_job_id(r2.output)
        id3 = _parse_job_id(r3.output)

        # IDs must be strictly increasing
        assert id1 < id2 < id3

        store = JobStore(live_cfg)
        assert len(store.all()) == 3
