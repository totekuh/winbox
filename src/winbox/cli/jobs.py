"""Job management commands — winbox jobs list/output/kill."""

from __future__ import annotations

import time

import click
from rich.table import Table

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.jobs import Job, JobMode, JobStatus, JobStore
from winbox.vm import GuestAgent, GuestAgentError, VM


def _poll_job_status(ga: GuestAgent, pid: int, *, attempts: int = 3) -> dict:
    """Query a job's status, retrying briefly before treating it as gone.

    Marking a job LOST is now permanent, so a single virtio-serial hiccup
    must not be enough to do it. Retries a couple of times and only lets
    the error escape if the agent consistently has no answer for this PID.
    """
    for attempt in range(attempts):
        try:
            return ga.exec_status(pid)
        except GuestAgentError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.5)
    raise AssertionError("unreachable")


def _pid_image_name(ga: GuestAgent, pid: int) -> str | None:
    """Return the image name for ``pid``, or None if unreachable."""
    try:
        r = ga.exec(f'tasklist /FI "PID eq {pid}" /NH /FO CSV', timeout=5)
        if r.exitcode != 0:
            return None
        for line in r.stdout.strip().splitlines():
            if line.startswith('"'):
                return line.split('"')[1].lower()
    except GuestAgentError:
        pass
    return None


def _exited_status(ga: GuestAgent, pid: int) -> dict | None:
    """Return the agent's finished-result dict for ``pid``, else None.

    None means "not finished, or the agent has no record" — the two cases
    a caller must not treat as a completed job. Errors are swallowed on
    purpose: this runs on failure paths where a probe blowing up should
    not replace the failure the caller is already reporting.
    """
    try:
        status = ga.exec_status(pid)
    except GuestAgentError:
        return None
    return status if status.get("exited") else None


@click.group()
@click.pass_context
def jobs(ctx: click.Context) -> None:
    """Manage background jobs."""
    pass


@jobs.command("list")
@click.pass_context
def jobs_list(ctx: click.Context) -> None:
    """List background jobs with live status."""
    cfg: Config = ctx.obj["cfg"]
    store = JobStore(cfg)
    all_jobs = store.all()

    if not all_jobs:
        console.print("No jobs.")
        return

    # Try to poll GA for running jobs (best-effort)
    ga: GuestAgent | None = None
    vm = VM(cfg)
    try:
        ga = GuestAgent(cfg)
        if vm.state().value != "running" or not ga.ping():
            ga = None
    except Exception:
        ga = None

    # Collect just the jobs we actually mutated and commit them in one
    # locked sweep -- writing each job individually would let another
    # concurrent `winbox jobs list` overwrite our updates with its own
    # stale snapshot in between locks.
    mutated: list[Job] = []
    for job in all_jobs:
        # LOST is terminal. We only get there with the agent otherwise
        # responsive and still refusing to answer for this PID after
        # retries, which means the agent has no record of it — and a
        # discarded result never comes back. Re-polling could therefore
        # never recover anything, but it could very much return a *new*
        # process's output once Windows recycled the number onto it, and
        # report that as this job's result.
        if job.status is not JobStatus.RUNNING:
            continue
        if ga is None:
            continue  # VM offline — skip, don't permanently mark LOST
        try:
            status = _poll_job_status(ga, job.pid)
            if status["exited"]:
                job.exitcode = status["exitcode"]
                job.stdout = status["stdout"]
                job.stderr = status["stderr"]
                job.status = JobStatus.DONE if job.exitcode == 0 else JobStatus.FAILED
                mutated.append(job)
        except GuestAgentError:
            job.status = JobStatus.LOST
            mutated.append(job)

    store.update_many(mutated)

    table = Table(show_header=True)
    table.add_column("ID", style="bold")
    table.add_column("PID")
    table.add_column("Status")
    table.add_column("Mode")
    table.add_column("Command")
    table.add_column("Age")

    for job in all_jobs:
        # Wall-clock age — Job.started is `time.time()` so an NTP step
        # between then and now can produce a negative delta. Guard
        # against negative values so the table doesn't print "-3000s".
        age = max(0, int(time.time() - job.started))
        if age < 60:
            age_str = f"{age}s"
        elif age < 3600:
            age_str = f"{age // 60}m"
        else:
            age_str = f"{age // 3600}h{(age % 3600) // 60}m"

        status_style = {
            JobStatus.RUNNING: "blue",
            JobStatus.DONE: "green",
            JobStatus.FAILED: "red",
            JobStatus.LOST: "yellow",
        }.get(job.status, "")

        table.add_row(
            str(job.id),
            str(job.pid),
            f"[{status_style}]{job.status.value}[/{status_style}]",
            job.mode.value,
            job.command,
            age_str,
        )

    console.print(table)


@jobs.command("output")
@click.argument("job_id", type=int)
@click.pass_context
def jobs_output(ctx: click.Context, job_id: int) -> None:
    """Print output from a background job."""
    cfg: Config = ctx.obj["cfg"]
    store = JobStore(cfg)
    job = store.get(job_id)

    if job is None:
        console.print(f"[red][-][/] Job {job_id} not found")
        raise SystemExit(1)

    if job.mode == JobMode.LOG:
        # Read from host filesystem
        stdout_path = store.log_path(job_id, "stdout")
        stderr_path = store.log_path(job_id, "stderr")
        if stdout_path.exists():
            console.print(stdout_path.read_text(), end="", markup=False, highlight=False)
        if stderr_path.exists():
            err = stderr_path.read_text()
            if err:
                console.print(err, end="", markup=False, style="red", highlight=False)
        if not stdout_path.exists() and not stderr_path.exists():
            console.print("[yellow][!][/] No output files yet")
        return

    # Buffered mode — check cached output first. Status must be checked
    # too: a DONE/FAILED job with no output on either stream (e.g. `mkdir`)
    # would otherwise fall through to re-polling the GA by PID, and that
    # PID's guest-exec slot may already have been recycled onto an
    # unrelated process by the time this runs.
    if job.status in (JobStatus.DONE, JobStatus.FAILED) or job.stdout or job.stderr:
        if job.stdout:
            console.print(job.stdout, end="", markup=False, highlight=False)
        if job.stderr:
            console.print(job.stderr, end="", markup=False, style="red", highlight=False)
        if not job.stdout and not job.stderr:
            console.print("[yellow][!][/] Job finished with no output")
        return

    if job.status == JobStatus.LOST:
        console.print("[red][-][/] Job lost — VM was unavailable, output not recoverable")
        raise SystemExit(1)

    # Try fetching from GA. Stays raw (no @needs_vm): LOG-mode jobs and
    # buffered jobs with cached output above already returned without
    # touching the VM. Decorating the function would boot the VM for every
    # `jobs output` call, even ones that just read host files.
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    try:
        status = ga.exec_status(job.pid)
    except GuestAgentError as e:
        console.print(f"[red][-][/] Cannot fetch output: {e}")
        raise SystemExit(1)

    if status["exited"]:
        job.exitcode = status["exitcode"]
        job.stdout = status["stdout"]
        job.stderr = status["stderr"]
        job.status = JobStatus.DONE if job.exitcode == 0 else JobStatus.FAILED
        store.update(job)

    if status["stdout"]:
        console.print(status["stdout"], end="", markup=False, highlight=False)
    if status["stderr"]:
        console.print(status["stderr"], end="", markup=False, style="red", highlight=False)
    if not status["stdout"] and not status["stderr"]:
        if status["exited"]:
            console.print("[yellow][!][/] Job finished with no output")
        else:
            console.print("[blue][*][/] Job still running — no output yet")


@jobs.command("kill")
@click.argument("job_id", type=int)
@click.pass_context
def jobs_kill(ctx: click.Context, job_id: int) -> None:
    """Kill a running background job."""
    cfg: Config = ctx.obj["cfg"]
    store = JobStore(cfg)
    job = store.get(job_id)

    if job is None:
        console.print(f"[red][-][/] Job {job_id} not found")
        raise SystemExit(1)

    if job.status != JobStatus.RUNNING:
        console.print(f"[yellow][!][/] Job {job_id} is not running ({job.status.value})")
        return

    # Stays raw (no @needs_vm): the early-return for non-RUNNING jobs above
    # is the common case. Decorating would boot the VM just to bail.
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # ── Check whether the job already exited BEFORE attempting taskkill ──
    # If the PID was recycled, a blind taskkill would kill an unrelated
    # process.  Checking first lets us record the real result and bail
    # without touching whatever now owns this PID number.
    exited = _exited_status(ga, job.pid)
    if exited is not None:
        job.exitcode = exited["exitcode"]
        job.stdout = exited["stdout"]
        job.stderr = exited["stderr"]
        job.status = JobStatus.DONE if job.exitcode == 0 else JobStatus.FAILED
        store.update(job)
        console.print(
            f"[yellow][!][/] Job {job_id} had already exited "
            f"(code {job.exitcode}) — nothing to kill; output preserved"
        )
        return

    image = _pid_image_name(ga, job.pid)
    if image is not None and image not in ("cmd.exe", "runex.exe"):
        console.print(
            f"[red][-][/] PID {job.pid} is now {image!r}, not cmd.exe — "
            f"the job's PID was recycled. Refusing to kill an unrelated process."
        )
        job.status = JobStatus.LOST
        store.update(job)
        raise SystemExit(1)

    try:
        kill = ga.exec(f"taskkill /PID {job.pid} /T /F", timeout=15)
    except GuestAgentError as e:
        console.print(f"[red][-][/] Kill failed: {e}")
        raise SystemExit(1)

    if kill.exitcode != 0:
        # taskkill exits 128 when the PID is gone and 1 on access-denied.
        # Still running (or unknowable) and taskkill refused: leave the
        # ledger alone — the job is not dead and its slot is not ours to
        # free. Reaping here would strand a live process's output.
        console.print(
            f"[red][-][/] Kill failed: taskkill exited {kill.exitcode}"
        )
        # taskkill writes its diagnostics to stderr, but the guest agent has
        # been seen surfacing them on stdout too — print whatever we got.
        detail = " ".join(
            part for part in (kill.stderr.strip(), kill.stdout.strip()) if part
        )
        if detail:
            console.print(f"    {detail}", markup=False, highlight=False)
        raise SystemExit(1)

    # Consume this job's buffered result so its slot is freed now, rather
    # than left for a future command that lands on the same PID.
    ga.reap(job.pid)

    job.status = JobStatus.FAILED
    job.exitcode = -1
    store.update(job)
    console.print(f"[green][+][/] Job {job_id} killed (PID {job.pid})")


REGISTER = ("Execute", [jobs])
