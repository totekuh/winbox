"""Job management commands — winbox jobs list/output/kill."""

from __future__ import annotations

import time

import click
from rich.table import Table

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.jobs import JobMode, JobStatus, JobStore
from winbox.vm import GuestAgent, GuestAgentError, VM


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

    updated = False
    for job in all_jobs:
        if job.status not in (JobStatus.RUNNING, JobStatus.LOST):
            continue
        if ga is None:
            continue  # VM offline — skip, don't permanently mark LOST
        try:
            status = ga.exec_status(job.pid)
            if status["exited"]:
                job.exitcode = status["exitcode"]
                job.stdout = status["stdout"]
                job.stderr = status["stderr"]
                job.status = JobStatus.DONE if job.exitcode == 0 else JobStatus.FAILED
                updated = True
        except GuestAgentError:
            job.status = JobStatus.LOST
            updated = True

    if updated:
        for job in all_jobs:
            store.update(job)

    table = Table(show_header=True)
    table.add_column("ID", style="bold")
    table.add_column("PID")
    table.add_column("Status")
    table.add_column("Mode")
    table.add_column("Command")
    table.add_column("Age")

    for job in all_jobs:
        age = int(time.time() - job.started)
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

    # Buffered mode — check cached output first
    if job.stdout or job.stderr:
        if job.stdout:
            console.print(job.stdout, end="", markup=False, highlight=False)
        if job.stderr:
            console.print(job.stderr, end="", markup=False, style="red", highlight=False)
        return

    if job.status == JobStatus.LOST:
        console.print("[red][-][/] Job lost — VM was unavailable, output not recoverable")
        raise SystemExit(1)

    # Try fetching from GA
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

    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    try:
        ga.exec(f"taskkill /PID {job.pid} /F", timeout=15)
    except GuestAgentError as e:
        console.print(f"[red][-][/] Kill failed: {e}")
        raise SystemExit(1)

    job.status = JobStatus.FAILED
    job.exitcode = -1
    store.update(job)
    console.print(f"[green][+][/] Job {job_id} killed (PID {job.pid})")


REGISTER = ("Execute", [jobs])
