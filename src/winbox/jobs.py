"""Background job tracking for winbox exec --bg."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)
from typing import TYPE_CHECKING, Callable, Iterator

if TYPE_CHECKING:
    from winbox.config import Config


class JobStatus(str, Enum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    LOST = "lost"


class JobMode(str, Enum):
    BUFFERED = "buffered"
    LOG = "log"


@dataclass
class Job:
    id: int
    pid: int
    command: str
    mode: JobMode
    status: JobStatus = JobStatus.RUNNING
    exitcode: int | None = None
    started: float = field(default_factory=time.time)
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "command": self.command,
            "mode": self.mode.value,
            "status": self.status.value,
            "exitcode": self.exitcode,
            "started": self.started,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Job:
        return cls(
            id=d["id"],
            pid=int(d["pid"]),
            command=d["command"],
            mode=JobMode(d["mode"]),
            status=JobStatus(d["status"]),
            exitcode=d.get("exitcode"),
            started=d.get("started", 0.0),
            stdout=d.get("stdout", ""),
            stderr=d.get("stderr", ""),
        )


class JobStore:
    """Persistent job registry backed by a JSON file."""

    def __init__(self, cfg: Config) -> None:
        self._path = cfg.jobs_file
        self._log_dir = cfg.jobs_log_dir
        self._jobs: dict[int, Job] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._jobs = {}
            return
        try:
            data = json.loads(self._path.read_text())
            self._jobs = {j["id"]: Job.from_dict(j) for j in data}
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # Preserve the bad file for forensics — losing job state silently
            # is worse than carrying around a `.bad-<ts>` file.
            try:
                bad = self._path.parent / f"{self._path.name}.bad-{int(time.time())}"
                self._path.rename(bad)
                logger.warning("Corrupt jobs.json moved to %s; resetting", bad)
            except OSError:
                logger.warning("Corrupt jobs.json (could not back up); resetting")
            self._jobs = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps([j.to_dict() for j in self._jobs.values()], indent=2)
        # Atomic write: temp file + rename to prevent corruption on crash
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent), suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(data)
            os.rename(tmp, str(self._path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold an exclusive `fcntl.flock` for the load → mutate → save window.

        Two concurrent ``winbox exec --bg`` invocations would otherwise read
        stale state, allocate the same ID, and overwrite each other (the last
        writer wins, the first job is silently lost). All mutating methods
        acquire this lock and re-load inside it.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_suffix(self._path.suffix + ".lock")
        with open(lock_path, "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                # flock is released when the file descriptor closes.
                pass

    def next_id(self) -> int:
        if not self._jobs:
            return 1
        return max(self._jobs) + 1

    def add(self, job: Job) -> None:
        with self._exclusive():
            self._load()
            self._jobs[job.id] = job
            self._save()

    def claim(self, build: Callable[[int], Job]) -> Job:
        """Allocate the next ID + run ``build(id)`` to construct/spawn the
        Job + persist, all under one exclusive flock.

        ``build`` is responsible for any side effects (e.g. spawning the
        VM-side process). It must return a Job whose ``id`` matches the
        allocated value. Holding the lock during spawn serializes
        concurrent background launches — for a single-user dev tool that's
        the desired trade-off vs losing a job to an ID collision.
        """
        with self._exclusive():
            self._load()
            job_id = max(self._jobs, default=0) + 1
            job = build(job_id)
            if job.id != job_id:
                raise ValueError(
                    f"build() must return Job with id={job_id}, got {job.id}"
                )
            self._jobs[job.id] = job
            self._save()
        return job

    def get(self, job_id: int) -> Job | None:
        return self._jobs.get(job_id)

    def update(self, job: Job) -> None:
        with self._exclusive():
            self._load()
            self._jobs[job.id] = job
            self._save()

    def all(self) -> list[Job]:
        return list(self._jobs.values())

    def log_path(self, job_id: int, stream: str = "stdout") -> Path:
        """Host-side path to a log file for the given job."""
        return self._log_dir / f"{job_id}.{stream}"

    def vm_log_path(self, job_id: int, stream: str = "stdout") -> str:
        """VM-side (Z: drive) path to a log file for the given job."""
        return f"Z:\\loot\\.jobs\\{job_id}.{stream}"
