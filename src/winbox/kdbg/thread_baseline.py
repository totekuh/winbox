"""Explicit, bounded host-side baselines for PDB-backed ETHREAD walks."""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from winbox.config import Config
from winbox.kdbg.memory import WalkCache
from winbox.kdbg.presentation import filetime_utc, ntstatus_hex, ntstatus_name
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.walk import ProcessRecord, ThreadRecord, find_process, list_threads


BASELINE_SCHEMA = "winbox.kdbg-thread-baseline/1"
DIFF_SCHEMA = "winbox.kdbg-thread-diff/1"
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_MAX_THREADS = 8192  # same hard traversal cap as list_threads


class ThreadBaselineError(RuntimeError):
    code = "baseline_error"


class BaselineNotFoundError(ThreadBaselineError):
    code = "baseline_not_found"


class BaselineExpiredError(ThreadBaselineError):
    code = "baseline_expired"


class BaselineIncompleteError(ThreadBaselineError):
    code = "baseline_incomplete"


@dataclass(frozen=True)
class ThreadCapture:
    """Complete current-thread evidence collected inside one existing stop."""

    vm_name: str
    target: ProcessRecord
    boot_identity: dict[str, Any]
    symbol_identity: dict[str, Any]
    threads: tuple[ThreadRecord, ...]
    captured_at: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _identity(process: ProcessRecord) -> dict[str, Any]:
    if process.create_time <= 0:
        raise ThreadBaselineError(
            f"pid {process.pid} has no EPROCESS.CreateTime; refusing an unsafe baseline"
        )
    return {
        "pid": process.pid,
        "name": process.name,
        "eprocess": f"0x{process.eprocess:016x}",
        "create_time": process.create_time,
        "create_time_utc": filetime_utc(process.create_time),
    }


def _thread_key(thread: ThreadRecord) -> str:
    if thread.create_time <= 0:
        raise ThreadBaselineError(
            f"tid {thread.tid} has no ETHREAD.CreateTime; refusing an unsafe baseline"
        )
    return f"{thread.ethread:016x}:{thread.create_time:016x}"


def _thread_observation(thread: ThreadRecord) -> dict[str, Any]:
    """Small, JSON-safe data necessary for a truthful later comparison."""
    return {
        "tid": thread.tid,
        "ethread": f"0x{thread.ethread:016x}",
        "create_time": thread.create_time,
        "create_time_utc": filetime_utc(thread.create_time),
        "state": {"raw": thread.state, "name": thread.state_name},
        "wait_reason": {"raw": thread.wait_reason, "name": thread.wait_reason_name},
        "priority": thread.priority,
        "base_priority": thread.base_priority,
        "context_switches": thread.context_switches,
        "exit_status": thread.exit_status,
        "exit_status_ntstatus": ntstatus_hex(thread.exit_status),
        "exit_status_name": ntstatus_name(thread.exit_status),
        "start_address": f"0x{thread.start_address:016x}",
        "win32_start_address": f"0x{thread.win32_start_address:016x}",
    }


def capture_threads(
    cfg: Config,
    store: SymbolStore,
    pid: int,
    *,
    cache: WalkCache | None = None,
) -> ThreadCapture:
    """Collect a baseline-safe complete ETHREAD set in the caller's snapshot."""
    cache = cache or WalkCache()
    target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
    if target is None:
        raise ThreadBaselineError(f"pid {pid} not found")
    target_identity = _identity(target)
    walked = list_threads(cfg.vm_name, store, target, cache=cache)
    if not walked.complete:
        raise BaselineIncompleteError(
            "thread walk is incomplete; baseline was not saved: "
            f"{walked.truncated_reason or 'unknown truncation'}"
        )
    if len(walked.threads) > _MAX_THREADS:
        raise BaselineIncompleteError(
            f"thread count exceeds baseline cap {_MAX_THREADS}; baseline was not saved"
        )
    system = target if target.pid == 4 else find_process(
        cfg.vm_name, store, pid=4, cache=cache,
    )
    if system is None:
        raise ThreadBaselineError("could not establish boot identity: System process not found")
    info = store.info("nt")
    try:
        symbol_mtime_ns = info.path.stat().st_mtime_ns
    except OSError as exc:
        raise ThreadBaselineError(f"could not stat active nt symbol store: {exc}") from exc
    return ThreadCapture(
        vm_name=cfg.vm_name,
        target=target,
        boot_identity={
            "system": _identity(system),
            "nt_base": f"0x{info.base:016x}" if info.base else None,
        },
        symbol_identity={
            "build": info.build,
            "path": info.path.name,
            "symbol_count": info.symbol_count,
            "type_count": info.type_count,
            "mtime_ns": symbol_mtime_ns,
        },
        threads=tuple(walked.threads),
        captured_at=_utc_now(),
    )


class ThreadBaselineStore:
    """Atomic per-name baseline storage under the user-owned winbox root."""

    def __init__(self, cfg: Config) -> None:
        self.root = cfg.winbox_dir / "kdbg" / "thread-baselines"

    @staticmethod
    def validate_name(name: str) -> str:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise ThreadBaselineError(
                "baseline name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
            )
        return name

    def path(self, name: str) -> Path:
        name = self.validate_name(name)
        return self.root / f"{name}.json"

    @contextmanager
    def _exclusive(self, name: str) -> Iterator[None]:
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        lock = path.with_suffix(path.suffix + ".lock")
        with lock.open("a+b") as handle:
            os.chmod(lock, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield

    @staticmethod
    def _atomic_write(path: Path, data: dict[str, Any]) -> None:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent),
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def save(self, name: str, capture: ThreadCapture) -> dict[str, Any]:
        name = self.validate_name(name)
        observations = {_thread_key(thread): _thread_observation(thread) for thread in capture.threads}
        if len(observations) != len(capture.threads):
            raise ThreadBaselineError("duplicate ETHREAD/create-time identity in current thread walk")
        data = {
            "schema": BASELINE_SCHEMA,
            "name": name,
            "captured_at": capture.captured_at,
            "vm_name": capture.vm_name,
            "target": _identity(capture.target),
            "boot_identity": capture.boot_identity,
            "symbol_identity": capture.symbol_identity,
            "thread_count": len(observations),
            "threads": observations,
        }
        with self._exclusive(name):
            self._atomic_write(self.path(name), data)
        return {
            "schema": BASELINE_SCHEMA,
            "name": name,
            "captured_at": capture.captured_at,
            "process": data["target"],
            "thread_count": len(observations),
            "boot_identity": capture.boot_identity,
            "symbol_identity": capture.symbol_identity,
        }

    def load(self, name: str) -> dict[str, Any]:
        path = self.path(name)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise BaselineNotFoundError(f"baseline {name!r} was not found") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ThreadBaselineError(f"could not read baseline {name!r}: {exc}") from exc
        if (
            not isinstance(data, dict)
            or data.get("schema") != BASELINE_SCHEMA
            or not isinstance(data.get("threads"), dict)
        ):
            raise ThreadBaselineError(f"baseline {name!r} has an unsupported or corrupt schema")
        return data

    @staticmethod
    def _assert_compatible(baseline: dict[str, Any], capture: ThreadCapture) -> None:
        comparisons = (
            ("vm", baseline.get("vm_name"), capture.vm_name),
            ("symbol store", baseline.get("symbol_identity"), capture.symbol_identity),
            ("boot identity", baseline.get("boot_identity"), capture.boot_identity),
            ("target identity", baseline.get("target"), _identity(capture.target)),
        )
        for label, previous, current in comparisons:
            if previous != current:
                raise BaselineExpiredError(
                    f"baseline expired: {label} changed; save a new explicit baseline"
                )

    @staticmethod
    def _changes(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        changes: dict[str, Any] = {}
        for field in ("tid", "state", "wait_reason", "priority", "base_priority", "exit_status"):
            if previous.get(field) != current.get(field):
                changes[field] = {"before": previous.get(field), "after": current.get(field)}
        before_switches = previous.get("context_switches")
        current_switches = current.get("context_switches")
        if isinstance(before_switches, int) and isinstance(current_switches, int) and before_switches != current_switches:
            wrapped = current_switches < before_switches
            changes["context_switches"] = {
                "before": before_switches,
                "after": current_switches,
                "delta": (current_switches - before_switches) & 0xFFFFFFFF,
                "wrapped": wrapped,
            }
        return changes

    def diff(self, name: str, capture: ThreadCapture, *, limit: int) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1024:
            raise ThreadBaselineError("limit must be an integer between 1 and 1024")
        name = self.validate_name(name)
        baseline = self.load(name)
        self._assert_compatible(baseline, capture)
        previous = baseline["threads"]
        current = {_thread_key(thread): _thread_observation(thread) for thread in capture.threads}
        if len(current) != len(capture.threads):
            raise ThreadBaselineError("duplicate ETHREAD/create-time identity in current thread walk")
        created_keys = sorted(set(current) - set(previous))
        exited_keys = sorted(set(previous) - set(current))
        changed = []
        for key in sorted(set(previous) & set(current)):
            changes = self._changes(previous[key], current[key])
            if changes:
                changed.append({"thread": current[key], "changes": changes})
        return {
            "schema": DIFF_SCHEMA,
            "name": name,
            "baseline": {
                "captured_at": baseline.get("captured_at"),
                "thread_count": baseline.get("thread_count"),
            },
            "current": {
                "captured_at": capture.captured_at,
                "thread_count": len(current),
            },
            "process": _identity(capture.target),
            "created_count": len(created_keys),
            "exited_count": len(exited_keys),
            "changed_count": len(changed),
            "created": [current[key] for key in created_keys[:limit]],
            "exited": [previous[key] for key in exited_keys[:limit]],
            "changed": changed[:limit],
            "created_truncated": len(created_keys) > limit,
            "exited_truncated": len(exited_keys) > limit,
            "changed_truncated": len(changed) > limit,
            "limit": limit,
        }

    def delete(self, name: str) -> None:
        """Test/helper cleanup of one exact validated baseline name."""
        name = self.validate_name(name)
        with self._exclusive(name):
            self.path(name).unlink(missing_ok=True)
