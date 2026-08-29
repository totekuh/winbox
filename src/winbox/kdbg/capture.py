"""One-stop immutable kdbg evidence captures and offline diffs."""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from winbox.config import Config
from winbox.kdbg.debugger.reader import debug_snapshot, snapshot_metadata, snapshot_phase
from winbox.kdbg.memory import WalkCache
from winbox.kdbg.objects import (
    ObjectEvidenceError, ensure_object_layouts, handle_table_status, token_evidence,
)
from winbox.kdbg.presentation import filetime_utc, thread_presentation_fields
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.vad import VadError, ensure_vad_layouts, list_vads
from winbox.kdbg.walk import (
    ProcessRecord, find_process, list_modules, list_processes_detailed,
    list_threads, list_user_modules,
)


SCHEMA = "winbox.kdbg-capture/1"
DIFF_SCHEMA = "winbox.kdbg-capture-diff/1"
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MAX_DIFF_ROWS = 1024


class CaptureError(RuntimeError):
    code = "capture_error"


class CaptureIncomplete(CaptureError):
    code = "incomplete_result"
    retryable = True


class CaptureIdentityError(CaptureError):
    code = "capture_identity_mismatch"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _process_record(process: ProcessRecord) -> dict[str, Any]:
    return {
        "pid": process.pid,
        "name": process.name,
        "eprocess": f"0x{process.eprocess:016x}",
        "dtb": f"0x{process.directory_table_base:012x}",
        "create_time": process.create_time,
        "create_time_utc": filetime_utc(process.create_time),
    }


def _thread_record(thread: Any) -> dict[str, Any]:
    record = {
        "tid": thread.tid,
        "ethread": f"0x{thread.ethread:016x}",
        "state": {"raw": thread.state, "name": thread.state_name},
        "wait_reason": {"raw": thread.wait_reason, "name": thread.wait_reason_name},
        "priority": thread.priority,
        "base_priority": thread.base_priority,
        "context_switches": thread.context_switches,
        "start_address": f"0x{thread.start_address:016x}",
        "win32_start_address": f"0x{thread.win32_start_address:016x}",
    }
    record.update(thread_presentation_fields(thread))
    return record


def _module_record(module: Any) -> dict[str, Any]:
    result = {
        "base": f"0x{module.base:016x}", "size": module.size,
        "name": module.name,
    }
    for field in ("path", "architecture"):
        value = getattr(module, field, None)
        if value is not None:
            result[field] = value
    return result


def _boot_identity(vm_name: str, store: SymbolStore, cache: WalkCache) -> dict[str, Any]:
    system = find_process(vm_name, store, pid=4, cache=cache)
    if system is None:
        raise CaptureError("could not establish boot identity: System process is absent")
    info = store.info("nt")
    return {
        "system": _process_record(system),
        "nt": {
            "build": info.build,
            "base": f"0x{info.base:016x}" if info.base else None,
            "store_file": info.path.name,
            "symbol_count": info.symbol_count,
            "type_count": info.type_count,
        },
    }


def capture_process_in_snapshot(
    cfg: Config, store: SymbolStore, pid: int, *, require_complete: bool = False,
) -> dict[str, Any]:
    """Build a bounded process capture while an existing snapshot is active."""
    cache = WalkCache()
    with snapshot_phase("process_identity"):
        target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
    if target is None:
        raise CaptureError(f"pid {pid} not found")
    with snapshot_phase("thread_walk"):
        threads = list_threads(cfg.vm_name, store, target, cache=cache)
    with snapshot_phase("module_walk"):
        kernel_modules = list_modules(cfg.vm_name, store, cache=cache)
        try:
            user_modules = list_user_modules(cfg.vm_name, store, target, cache=cache)
            user_modules_error = None
        except Exception as exc:
            user_modules = []
            user_modules_error = f"{type(exc).__name__}: {exc}"[:512]
    with snapshot_phase("vad_walk"):
        try:
            vads = list_vads(
                cfg.vm_name, store, target, cache=cache, executable_only=True,
                limit=256, probe_header=True,
            )
            vads_value = vads.public()
            vads_error = None
        except VadError as exc:
            vads_value = {"records": [], "returned": 0, "complete": False, "truncation": None}
            vads_error = str(exc)[:512]
    with snapshot_phase("object_evidence"):
        try:
            token = token_evidence(cfg.vm_name, store, target, cache=cache)
            token_error = None
        except ObjectEvidenceError as exc:
            token = None
            token_error = str(exc)[:512]
        try:
            handles = handle_table_status(cfg.vm_name, store, target, cache=cache)
            handles_error = None
        except ObjectEvidenceError as exc:
            handles = None
            handles_error = str(exc)[:512]
    complete = bool(threads.complete and vads_value["complete"])
    if require_complete and not complete:
        error = CaptureIncomplete("process capture contains an explicit partial boundary")
        error.details = {
            "thread_complete": threads.complete,
            "thread_truncation": getattr(threads, "truncated_reason", None),
            "vad_complete": vads_value["complete"],
            "vad_truncation": vads_value["truncation"],
        }
        raise error
    result = {
        "profile": "process",
        "boot_identity": _boot_identity(cfg.vm_name, store, cache),
        "process": _process_record(target),
        "complete": complete,
        "threads": {
            "complete": threads.complete,
            "truncated_reason": threads.truncated_reason,
            "records": [_thread_record(thread) for thread in threads.threads],
        },
        "modules": {
            "kernel": [_module_record(module) for module in kernel_modules],
            "user": [_module_record(module) for module in user_modules],
            "user_error": user_modules_error,
        },
        "executable_vads": vads_value,
        "vad_error": vads_error,
        "token": token,
        "token_error": token_error,
        "handles": handles,
        "handles_error": handles_error,
    }
    return result


def capture_system_in_snapshot(cfg: Config, store: SymbolStore, *, require_complete: bool = False) -> dict[str, Any]:
    cache = WalkCache()
    with snapshot_phase("process_walk"):
        walked = list_processes_detailed(cfg.vm_name, store, cache=cache)
    with snapshot_phase("module_walk"):
        modules = list_modules(cfg.vm_name, store, cache=cache)
    if require_complete and not walked.complete:
        error = CaptureIncomplete("system capture process list is incomplete")
        error.details = {"truncation": walked.truncation.public() if walked.truncation else None}
        raise error
    return {
        "profile": "system",
        "boot_identity": _boot_identity(cfg.vm_name, store, cache),
        "complete": walked.complete,
        "processes": [_process_record(process) for process in walked.processes],
        "process_truncation": walked.truncation.public() if walked.truncation else None,
        "kernel_modules": [_module_record(module) for module in modules],
    }


def capture_live(
    cfg: Config, store: SymbolStore, *, profile: str, pid: int | None = None,
    require_complete: bool = False,
) -> dict[str, Any]:
    if profile not in {"process", "system"}:
        raise CaptureError("profile must be 'process' or 'system'")
    if profile == "process" and (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0):
        raise CaptureError("process profile requires a positive pid")
    if profile == "system" and pid is not None:
        raise CaptureError("system profile does not accept pid")
    # PDB extraction is host work.  Never let first-use llvm-pdbutil consume
    # the finite stopped-guest budget.
    ensure_vad_layouts(cfg, store)
    ensure_object_layouts(cfg, store)
    with debug_snapshot(cfg, operation=f"capture.{profile}") as snapshot:
        with snapshot_phase("capture"):
            payload = (
                capture_process_in_snapshot(cfg, store, int(pid), require_complete=require_complete)
                if profile == "process" else capture_system_in_snapshot(
                    cfg, store, require_complete=require_complete,
                )
            )
        metadata = snapshot_metadata(snapshot)
    return {
        "schema": SCHEMA,
        "captured_at": _utc_now(),
        "vm_name": cfg.vm_name,
        "boot_identity": _boot_identity_for_capture(payload, cfg, store),
        "snapshot_metadata": metadata,
        "capture": payload,
    }


def _boot_identity_for_capture(payload: dict[str, Any], cfg: Config, store: SymbolStore) -> dict[str, Any]:
    """Capture-safe identity already read during the stop when available.

    ``capture_live`` calls this only after resume, so it must use the saved
    system row for system captures.  Process captures carry no System row;
    their nt identity still binds the artifact and the explicit boot check is
    represented as unavailable rather than causing a hidden second stop.
    """
    existing = payload.get("boot_identity")
    if isinstance(existing, dict):
        return existing
    info = store.info("nt")
    system = None
    if payload.get("profile") == "system":
        system = next((row for row in payload.get("processes", []) if row.get("pid") == 4), None)
    return {
        "system": system,
        "nt": {
            "build": info.build,
            "base": f"0x{info.base:016x}" if info.base else None,
            "store_file": info.path.name,
        },
        "system_identity_scope": "captured" if system else "not_captured_by_profile",
    }


class CaptureStore:
    def __init__(self, cfg: Config) -> None:
        self.root = cfg.winbox_dir / "kdbg" / "captures"

    @staticmethod
    def validate_name(name: str) -> str:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise CaptureError("capture name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
        return name

    def path(self, name: str) -> Path:
        return self.root / f"{self.validate_name(name)}.json"

    @contextmanager
    def _exclusive(self, name: str) -> Iterator[None]:
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        lock = path.with_suffix(".lock")
        with lock.open("a+b") as handle:
            os.chmod(lock, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield

    def save(self, name: str, capture: dict[str, Any]) -> dict[str, Any]:
        name = self.validate_name(name)
        if capture.get("schema") != SCHEMA:
            raise CaptureError("refusing to save unsupported capture schema")
        path = self.path(name)
        with self._exclusive(name):
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(capture, output, indent=2, sort_keys=True)
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        return {"name": name, "path": str(path), "schema": SCHEMA, "captured_at": capture.get("captured_at")}

    def load(self, name: str) -> dict[str, Any]:
        path = self.path(name)
        try:
            if path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
                raise CaptureError(f"capture {name!r} is unsafe or too large")
            capture = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CaptureError(f"capture {name!r} was not found") from exc
        except (OSError, ValueError, TypeError) as exc:
            raise CaptureError(f"could not load capture {name!r}: {exc}") from exc
        if not isinstance(capture, dict) or capture.get("schema") != SCHEMA:
            raise CaptureError(f"capture {name!r} has an unsupported or corrupt schema")
        return capture

    def inventory(self) -> dict[str, Any]:
        try:
            entries = sorted(self.root.glob("*.json")) if self.root.is_dir() else []
        except OSError:
            entries = []
        rows: list[dict[str, Any]] = []
        for path in entries[:128]:
            try:
                value = self.load(path.stem)
                rows.append({
                    "name": path.stem, "profile": value.get("capture", {}).get("profile"),
                    "captured_at": value.get("captured_at"), "size": path.stat().st_size,
                })
            except (CaptureError, OSError):
                continue
        return {"count": len(rows), "captures": rows}


def _identity(capture: dict[str, Any]) -> tuple[Any, Any, Any]:
    boot = capture.get("boot_identity") if isinstance(capture.get("boot_identity"), dict) else {}
    nt = boot.get("nt") if isinstance(boot.get("nt"), dict) else {}
    system = boot.get("system") if isinstance(boot.get("system"), dict) else None
    return capture.get("vm_name"), nt.get("build"), system.get("create_time") if system else None


def _diff_sets(left: list[dict[str, Any]], right: list[dict[str, Any]], key: str, *, limit: int) -> dict[str, Any]:
    before = {str(row.get(key)): row for row in left if isinstance(row, dict) and row.get(key) is not None}
    after = {str(row.get(key)): row for row in right if isinstance(row, dict) and row.get(key) is not None}
    created = [after[key] for key in sorted(set(after) - set(before))][:limit]
    removed = [before[key] for key in sorted(set(before) - set(after))][:limit]
    changed = [
        {"key": key, "before": before[key], "after": after[key]}
        for key in sorted(set(before) & set(after)) if before[key] != after[key]
    ][:limit]
    return {"created": created, "removed": removed, "changed": changed}


def diff_captures(
    left: dict[str, Any], right: dict[str, Any], *, limit: int = 128,
    allow_identity_mismatch: bool = False,
) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_DIFF_ROWS:
        raise CaptureError(f"limit must be between 1 and {MAX_DIFF_ROWS}")
    if left.get("schema") != SCHEMA or right.get("schema") != SCHEMA:
        raise CaptureError("both inputs must be kdbg capture artifacts")
    left_id, right_id = _identity(left), _identity(right)
    if not allow_identity_mismatch and left_id != right_id:
        raise CaptureIdentityError("capture VM, nt build, or captured boot identity differs; refuse unsafe comparison")
    before = left.get("capture") if isinstance(left.get("capture"), dict) else {}
    after = right.get("capture") if isinstance(right.get("capture"), dict) else {}
    if before.get("profile") != after.get("profile"):
        raise CaptureIdentityError("capture profiles differ")
    result: dict[str, Any] = {
        "schema": DIFF_SCHEMA,
        "profile": before.get("profile"),
        "identity_match": left_id == right_id,
        "left_captured_at": left.get("captured_at"),
        "right_captured_at": right.get("captured_at"),
        "limit": limit,
    }
    if before.get("profile") == "process":
        result["threads"] = _diff_sets(
            before.get("threads", {}).get("records", []), after.get("threads", {}).get("records", []),
            "ethread", limit=limit,
        )
        result["modules"] = _diff_sets(
            before.get("modules", {}).get("user", []), after.get("modules", {}).get("user", []),
            "base", limit=limit,
        )
        result["executable_vads"] = _diff_sets(
            before.get("executable_vads", {}).get("records", []), after.get("executable_vads", {}).get("records", []),
            "start", limit=limit,
        )
    else:
        result["processes"] = _diff_sets(before.get("processes", []), after.get("processes", []), "eprocess", limit=limit)
        result["kernel_modules"] = _diff_sets(before.get("kernel_modules", []), after.get("kernel_modules", []), "base", limit=limit)
    return result
