#!/usr/bin/env python3
"""Persistent, serialized PyGhidra worker.

This file is deliberately executable by a *different* Python environment from
winbox's.  A pipx PyGhidra interpreter can run it by absolute path without
installing winbox into the JVM environment.  Keep imports before ``_start`` to
the standard library only.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import signal
import socket
import sys
import threading
import time
import traceback
import re
from pathlib import Path


MAX_REQUEST = 64 * 1024
MAX_CODE = 256 * 1024
MAX_CONTEXT_LINES = 20
DEFAULT_MAX_OPEN_PROGRAMS = 1
MAX_LINE_BATCH = 100
MAX_MAPPED_INSTRUCTION_ASSOCIATIONS = 512
WORKER_API = "6"
ANALYSIS_PROFILE = "winbox-pdb-enrichment-v3"
REQUEST_READ_TIMEOUT = 5.0
ERROR_SCHEMA = "winbox.error/1"
HEARTBEAT_INTERVAL = 1.0
MAX_ENRICHMENT_BYTES = 4 * 1024 * 1024
MAX_ENRICHMENT_RECORDS = 8192
MAX_ENRICHMENT_EVENTS = MAX_ENRICHMENT_RECORDS * 3
ENRICHMENT_REVISION = 2

_PHASE_PROGRESS = {
    "validating_input": 0,
    "starting_jvm": 1,
    "staging_binary": 2,
    "importing_program": 3,
    "opening_cached_program": 3,
    "opening_project": 3,
    "analyzing_program": 4,
    "enriching_program": 5,
    "decompiling": 6,
    "mapping": 7,
    "saving_cache": 8,
}
_TOTAL_PHASES = 9


class WorkerError(RuntimeError):
    def __init__(
        self, message, *, code="operation_failed", retryable=False, details=None,
    ):
        super().__init__(str(message)[:2048])
        self.code = code
        self.retryable = bool(retryable)
        self.details = details if isinstance(details, dict) else {}


def _error_info(exc):
    code = getattr(exc, "code", "operation_failed")
    retryable = bool(getattr(exc, "retryable", False))
    details = getattr(exc, "details", {})
    if not isinstance(details, dict):
        details = {}
    safe_details = {}
    for key, value in list(details.items())[:16]:
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe_details[str(key)[:64]] = value[:512] if isinstance(value, str) else value
    return {
        "schema": ERROR_SCHEMA,
        "code": str(code)[:64],
        "message": str(exc)[:2048],
        "retryable": retryable,
        "details": safe_details,
    }


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def _safe_binary_name(value) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1][:260]


def _looks_like_project_corruption(exc) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    if any(token in text for token in (
        "permission denied", "access denied", "outofmemory", "out of memory",
        "cancelled", "canceled",
    )):
        return False
    return any(token in text for token in (
        "corrupt", "malformed", "truncated", "invalid project",
        "invalid repository", "repository error", "not a ghidra project",
        "project data", "project file", "xml parse error", "properties file",
    ))


class OpenProgram:
    def __init__(self, context, api, decompiler):
        self.context = context
        self.api = api
        self.program = api.getCurrentProgram()
        self.decompiler = decompiler
        self.decompile_cache: collections.OrderedDict[int, object] = (
            collections.OrderedDict()
        )
        self.enrichment_key = None
        self.enrichment_summary = None

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.decompiler.dispose()
        with contextlib.suppress(Exception):
            self.context.__exit__(None, None, None)


class Worker:
    def __init__(
        self, cache: Path, projects: Path, ghidra_install_dir: str | None,
        *, max_open_programs: int = DEFAULT_MAX_OPEN_PROGRAMS,
    ):
        self.cache = cache
        self.projects = projects
        self.ghidra_install_dir = ghidra_install_dir
        self.started = False
        self.pyghidra = None
        self.ghidra_version = None
        self.programs: collections.OrderedDict[str, OpenProgram] = (
            collections.OrderedDict()
        )
        self.shutdown = False
        self.max_open_programs = max(1, min(int(max_open_programs), 4))
        self.progress_callback = None

    def _phase(self, phase: str, **details) -> None:
        if self.progress_callback is not None:
            self.progress_callback(phase, details)

    def start_ghidra(self) -> None:
        if self.started:
            return
        self._phase("starting_jvm")
        try:
            import pyghidra
        except ImportError as exc:
            raise WorkerError(
                "this worker interpreter does not contain pyghidra"
            ) from exc
        try:
            if not pyghidra.started():
                if self.ghidra_install_dir:
                    pyghidra.start(install_dir=self.ghidra_install_dir)
                else:
                    pyghidra.start()
            from ghidra.framework import Application
            self.ghidra_version = str(Application.getApplicationVersion())
        except Exception as exc:
            hint = (
                " (set GHIDRA_INSTALL_DIR to the Ghidra installation)"
                if not self.ghidra_install_dir else ""
            )
            raise WorkerError(f"could not start Ghidra: {exc}{hint}") from exc
        self.pyghidra = pyghidra
        self.started = True

    def handle(self, op: str, args: dict) -> dict:
        if op == "status":
            return {
                "worker_api": WORKER_API,
                "analysis_profile": ANALYSIS_PROFILE,
                "jvm_started": self.started,
                "ghidra_version": self.ghidra_version,
                "worker_pid": os.getpid(),
                "open_programs": len(self.programs),
                "max_open_programs": self.max_open_programs,
                "cached_programs": _count_projects(self.projects),
            }
        if op == "shutdown":
            self.shutdown = True
            return {"shutting_down": True}
        if op == "repair":
            return self.repair(args)
        if op == "prepare":
            return self.prepare(args)
        if op != "decompile":
            raise WorkerError(
                f"unknown operation: {op!r}", code="unknown_operation",
                details={"operation": op},
            )
        return self.decompile(args)

    def decompile(self, args: dict) -> dict:
        self._phase(
            "validating_input",
            binary_name=_safe_binary_name(args.get("binary_name")),
            binary_sha256=str(args.get("sha256") or "")[:64],
        )
        binary = Path(str(args.get("binary", ""))).expanduser().resolve()
        expected_sha = str(args.get("sha256", "")).lower()
        if not binary.is_file():
            raise WorkerError(
                f"binary does not exist: {binary}", code="prerequisite_missing",
            )
        if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
            raise WorkerError(
                "sha256 must be 64 lowercase hexadecimal characters",
                code="invalid_argument",
            )
        actual_sha = _sha256(binary)
        if actual_sha != expected_sha:
            raise WorkerError(
                f"binary changed before analysis: expected {expected_sha}, got {actual_sha}",
                code="identity_mismatch",
            )
        try:
            rva = int(args.get("rva"))
        except (TypeError, ValueError) as exc:
            raise WorkerError("rva must be an integer", code="invalid_argument") from exc
        if rva < 0 or rva >= (1 << 32):
            raise WorkerError(
                f"rva outside supported PE range: {rva}", code="invalid_argument",
            )
        before = max(0, min(int(args.get("before", 3)), MAX_CONTEXT_LINES))
        after = max(0, min(int(args.get("after", 5)), MAX_CONTEXT_LINES))
        full = bool(args.get("full", False))
        timeout = max(5, min(int(args.get("decompile_timeout", 60)), 300))
        line_start, line_end = _requested_lines(args)
        assembly_mode = str(args.get("assembly", "nearby")).strip().lower()
        if assembly_mode not in {"nearby", "mapped"}:
            raise WorkerError(
                "assembly must be 'nearby' or 'mapped'", code="invalid_argument",
            )

        request_id = str(args.get("_request_id") or "")
        try:
            analysis_timeout = int(args.get("analysis_timeout", 900))
        except (TypeError, ValueError) as exc:
            raise WorkerError(
                "analysis_timeout must be an integer", code="invalid_argument",
            ) from exc
        if not 5 <= analysis_timeout <= 1800:
            raise WorkerError(
                "analysis_timeout must be between 5 and 1800 seconds",
                code="invalid_argument",
            )
        self._check_cancelled(request_id)
        opened, cache_hit, cache_recovery = self._open(
            binary, expected_sha, request_id=request_id,
            analysis_timeout=analysis_timeout,
            enrichment=str(args.get("enrichment") or ""),
        )
        self._check_cancelled(request_id)
        program = opened.program
        image_base = int(program.getImageBase().getOffset())
        target_value = image_base + rva
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            target_value
        )
        memory = program.getMemory()
        if not memory.contains(address):
            raise WorkerError(
                f"RVA 0x{rva:x} maps to {address}, outside Ghidra memory blocks"
            )
        manager = program.getFunctionManager()
        function = manager.getFunctionContaining(address)
        function_source = "analysis"
        if function is None:
            function, function_source = _recover_function(
                opened.api, program, address, rva, args.get("symbol_hint")
            )
        if function is None or not function.getBody().contains(address):
            instruction = program.getListing().getInstructionContaining(address)
            suffix = " (instruction exists but no containing function)" if instruction else ""
            raise WorkerError(f"no analyzed function contains RVA 0x{rva:x}{suffix}")

        entry = int(function.getEntryPoint().getOffset())
        function_rva = entry - image_base
        persisted_source = self._recovery_provenance(expected_sha, function_rva)
        if function_source == "analysis" and persisted_source:
            function_source = persisted_source
        elif function_source.startswith("pdb-public-"):
            self._record_recovery_provenance(
                expected_sha, function_rva, function_source, args.get("symbol_hint"),
            )
        result = opened.decompile_cache.pop(entry, None)
        decompile_cache_hit = result is not None
        if result is None:
            self._phase("decompiling")
            from ghidra.util.task import ConsoleTaskMonitor
            monitor = ConsoleTaskMonitor()
            finished = threading.Event()
            watcher = None
            if request_id:
                marker = self.cache / "cancel" / request_id
                def watch_cancel():
                    while not finished.wait(0.1):
                        if marker.exists():
                            with contextlib.suppress(Exception):
                                monitor.cancel()
                            return
                watcher = threading.Thread(target=watch_cancel, daemon=True)
                watcher.start()
            try:
                result = opened.decompiler.decompileFunction(function, timeout, monitor)
            finally:
                finished.set()
                if watcher is not None:
                    watcher.join(timeout=1.0)
        self._check_cancelled(request_id)
        if result is None or not result.decompileCompleted():
            message = result.getErrorMessage() if result is not None else "no result"
            raise WorkerError(
                f"Ghidra could not decompile {function.getName()}: {message}"
            )
        opened.decompile_cache[entry] = result
        while len(opened.decompile_cache) > 32:
            opened.decompile_cache.popitem(last=False)
        decompiled = result.getDecompiledFunction()
        code = decompiled.getC() if decompiled is not None else None
        if code is None:
            raise WorkerError(f"Ghidra returned no C for {function.getName()}")
        full_code = code
        returned_code, code_stats = _bounded_code_payload(full_code, full=full)

        self._phase("mapping")
        mapping = _map_source(
            result.getCCodeMarkup(), address, full_code, before, after,
            line_start=line_start, line_end=line_end,
        )
        if assembly_mode == "mapped":
            mapping["assembly_truncated"] = _attach_mapped_assembly(
                program, function, mapping
            )
        instructions, instruction_location = _nearby_instructions(
            program, function, address
        )
        verified_name = _verified_function_name(
            args.get("symbol_hint"), entry - image_base,
        )
        response = {
            "cache_hit": cache_hit,
            "decompile_cache_hit": decompile_cache_hit,
            "ghidra_version": self.ghidra_version,
            "analysis_profile": ANALYSIS_PROFILE,
            "ghidra_image_base": f"0x{image_base:x}",
            "ghidra_address": f"0x{target_value:x}",
            "function": {
                "name": str(function.getName()),
                "verified_name": verified_name,
                "name_source": "verified-pdb-public" if verified_name else "ghidra",
                "entry": f"0x{entry:x}",
                "rva": f"0x{entry - image_base:x}",
                "offset": f"0x{target_value - entry:x}",
                "signature": str(function.getSignature()),
                "is_thunk": bool(function.isThunk()),
                "source": function_source,
                "contains_requested_address": True,
            },
            "mapping": mapping,
            "assembly_mode": assembly_mode,
            "instructions": instructions,
            "instruction_location": instruction_location,
            "analysis": {
                "binary_sha256": expected_sha,
                "project_cached": True,
                "enrichment": opened.enrichment_summary,
                **code_stats,
            },
        }
        if cache_recovery is not None:
            response["analysis"]["cache_recovery"] = cache_recovery
        if full:
            response["code"] = returned_code
        self._phase("saving_cache")
        self._record_metadata(
            expected_sha, _safe_binary_name(args.get("binary_name")) or binary.name,
            project_name=_project_name(self.ghidra_version, expected_sha),
        )
        return response

    def prepare(self, args: dict) -> dict:
        """Import/analyze/enrich one exact artifact without a debugger stop."""
        started = time.monotonic()
        binary = Path(str(args.get("binary", ""))).expanduser().resolve()
        digest = str(args.get("sha256") or "").lower()
        if not binary.is_file():
            raise WorkerError("binary does not exist", code="prerequisite_missing")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise WorkerError(
                "sha256 must be 64 lowercase hexadecimal characters",
                code="invalid_argument",
            )
        if _sha256(binary) != digest:
            raise WorkerError("binary fails its exact digest", code="identity_mismatch")
        try:
            analysis_timeout = int(args.get("analysis_timeout", 900))
        except (TypeError, ValueError) as exc:
            raise WorkerError("analysis_timeout must be an integer", code="invalid_argument") from exc
        if not 5 <= analysis_timeout <= 1800:
            raise WorkerError(
                "analysis_timeout must be between 5 and 1800 seconds",
                code="invalid_argument",
            )
        request_id = str(args.get("_request_id") or "")
        self._check_cancelled(request_id)
        opened, cache_hit, recovery = self._open(
            binary, digest, request_id=request_id,
            analysis_timeout=analysis_timeout,
            enrichment=str(args.get("enrichment") or ""),
        )
        self._check_cancelled(request_id)
        self._phase("saving_cache")
        self._record_metadata(
            digest, _safe_binary_name(args.get("binary_name")) or binary.name,
            project_name=_project_name(self.ghidra_version, digest),
        )
        result = {
            "schema": "winbox.decomp-prepare/1",
            "prepared": True,
            "binary_sha256": digest,
            "binary_name": _safe_binary_name(args.get("binary_name")) or binary.name,
            "cache_hit": cache_hit,
            "ghidra_version": self.ghidra_version,
            "analysis_profile": ANALYSIS_PROFILE,
            "enrichment": opened.enrichment_summary,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        if recovery is not None:
            result["cache_recovery"] = recovery
        return result

    def _check_cancelled(self, request_id: str) -> None:
        if not request_id:
            return
        marker = self.cache / "cancel" / request_id
        if marker.exists():
            with contextlib.suppress(OSError):
                marker.unlink()
            raise WorkerError(
                f"request {request_id} was cancelled by its client",
                code="cancelled", retryable=True,
                details={"request_id": request_id},
            )

    def _record_metadata(self, digest: str, binary_name: str, *, project_name: str) -> None:
        root = self.cache / "metadata"
        root.mkdir(parents=True, exist_ok=True)
        value = {
            "schema": "winbox.decomp-cache/1", "sha256": digest,
            "binary_name": binary_name[:260], "project_name": project_name,
            "ghidra_version": self.ghidra_version,
            "analysis_profile": ANALYSIS_PROFILE, "last_used": time.time(),
        }
        temporary = root / f".{digest}.{os.getpid()}.tmp"
        temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, root / f"{digest}.json")

    def _provenance_path(self, digest: str) -> Path:
        return self.cache / "provenance" / f"{ANALYSIS_PROFILE}_{digest}.json"

    def _recovery_provenance(self, digest: str, function_rva: int) -> str | None:
        try:
            value = json.loads(self._provenance_path(digest).read_text(encoding="utf-8"))
            entry = value.get(str(function_rva))
            source = entry.get("source") if isinstance(entry, dict) else None
            return str(source) if source else None
        except (OSError, ValueError, TypeError):
            return None

    def _record_recovery_provenance(
        self, digest: str, function_rva: int, source: str, hint,
    ) -> None:
        path = self._provenance_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                value = {}
        except (OSError, ValueError):
            value = {}
        hint_name = hint.get("name") if isinstance(hint, dict) else ""
        value[str(function_rva)] = {
            "source": source, "symbol": str(hint_name or "")[:512],
            "recorded_at": time.time(),
        }
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _project_paths(self, project_name: str) -> list[Path]:
        return [
            self.projects / f"{project_name}{suffix}"
            for suffix in (".gpr", ".rep", ".lock", ".lock~")
        ]

    def _reset_project(self, project_name: str, *, reason: str) -> dict:
        """Delete only one internally generated digest-keyed project pair."""
        if not re.fullmatch(r"[A-Za-z0-9_]{1,240}", project_name):
            raise WorkerError(
                "refusing unsafe internal project name",
                code="cache_reset_failed", details={"project": project_name[:240]},
            )
        removed = []
        try:
            for path in self._project_paths(project_name):
                if path.is_symlink():
                    raise OSError(f"refusing symlink cache entry {path.name}")
                if path.is_dir():
                    shutil.rmtree(path)
                    removed.append(path.name)
                elif path.is_file():
                    path.unlink()
                    removed.append(path.name)
                elif path.exists():
                    raise OSError(f"unsupported cache entry type {path.name}")
        except Exception as exc:
            raise WorkerError(
                f"exact corrupt project reset failed: {exc}",
                code="cache_reset_failed", retryable=False,
                details={
                    "project": project_name,
                    "removed_files": ",".join(removed)[:512],
                },
            ) from exc
        return {
            "schema": "winbox.decomp-cache-reset/1",
            "project": project_name,
            "removed_files": removed,
            "original_failure": str(reason)[:1024],
        }

    def _enter_project(
        self, cached_binary: Path, project_name: str, program_name: str,
    ) -> OpenProgram:
        context = self.pyghidra.open_program(
            str(cached_binary),
            project_location=str(self.projects),
            project_name=project_name,
            program_name=program_name,
            nested_project_location=False,
            # Import/open and auto-analysis are separate phases.  PyGhidra's
            # analyze=True path creates its own non-cancellable monitor.
            analyze=False,
        )
        try:
            api = context.__enter__()
        except BaseException:
            with contextlib.suppress(Exception):
                context.__exit__(*sys.exc_info())
            raise
        try:
            from ghidra.app.decompiler import DecompInterface
            decompiler = DecompInterface()
            if not decompiler.openProgram(api.getCurrentProgram()):
                raise WorkerError("Ghidra decompiler rejected the imported program")
            return OpenProgram(context, api, decompiler)
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise

    def _run_cancellable(
        self, request_id: str, timeout: int, callback,
        *, timeout_code: str, timeout_message: str,
    ):
        from ghidra.util.task import ConsoleTaskMonitor
        monitor = ConsoleTaskMonitor()
        finished = threading.Event()
        timed_out = threading.Event()
        deadline = time.monotonic() + timeout

        def watch() -> None:
            marker = self.cache / "cancel" / request_id if request_id else None
            while not finished.wait(0.1):
                if marker is not None and marker.exists():
                    with contextlib.suppress(Exception):
                        monitor.cancel()
                    return
                if time.monotonic() >= deadline:
                    timed_out.set()
                    with contextlib.suppress(Exception):
                        monitor.cancel()
                    return

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        try:
            result = callback(monitor)
        except Exception as exc:
            if timed_out.is_set():
                raise WorkerError(
                    timeout_message, code=timeout_code, retryable=True,
                    details={"timeout_seconds": timeout},
                ) from exc
            self._check_cancelled(request_id)
            raise
        finally:
            finished.set()
            watcher.join(timeout=1.0)
        if timed_out.is_set():
            raise WorkerError(
                timeout_message, code=timeout_code, retryable=True,
                details={"timeout_seconds": timeout},
            )
        self._check_cancelled(request_id)
        return result

    def _analyze_opened(
        self, opened: OpenProgram, *, request_id: str, timeout: int,
    ) -> bool:
        from ghidra.program.util import GhidraProgramUtilities
        if not GhidraProgramUtilities.shouldAskToAnalyze(opened.program):
            return False
        self._phase("analyzing_program")

        def analyze(monitor):
            from ghidra.app.script import GhidraScriptUtil
            from ghidra.program.flatapi import FlatProgramAPI
            GhidraScriptUtil.acquireBundleHostReference()
            try:
                FlatProgramAPI(opened.program, monitor).analyzeAll(opened.program)
            finally:
                GhidraScriptUtil.releaseBundleHostReference()

        self._run_cancellable(
            request_id, timeout, analyze,
            timeout_code="analysis_timeout",
            timeout_message=f"Ghidra analysis exceeded {timeout} seconds",
        )
        GhidraProgramUtilities.markProgramAnalyzed(opened.program)
        return True

    def _load_enrichment(self, value: str, digest: str) -> tuple[str, dict] | None:
        if not value:
            return None
        path = Path(value)
        try:
            resolved = path.resolve(strict=True)
            root = (self.cache / "enrichment").resolve(strict=True)
        except OSError as exc:
            raise WorkerError(
                "exact PDB enrichment sidecar is missing",
                code="prerequisite_missing",
            ) from exc
        if path.is_symlink() or not resolved.is_file() or not resolved.is_relative_to(root):
            raise WorkerError("unsafe PDB enrichment path", code="invalid_argument")
        if resolved.stat().st_size > MAX_ENRICHMENT_BYTES:
            raise WorkerError("PDB enrichment sidecar exceeds size cap", code="invalid_argument")
        try:
            raw = resolved.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerError("invalid PDB enrichment sidecar", code="invalid_argument") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != "winbox.pdb-enrichment/1"
            or payload.get("revision") != ENRICHMENT_REVISION
            or payload.get("analysis_profile") != ANALYSIS_PROFILE
            or payload.get("binary_sha256") != digest
        ):
            raise WorkerError("PDB enrichment identity mismatch", code="identity_mismatch")
        for field in ("functions", "globals"):
            records = payload.get(field)
            if not isinstance(records, list) or len(records) > MAX_ENRICHMENT_RECORDS:
                raise WorkerError(f"invalid bounded enrichment {field}", code="invalid_argument")
            for record in records:
                if not isinstance(record, dict):
                    raise WorkerError(f"invalid enrichment {field} record", code="invalid_argument")
                name = record.get("name")
                rva = record.get("rva")
                if (
                    not isinstance(name, str) or not 1 <= len(name) <= 512 or "\0" in name
                    or isinstance(rva, bool) or not isinstance(rva, int)
                    or not 0 <= rva < (1 << 32)
                ):
                    raise WorkerError(f"invalid enrichment {field} identity", code="invalid_argument")
        return hashlib.sha256(raw).hexdigest(), payload

    @staticmethod
    def _safe_symbol_name(value: str, rva: int) -> str:
        safe = re.sub(r"[^A-Za-z0-9_?$@]", "_", value[:200])
        if not safe or safe[0].isdigit():
            safe = f"winbox_{rva:x}_{safe}"
        return safe

    @staticmethod
    def _signature_type(spec: dict, manager):
        from ghidra.program.model import data as types
        classes = {
            "void": types.VoidDataType,
            "bool": types.BooleanDataType,
            "char": types.CharDataType,
            "signed char": types.SignedCharDataType,
            "unsigned char": types.UnsignedCharDataType,
            "short": types.ShortDataType,
            "unsigned short": types.UnsignedShortDataType,
            "int": types.IntegerDataType,
            "unsigned int": types.UnsignedIntegerDataType,
            "long": types.LongDataType,
            "unsigned long": types.UnsignedLongDataType,
            "__int64": types.LongLongDataType,
            "unsigned __int64": types.UnsignedLongLongDataType,
            "float": types.FloatDataType,
            "double": types.DoubleDataType,
            "wchar_t": types.WideCharDataType,
        }
        if not isinstance(spec, dict) or spec.get("base") not in classes:
            raise ValueError("unsupported signature type")
        pointers = spec.get("pointers", 0)
        if isinstance(pointers, bool) or not isinstance(pointers, int) or not 0 <= pointers <= 2:
            raise ValueError("invalid pointer depth")
        value = classes[spec["base"]](manager)
        for _ in range(pointers):
            value = types.PointerDataType(value, manager)
        return value

    def _apply_signature(self, program, function, signature: dict, name: str) -> bool:
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl
        from ghidra.program.model.symbol import SourceType
        if function.getSignatureSource() not in (SourceType.DEFAULT, SourceType.ANALYSIS):
            return False
        manager = program.getDataTypeManager()
        definition = FunctionDefinitionDataType(name, manager)
        definition.setReturnType(self._signature_type(signature.get("return"), manager))
        parameters = [
            ParameterDefinitionImpl(
                f"param_{index + 1}", self._signature_type(spec, manager), None,
            )
            for index, spec in enumerate(signature.get("parameters") or [])
        ]
        definition.setArguments(parameters)
        command = ApplyFunctionSignatureCmd(
            function.getEntryPoint(), definition, SourceType.IMPORTED,
        )
        return bool(command.applyTo(program))

    def _enrichment_result_path(self, digest: str) -> Path:
        return (
            self.cache / "enrichment-results"
            / f"{ANALYSIS_PROFILE}_{digest}.json"
        )

    def _record_enrichment_result(
        self, digest: str, sidecar_sha256: str, stats: dict, events: list[dict],
    ) -> str:
        """Atomically persist every bounded enrichment decision and its source."""
        if len(events) > MAX_ENRICHMENT_EVENTS:
            raise WorkerError(
                "enrichment result exceeds bounded event cap",
                code="invalid_argument",
            )
        path = self._enrichment_result_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "winbox.ghidra-enrichment-provenance/1",
            "analysis_profile": ANALYSIS_PROFILE,
            "binary_sha256": digest,
            "sidecar_sha256": sidecar_sha256,
            "recorded_at": time.time(),
            "summary": stats,
            "events": events,
        }
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, separators=(",", ":")), encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise WorkerError(
                "could not persist exact PDB enrichment provenance",
                code="cache_write_failed", retryable=True,
            ) from exc
        return str(path.relative_to(self.cache))

    def _apply_enrichment(self, opened: OpenProgram, digest: str, value: str) -> dict | None:
        loaded = self._load_enrichment(value, digest)
        if loaded is None:
            return None
        key, payload = loaded
        if opened.enrichment_key == key:
            return opened.enrichment_summary
        self._phase("enriching_program")
        from ghidra.program.model.symbol import SourceType
        program = opened.program
        base = int(program.getImageBase().getOffset())
        space = program.getAddressFactory().getDefaultAddressSpace()
        memory = program.getMemory()
        manager = program.getFunctionManager()
        symbols = program.getSymbolTable()
        stats = {
            "schema": "winbox.ghidra-enrichment-result/1",
            "pdb_build": str(payload.get("pdb_build") or "")[:64],
            "functions_named": 0, "signatures_applied": 0,
            "globals_named": 0, "reused": 0, "conflicts": 0,
            "invalid": 0, "truncated": bool(payload.get("truncated")),
        }
        events: list[dict] = []

        def event(item: dict, kind: str, action: str, **details) -> None:
            value = {
                "kind": kind, "rva": item["rva"],
                "name": str(item["name"])[:512],
                "source": str(item.get("source") or "exact-pdb")[:64],
                "action": action,
            }
            value.update(details)
            events.append(value)
        commit = False
        transaction = program.startTransaction("winbox exact PDB enrichment")
        try:
            for item in payload["functions"]:
                rva = item["rva"]
                address = space.getAddress(base + rva)
                if not memory.contains(address):
                    stats["invalid"] += 1
                    event(item, "function_name", "invalid", reason="outside-memory")
                    continue
                safe_name = self._safe_symbol_name(item["name"], rva)
                function = manager.getFunctionAt(address)
                if function is None:
                    if program.getListing().getInstructionAt(address) is None:
                        opened.api.disassemble(address)
                    try:
                        function = opened.api.createFunction(address, safe_name)
                    except Exception:
                        function = opened.api.createFunction(
                            address, f"{safe_name}__rva_{rva:x}",
                        )
                if function is None:
                    stats["conflicts"] += 1
                    event(item, "function_name", "conflict", reason="create-failed")
                    continue
                current_name = str(function.getName())
                source = function.getSymbol().getSource()
                if current_name == safe_name:
                    stats["reused"] += 1
                    event(item, "function_name", "reused")
                elif source in (SourceType.DEFAULT, SourceType.ANALYSIS):
                    try:
                        function.setName(safe_name, SourceType.IMPORTED)
                        applied_name = safe_name
                    except Exception:
                        applied_name = f"{safe_name}__rva_{rva:x}"
                        function.setName(applied_name, SourceType.IMPORTED)
                    stats["functions_named"] += 1
                    event(
                        item, "function_name", "applied",
                        applied_name=applied_name[:512],
                    )
                else:
                    stats["conflicts"] += 1
                    event(
                        item, "function_name", "conflict",
                        reason="preserved-existing", existing=current_name[:512],
                    )
                if isinstance(item.get("signature"), dict):
                    signature_item = dict(item)
                    signature_item["source"] = item.get(
                        "signature_source", item.get("source", "exact-pdb"),
                    )
                    try:
                        if self._apply_signature(program, function, item["signature"], safe_name):
                            stats["signatures_applied"] += 1
                            event(signature_item, "function_signature", "applied")
                        else:
                            stats["conflicts"] += 1
                            event(
                                signature_item, "function_signature", "conflict",
                                reason="preserved-existing",
                            )
                    except Exception:
                        stats["invalid"] += 1
                        event(
                            signature_item, "function_signature", "invalid",
                            reason="signature-application-failed",
                        )
            for item in payload["globals"]:
                rva = item["rva"]
                address = space.getAddress(base + rva)
                if not memory.contains(address):
                    stats["invalid"] += 1
                    event(item, "global_name", "invalid", reason="outside-memory")
                    continue
                safe_name = self._safe_symbol_name(item["name"], rva)
                primary = symbols.getPrimarySymbol(address)
                existing = next((
                    symbol for symbol in symbols.getSymbols(address)
                    if str(symbol.getName()) == safe_name
                ), None)
                if existing is not None and (
                    primary is None or primary.getSource() in (
                        SourceType.DEFAULT, SourceType.ANALYSIS,
                    )
                ):
                    existing.setPrimary()
                    stats["reused"] += 1
                    event(item, "global_name", "reused", applied_name=safe_name)
                elif primary is not None and str(primary.getName()) == safe_name:
                    stats["reused"] += 1
                    event(item, "global_name", "reused")
                elif primary is None or primary.getSource() in (
                    SourceType.DEFAULT, SourceType.ANALYSIS,
                ):
                    applied_name = safe_name
                    try:
                        created = symbols.createLabel(
                            address, applied_name, SourceType.IMPORTED,
                        )
                    except Exception:
                        applied_name = f"{safe_name}__rva_{rva:x}"
                        created = symbols.createLabel(
                            address, applied_name, SourceType.IMPORTED,
                        )
                    created.setPrimary()
                    stats["globals_named"] += 1
                    event(
                        item, "global_name", "applied",
                        applied_name=applied_name[:512],
                    )
                else:
                    stats["conflicts"] += 1
                    event(
                        item, "global_name", "conflict",
                        reason="preserved-existing",
                        existing=str(primary.getName())[:512],
                    )
            commit = True
        finally:
            program.endTransaction(transaction, commit)
        stats["event_count"] = len(events)
        stats["provenance_file"] = self._record_enrichment_result(
            digest, key, stats, events,
        )
        opened.decompile_cache.clear()
        opened.enrichment_key = key
        opened.enrichment_summary = stats
        return stats

    def _open(
        self, binary: Path, digest: str, *, request_id: str = "",
        analysis_timeout: int = 900, enrichment: str = "",
    ) -> tuple[OpenProgram, bool, dict | None]:
        self.start_ghidra()
        if not enrichment:
            candidate = self.cache / "enrichment" / f"{ANALYSIS_PROFILE}_{digest}.json"
            if candidate.is_file() and not candidate.is_symlink():
                enrichment = str(candidate)
        if digest in self.programs:
            self._phase("opening_cached_program")
            value = self.programs.pop(digest)
            self.programs[digest] = value
            self._apply_enrichment(value, digest, enrichment)
            return value, True, None

        binaries = self.cache / "binaries"
        binaries.mkdir(parents=True, exist_ok=True)
        self.projects.mkdir(parents=True, exist_ok=True)
        cached_binary = binaries / f"{digest}{binary.suffix.lower()}"
        if not cached_binary.exists() or _sha256(cached_binary) != digest:
            self._phase("staging_binary")
            temp = cached_binary.with_suffix(cached_binary.suffix + ".part")
            shutil.copyfile(binary, temp)
            if _sha256(temp) != digest:
                with contextlib.suppress(OSError):
                    temp.unlink()
                raise WorkerError(
                    "binary changed while copying into analysis cache",
                    code="identity_mismatch",
                )
            os.replace(temp, cached_binary)

        # Full digest, not a display-length prefix: binaries are attacker-
        # controlled and a project collision would silently reuse analysis of
        # the wrong content even though the immutable copy itself was exact.
        project_name = _project_name(self.ghidra_version, digest)
        program_name = f"binary_{digest}{cached_binary.suffix}"
        project_paths = self._project_paths(project_name)
        if any(path.is_symlink() for path in project_paths):
            raise WorkerError(
                "refusing symlink in exact project cache",
                code="cache_reset_failed", retryable=False,
                details={"project": project_name},
            )
        # A forced worker/container termination can leave the repository or a
        # lock behind after the small .gpr metadata file disappeared.  Treat
        # any exact-project residue as an existing cache so a proven corrupt
        # open takes the same bounded reset-and-rebuild path.
        project_exists = any(path.exists() for path in project_paths)
        self._phase("opening_project" if project_exists else "importing_program")
        recovery = None
        try:
            opened = self._enter_project(cached_binary, project_name, program_name)
        except Exception as original:
            if not project_exists:
                raise WorkerError(
                    f"Ghidra import/analysis failed: {original}",
                    code="analysis_failed", retryable=False,
                    details={"project": project_name},
                ) from original
            if not _looks_like_project_corruption(original):
                raise WorkerError(
                    f"existing Ghidra project could not be opened: {original}",
                    code="project_open_failed", retryable=True,
                    details={"project": project_name},
                ) from original
            try:
                recovery = self._reset_project(
                    project_name, reason=f"{type(original).__name__}: {original}",
                )
            except WorkerError:
                raise
            self._phase("importing_program")
            try:
                opened = self._enter_project(cached_binary, project_name, program_name)
            except Exception as rebuild_error:
                raise WorkerError(
                    f"clean rebuild after exact corrupt-project reset failed: {rebuild_error}",
                    code="cache_rebuild_failed", retryable=False,
                    details={
                        "project": project_name,
                        "original_failure": str(original)[:512],
                        "rebuild_failure": str(rebuild_error)[:512],
                    },
                ) from rebuild_error
            recovery["rebuild"] = "succeeded"
        try:
            analyzed = self._analyze_opened(
                opened, request_id=request_id, timeout=analysis_timeout,
            )
            self._apply_enrichment(opened, digest, enrichment)
        except Exception:
            opened.close()
            raise
        self.programs[digest] = opened
        while len(self.programs) > self.max_open_programs:
            _, evicted = self.programs.popitem(last=False)
            evicted.close()
        return opened, project_exists and recovery is None and not analyzed, recovery

    def repair(self, args: dict) -> dict:
        digest = str(args.get("sha256") or "").lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise WorkerError(
                "sha256 must be 64 lowercase hexadecimal characters",
                code="invalid_argument",
            )
        self.start_ghidra()
        binaries = self.cache / "binaries"
        binary = next((
            path for path in [binaries / digest, *binaries.glob(f"{digest}.*")]
            if path.is_file() and not path.is_symlink()
            and not path.name.endswith((".part", ".lock"))
        ), None)
        if binary is None or _sha256(binary) != digest:
            raise WorkerError(
                "exact cached binary is missing or fails its digest",
                code="cache_entry_missing", details={"sha256": digest},
            )
        opened = self.programs.pop(digest, None)
        if opened is not None:
            opened.close()
        project_name = _project_name(self.ghidra_version, digest)
        self._phase("opening_project", binary_sha256=digest)
        recovery = self._reset_project(
            project_name, reason="explicit exact repair",
        )
        self._phase("importing_program", binary_sha256=digest)
        try:
            rebuilt, _, _ = self._open(binary, digest)
        except Exception as exc:
            raise WorkerError(
                f"explicit clean rebuild failed: {exc}",
                code="cache_rebuild_failed", retryable=False,
                details={
                    "project": project_name,
                    "rebuild_failure": str(exc)[:512],
                },
            ) from exc
        recovery.update({
            "schema": "winbox.decomp-cache-repair/1",
            "sha256": digest,
            "binary_retained": True,
            "rebuild": "succeeded",
            "project_open": rebuilt is not None,
        })
        return recovery

    def close(self) -> None:
        for opened in self.programs.values():
            opened.close()
        self.programs.clear()


def _walk_tokens(node):
    try:
        count = int(node.numChildren())
    except Exception:
        count = 0
    if count:
        for index in range(count):
            yield from _walk_tokens(node.Child(index))
    else:
        yield node


def _recover_function(api, program, address, rva: int, hint):
    """Create one missed function only from a close, verified PDB public RVA."""
    if not isinstance(hint, dict) or hint.get("is_function") is not True:
        return None, "none"
    try:
        hint_rva = int(hint["rva"])
        offset = int(hint["offset"])
    except (KeyError, TypeError, ValueError):
        return None, "none"
    if hint_rva < 0 or hint_rva > rva or offset > 64 * 1024:
        return None, "none"
    image_base = int(program.getImageBase().getOffset())
    hint_address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
        image_base + hint_rva
    )
    memory = program.getMemory()
    if not memory.contains(hint_address):
        return None, "none"
    block = memory.getBlock(hint_address)
    if block is None or not block.isExecute():
        return None, "none"
    manager = program.getFunctionManager()
    existing = manager.getFunctionContaining(hint_address)
    if existing is not None and existing.getBody().contains(address):
        return existing, "pdb-public-existing"

    # A public name is untrusted input from a PDB. Keep the useful readable
    # portion but force it into a legal, bounded Ghidra symbol.
    raw_name = str(hint.get("name") or f"winbox_{hint_rva:x}")[:200]
    safe_name = re.sub(r"[^A-Za-z0-9_?$@]", "_", raw_name)
    if not safe_name or safe_name[0].isdigit():
        safe_name = f"winbox_{hint_rva:x}_{safe_name}"
    success = False
    transaction = program.startTransaction("winbox PDB function recovery")
    try:
        if program.getListing().getInstructionAt(hint_address) is None:
            api.disassemble(hint_address)
        function = manager.getFunctionAt(hint_address)
        if function is None:
            function = api.createFunction(hint_address, safe_name)
        success = function is not None
    finally:
        program.endTransaction(transaction, success)
    if function is not None and function.getBody().contains(address):
        return function, "pdb-public-recovery"

    # Ghidra occasionally created a tiny/truncated function at the public
    # entry, leaving later instructions unowned. Recover at the exact queried
    # instruction only after the close PDB hint established which routine this
    # gap belongs to. Label it as a split so consumers never mistake the
    # synthetic entry for the real PDB entry.
    instruction = program.getListing().getInstructionContaining(address)
    if instruction is None:
        success = False
        transaction = program.startTransaction("winbox instruction disassembly")
        try:
            success = bool(api.disassemble(address))
        finally:
            program.endTransaction(transaction, success)
        instruction = program.getListing().getInstructionContaining(address)
    if instruction is None:
        return None, "none"
    split_address = instruction.getAddress()
    split_name = f"{safe_name}__winbox_at_{rva:x}"
    success = False
    transaction = program.startTransaction("winbox instruction function recovery")
    try:
        function = manager.getFunctionContaining(split_address)
        if function is None:
            function = api.createFunction(split_address, split_name)
        success = function is not None
    finally:
        program.endTransaction(transaction, success)
    if function is not None and function.getBody().contains(address):
        return function, "pdb-public-split-recovery"
    return None, "none"


def _map_source(
    markup,
    address,
    code: str,
    before: int,
    after: int,
    *,
    line_start: int | None = None,
    line_end: int | None = None,
) -> dict:
    target = int(address.getOffset())
    addressed: list[tuple[int, int, int]] = []
    for token in _walk_tokens(markup):
        try:
            minimum = token.getMinAddress()
            maximum = token.getMaxAddress()
            parent = token.getLineParent()
            if minimum is None or maximum is None or parent is None:
                continue
            lo = int(minimum.getOffset())
            hi = int(maximum.getOffset())
            line = int(parent.getLineNumber())
        except Exception:
            continue
        addressed.append((lo, hi, line))

    by_line: dict[int, set[tuple[int, int]]] = {}
    for lo, hi, line in addressed:
        by_line.setdefault(line, set()).add((lo, hi))

    exact_lines = sorted(
        line
        for line, ranges in by_line.items()
        if any(lo <= target <= hi for lo, hi in ranges)
    )
    candidate_lines: list[int]
    direction: str | None
    distance: int | None
    if exact_lines:
        selected = exact_lines[0]
        candidate_lines = exact_lines
        direction = "overlap"
        distance = 0
        if len(exact_lines) > 1:
            kind = "ambiguous"
        elif any(
            lo == target == hi for lo, hi in by_line.get(selected, set())
        ):
            kind = "exact"
        else:
            kind = "range"
        confidence = "exact"
    elif addressed:
        def gap(item: tuple[int, int, int]) -> int:
            lo, hi, _ = item
            if target < lo:
                return lo - target
            if target > hi:
                return target - hi
            return 0

        distance = min(gap(item) for item in addressed)
        nearest = [item for item in addressed if gap(item) == distance]
        candidate_lines = sorted({line for _, _, line in nearest})
        selected = candidate_lines[0]
        directions = {
            "forward" if target < lo else "backward" if target > hi else "overlap"
            for lo, hi, _ in nearest
        }
        direction = next(iter(directions)) if len(directions) == 1 else "mixed"
        kind = (
            "ambiguous"
            if len(candidate_lines) > 1
            else f"nearest-{direction}"
        )
        confidence = "nearest"
    else:
        selected = 1
        candidate_lines = []
        direction = None
        distance = None
        kind = "unmapped"
        confidence = "function-only"

    lines = code.splitlines()
    selected = max(1, min(selected, max(1, len(lines))))
    if line_start is not None and line_end is not None:
        if line_start > len(lines):
            raise WorkerError(
                f"requested pseudocode line {line_start} exceeds function length "
                f"({len(lines)} lines)"
            )
        start = line_start
        end = min(line_end, len(lines))
        selection = {
            "mode": "lines",
            "requested": {"start": line_start, "end": line_end},
            "start": start,
            "end": end,
            "truncated": end != line_end,
        }
    else:
        start = max(1, selected - before)
        end = min(len(lines), selected + after)
        selection = {
            "mode": "context",
            "start": start,
            "end": end,
            "truncated": False,
        }
    selection.update({
        "total_lines": len(lines),
        "has_more": end < len(lines),
        "next_start": end + 1 if end < len(lines) else None,
    })
    excerpt = []
    for number in range(start, end + 1):
        item = {"line": number, "text": lines[number - 1]}
        ranges = sorted(by_line.get(number, set()))
        if ranges:
            item["address_ranges"] = [
                {"start": f"0x{lo:x}", "end": f"0x{hi:x}"}
                for lo, hi in ranges
            ]
        if kind != "unmapped" and number in candidate_lines:
            item["relation"] = kind
        excerpt.append(item)

    selected_ranges = sorted(by_line.get(selected, set()))
    return {
        "confidence": confidence,
        "kind": kind,
        "line": None if kind == "unmapped" else selected,
        "candidate_lines": candidate_lines,
        "distance_bytes": distance,
        "direction": direction,
        "selection": selection,
        # Retain the old flat field in diagnostic output for clients that only
        # understand confidence/line/addresses. New clients should use the
        # explicit ranges and mapping kind above.
        "addresses": sorted(
            {f"0x{x:x}" for lo, hi in selected_ranges for x in (lo, hi)}
        ),
        "excerpt": excerpt,
    }


def _requested_lines(args: dict) -> tuple[int | None, int | None]:
    start_raw = args.get("line_start")
    end_raw = args.get("line_end")
    if start_raw is None and end_raw is None:
        return None, None
    if start_raw is None or end_raw is None:
        raise WorkerError("line_start and line_end must be supplied together")
    try:
        start = int(start_raw)
        end = int(end_raw)
    except (TypeError, ValueError) as exc:
        raise WorkerError("line_start and line_end must be integers") from exc
    if start < 1 or end < start:
        raise WorkerError("line range must be positive and ascending")
    if end - start + 1 > MAX_LINE_BATCH:
        raise WorkerError(f"line range may contain at most {MAX_LINE_BATCH} lines")
    return start, end


def _bounded_code_payload(code: str, *, full: bool) -> tuple[str, dict]:
    """Bound only the optional full-code payload, never mapping input."""
    encoded = code.encode("utf-8")
    returned = code
    truncated = len(encoded) > MAX_CODE
    if truncated:
        returned = encoded[:MAX_CODE].decode("utf-8", errors="ignore")
    return returned, {
        "code_truncated": truncated,
        "code_bytes": len(encoded),
        "code_lines": len(code.splitlines()),
        "returned_code_bytes": len(returned.encode("utf-8")) if full else 0,
        "returned_code_lines": len(returned.splitlines()) if full else 0,
    }


def _attach_mapped_assembly(program, function, mapping: dict) -> bool:
    """Attach bounded instruction lists to every address-bearing source line."""
    listing = program.getListing()
    instructions = []
    for instruction in listing.getInstructions(function.getBody(), True):
        start = int(instruction.getAddress().getOffset())
        end = start + int(instruction.getLength()) - 1
        instructions.append((start, end, instruction))

    associations = 0
    truncated = False
    first_truncated_line = None
    last_truncated_line = None
    for source_line in mapping.get("excerpt") or []:
        ranges = []
        for address_range in source_line.get("address_ranges") or []:
            try:
                ranges.append((
                    int(str(address_range["start"]), 0),
                    int(str(address_range["end"]), 0),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        if not ranges:
            continue
        mapped = []
        complete = True
        seen: set[int] = set()
        for start, end, instruction in instructions:
            if not any(start <= high and end >= low for low, high in ranges):
                continue
            if start in seen:
                continue
            if associations >= MAX_MAPPED_INSTRUCTION_ASSOCIATIONS:
                truncated = True
                complete = False
                if first_truncated_line is None:
                    first_truncated_line = source_line.get("line")
                last_truncated_line = source_line.get("line")
                break
            seen.add(start)
            mapped.append(_instruction_payload(instruction))
            associations += 1
        if mapped:
            source_line["assembly"] = mapped
        source_line["assembly_complete"] = complete
    if truncated:
        mapping["assembly_truncation"] = {
            "first_line": first_truncated_line,
            "last_line": last_truncated_line,
            "association_limit": MAX_MAPPED_INSTRUCTION_ASSOCIATIONS,
        }
    return truncated


def _nearby_instructions(program, function, address) -> tuple[list[dict], dict]:
    listing = program.getListing()
    target = int(address.getOffset())
    before = collections.deque(maxlen=2)
    after: list = []
    current = None
    for instruction in listing.getInstructions(function.getBody(), True):
        start = int(instruction.getAddress().getOffset())
        end = start + int(instruction.getLength()) - 1
        if start <= target <= end:
            current = instruction
            continue
        if end < target:
            before.append(instruction)
        elif start > target and len(after) < 2:
            after.append(instruction)
        elif start > target and len(after) >= 2:
            break
    selected = list(before) + ([current] if current is not None else []) + after
    output = []
    for instruction in selected:
        item = _instruction_payload(instruction)
        item["current"] = instruction is current
        output.append(item)
    location = {
        "requested_address": f"0x{target:x}",
        "decoded": current is not None,
        "kind": "instruction" if current is not None else "undecoded-gap",
        "previous_address": (
            f"0x{int(before[-1].getAddress().getOffset()):x}" if before else None
        ),
        "next_address": (
            f"0x{int(after[0].getAddress().getOffset()):x}" if after else None
        ),
    }
    return output, location


def _instruction_payload(instruction) -> dict:
    raw = bytes((int(value) & 0xFF) for value in instruction.getBytes())
    address = int(instruction.getAddress().getOffset())
    payload = {
        "address": f"0x{address:x}",
        "bytes": raw.hex(),
        "text": str(instruction),
    }
    try:
        flows = sorted({int(flow.getOffset()) for flow in instruction.getFlows()})
    except Exception:
        flows = []
    if flows:
        payload["flow_targets"] = [f"0x{target:x}" for target in flows]
    return payload


def _count_projects(path: Path) -> int:
    try:
        return sum(1 for _ in path.glob("*.gpr"))
    except OSError:
        return 0


def _project_name(version: object, digest: str) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in str(version))
    profile = "".join(c if c.isalnum() else "_" for c in ANALYSIS_PROFILE)
    return f"p_{safe}_{profile}_{digest}"


def _verified_function_name(hint, function_rva: int) -> str | None:
    if not isinstance(hint, dict) or hint.get("is_function") is not True:
        return None
    try:
        if int(hint.get("rva")) != function_rva:
            return None
    except (TypeError, ValueError):
        return None
    value = str(hint.get("name") or "").strip()
    return value[:512] or None


def _read_request(conn: socket.socket) -> dict:
    data = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            raise WorkerError("connection closed before request newline")
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            data = data[:newline]
            break
        if len(data) > MAX_REQUEST:
            raise WorkerError(f"request exceeds {MAX_REQUEST} bytes")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError(f"invalid request JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("op"), str):
        raise WorkerError("request must contain a string op")
    args = value.get("args") or {}
    if not isinstance(args, dict):
        raise WorkerError("request args must be an object")
    request_id = value.get("request_id")
    if (
        not isinstance(request_id, str) or not 1 <= len(request_id) <= 64
        or any(c not in "0123456789abcdef" for c in request_id)
    ):
        raise WorkerError("request_id must be 1-64 lowercase hexadecimal characters")
    return {"op": value["op"], "args": args, "request_id": request_id}


def _write_session(path: Path, value: dict) -> None:
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _serve(args) -> int:
    os.umask(0o077)
    # Containers deliberately use a tmpfs HOME with a read-only root. Ghidra's
    # LaunchSupport persists JDK/user settings there on first JVM startup.
    Path.home().mkdir(parents=True, exist_ok=True, mode=0o700)
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    args.projects.mkdir(parents=True, exist_ok=True)
    os.chmod(args.socket.parent, 0o700)
    os.chmod(args.projects, 0o700)
    lock_fd = os.open(args.lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock_fd)
        return 0
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    worker = Worker(
        args.cache, args.projects, args.ghidra_install_dir,
        max_open_programs=args.max_open_programs,
    )
    try:
        with contextlib.suppress(FileNotFoundError):
            args.socket.unlink()
        listener.bind(str(args.socket))
        os.chmod(args.socket, 0o600)
        listener.listen(16)
        listener.settimeout(0.5)
        session_state = {
            "schema": "winbox.decomp-worker-session/2",
            "pid": os.getpid(),
            "backend": args.backend,
            "worker_api": WORKER_API,
            "analysis_profile": ANALYSIS_PROFILE,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "socket": str(args.socket),
            "heartbeat_at": time.time(),
            "current_operation": None,
            "last_failure": None,
        }
        session_lock = threading.Lock()

        def publish_session() -> None:
            session_state["worker_state"] = {
                "jvm_started": worker.started,
                "ghidra_version": worker.ghidra_version,
                "open_programs": len(worker.programs),
                "max_open_programs": worker.max_open_programs,
            }
            _write_session(args.session, session_state)

        def report_phase(phase: str, details: dict) -> None:
            now = time.time()
            with session_lock:
                current = session_state.get("current_operation")
                if not isinstance(current, dict):
                    return
                current.update({
                    "phase": phase,
                    "phase_started_at": now,
                    "last_progress_at": now,
                    "progress": {
                        "completed": _PHASE_PROGRESS.get(phase, 0),
                        "total": _TOTAL_PHASES,
                        "unit": "phases",
                        "determinate": False,
                    },
                })
                for key in ("binary_name", "binary_sha256"):
                    value = details.get(key)
                    if isinstance(value, str) and value:
                        current[key] = value[:260 if key == "binary_name" else 64]
                session_state["heartbeat_at"] = now
                publish_session()

        worker.progress_callback = report_phase
        with session_lock:
            publish_session()

        heartbeat_stop = threading.Event()

        def heartbeat_loop() -> None:
            while not heartbeat_stop.wait(HEARTBEAT_INTERVAL):
                with session_lock:
                    now = time.time()
                    session_state["heartbeat_at"] = now
                    current = session_state.get("current_operation")
                    if isinstance(current, dict):
                        request_id = str(current.get("request_id") or "")
                        marker = args.cache / "cancel" / request_id
                        if request_id and marker.exists():
                            current["cancellation_state"] = "requested"
                    with contextlib.suppress(OSError):
                        publish_session()

        heartbeat_thread = threading.Thread(
            target=heartbeat_loop, name="winbox-decomp-heartbeat", daemon=True,
        )
        heartbeat_thread.start()

        def stop(_signum, _frame):
            worker.shutdown = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        while not worker.shutdown:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if worker.shutdown:
                    break
                raise
            with conn:
                request = None
                try:
                    conn.settimeout(REQUEST_READ_TIMEOUT)
                    request = _read_request(conn)
                    request["args"]["_request_id"] = request["request_id"]
                    now = time.time()
                    with session_lock:
                        session_state["current_operation"] = {
                            "request_id": request["request_id"], "op": request["op"],
                            "phase": "accepted", "started_at": now,
                            "phase_started_at": now, "last_progress_at": now,
                            "cancellation_state": "not_requested",
                            "binary_sha256": str(
                                request["args"].get("sha256") or ""
                            )[:64],
                            "binary_name": str(
                                _safe_binary_name(request["args"].get("binary_name"))
                            ),
                            "progress": {
                                "completed": 0, "total": _TOTAL_PHASES,
                                "unit": "phases", "determinate": False,
                            },
                        }
                        session_state["last_failure"] = None
                        session_state["heartbeat_at"] = now
                        publish_session()
                    result = worker.handle(request["op"], request["args"])
                    reply = {
                        "ok": True, "result": result,
                        "request_id": request["request_id"],
                    }
                except Exception as exc:
                    traceback.print_exc(file=sys.stderr)
                    info = _error_info(exc)
                    legacy_error = f"{type(exc).__name__}: {exc}"[:2048]
                    reply = {
                        "ok": False, "error": legacy_error,
                        "error_info": info,
                        "request_id": request.get("request_id") if request else None,
                    }
                    with session_lock:
                        status_info = dict(info)
                        raw_binary = str(
                            (request or {}).get("args", {}).get("binary") or ""
                        )
                        if raw_binary:
                            message = str(status_info.get("message") or "")
                            candidates = {raw_binary}
                            with contextlib.suppress(OSError):
                                candidates.add(str(Path(raw_binary).expanduser().resolve()))
                            for candidate in candidates:
                                message = message.replace(candidate, "<binary>")
                            status_info["message"] = message
                        session_state["last_failure"] = status_info
                finally:
                    with session_lock:
                        session_state["current_operation"] = None
                        session_state["heartbeat_at"] = time.time()
                        with contextlib.suppress(OSError):
                            publish_session()
                encoded = json.dumps(reply, separators=(",", ":")).encode("utf-8") + b"\n"
                with contextlib.suppress(OSError):
                    conn.sendall(encoded)
    finally:
        if "heartbeat_stop" in locals():
            heartbeat_stop.set()
        if "heartbeat_thread" in locals():
            heartbeat_thread.join(timeout=2.0)
        worker.close()
        listener.close()
        with contextlib.suppress(FileNotFoundError):
            args.socket.unlink()
        with contextlib.suppress(FileNotFoundError):
            args.session.unlink()
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--projects", type=Path, required=True)
    parser.add_argument("--ghidra-install-dir")
    parser.add_argument("--backend", choices=("docker", "host"), default="host")
    parser.add_argument("--max-open-programs", type=int, default=1)
    return _serve(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
