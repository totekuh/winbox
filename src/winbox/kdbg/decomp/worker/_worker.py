"""Core Worker class for Ghidra decompilation operations."""

from __future__ import annotations

import collections
import contextlib
import json
import os
import re
import shutil
import sys
import threading
import time
from pathlib import Path

from winbox.kdbg.decomp.worker._common import (
    ANALYSIS_PROFILE,
    DEFAULT_MAX_OPEN_PROGRAMS,
    MAX_CONTEXT_LINES,
    WORKER_API,
    WorkerError,
    _count_projects,
    _looks_like_project_corruption,
    _project_name,
    _safe_binary_name,
    _sha256,
    _verified_function_name,
)
from winbox.kdbg.decomp.worker._enrichment import _EnrichmentMixin
from winbox.kdbg.decomp.worker._mapping import (
    _attach_mapped_assembly,
    _bounded_code_payload,
    _map_source,
    _nearby_instructions,
    _requested_lines,
)
from winbox.kdbg.decomp.worker._recovery import _recover_function


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


class Worker(_EnrichmentMixin):
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

        project_name = _project_name(self.ghidra_version, digest)
        program_name = f"binary_{digest}{cached_binary.suffix}"
        project_paths = self._project_paths(project_name)
        if any(path.is_symlink() for path in project_paths):
            raise WorkerError(
                "refusing symlink in exact project cache",
                code="cache_reset_failed", retryable=False,
                details={"project": project_name},
            )
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
