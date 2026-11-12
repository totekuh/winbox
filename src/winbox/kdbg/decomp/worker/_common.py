"""Shared constants, exceptions, and stateless utilities for the worker."""

from __future__ import annotations

import hashlib
import json
import os
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
