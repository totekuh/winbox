"""Bounded exact-PDB enrichment records for the isolated Ghidra worker."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from winbox.kdbg.decomp.client import DecompError, cache_dir
from winbox.kdbg.pdb import load_section_headers
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.symbols import SymbolLoadError, cached_pdb_path, _sha256


ENRICHMENT_SCHEMA = "winbox.pdb-enrichment/1"
ENRICHMENT_REVISION = 2
ANALYSIS_PROFILE = "winbox-pdb-enrichment-v3"
MAX_FUNCTIONS = 8192
MAX_GLOBALS = 8192
MAX_SYMBOL_OUTPUT = 64 * 1024 * 1024
MAX_NAME = 512
MAX_PARAMETERS = 32

_RECORD_RE = re.compile(
    r"S_(?P<scope>[GL])(?P<kind>PROC32|DATA32) \[size = \d+\] `(?P<name>[^`]+)`"
)
_ADDR_RE = re.compile(r"addr\s*=\s*(\d+):(\d+)")
_PROC_TYPE_RE = re.compile(r"type\s*=\s*`0x[0-9A-Fa-f]+ \((.*)\)`")
_TYPE_TOKEN_RE = re.compile(
    r"^(?P<const>const )?"
    r"(?P<base>void|bool|char|signed char|unsigned char|short|unsigned short|"
    r"int|unsigned int|long|unsigned long|__int64|unsigned __int64|float|double|"
    r"wchar_t)(?P<pointers>\*{0,2})$"
)


def _terminate_and_reap(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        process.wait()
        return
    process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _bounded_command(
    command: list[str], *, timeout: float, max_stdout: int,
    max_stderr: int = 2048,
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[bytes, bytes, int]:
    """Run one exact child without ever buffering beyond declared caps."""
    if timeout <= 0 or max_stdout < 0 or max_stderr < 0:
        raise ValueError("invalid bounded-command limits")
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True,
        )
    except FileNotFoundError:
        raise
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()

    def drain(stream, target: bytearray, cap: int, *, enforce: bool) -> None:
        total = 0
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                total += len(chunk)
                remaining = max(0, cap + (1 if enforce else 0) - len(target))
                if remaining:
                    target.extend(chunk[:remaining])
                if enforce and total > cap:
                    overflow.set()
        finally:
            stream.close()

    stdout_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout, max_stdout),
        kwargs={"enforce": True}, daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr, max_stderr),
        kwargs={"enforce": False}, daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    cancelled = False
    try:
        while process.poll() is None:
            if cancel_requested is not None and cancel_requested():
                cancelled = True
                _terminate_and_reap(process)
                break
            if overflow.is_set():
                _terminate_and_reap(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_and_reap(process)
                break
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
    except BaseException:
        _terminate_and_reap(process)
        raise
    finally:
        stdout_thread.join(timeout=2.0)
        stderr_thread.join(timeout=2.0)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _terminate_and_reap(process)
            raise DecompError(
                "PDB extraction pipe did not close after child exit",
                code="pdb_enrichment_failed", retryable=True,
            )
    if cancelled:
        raise DecompError(
            "PDB enrichment was cancelled", code="cancelled", retryable=True,
        )
    if timed_out:
        raise DecompError(
            f"PDB enrichment timed out after {timeout:g}s",
            code="analysis_timeout", retryable=True,
        )
    if overflow.is_set() or len(stdout) > max_stdout:
        raise DecompError(
            f"PDB symbol output exceeds {max_stdout} bytes",
            code="pdb_enrichment_too_large",
        )
    return bytes(stdout), bytes(stderr), int(process.returncode)


def _bounded_symbol_dump(
    pdb_path: Path, *, timeout: int = 300,
    cancel_requested: Callable[[], bool] | None = None,
) -> str:
    try:
        stdout, stderr, returncode = _bounded_command(
            ["llvm-pdbutil", "dump", "--symbols", str(pdb_path)],
            timeout=timeout, max_stdout=MAX_SYMBOL_OUTPUT,
            cancel_requested=cancel_requested,
        )
    except FileNotFoundError as exc:
        raise DecompError(
            "llvm-pdbutil not found — install the llvm package",
            code="prerequisite_missing",
        ) from exc
    if returncode != 0:
        detail = stderr.decode("latin-1", errors="replace")[:2048].strip()
        raise DecompError(
            f"llvm-pdbutil symbol extraction failed: {detail}",
            code="pdb_enrichment_failed",
        )
    return stdout.decode("latin-1", errors="replace")


def _simple_type(value: str) -> dict[str, Any] | None:
    normalized = " ".join(value.strip().split()).replace(" *", "*")
    match = _TYPE_TOKEN_RE.fullmatch(normalized)
    if match is None:
        return None
    return {
        "base": match.group("base"),
        "const": bool(match.group("const")),
        "pointers": len(match.group("pointers")),
    }


def parse_rendered_signature(value: str) -> dict[str, Any] | None:
    """Accept only finite primitive/pointer signatures rendered by LLVM."""
    if not value or "..." in value or len(value) > 1024:
        return None
    split = value.find(" (")
    if split <= 0 or not value.endswith(")"):
        return None
    returned = _simple_type(value[:split])
    if returned is None:
        return None
    raw_parameters = value[split + 2:-1].strip()
    if not raw_parameters or raw_parameters == "void":
        parameters: list[dict[str, Any]] = []
    else:
        pieces = [piece.strip() for piece in raw_parameters.split(",")]
        if len(pieces) > MAX_PARAMETERS:
            return None
        parameters = []
        for piece in pieces:
            parsed = _simple_type(piece)
            if parsed is None:
                return None
            parameters.append(parsed)
    return {"return": returned, "parameters": parameters, "calling_convention": "cdecl"}


def parse_symbol_enrichment(
    text: str, sections: dict[int, int],
) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    """Return typed procedures and named data keyed by exact RVA."""
    procedures: dict[int, dict[str, Any]] = {}
    data: dict[int, dict[str, Any]] = {}
    pending: dict[str, Any] | None = None
    for line in text.splitlines():
        record = _RECORD_RE.search(line)
        if record:
            pending = {
                "scope": record.group("scope"),
                "kind": record.group("kind"),
                "name": record.group("name")[:MAX_NAME],
                "rva": None,
            }
            continue
        if pending is None:
            continue
        address = _ADDR_RE.search(line)
        if address:
            section = sections.get(int(address.group(1)))
            if section is None:
                pending = None
                continue
            pending["rva"] = section + int(address.group(2))
            if pending["kind"] == "DATA32":
                data.setdefault(int(pending["rva"]), {
                    "name": pending["name"], "scope": pending["scope"],
                })
                pending = None
                continue
        if pending is not None and pending["kind"] == "PROC32":
            type_match = _PROC_TYPE_RE.search(line)
            if type_match and pending.get("rva") is not None:
                signature = parse_rendered_signature(type_match.group(1))
                item = {
                    "name": pending["name"], "scope": pending["scope"],
                }
                if signature is not None:
                    item["signature"] = signature
                procedures.setdefault(int(pending["rva"]), item)
                pending = None
            elif "type = `<no type>`" in line:
                if pending.get("rva") is not None:
                    procedures.setdefault(int(pending["rva"]), {
                        "name": pending["name"], "scope": pending["scope"],
                    })
                pending = None
    return procedures, data


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def enrichment_path(cfg, digest: str) -> Path:
    return cache_dir(cfg) / "enrichment" / f"{ANALYSIS_PROFILE}_{digest}.json"


def build_enrichment(
    cfg, store: SymbolStore, module: str, *, force: bool = False,
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Build one exact, bounded sidecar without starting Ghidra."""
    try:
        record = store.load(module)
    except (SymbolStoreError, OSError, ValueError) as exc:
        raise DecompError(
            f"symbol module is not loaded: {module}", code="cache_entry_missing",
        ) from exc
    digest = str(record.get("pe_sha256") or "").lower()
    pe_value = str(record.get("pe_path") or "")
    build = str(record.get("build") or "")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise DecompError(f"{module} has no exact PE digest", code="identity_mismatch")
    try:
        pe_path = Path(pe_value).resolve(strict=True)
    except OSError as exc:
        raise DecompError(f"{module} exact PE is missing", code="cache_entry_missing") from exc
    if not pe_path.is_file() or _sha256(pe_path) != digest:
        raise DecompError(f"{module} exact PE fails its digest", code="identity_mismatch")
    target = enrichment_path(cfg, digest)
    if target.is_file() and not target.is_symlink() and not force:
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
            if (
                existing.get("schema") == ENRICHMENT_SCHEMA
                and existing.get("revision") == ENRICHMENT_REVISION
                and existing.get("analysis_profile") == ANALYSIS_PROFILE
                and existing.get("binary_sha256") == digest
                and existing.get("pdb_build") == build
            ):
                return target, existing
        except (OSError, ValueError, TypeError):
            pass
    try:
        pdb_path = cached_pdb_path(cfg, store, module)
        sections = load_section_headers(pdb_path)
    except (SymbolLoadError, OSError, ValueError) as exc:
        raise DecompError(str(exc), code="prerequisite_missing") from exc
    typed, private_data = parse_symbol_enrichment(
        _bounded_symbol_dump(pdb_path, cancel_requested=cancel_requested), sections,
    )
    symbols = record.get("symbols") if isinstance(record.get("symbols"), dict) else {}
    function_names = set(record.get("function_symbols") or [])
    functions: list[dict[str, Any]] = []
    globals_: list[dict[str, Any]] = []
    function_total = global_total = 0
    for name, raw_rva in sorted(symbols.items(), key=lambda item: (int(item[1]), item[0])):
        try:
            rva = int(raw_rva)
        except (TypeError, ValueError):
            continue
        if not 0 <= rva < (1 << 32) or not isinstance(name, str) or not name:
            continue
        if name in function_names:
            function_total += 1
            if len(functions) < MAX_FUNCTIONS:
                item: dict[str, Any] = {"rva": rva, "name": name[:MAX_NAME]}
                item["source"] = "exact-pdb-public"
                typed_item = typed.get(rva)
                if typed_item and typed_item.get("signature"):
                    item["signature"] = typed_item["signature"]
                    item["signature_source"] = "exact-pdb-private"
                functions.append(item)
        else:
            global_total += 1
            if len(globals_) < MAX_GLOBALS:
                globals_.append({
                    "rva": rva, "name": name[:MAX_NAME],
                    "source": "exact-pdb-public",
                })
    # Private procedures remain exact named evidence even if their type is too
    # complex for the deliberately small safe-signature grammar.
    function_rvas = {item["rva"] for item in functions}
    for rva, typed_item in sorted(typed.items()):
        if rva in function_rvas:
            continue
        function_total += 1
        function_rvas.add(rva)
        if len(functions) >= MAX_FUNCTIONS:
            continue
        item = {
            "rva": rva, "name": typed_item["name"][:MAX_NAME],
            "source": "exact-pdb-private",
        }
        if typed_item.get("signature"):
            item["signature"] = typed_item["signature"]
            item["signature_source"] = "exact-pdb-private"
        functions.append(item)
    # Private PDB data that is not public still has an exact typed address.
    global_rvas = {item["rva"] for item in globals_}
    for rva, item in sorted(private_data.items()):
        if rva not in global_rvas:
            global_rvas.add(rva)
            global_total += 1
            if len(globals_) < MAX_GLOBALS:
                globals_.append({
                    "rva": rva, "name": item["name"],
                    "source": "exact-pdb-private",
                })
    value = {
        "schema": ENRICHMENT_SCHEMA,
        "revision": ENRICHMENT_REVISION,
        "analysis_profile": ANALYSIS_PROFILE,
        "binary_sha256": digest,
        "pdb_build": build,
        "module": module[:260],
        "functions": functions,
        "globals": globals_,
        "counts": {
            "functions": function_total, "globals": global_total,
            "typed_signatures": sum("signature" in item for item in functions),
        },
        "truncated": function_total > len(functions) or global_total > len(globals_),
    }
    _atomic_json(target, value)
    return target, value
