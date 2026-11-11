"""Binary resolution, cursor encoding, validation, and symbol hints."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError, cache_dir
from winbox.kdbg.decomp.identity import (
    IdentityError,
    parse_static_pe,
    validate_identity,
)
from winbox.kdbg.store import SymbolStore

MAX_CONTEXT_LINES = 20
MAX_LIVE_READ = 64 * 1024
MAX_LINE_BATCH = 100
DETAIL_LEVELS = {"compact", "standard", "diagnostic"}
ASSEMBLY_MODES = {"nearby", "mapped"}


def _hex_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str) -> dict[str, Any]:
    raw = str(value).strip()
    if not raw or len(raw) > 4096:
        raise DecompError("invalid or oversized continuation cursor")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.b64decode(
            padded, altchars=b"-_", validate=True
        ).decode("utf-8"))
        required = {
            "module", "function_rva", "next_start", "page_size",
            "session_id", "stop_id", "binary_sha256", "ghidra_version",
            "analysis_profile",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise ValueError("unexpected cursor fields")
        if (
            not isinstance(payload["module"], str)
            or not payload["module"].strip()
            or len(payload["module"]) > 260
            or "\0" in payload["module"]
        ):
            raise ValueError("empty module")
        for key in ("function_rva", "next_start", "page_size", "stop_id"):
            if isinstance(payload[key], bool) or not isinstance(payload[key], int):
                raise ValueError(f"{key} is not an integer")
        if not 0 <= payload["function_rva"] < (1 << 32):
            raise ValueError("function RVA out of range")
        if not 1 <= payload["next_start"] <= 1_000_000:
            raise ValueError("next line out of range")
        if not 1 <= payload["page_size"] <= MAX_LINE_BATCH:
            raise ValueError("line window out of range")
        if payload["stop_id"] < 1:
            raise ValueError("stop id out of range")
        if (
            not isinstance(payload["session_id"], str)
            or not 1 <= len(payload["session_id"]) <= 128
            or not isinstance(payload["binary_sha256"], str)
            or len(payload["binary_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in payload["binary_sha256"])
            or not isinstance(payload["ghidra_version"], str)
            or not 1 <= len(payload["ghidra_version"]) <= 64
            or not isinstance(payload["analysis_profile"], str)
            or not 1 <= len(payload["analysis_profile"]) <= 128
        ):
            raise ValueError("invalid cursor identity")
        return payload
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DecompError(f"invalid continuation cursor: {exc}") from exc


def _annotate_flow_symbols(
    result: dict[str, Any], store: SymbolStore, module_name: str, module_size: int
) -> None:
    """Attach reusable module-relative symbol labels to branch/call targets."""
    ghidra_base = _hex_int(result.get("ghidra_image_base"))
    if ghidra_base is None:
        return
    instructions = list(result.get("instructions") or [])
    for source_line in (result.get("mapping") or {}).get("excerpt") or []:
        instructions.extend(source_line.get("assembly") or [])
    for instruction in instructions:
        symbols = {}
        for target in instruction.get("flow_targets") or []:
            static_target = _hex_int(target)
            if static_target is None:
                continue
            target_rva = static_target - ghidra_base
            if not 0 <= target_rva < module_size:
                continue
            hint = _nearest_symbol_hint(store, module_name, target_rva)
            if hint is None:
                continue
            suffix = f"+0x{hint['offset']:x}" if hint["offset"] else ""
            symbols[str(target)] = f"{hint['module']}!{hint['name']}{suffix}"
        if symbols:
            instruction["flow_target_symbols"] = symbols


def _binary_candidates(cfg: Config, module_name: str, explicit: str) -> list[Path]:
    if explicit and explicit.strip():
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise DecompError(f"binary does not exist or is not a regular file: {path}")
        return [path]

    root = Path(cfg.symbols_dir)
    resolved_root = root.resolve()
    normalized = module_name.lower()
    candidates: list[Path] = []
    if normalized in {"ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "nt"}:
        candidates.append(root / "ntoskrnl.exe")
    candidates.extend((root / module_name, root / Path(module_name).name))
    try:
        candidates.extend(
            item for item in root.iterdir()
            if item.is_file() and item.name.lower() == normalized
        )
    except OSError:
        pass
    build_root = root / "pe" / Path(module_name).name.lower()
    if build_root.is_dir():
        candidates.extend(sorted(build_root.iterdir(), reverse=True))
    seen: set[Path] = set()
    result = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_relative_to(resolved_root) and resolved.is_file():
            result.append(resolved)
    if result:
        return result
    raise DecompError(
        f"no cached PE for live module {module_name!r}. Before attaching, run "
        "`kdbg_user_symbols_load` for that module, or pass `binary` as the "
        "exact host-side PE path."
    )


def _resolve_binary(cfg: Config, module_name: str, explicit: str) -> Path:
    """Compatibility helper returning the first eligible path before verification."""
    return _binary_candidates(cfg, module_name, explicit)[0]


def _snapshot_binary(cfg: Config, source: Path) -> Path:
    """Copy from one opened file into an immutable content-addressed input."""
    root = cache_dir(cfg) / "verified-binaries"
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    temporary = root / f".{os.getpid()}.{secrets.token_hex(8)}.part"
    digest = hashlib.sha256()
    try:
        with source.open("rb") as src, temporary.open("xb") as dst:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        suffix = source.suffix.lower()
        if len(suffix) > 16 or any(c not in ".abcdefghijklmnopqrstuvwxyz0123456789" for c in suffix):
            suffix = ".bin"
        target = root / f"{digest.hexdigest()}{suffix}"
        lock = root / f"{digest.hexdigest()}.lock"
        with lock.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            if not target.exists():
                os.chmod(temporary, 0o600)
                os.replace(temporary, target)
        return target
    except OSError as exc:
        raise DecompError(f"could not snapshot binary {source}: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _resolve_verified_binary(
    cfg: Config, module_name: str, explicit: str, live_identity,
    module_size: int,
) -> tuple[Path, Any, str]:
    failures = []
    for candidate in _binary_candidates(cfg, module_name, explicit):
        try:
            snapshot = _snapshot_binary(cfg, candidate)
            static = parse_static_pe(snapshot)
            confidence = validate_identity(
                live_identity, static, module_name=module_name or candidate.name,
                live_module_size=module_size,
            )
            return snapshot, static, confidence
        except (DecompError, IdentityError) as exc:
            failures.append(f"{candidate.name}: {exc}")
    detail = failures[-1] if failures else "no candidate"
    raise DecompError(f"no cached PE matches live {module_name!r}: {detail}")


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DecompError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise DecompError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _detail_level(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in DETAIL_LEVELS:
        choices = ", ".join(sorted(DETAIL_LEVELS))
        raise DecompError(f"detail must be one of: {choices}")
    return normalized


def _line_range(value: str) -> tuple[int, int] | None:
    raw = str(value).strip()
    if not raw:
        return None
    parts = [part.strip() for part in raw.split("-")]
    if len(parts) not in {1, 2} or any(not part.isdigit() for part in parts):
        raise DecompError("lines must be N or N-M (for example, 1-22)")
    start = int(parts[0])
    end = int(parts[-1])
    if start < 1 or end < start:
        raise DecompError("lines must be a positive ascending range")
    if end - start + 1 > MAX_LINE_BATCH:
        raise DecompError(f"lines may select at most {MAX_LINE_BATCH} lines")
    return start, end


def _assembly_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in ASSEMBLY_MODES:
        choices = ", ".join(sorted(ASSEMBLY_MODES))
        raise DecompError(f"assembly must be one of: {choices}")
    return normalized


def _nearest_symbol_hint(
    store: SymbolStore, module_name: str, rva: int, *, build: str | None = None,
) -> dict[str, object] | None:
    """Return a bounded PDB-public hint for Ghidra's missed-function case."""
    normalized = module_name.lower()
    if normalized.startswith("ntoskrnl") or normalized.startswith("ntkrnl"):
        keys = ["nt"]
    else:
        keys = [Path(normalized).stem, normalized]
    for key in keys:
        try:
            data = store.load_build(key, build) if build else store.load(key)
            symbols = data.get("symbols", {})
            function_symbols = set(data.get("function_symbols") or [])
        except Exception:
            continue
        best_name = None
        best_rva = -1
        for name, value in symbols.items():
            if isinstance(value, int) and best_rva < value <= rva:
                best_name, best_rva = name, value
        if best_name is None:
            continue
        offset = rva - best_rva
        if offset > 64 * 1024:
            return None
        return {
            "module": key,
            "name": best_name,
            "rva": best_rva,
            "offset": offset,
            "is_function": best_name in function_symbols,
        }
    return None
