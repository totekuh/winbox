"""Module resolution and artifact loading for static PE search."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import cache_dir
from winbox.kdbg.decomp.identity import PeIdentity, parse_static_pe
from winbox.kdbg.store import SymbolStore, SymbolStoreError

from winbox.kdbg.static_search_types import (
    MAX_CACHE_METADATA_BYTES,
    MAX_CACHE_METADATA_RECORDS,
    MAX_FILE_BYTES,
    StaticSearchError,
    _validate_sha256,
)


def _aliases(store_name: str, record: dict[str, Any]) -> set[str]:
    values = {store_name}
    for key in ("module", "image"):
        value = record.get(key)
        if isinstance(value, str) and value:
            values.add(value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
    aliases: set[str] = set()
    for value in values:
        folded = value.strip().lower()
        if folded:
            aliases.add(folded)
            aliases.add(Path(folded).stem)
    return aliases


def _select_module(store: SymbolStore, requested: str) -> tuple[str, dict[str, Any]] | None:
    needle = requested.lower()
    stem = Path(needle).stem
    matches: list[tuple[str, dict[str, Any]]] = []
    for store_name in store.list_modules():
        try:
            record = store.load(store_name)
        except (SymbolStoreError, OSError, TypeError, ValueError):
            continue
        aliases = _aliases(store_name, record)
        if needle in aliases or stem in aliases:
            matches.append((store_name, record))
    if not matches:
        return None
    if len(matches) > 1:
        names = ", ".join(name for name, _ in matches[:8])
        raise StaticSearchError(
            f"module {requested!r} is ambiguous across cached artifacts: {names}",
        )
    return matches[0]


def _safe_cache_binary_name(value: object) -> str:
    if not isinstance(value, str):
        return ""
    name = value.strip()
    if (
        not name or len(name) > 260 or name != Path(name).name
        or "/" in name or "\\" in name or "\0" in name
    ):
        return ""
    return name


def _cache_binary_for_digest(root: Path, digest: str) -> Path | None:
    """Find one immutable cache copy without accepting lock/partial files."""
    for directory in (root / "verified-binaries", root / "binaries"):
        try:
            candidates = [directory / digest, *sorted(directory.glob(f"{digest}.*"))]
        except OSError:
            continue
        for path in candidates:
            if (
                path.name.endswith((".lock", ".part"))
                or path.is_symlink() or not path.is_file()
            ):
                continue
            return path
    return None


def _cache_metadata_records(cfg: Config) -> list[tuple[str, dict[str, Any]]]:
    """Read bounded decomp metadata to recover names for symbol-less PEs."""
    root = cache_dir(cfg)
    metadata = root / "metadata"
    try:
        paths = sorted(metadata.glob("*.json"))[:MAX_CACHE_METADATA_RECORDS]
    except OSError:
        return []
    records: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > MAX_CACHE_METADATA_BYTES:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if not isinstance(value, dict):
            continue
        try:
            digest = _validate_sha256(value.get("sha256"))
        except StaticSearchError:
            continue
        name = _safe_cache_binary_name(value.get("binary_name"))
        binary = _cache_binary_for_digest(root, digest) if digest else None
        if not digest or not name or binary is None:
            continue
        records.append((digest, {
            "module": Path(name).stem,
            "image": name,
            "pe_path": str(binary),
            "pe_sha256": digest,
            "artifact_source": "decomp-cache",
        }))
    return records


def _select_cache_module(
    cfg: Config, requested: str, *, sha256: str,
) -> tuple[str, dict[str, Any]]:
    root = cache_dir(cfg)
    if sha256:
        binary = _cache_binary_for_digest(root, sha256)
        if binary is None:
            raise StaticSearchError(
                f"no exact decomp-cache binary matches sha256 {sha256}",
            )
        record = next(
            (value for digest, value in _cache_metadata_records(cfg) if digest == sha256),
            None,
        )
        if record is None:
            record = {
                "module": Path(binary.name).stem,
                "image": binary.name,
                "pe_path": str(binary),
                "pe_sha256": sha256,
                "artifact_source": "decomp-cache",
            }
        return Path(str(record["image"])).stem, record

    needle = requested.lower()
    stem = Path(needle).stem
    matches: list[tuple[str, dict[str, Any]]] = []
    for digest, record in _cache_metadata_records(cfg):
        aliases = _aliases(str(record["module"]), record)
        if needle in aliases or stem in aliases:
            matches.append((digest, record))
    if not matches:
        raise StaticSearchError(
            f"no exact cached PE matches module {requested!r}; no symbol-store "
            "record or named decomp-cache artifact is available",
        )
    unique = {digest: record for digest, record in matches}
    if len(unique) != 1:
        choices = ", ".join(
            f"{record['image']}@{digest[:12]}" for digest, record in list(unique.items())[:8]
        )
        raise StaticSearchError(
            f"module {requested!r} is ambiguous across decomp-cache artifacts: "
            f"{choices}; repeat with sha256=<full digest>",
        )
    _digest, record = next(iter(unique.items()))
    return str(record["module"]), record


def _read_bounded_regular_file(path: Path, *, label: str) -> bytes:
    """Read one non-symlink regular artifact without trusting a prior stat.

    The local symbol cache is normally operator-owned, but these records can
    originate from a target-controlled loader name.  Holding the descriptor
    while checking type/size avoids the easy path-swap and unbounded-read
    failures that would otherwise turn a supposedly offline lookup into a host
    memory pressure primitive.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StaticSearchError(f"{label} is missing or unsafe: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise StaticSearchError(f"{label} is not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise StaticSearchError(
                f"{label} exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB search cap"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            data = handle.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise StaticSearchError(
                f"{label} grew beyond the {MAX_FILE_BYTES // (1024 * 1024)} MiB search cap"
            )
        return data
    except StaticSearchError:
        raise
    except OSError as exc:
        raise StaticSearchError(f"could not read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_exact_artifact(
    cfg: Config, store: SymbolStore, module: str, *, sha256: str,
) -> tuple[str, dict[str, Any], Path, PeIdentity, bytes]:
    if sha256:
        store_name, record = _select_cache_module(cfg, module, sha256=sha256)
    else:
        selected = _select_module(store, module)
        if selected is None:
            store_name, record = _select_cache_module(cfg, module, sha256="")
        else:
            store_name, record = selected
    raw_path = record.get("pe_path")
    expected = str(record.get("pe_sha256") or "").lower()
    if not isinstance(raw_path, str) or not raw_path:
        raise StaticSearchError(f"{store_name!r} has no staged PE artifact")
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise StaticSearchError(f"{store_name!r} has no valid staged PE digest")
    path = Path(raw_path).expanduser()
    try:
        data = _read_bounded_regular_file(path, label=f"{store_name!r} staged PE")
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise StaticSearchError(f"{store_name!r} staged PE digest does not match its record")
    except StaticSearchError:
        raise
    except OSError as exc:
        raise StaticSearchError(f"could not read staged PE for {store_name!r}: {exc}") from exc
    try:
        identity = parse_static_pe(path)
    except Exception as exc:
        raise StaticSearchError(f"could not parse staged PE for {store_name!r}: {exc}") from exc
    if identity.sha256 != expected:
        raise StaticSearchError(f"{store_name!r} staged PE changed while being searched")
    return store_name, record, path, identity, data
