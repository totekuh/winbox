"""One-stop, bounded VAD byte extraction as immutable host-side evidence.

The ordinary VAD walker proves a process range and its kernel-owned mapping
metadata.  This module deliberately performs the follow-up byte read in that
same stopped snapshot, so an artifact cannot pair a VAD from one process state
with bytes read after it resumed.  Raw bytes are written only to a mode-0600
host artifact; CLI and MCP return the manifest, never a hex dump.
"""

from __future__ import annotations

import fcntl
import hashlib
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
from winbox.kdbg.debugger.reader import (
    ReaderError,
    SnapshotBudgetError,
    debug_snapshot,
    snapshot_metadata,
    snapshot_phase,
)
from winbox.kdbg.debugger.rsp import RspError
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import WalkCache, read_virt_cr3
from winbox.kdbg.presentation import filetime_utc
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.vad import (
    VadError,
    ensure_vad_layouts,
    lookup_vad,
)
from winbox.kdbg.walk import ProcessRecord, find_process


SCHEMA = "winbox.kdbg-vad-extract/1"
DEFAULT_EXTRACT_BYTES = 1 * 1024 * 1024
MAX_EXTRACT_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 4096
MAX_MANIFEST_BYTES = 1 * 1024 * 1024
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class VadExtractError(VadError):
    code = "vad_extract_error"


class VadExtractIncomplete(VadExtractError):
    code = "incomplete_result"
    retryable = True


@dataclass
class _Segment:
    address: int
    blob_offset: int
    length: int
    hasher: Any

    def append(self, data: bytes) -> None:
        self.length += len(data)
        self.hasher.update(data)

    def public(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:016x}",
            "length": self.length,
            "blob_offset": self.blob_offset,
            "sha256": self.hasher.hexdigest(),
        }


@dataclass(frozen=True)
class VadExtraction:
    """Manifest plus private in-memory bytes pending host-side persistence."""

    manifest: dict[str, Any]
    blob: bytes


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z",
    )


def _process_public(process: ProcessRecord) -> dict[str, Any]:
    return {
        "pid": process.pid,
        "name": process.name,
        "eprocess": f"0x{process.eprocess:016x}",
        "dtb": f"0x{process.directory_table_base:012x}",
        "create_time": process.create_time,
        "create_time_utc": filetime_utc(process.create_time),
    }


def _symbol_identity(store: SymbolStore) -> dict[str, Any]:
    info = store.info("nt")
    return {
        "build": info.build,
        "base": f"0x{info.base:016x}" if info.base else None,
        "store_file": info.path.name,
        "symbol_count": info.symbol_count,
        "type_count": info.type_count,
    }


def _validate_length(value: int | None, available: int) -> int:
    if value is None:
        return min(DEFAULT_EXTRACT_BYTES, available)
    if isinstance(value, bool) or not isinstance(value, int):
        raise VadExtractError("length must be an integer number of bytes")
    if not 1 <= value <= MAX_EXTRACT_BYTES:
        raise VadExtractError(
            f"length must be between 1 and {MAX_EXTRACT_BYTES} bytes",
        )
    if value > available:
        raise VadExtractError(
            "requested range extends past the validated VAD boundary",
        )
    return value


def _validate_request(pid: int, address: int) -> None:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise VadExtractError("pid must be a positive integer")
    if (
        isinstance(address, bool) or not isinstance(address, int)
        or not 0 <= address <= 0x0000_7FFF_FFFF_FFFF
    ):
        raise VadExtractError("address must be a canonical user-mode virtual address")


def _append_hole(
    holes: list[dict[str, Any]], *, address: int, length: int, reason: str,
) -> None:
    if holes:
        prior = holes[-1]
        prior_address = int(prior["_address"])
        if prior_address + int(prior["length"]) == address and prior["reason"] == reason:
            prior["length"] = int(prior["length"]) + length
            return
    holes.append({"_address": address, "address": f"0x{address:016x}", "length": length, "reason": reason})


def _append_data(
    segments: list[_Segment], blob: bytearray, *, address: int, data: bytes,
) -> None:
    """Append readable bytes, extending the preceding physical segment if apt."""
    if not data:
        return
    blob_offset = len(blob)
    if (
        segments
        and segments[-1].address + segments[-1].length == address
        and segments[-1].blob_offset + segments[-1].length == blob_offset
    ):
        segments[-1].append(data)
    else:
        segment = _Segment(
            address=address,
            blob_offset=blob_offset,
            length=0,
            hasher=hashlib.sha256(),
        )
        segment.append(data)
        segments.append(segment)
    blob.extend(data)


def extract_vad_in_snapshot(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    address: int,
    *,
    length: int | None = None,
    require_complete: bool = False,
    cache: WalkCache | None = None,
) -> VadExtraction:
    """Read a bounded selected range while a caller-owned snapshot is active.

    A failed page is a hole, not a reason to discard prior valid bytes.  The
    snapshot's own budget error remains fatal: treating it as an ordinary
    unreadable page would hide the broker's stop contract from callers.
    """
    if not isinstance(require_complete, bool):
        raise VadExtractError("require_complete must be a boolean")
    _validate_request(target.pid, address)
    cache = cache or WalkCache()
    with snapshot_phase("vad_lookup"):
        vad = lookup_vad(
            vm_name, store, target, address, cache=cache, probe_header=True,
        )
    if vad is None:
        error = VadExtractError("address is not covered by a validated user VAD")
        error.code = "vad_not_found"
        raise error
    available = vad.end - address + 1
    selected_length = _validate_length(length, available)
    selected_end = address + selected_length - 1
    blob = bytearray()
    segments: list[_Segment] = []
    holes: list[dict[str, Any]] = []

    with snapshot_phase("vad_extract"):
        cursor = address
        remaining = selected_length
        while remaining:
            # Do not let a single failure erase a larger interval than a page.
            take = min(remaining, READ_CHUNK_BYTES - (cursor & (READ_CHUNK_BYTES - 1)))
            try:
                data = read_virt_cr3(
                    vm_name, target.directory_table_base, cursor, take, cache=cache,
                )
            except SnapshotBudgetError:
                raise
            except RspError as error:
                partial = error.partial
                if not isinstance(partial, bytes):
                    partial = b""
                if len(partial) > take:
                    raise VadExtractError("debugger returned more bytes than requested")
                _append_data(segments, blob, address=cursor, data=partial)
                if len(partial) < take:
                    _append_hole(
                        holes,
                        address=cursor + len(partial),
                        length=take - len(partial),
                        reason="rsp_partial" if partial else "unreadable",
                    )
            except (ReaderError, HmpError, OSError):
                _append_hole(holes, address=cursor, length=take, reason="unreadable")
            else:
                if len(data) > take:
                    raise VadExtractError("debugger returned more bytes than requested")
                _append_data(segments, blob, address=cursor, data=data)
                if len(data) < take:
                    _append_hole(
                        holes, address=cursor + len(data),
                        length=take - len(data), reason="short_read",
                    )
            cursor += take
            remaining -= take

    complete = not holes and len(blob) == selected_length
    if require_complete and not complete:
        error = VadExtractIncomplete("selected VAD range is incomplete")
        error.details = {
            "requested_bytes": selected_length,
            "captured_bytes": len(blob),
            "holes": [{key: value for key, value in hole.items() if key != "_address"} for hole in holes],
        }
        raise error
    result = {
        "schema": SCHEMA,
        "captured_at": _utc_now(),
        "target": _process_public(target),
        "vad": vad.public(),
        "range": {
            "address": f"0x{address:016x}",
            "end": f"0x{selected_end:016x}",
            "requested_bytes": selected_length,
        },
        "complete": complete,
        "segments": [segment.public() for segment in segments],
        "holes": [{key: value for key, value in hole.items() if key != "_address"} for hole in holes],
        "blob": {
            "size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "layout": "concatenated_successful_segments",
        },
        "provenance": {
            "vad": "exact_nt_pdb",
            "bytes": "same_snapshot_process_cr3",
            "raw_bytes_returned": False,
        },
    }
    return VadExtraction(manifest=result, blob=bytes(blob))


def extract_live(
    cfg: Config,
    store: SymbolStore,
    *,
    pid: int,
    address: int,
    length: int | None = None,
    require_complete: bool = False,
) -> VadExtraction:
    """Preflight exact layouts, take one stop, and return a saveable artifact."""
    _validate_request(pid, address)
    ensure_vad_layouts(cfg, store)
    with debug_snapshot(cfg, operation="vad_extract") as snapshot:
        cache = WalkCache()
        with snapshot_phase("process_identity"):
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                raise VadExtractError(f"pid {pid} not found")
            system = target if target.pid == 4 else find_process(
                cfg.vm_name, store, pid=4, cache=cache,
            )
        if system is None:
            raise VadExtractError("could not establish captured System identity")
        extraction = extract_vad_in_snapshot(
            cfg.vm_name, store, target, address, length=length,
            require_complete=require_complete, cache=cache,
        )
        metadata = snapshot_metadata(snapshot)
        manifest = dict(extraction.manifest)
        manifest["snapshot_metadata"] = metadata
        manifest["vm_name"] = cfg.vm_name
        manifest["boot_identity"] = {"system": _process_public(system)}
        manifest["symbol_identity"] = _symbol_identity(store)
    return VadExtraction(manifest=manifest, blob=extraction.blob)


class VadExtractStore:
    """Atomic, append-only VAD byte-artifact storage under the KDBG root."""

    def __init__(self, cfg: Config) -> None:
        self.root = cfg.winbox_dir / "kdbg" / "vad-extracts"

    @staticmethod
    def validate_name(name: str) -> str:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise VadExtractError(
                "artifact name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}",
            )
        return name

    def path(self, name: str) -> Path:
        return self.root / f"{self.validate_name(name)}.json"

    def blob_path(self, name: str) -> Path:
        return self.root / f"{self.validate_name(name)}.bin"

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

    @staticmethod
    def _safe_existing(path: Path) -> bool:
        return path.exists() or path.is_symlink()

    def _assert_absent(self, name: str) -> None:
        if self._safe_existing(self.path(name)) or self._safe_existing(self.blob_path(name)):
            raise VadExtractError(f"VAD extraction artifact {name!r} already exists and is immutable")

    def ensure_available(self, name: str) -> str:
        """Reject an existing artifact before a caller spends a VM stop.

        ``save`` repeats the check under its publication lock.  This early
        check is an efficiency guard for ordinary CLI/MCP duplicate names, not
        a replacement for the race-safe write-time invariant.
        """
        name = self.validate_name(name)
        with self._exclusive(name):
            self._assert_absent(name)
        return name

    @staticmethod
    def _validate(extraction: VadExtraction) -> None:
        manifest = extraction.manifest
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
            raise VadExtractError("refusing to save unsupported VAD extraction schema")
        blob = manifest.get("blob") if isinstance(manifest.get("blob"), dict) else {}
        if blob.get("size") != len(extraction.blob):
            raise VadExtractError("VAD extraction blob size does not match manifest")
        if blob.get("sha256") != hashlib.sha256(extraction.blob).hexdigest():
            raise VadExtractError("VAD extraction blob digest does not match manifest")

    def save(self, name: str, extraction: VadExtraction) -> dict[str, Any]:
        name = self.validate_name(name)
        self._validate(extraction)
        path = self.path(name)
        blob_path = self.blob_path(name)
        manifest = dict(extraction.manifest)
        manifest["artifact_name"] = name
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > MAX_MANIFEST_BYTES:
            raise VadExtractError("VAD extraction manifest exceeds its hard size cap")
        blob_published = False
        with self._exclusive(name):
            self._assert_absent(name)
            blob_fd, blob_temp_name = tempfile.mkstemp(
                prefix=f".{blob_path.name}.", suffix=".tmp", dir=blob_path.parent,
            )
            manifest_fd, manifest_temp_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
            )
            blob_temp = Path(blob_temp_name)
            manifest_temp = Path(manifest_temp_name)
            try:
                os.fchmod(blob_fd, 0o600)
                with os.fdopen(blob_fd, "wb") as output:
                    output.write(extraction.blob)
                    output.flush()
                    os.fsync(output.fileno())
                os.fchmod(manifest_fd, 0o600)
                with os.fdopen(manifest_fd, "wb") as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                # Readers require the manifest, so publish bytes first and
                # make the manifest the atomic visibility boundary.
                os.replace(blob_temp, blob_path)
                blob_published = True
                os.replace(manifest_temp, path)
            except BaseException:
                if blob_published and not path.exists():
                    blob_path.unlink(missing_ok=True)
                raise
            finally:
                blob_temp.unlink(missing_ok=True)
                manifest_temp.unlink(missing_ok=True)
        return {
            "name": name,
            "manifest_path": str(path),
            "blob_path": str(blob_path),
            "schema": SCHEMA,
            "captured_at": manifest.get("captured_at"),
            "complete": manifest.get("complete"),
            "blob": manifest.get("blob"),
        }

    def load(self, name: str) -> dict[str, Any]:
        path = self.path(name)
        blob_path = self.blob_path(name)
        try:
            if (
                path.is_symlink() or blob_path.is_symlink()
                or path.stat().st_size > MAX_MANIFEST_BYTES
                or blob_path.stat().st_size > MAX_EXTRACT_BYTES
            ):
                raise VadExtractError(f"VAD extraction artifact {name!r} is unsafe or too large")
            manifest = json.loads(path.read_text(encoding="utf-8"))
            blob = blob_path.read_bytes()
        except FileNotFoundError as exc:
            raise VadExtractError(f"VAD extraction artifact {name!r} was not found") from exc
        except (OSError, TypeError, ValueError) as exc:
            raise VadExtractError(f"could not load VAD extraction artifact {name!r}: {exc}") from exc
        extraction = VadExtraction(manifest=manifest, blob=blob)
        self._validate(extraction)
        if manifest.get("artifact_name") != self.validate_name(name):
            raise VadExtractError(f"VAD extraction artifact {name!r} has an invalid manifest name")
        return manifest

    def delete(self, name: str) -> None:
        """Test/helper cleanup of one exact artifact pair."""
        name = self.validate_name(name)
        with self._exclusive(name):
            self.path(name).unlink(missing_ok=True)
            self.blob_path(name).unlink(missing_ok=True)
