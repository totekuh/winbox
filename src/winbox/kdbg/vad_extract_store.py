"""Atomic, append-only VAD byte-artifact persistence under the KDBG root."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from winbox.config import Config
from winbox.kdbg.vad_extract import (
    SCHEMA, MAX_EXTRACT_BYTES, MAX_MANIFEST_BYTES, _NAME_RE,
    VadExtractError, VadExtraction,
)


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
        """Reject an existing artifact before a caller spends a VM stop."""
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
