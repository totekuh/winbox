"""Data model types for bounded user-module staging manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MAX_MANIFEST_MODULES = 256
MAX_MODULE_IMAGE_SIZE = 512 * 1024 * 1024
MAX_MODULE_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_IMAGE_SIZE = 2 * 1024 * 1024 * 1024
MAX_FAILURES = 64
MAX_ERROR_CHARS = 512
STAGING_POLICIES = ("full", "binaries", "cached-only")
MAX_PROGRESS_RECORDS = 64


class StagingError(RuntimeError):
    """The target inventory itself could not be frozen safely."""


def _bounded_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return text if len(text) <= MAX_ERROR_CHARS else text[:MAX_ERROR_CHARS - 3] + "..."


def store_name_for(name: str, architecture: str) -> str:
    stem = name.rsplit(".", 1)[0].lower()
    return stem + ("_x86" if architecture == "x86" else "")


@dataclass(frozen=True)
class StagedUserModule:
    name: str
    full_path: str
    architecture: str
    base: int
    size: int
    pe_path: str
    pe_sha256: str
    store_name: str
    store_build: str | None = None
    pdb_build: str | None = None
    symbol_error: str | None = None
    artifact_source: str = "guest-copy"

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "full_path": self.full_path,
            "architecture": self.architecture,
            "base": f"0x{self.base:x}",
            "size": self.size,
            "pe_path": self.pe_path,
            "pe_sha256": self.pe_sha256,
            "store_name": self.store_name,
            "store_build": self.store_build,
            "pdb_build": self.pdb_build,
        }
        if self.symbol_error:
            result["symbol_error"] = self.symbol_error
        result["artifact_source"] = self.artifact_source
        return result


@dataclass(frozen=True)
class FrozenUserModule:
    """One loader entry captured before the daemon takes RSP ownership."""

    name: str
    full_path: str
    architecture: str
    base: int
    size: int


@dataclass(frozen=True)
class UserModuleManifest:
    pid: int
    modules: tuple[StagedUserModule, ...]
    inventory: tuple[FrozenUserModule, ...] = ()
    failures: tuple[str, ...] = ()
    total_file_bytes: int = 0
    failure_count: int | None = None
    staging_policy: str = "full"
    elapsed_seconds: float = 0.0
    module_progress: tuple[dict[str, Any], ...] = ()
    progress_truncated: bool = False
    schema: str = "winbox.kdbg-user-manifest/1"

    def by_base(self, base: int, architecture: str | None = None) -> StagedUserModule | None:
        matches = [
            module for module in self.modules
            if module.base == base and (
                architecture is None or module.architecture == architecture
            )
        ]
        return matches[0] if len(matches) == 1 else None

    def summary(self) -> dict[str, Any]:
        enriched = sum(module.store_build is not None for module in self.modules)
        symbol_failures = [
            f"{module.name}@{module.architecture}: {module.symbol_error}"
            for module in self.modules
            if module.symbol_error and module.store_build is None
        ]
        symbol_warnings = [
            f"{module.name}@{module.architecture}: {module.symbol_error}"
            for module in self.modules
            if module.symbol_error and module.store_build is not None
        ]
        return {
            "schema": self.schema,
            "pid": self.pid,
            "discovered": len(self.inventory) if self.inventory else len(self.modules),
            "staged": len(self.modules),
            "symbol_enriched": enriched,
            "symbol_failed": len(symbol_failures),
            "symbol_warning_count": len(symbol_warnings),
            "failed": (
                self.failure_count
                if self.failure_count is not None else len(self.failures)
            ),
            "total_file_bytes": self.total_file_bytes,
            "symbol_failures": symbol_failures[:16],
            "symbol_warnings": symbol_warnings[:16],
            "failures": list(self.failures[:16]),
            "staging_policy": self.staging_policy,
            "complete_exact_snapshot": self.staging_policy == "full" and (
                len(self.modules) == len(self.inventory) and not self.failure_count
            ),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "module_progress": list(self.module_progress),
            "progress_truncated": self.progress_truncated,
        }

    def loader_modules(self) -> tuple[FrozenUserModule | StagedUserModule, ...]:
        """Return every frozen loader entry, including copy failures."""
        return self.inventory or self.modules
