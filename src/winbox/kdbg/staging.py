"""Bounded pre-attach staging for exact user-mode unwind artifacts.

The interactive daemon owns QEMU's only RSP client, so it cannot safely ask
the guest agent to copy a dependency discovered during an unwind.  This module
does that work before attach and freezes the result into a content-addressed
manifest.  Missing PDBs are non-fatal: an exact PE still supplies x64 pdata,
while every consumer continues to fail closed on identity mismatches.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any, Callable

from winbox.kdbg.debugger.reader import debug_snapshot
from winbox.kdbg.memory import WalkCache
from winbox.kdbg.pe import PeError, read_pdb_ref
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.symbols import (
    SymbolLoadError,
    _sha256,
    copy_user_module,
    ensure_types_loaded,
    load_module,
)
from winbox.kdbg.walk import find_process, list_user_modules

if TYPE_CHECKING:
    from winbox.config import Config
    from winbox.vm import GuestAgent


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


def _matching_store_build(
    store: SymbolStore,
    store_name: str,
    digest: str,
    architecture: str,
) -> str | None:
    try:
        record = store.load(store_name)
    except (SymbolStoreError, OSError, ValueError):
        return None
    if str(record.get("pe_sha256") or "").lower() != digest.lower():
        return None
    if str(record.get("architecture") or "").lower() != architecture:
        return None
    build = str(record.get("build") or "")
    return build or None


def _validate_pid(pid: object) -> int:
    if isinstance(pid, bool):
        raise StagingError("pid must be an integer between 1 and 0xffffffff")
    try:
        parsed_pid = int(pid)
    except (TypeError, ValueError, OverflowError) as exc:
        raise StagingError(
            "pid must be an integer between 1 and 0xffffffff"
        ) from exc
    if not 0 < parsed_pid <= 0xFFFFFFFF:
        raise StagingError("pid must be an integer between 1 and 0xffffffff")
    return parsed_pid


def _freeze_loader_inventory(
    cfg: Config, store: SymbolStore, pid: object, *, ensure_types: bool,
) -> tuple[int, tuple[FrozenUserModule, ...]]:
    parsed_pid = _validate_pid(pid)
    try:
        if ensure_types:
            ensure_types_loaded(
                cfg, store, [
                    "_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS", "_KPCR",
                    "_KPRCB", "_KTHREAD", "_KTRAP_FRAME",
                ], module="nt",
            )
        with debug_snapshot(cfg):
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=parsed_pid, cache=cache)
            if target is None:
                raise StagingError(f"pid {parsed_pid} not found")
            live_modules = list_user_modules(
                cfg.vm_name, store, target, cache=cache,
            )
    except StagingError:
        raise
    except Exception as exc:
        raise StagingError(f"cannot freeze target loader inventory: {exc}") from exc

    if len(live_modules) > MAX_MANIFEST_MODULES:
        raise StagingError(
            f"target exposes {len(live_modules)} modules; cap is "
            f"{MAX_MANIFEST_MODULES}"
        )

    total_images = 0
    identities: set[tuple[int, str]] = set()
    for module in live_modules:
        if module.architecture not in {"x86", "x64"}:
            raise StagingError(
                f"{module.name}: invalid architecture {module.architecture!r}"
            )
        if module.base <= 0 or module.size <= 0:
            raise StagingError(f"{module.name}: invalid base/size")
        if module.size > MAX_MODULE_IMAGE_SIZE:
            raise StagingError(
                f"{module.name}: image size {module.size} exceeds "
                f"{MAX_MODULE_IMAGE_SIZE}"
            )
        if module.architecture == "x86" and module.base + module.size > (1 << 32):
            raise StagingError(f"{module.name}: x86 image exceeds uint32")
        identity = (module.base, module.architecture)
        if identity in identities:
            raise StagingError(
                f"duplicate loader identity 0x{module.base:x}@{module.architecture}"
            )
        identities.add(identity)
        total_images += module.size
        if total_images > MAX_TOTAL_IMAGE_SIZE:
            raise StagingError(
                f"combined mapped image size exceeds {MAX_TOTAL_IMAGE_SIZE}"
            )
    return parsed_pid, tuple(FrozenUserModule(
        name=module.name,
        full_path=module.full_path,
        architecture=module.architecture,
        base=module.base,
        size=module.size,
    ) for module in live_modules)


def preflight_user_module_staging(
    cfg: Config, store: SymbolStore, pid: object, *, policy: str = "full",
) -> dict[str, Any]:
    """Return a bounded, mutation-free attach staging plan."""
    if policy not in STAGING_POLICIES:
        raise StagingError(f"staging policy must be one of {', '.join(STAGING_POLICIES)}")
    started = time.monotonic()
    parsed_pid, inventory = _freeze_loader_inventory(
        cfg, store, pid, ensure_types=False,
    )
    total = sum(module.size for module in inventory)
    return {
        "schema": "winbox.kdbg-staging-preflight/1",
        "pid": parsed_pid,
        "staging_policy": policy,
        "discovered": len(inventory),
        "mapped_image_bytes": total,
        "guest_copies": policy != "cached-only",
        "network_symbol_enrichment": policy == "full",
        "modules": [
            {
                "name": module.name,
                "architecture": module.architecture,
                "base": f"0x{module.base:x}",
                "size": module.size,
            }
            for module in inventory[:MAX_PROGRESS_RECORDS]
        ],
        "modules_truncated": len(inventory) > MAX_PROGRESS_RECORDS,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "dry_run": True,
    }


def _cached_module(
    store: SymbolStore, module: FrozenUserModule,
) -> StagedUserModule:
    """Reuse one self-consistent store artifact without guest I/O or downloads."""
    store_name = store_name_for(module.name, module.architecture)
    record = store.load(store_name)
    if str(record.get("architecture") or "").lower() != module.architecture:
        raise StagingError("cached symbol record architecture does not match")
    raw_path = str(record.get("pe_path") or "")
    digest = str(record.get("pe_sha256") or "").lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise StagingError("cached symbol record has no valid PE digest")
    path = Path(raw_path).resolve(strict=True)
    if not path.is_file() or _sha256(path) != digest:
        raise StagingError("cached PE is missing or fails its recorded digest")
    try:
        pdb_build = read_pdb_ref(path).build_key
    except (PeError, OSError, ValueError):
        pdb_build = None
    build = str(record.get("build") or "") or None
    return StagedUserModule(
        name=module.name, full_path=module.full_path,
        architecture=module.architecture, base=module.base, size=module.size,
        pe_path=str(path), pe_sha256=digest, store_name=store_name,
        store_build=build, pdb_build=pdb_build,
        artifact_source="cached-store",
    )


def prepare_user_module_manifest(
    cfg: Config,
    ga: GuestAgent,
    store: SymbolStore,
    pid: int,
    *,
    enrich_symbols: bool = True,
    policy: str = "full",
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> UserModuleManifest:
    """Freeze target loader entries into exact immutable PE artifacts.

    Inventory corruption is fatal because it would make the snapshot
    ambiguous.  Individual copy/PDB failures are retained in the manifest and
    attach continues with truthful partial-unwind behavior.
    """
    if policy not in STAGING_POLICIES:
        raise StagingError(f"staging policy must be one of {', '.join(STAGING_POLICIES)}")
    if policy != "full":
        enrich_symbols = False
    started = time.monotonic()
    parsed_pid, inventory = _freeze_loader_inventory(
        cfg, store, pid, ensure_types=True,
    )

    staged: list[StagedUserModule] = []
    failures: list[str] = []
    progress_records: list[dict[str, Any]] = []
    failure_count = 0
    total_files = 0
    for index, module in enumerate(inventory, 1):
        module_started = time.monotonic()
        state = "failed"
        symbol_state = "not-requested"
        store_name = store_name_for(module.name, module.architecture)
        try:
            if policy == "cached-only":
                cached = _cached_module(store, module)
                staged.append(cached)
                total_files += Path(cached.pe_path).stat().st_size
                state = "reused"
                symbol_state = "reused" if cached.store_build else "missing"
                continue

            remaining = MAX_TOTAL_IMAGE_SIZE - total_files
            path = copy_user_module(
                cfg, ga, module.full_path, module.name,
                architecture=module.architecture,
                expected_size=module.size,
                max_file_size=min(MAX_MODULE_FILE_SIZE, remaining),
            ).resolve(strict=True)
            file_size = path.stat().st_size
            total_files += file_size
            if total_files > MAX_TOTAL_IMAGE_SIZE:
                raise SymbolLoadError("combined staged file size exceeds cap")
            digest = _sha256(path)
            try:
                pdb_build = read_pdb_ref(path).build_key
            except (PeError, OSError, ValueError):
                pdb_build = None

            store_build = _matching_store_build(
                store, store_name, digest, module.architecture,
            )
            symbol_error = None
            if store_build is None and enrich_symbols and pdb_build is not None:
                try:
                    info = load_module(
                        cfg, store, pe_path=path, module_name=store_name,
                        base=module.base, wanted_types=(),
                    )
                    store_build = info.build
                    symbol_state = "enriched"
                except Exception as exc:  # exact PE remains independently useful
                    symbol_error = _bounded_error(exc)
                    symbol_state = "failed"
            elif store_build is not None:
                symbol_state = "reused"
                # ASLR relocation does not change the exact artifact or PDB.
                try:
                    store.set_base(store_name, module.base)
                except Exception as exc:
                    # The build-keyed record remains valid for frame metadata;
                    # the manifest, rather than the mutable active index, owns
                    # the load base used by this daemon.
                    symbol_error = _bounded_error(exc)

            staged.append(StagedUserModule(
                name=module.name,
                full_path=module.full_path,
                architecture=module.architecture,
                base=module.base,
                size=module.size,
                pe_path=str(path),
                pe_sha256=digest,
                store_name=store_name,
                store_build=store_build,
                pdb_build=pdb_build,
                symbol_error=symbol_error,
                artifact_source="guest-copy",
            ))
            state = "copied"
        except Exception as exc:
            failure_count += 1
            if len(failures) < MAX_FAILURES:
                failures.append(
                    f"{module.name}@{module.architecture}: {_bounded_error(exc)}"
                )
        finally:
            item = {
                "index": index, "total": len(inventory),
                "name": module.name[:260], "architecture": module.architecture,
                "state": state, "symbol_state": symbol_state,
                "elapsed_seconds": round(time.monotonic() - module_started, 3),
            }
            if len(progress_records) < MAX_PROGRESS_RECORDS:
                progress_records.append(item)
            if progress is not None:
                try:
                    progress(item)
                except Exception:
                    pass

    return UserModuleManifest(
        pid=parsed_pid, modules=tuple(staged), inventory=inventory,
        failures=tuple(failures),
        total_file_bytes=total_files, failure_count=failure_count,
        staging_policy=policy,
        elapsed_seconds=time.monotonic() - started,
        module_progress=tuple(progress_records),
        progress_truncated=len(inventory) > len(progress_records),
    )
