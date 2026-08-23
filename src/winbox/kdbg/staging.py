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
from typing import TYPE_CHECKING, Any

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


def prepare_user_module_manifest(
    cfg: Config,
    ga: GuestAgent,
    store: SymbolStore,
    pid: int,
    *,
    enrich_symbols: bool = True,
) -> UserModuleManifest:
    """Freeze target loader entries into exact immutable PE artifacts.

    Inventory corruption is fatal because it would make the snapshot
    ambiguous.  Individual copy/PDB failures are retained in the manifest and
    attach continues with truthful partial-unwind behavior.
    """
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

    try:
        ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt",
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

    staged: list[StagedUserModule] = []
    inventory = tuple(FrozenUserModule(
        name=module.name,
        full_path=module.full_path,
        architecture=module.architecture,
        base=module.base,
        size=module.size,
    ) for module in live_modules)
    failures: list[str] = []
    failure_count = 0
    total_files = 0
    for module in live_modules:
        store_name = store_name_for(module.name, module.architecture)
        try:
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
                except Exception as exc:  # exact PE remains independently useful
                    symbol_error = _bounded_error(exc)
            elif store_build is not None:
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
            ))
        except Exception as exc:
            failure_count += 1
            if len(failures) < MAX_FAILURES:
                failures.append(
                    f"{module.name}@{module.architecture}: {_bounded_error(exc)}"
                )

    return UserModuleManifest(
        pid=parsed_pid, modules=tuple(staged), inventory=inventory,
        failures=tuple(failures),
        total_file_bytes=total_files, failure_count=failure_count,
    )
