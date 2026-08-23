"""Composition layer joining a live kdbg stop to focused Ghidra output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.identity import (
    IdentityError,
    parse_live_pe,
    parse_static_pe,
    static_bytes_at_rva,
    validate_identity,
)
from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.format import symbolicate_va
from winbox.kdbg.store import SymbolStore


MAX_CONTEXT_LINES = 20
MAX_LIVE_READ = 64 * 1024


def worker_status(cfg: Config) -> dict[str, Any]:
    return DecompClient(cfg).status()


def install_service(cfg: Config, *, pull: bool = True) -> dict[str, Any]:
    """Build the pinned, self-contained PyGhidra image."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).install(pull=pull)
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def start_service(cfg: Config) -> dict[str, Any]:
    """Start the private Unix-socket API without loading the JVM yet."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    manager = DockerManager(cfg)
    try:
        # Do not stop a legacy host worker unless the replacement image is
        # definitely available.
        if manager.image_info() is None:
            raise DockerError(
                "PyGhidra image is not installed; run `winbox kdbg ghidra install`"
            )
        DecompClient(cfg).ensure_selected_backend()
        result = manager.start()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc
    # Prove the API, not merely Docker's process state.
    status = DecompClient(cfg).call("status", start=False, timeout=10.0)
    return {**result, "api": status}


def stop_service(cfg: Config) -> dict[str, Any]:
    """Stop and remove only the precisely labelled winbox container."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).stop()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def query_decomp(
    cfg: Config,
    *,
    addr: str = "",
    before: int = 3,
    after: int = 5,
    full: bool = False,
    binary: str = "",
    timeout: int = 60,
    daemon_client: DaemonClient | None = None,
    decomp_client: DecompClient | None = None,
) -> dict[str, Any]:
    """Return focused pseudocode for ``addr`` (current RIP by default).

    The order is intentionally fail-closed: fresh live module resolution,
    exact PE identity validation, RVA mapping, and only then Ghidra. A stale
    same-named file never reaches the decompiler cache.
    """
    before = _bounded_int("before", before, 0, MAX_CONTEXT_LINES)
    after = _bounded_int("after", after, 0, MAX_CONTEXT_LINES)
    timeout = _bounded_int("timeout", timeout, 5, 300)
    daemon = daemon_client or DaemonClient(cfg)
    worker = decomp_client or DecompClient(cfg)

    try:
        status = daemon.call("status")
        target = status.get("target") or {}
        if addr and addr.strip():
            runtime_va = int(addr.strip(), 0)
        else:
            registers = daemon.call("regs")
            runtime_va = int(str(registers.get("rip", "0")), 0)
        if runtime_va < 0 or runtime_va >= (1 << 64):
            raise ValueError("address outside uint64 range")
    except (ClientError, TypeError, ValueError) as exc:
        raise DecompError(f"could not resolve live address: {exc}") from exc

    try:
        module = daemon.call("module_at", va=f"0x{runtime_va:x}")
        module_base = int(str(module["base"]), 0)
        module_size = int(module["size"])
        rva = runtime_va - module_base
    except (ClientError, KeyError, TypeError, ValueError) as exc:
        raise DecompError(f"could not resolve live module: {exc}") from exc
    if rva < 0 or rva >= module_size:
        raise DecompError(
            f"resolved RVA 0x{rva:x} lies outside {module.get('name')} "
            f"(size 0x{module_size:x})"
        )

    binary_path = _resolve_binary(cfg, str(module.get("name", "")), binary)

    def live_read(address: int, length: int) -> bytes:
        if length < 0 or length > (1 << 20):
            raise IdentityError(f"invalid live read length: {length}")
        chunks: list[bytes] = []
        offset = 0
        while offset < length:
            size = min(MAX_LIVE_READ, length - offset)
            try:
                reply = daemon.call(
                    "mem", va=f"0x{address + offset:x}", length=size,
                )
                chunk = bytes.fromhex(str(reply["bytes"]))
            except (ClientError, KeyError, ValueError) as exc:
                raise IdentityError(str(exc)) from exc
            if len(chunk) != size:
                raise IdentityError(f"short daemon memory read: {len(chunk)}/{size}")
            chunks.append(chunk)
            offset += size
        return b"".join(chunks)

    try:
        static_identity = parse_static_pe(binary_path)
        live_identity = parse_live_pe(live_read, module_base)
        identity_confidence = validate_identity(
            live_identity,
            static_identity,
            module_name=str(module.get("name") or binary_path.name),
            live_module_size=module_size,
        )
    except IdentityError as exc:
        raise DecompError(str(exc)) from exc

    store = SymbolStore(cfg.symbols_dir)
    runtime_symbol = symbolicate_va(store, runtime_va)
    symbol_hint = _nearest_symbol_hint(store, str(module.get("name", "")), rva)

    result = worker.call(
        "decompile",
        timeout=float(timeout) + 840.0,
        binary=str(binary_path),
        sha256=static_identity.sha256,
        rva=rva,
        before=before,
        after=after,
        full=bool(full),
        decompile_timeout=timeout,
        symbol_hint=symbol_hint,
    )

    warnings: list[str] = []
    live_bytes_match: bool | None = None
    current = next(
        (item for item in result.get("instructions", []) if item.get("current")),
        None,
    )
    if current is not None:
        try:
            static_instruction = bytes.fromhex(str(current.get("bytes", "")))
            instruction_address = int(str(current["address"]), 0)
            ghidra_base = int(str(result["ghidra_image_base"]), 0)
            instruction_rva = instruction_address - ghidra_base
            raw_file = static_bytes_at_rva(
                binary_path, static_identity, instruction_rva, len(static_instruction)
            )
            if raw_file and raw_file != static_instruction:
                warnings.append(
                    "Ghidra instruction bytes differ from the cached PE; "
                    "rebuild the analysis cache"
                )
            live_instruction = live_read(
                module_base + instruction_rva, len(static_instruction)
            )
            live_bytes_match = live_instruction == static_instruction
            if not live_bytes_match:
                warnings.append(
                    "live instruction bytes differ from the exact cached PE "
                    "(software breakpoint, hotpatch, runtime patch, or relocation)"
                )
        except (IdentityError, KeyError, TypeError, ValueError):
            warnings.append("could not compare live and static instruction bytes")

    return {
        "target": {"pid": target.get("pid"), "name": target.get("name")},
        "module": {
            **module,
            "runtime_va": f"0x{runtime_va:x}",
            "rva": f"0x{rva:x}",
            "binary": str(binary_path),
        },
        "identity": {
            "confidence": identity_confidence,
            "live": live_identity.public(),
            "static": static_identity.public(),
            "live_bytes_match": live_bytes_match,
        },
        "runtime_symbol": runtime_symbol,
        "symbol_hint": symbol_hint,
        **result,
        "warnings": warnings,
    }


def _resolve_binary(cfg: Config, module_name: str, explicit: str) -> Path:
    if explicit and explicit.strip():
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise DecompError(f"binary does not exist or is not a regular file: {path}")
        return path

    root = Path(cfg.symbols_dir)
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
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file():
            return resolved
    raise DecompError(
        f"no cached PE for live module {module_name!r}. Before attaching, run "
        "`kdbg_user_symbols_load` for that module, or pass `binary` as the "
        "exact host-side PE path."
    )


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DecompError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise DecompError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _nearest_symbol_hint(
    store: SymbolStore, module_name: str, rva: int
) -> dict[str, object] | None:
    """Return a bounded PDB-public hint for Ghidra's missed-function case."""
    normalized = module_name.lower()
    if normalized.startswith("ntoskrnl") or normalized.startswith("ntkrnl"):
        keys = ["nt"]
    else:
        keys = [Path(normalized).stem, normalized]
    for key in keys:
        try:
            symbols = store.load(key).get("symbols", {})
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
        # A far-away public is more likely the previous unrelated symbol than
        # a useful function boundary. Never let it create a giant function.
        if offset > 64 * 1024:
            return None
        return {
            "module": key,
            "name": best_name,
            "rva": best_rva,
            "offset": offset,
        }
    return None
