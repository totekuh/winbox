"""kdbg walk tools — ps, lm, vad, token, handles, object, capture."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp._common import _get_state, _research_ok, _research_error
from winbox.mcp._kdbg_infra import _kdbg_get_store

from winbox.config import Config
from winbox.vm import VMState
from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStore as _KdbgStore,
    SymbolStoreError as _KdbgStoreError,
    WalkCache as _KdbgWalkCache,
    ensure_types_loaded as _kdbg_ensure_types_loaded,
    read_virt_cr3 as _kdbg_read_virt_cr3,
    copy_user_module as _kdbg_copy_user_module,
    load_module as _kdbg_load_module,
)
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.kdbg.pe import PeError as _KdbgPeError
from winbox.kdbg.debugger.reader import (
    debug_snapshot as _kdbg_debug_snapshot,
    snapshot_metadata as _kdbg_snapshot_metadata,
)
from winbox.kdbg.objects import (
    ObjectEvidenceError as _KdbgObjectEvidenceError,
    ensure_object_layouts as _kdbg_ensure_object_layouts,
    handle_table_status as _kdbg_handle_table_status,
    object_header as _kdbg_object_header,
    token_evidence as _kdbg_token_evidence,
)
from winbox.kdbg.vad import (
    VadError as _KdbgVadError,
    ensure_vad_layouts as _kdbg_ensure_vad_layouts,
    list_vads as _kdbg_list_vads,
    lookup_vad as _kdbg_lookup_vad,
)
from winbox.kdbg.vad_extract import (
    VadExtractError as _KdbgVadExtractError,
    VadExtractStore as _KdbgVadExtractStore,
    extract_live as _kdbg_extract_vad_live,
)
from winbox.kdbg.capture import (
    CaptureError as _KdbgCaptureError,
    CaptureStore as _KdbgCaptureStore,
    capture_live as _kdbg_capture_live,
)
from winbox.kdbg.capture_diff import diff_captures as _kdbg_diff_captures
from winbox.kdbg.walk import (
    find_process as _kdbg_find_process,
    list_modules as _kdbg_list_modules,
    list_processes as _kdbg_list_processes,
    list_user_modules as _kdbg_list_user_modules,
    is_wow64 as _kdbg_is_wow64,
)


def _kdbg_target_for_evidence(cfg: Config, store: _KdbgStore, pid: int, cache: _KdbgWalkCache):
    target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
    if target is None:
        raise _KdbgHmpError(f"pid {pid} not found")
    return target


@mcp.tool()
def kdbg_ps() -> dict[str, Any]:
    """Walk ``PsActiveProcessHead`` and return all running processes.

    The envelope result is ``{processes, count}``; each process contains
    ``{pid, dtb, eprocess, name}``. ``dtb`` is the DirectoryTableBase.

    Requires ``kdbg_symbols_load`` to have been run first.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_ps"
        )
    try:
        with _kdbg_debug_snapshot(cfg) as snapshot:
            store = _kdbg_get_store()
            procs = _kdbg_list_processes(cfg.vm_name, store)
            snapshot_metadata = _kdbg_snapshot_metadata(snapshot)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_ps")
    out = [
        {
            "pid": p.pid,
            "dtb": f"0x{p.directory_table_base:012x}",
            "eprocess": f"0x{p.eprocess:016x}",
            "name": p.name,
        }
        for p in procs
    ]
    return _research_ok({
        "processes": out, "count": len(out), "snapshot_metadata": snapshot_metadata,
    })


@mcp.tool()
def kdbg_vad(
    pid: int, address: str = "", executable: bool = False, limit: int = 128,
    probe_header: bool = False, require_complete: bool = False,
) -> dict[str, Any]:
    """Resolve one user VA or list bounded executable VAD evidence.

    The default address lookup follows only one PDB-validated AVL path.  With
    no address, returns a bounded in-order executable VAD map.  A loader miss
    remains a lead unless this walker proves a range; `private` or `image`
    labels are kernel VAD facts, not a malware verdict.

    Args:
        pid: Target process ID from kdbg_ps.
        address: Optional canonical user VA (for one direct lookup).
        executable: Include only executable mappings in map mode.
        limit: Map result cap (1..4096).
        probe_header: Read two bytes at each returned range base for MZ evidence.
        require_complete: Reject a truncated map instead of returning its prefix.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 4096:
        return _research_error("limit must be an integer between 1 and 4096", operation="kdbg_vad")
    if not isinstance(executable, bool) or not isinstance(probe_header, bool) or not isinstance(require_complete, bool):
        return _research_error("executable, probe_header, and require_complete must be booleans", operation="kdbg_vad")
    parsed_address: int | None = None
    if address:
        try:
            parsed_address = int(address, 0)
        except (TypeError, ValueError):
            return _research_error(f"invalid address: {address!r}", operation="kdbg_vad")
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_vad")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_vad_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="vad") as snapshot:
            cache = _KdbgWalkCache()
            target = _kdbg_target_for_evidence(cfg, store, pid, cache)
            if parsed_address is not None:
                record = _kdbg_lookup_vad(
                    cfg.vm_name, store, target, parsed_address, cache=cache,
                    probe_header=probe_header,
                )
                result = {
                    "pid": pid, "address": f"0x{parsed_address:016x}",
                    "found": record is not None,
                    "vad": record.public() if record is not None else None,
                    "complete": True,
                }
            else:
                walked = _kdbg_list_vads(
                    cfg.vm_name, store, target, cache=cache,
                    executable_only=executable, limit=limit, probe_header=probe_header,
                )
                if require_complete and not walked.complete:
                    error = _KdbgVadError("VAD map is incomplete")
                    error.code = "incomplete_result"
                    error.retryable = True
                    error.details = {"truncation": walked.truncation}
                    raise error
                result = {"pid": pid, "executable_only": executable, **walked.public()}
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgVadError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_vad")


@mcp.tool()
def kdbg_vad_extract(
    pid: int, address: str, name: str, length: int = 0,
    require_complete: bool = False,
) -> dict[str, Any]:
    """Extract bytes from one validated process VAD into an immutable artifact.

    The VAD proof and process-CR3 byte reads occur in one bounded stop. Raw
    bytes are never returned in MCP; the response contains only the manifest
    and mode-0600 host artifact locations. A partial normal extraction retains
    its hole map, while `require_complete=true` publishes nothing on a hole.

    Args:
        pid: Target process ID from kdbg_ps.
        address: Canonical user-mode address inside the VAD to extract from.
        name: New immutable artifact name, 1..64 safe filename characters.
        length: Byte count (1..8 MiB), or 0 for up to 1 MiB within the VAD.
        require_complete: Refuse an artifact when any selected page is unreadable.
    """
    try:
        parsed_address = int(address, 0)
    except (TypeError, ValueError):
        return _research_error(f"invalid address: {address!r}", operation="kdbg_vad_extract")
    if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= 8 * 1024 * 1024:
        return _research_error("length must be an integer between 0 and 8388608", operation="kdbg_vad_extract")
    if not isinstance(require_complete, bool):
        return _research_error("require_complete must be a boolean", operation="kdbg_vad_extract")
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_vad_extract")
    try:
        artifacts = _KdbgVadExtractStore(cfg)
        artifacts.validate_name(name)
        artifacts.ensure_available(name)
        store = _kdbg_get_store()
        extraction = _kdbg_extract_vad_live(
            cfg, store, pid=pid, address=parsed_address,
            length=(length or None), require_complete=require_complete,
        )
        saved = artifacts.save(name, extraction)
        return _research_ok({"extraction": extraction.manifest, "saved": saved})
    except (_KdbgVadExtractError, _KdbgVadError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_vad_extract")


@mcp.tool()
def kdbg_token(pid: int) -> dict[str, Any]:
    """Return PDB-backed primary-token identity and raw privilege masks."""
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_token")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_object_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="token") as snapshot:
            target = _kdbg_target_for_evidence(cfg, store, pid, _KdbgWalkCache())
            result = _kdbg_token_evidence(cfg.vm_name, store, target)
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_token")


@mcp.tool()
def kdbg_handles(pid: int) -> dict[str, Any]:
    """Return a validated process handle-table root and enumeration support state.

    Public PDBs may omit the private entry union.  In that case this returns
    the proven root and a refusal rather than guessed 16-byte slot decoding.
    """
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_handles")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_object_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="handles") as snapshot:
            target = _kdbg_target_for_evidence(cfg, store, pid, _KdbgWalkCache())
            result = _kdbg_handle_table_status(cfg.vm_name, store, target)
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_handles")


@mcp.tool()
def kdbg_object(body: str) -> dict[str, Any]:
    """Decode a kernel object header for a caller-proven object body pointer."""
    try:
        value = int(body, 0)
    except (TypeError, ValueError):
        return _research_error(f"invalid object body: {body!r}", operation="kdbg_object")
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_object")
    try:
        store = _kdbg_get_store()
        _kdbg_ensure_object_layouts(cfg, store)
        with _kdbg_debug_snapshot(cfg, operation="object") as snapshot:
            result = _kdbg_object_header(cfg.vm_name, store, value).public()
            result["snapshot_metadata"] = _kdbg_snapshot_metadata(snapshot)
        return _research_ok(result)
    except (_KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_object")


@mcp.tool()
def kdbg_capture(
    profile: str = "process", pid: int = 0, name: str = "", require_complete: bool = False,
) -> dict[str, Any]:
    """Take one bounded, immutable process or system evidence capture.

    Exact PDB extraction occurs before the single RSP stop.  Optional `name`
    atomically saves the resulting artifact under the host-owned kdbg capture
    store; without it the same bounded artifact is returned directly.
    """
    cfg, vm, _ = _get_state()
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(f"VM is not running (state: {vm.state().value})", operation="kdbg_capture")
    try:
        if not isinstance(require_complete, bool):
            raise _KdbgCaptureError("require_complete must be a boolean")
        store = _kdbg_get_store()
        capture = _kdbg_capture_live(
            cfg, store, profile=profile, pid=(pid if pid else None),
            require_complete=require_complete,
        )
        if name:
            saved = _KdbgCaptureStore(cfg).save(name, capture)
            return _research_ok({"capture": capture, "saved": saved})
        return _research_ok({"capture": capture, "saved": None})
    except (_KdbgCaptureError, _KdbgVadError, _KdbgObjectEvidenceError, _KdbgStoreError, _KdbgHmpError) as exc:
        return _research_error(exc, operation="kdbg_capture")


@mcp.tool()
def kdbg_capture_diff(
    left: str, right: str, limit: int = 128, allow_identity_mismatch: bool = False,
) -> dict[str, Any]:
    """Diff two named captures entirely offline; no VM/RSP access occurs."""
    cfg, _, _ = _get_state()
    try:
        if not isinstance(allow_identity_mismatch, bool):
            raise _KdbgCaptureError("allow_identity_mismatch must be a boolean")
        captures = _KdbgCaptureStore(cfg)
        result = _kdbg_diff_captures(
            captures.load(left), captures.load(right), limit=limit,
            allow_identity_mismatch=allow_identity_mismatch,
        )
        return _research_ok(result)
    except _KdbgCaptureError as exc:
        return _research_error(exc, operation="kdbg_capture_diff")


@mcp.tool()
def kdbg_lm() -> dict[str, Any]:
    """Walk ``PsLoadedModuleList`` and return all loaded kernel modules.

    The envelope result is ``{modules, count}``; each module contains
    ``{base, size, name}``. ``base`` is DllBase and ``size`` is SizeOfImage.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_lm"
        )
    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
            mods = _kdbg_list_modules(cfg.vm_name, store)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_lm")
    out = [
        {
            "base": f"0x{m.base:016x}",
            "size": f"0x{m.size:08x}",
            "name": m.name,
        }
        for m in mods
    ]
    return _research_ok({"modules": out, "count": len(out)})
