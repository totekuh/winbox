"""kdbg user-mode module tools — user-lm, user-symbols, read-va."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import _get_state, _research_ok, _research_error

from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStoreError as _KdbgStoreError,
    WalkCache as _KdbgWalkCache,
    copy_user_module as _kdbg_copy_user_module,
    ensure_types_loaded as _kdbg_ensure_types_loaded,
    load_module as _kdbg_load_module,
    read_virt_cr3 as _kdbg_read_virt_cr3,
)
from winbox.kdbg.debugger.reader import debug_snapshot as _kdbg_debug_snapshot
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.kdbg.pe import PeError as _KdbgPeError
from winbox.kdbg.walk import (
    find_process as _kdbg_find_process,
    list_user_modules as _kdbg_list_user_modules,
    is_wow64 as _kdbg_is_wow64,
)
from winbox.vm import VMState

from winbox.mcp._kdbg_infra import _kdbg_get_store


@mcp.tool()
def kdbg_user_lm(pid: int) -> dict[str, Any]:
    """Walk PEB.Ldr and return all user-mode modules in ``pid``.

    The user-space mirror of ``kdbg_lm``. Shows the EXE plus every DLL
    Windows mapped into the target's address space, in load order.

    The envelope result is ``{pid, modules, count, wow64}``; each module
    contains ``{base, size, name, full_path, architecture}``. WoW64 processes
    include both loader views with x86/x64 same-name DLLs kept distinct.
    ``base`` is a user VA meaningful only against that process's CR3.

    First call after a fresh VM auto-extracts the PEB struct layouts
    from the cached PDB if they're missing — no kdbg_symbols_load
    re-run needed.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_user_lm"
        )
    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
        _kdbg_ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt"
        )
    except (_KdbgStoreError, _KdbgSymbolLoadError) as e:
        return _research_error(e, operation="kdbg_user_lm")

    try:
        with _kdbg_debug_snapshot(cfg):
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(
                    f"pid {pid} not found", operation="kdbg_user_lm"
                )
            mods = _kdbg_list_user_modules(cfg.vm_name, store, target, cache=cache)
            try:
                wow64 = _kdbg_is_wow64(cfg.vm_name, store, target, cache=cache)
            except Exception:
                wow64 = False
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_user_lm")
    out = [
        {
            "base": f"0x{m.base:016x}",
            "size": f"0x{m.size:08x}",
            "name": m.name,
            "full_path": m.full_path,
            "architecture": m.architecture,
        }
        for m in mods
    ]
    result: dict = {
        "pid": pid, "modules": out, "count": len(out), "wow64": wow64,
    }
    return _research_ok(result)


@mcp.tool()
def kdbg_user_symbols_load(
    pid: int, module: str, architecture: str = "auto",
) -> dict[str, Any]:
    """Load PDB symbols for a user-mode module in ``pid``.

    Pulls the binary out of the VM via VirtIO-FS, fetches the matching
    PDB from msdl, persists it under a short module name (e.g.
    ``notepad`` for notepad.exe). Subsequent ``kdbg_sym`` calls with
    ``<short>!<symbol>`` resolve against this store.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
        module: Substring matched against PEB.Ldr BaseDllName, then
            FullDllName. Examples: 'notepad.exe', 'ntdll', 'kernelbase'.
        architecture: ``auto``, ``x86``, or ``x64``. Auto refuses an
            ambiguous same-name WoW64 match instead of mixing symbol stores.

    Returns module/build/symbol-count/base metadata in the common envelope.
    """
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
        _kdbg_ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt"
        )
    except (_KdbgStoreError, _KdbgSymbolLoadError) as e:
        return _research_error(e, operation="kdbg_user_symbols_load")

    try:
        with _kdbg_debug_snapshot(cfg):
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(
                    f"pid {pid} not found", operation="kdbg_user_symbols_load"
                )
            mods = _kdbg_list_user_modules(cfg.vm_name, store, target, cache=cache)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return _research_error(e, operation="kdbg_user_symbols_load")

    architecture = architecture.lower().strip()
    if architecture not in {"auto", "x86", "x64"}:
        return _research_error(
            "architecture must be 'auto', 'x86', or 'x64'",
            operation="kdbg_user_symbols_load",
        )
    needle = module.lower()
    matches = [m for m in mods if needle in m.name.lower()]
    if not matches:
        matches = [m for m in mods if needle in m.full_path.lower()]
    if architecture != "auto":
        matches = [m for m in matches if m.architecture == architecture]
    if not matches:
        return _research_error(
            f"no module matching {module!r} in pid {pid}",
            operation="kdbg_user_symbols_load",
        )
    identities = {(m.name.lower(), m.architecture) for m in matches}
    if architecture == "auto" and len(identities) > 1:
        choices = ", ".join(f"{name}@{arch}" for name, arch in sorted(identities))
        return _research_error(
            f"ambiguous module {module!r}; choose architecture: {choices}",
            operation="kdbg_user_symbols_load",
        )
    match = matches[0]

    short_name = match.name.rsplit(".", 1)[0].lower()
    if match.architecture == "x86":
        short_name += "_x86"
    cached_basename = match.name

    try:
        pe_path = _kdbg_copy_user_module(
            cfg, ga, match.full_path, cached_basename,
            architecture=match.architecture,
            expected_size=match.size,
        )
        info = _kdbg_load_module(
            cfg, store,
            pe_path=pe_path,
            module_name=short_name,
            base=match.base,
            wanted_types=(),
        )
    except (_KdbgSymbolLoadError, _KdbgStoreError, _KdbgPeError) as e:
        return _research_error(e, operation="kdbg_user_symbols_load")

    return _research_ok({
        "pid": pid, "module": short_name, "build": info.build,
        "symbol_count": info.symbol_count, "base": f"0x{info.base:x}",
        "architecture": match.architecture,
    })


@mcp.tool()
def kdbg_read_va(pid: int, address: str, length: int) -> dict[str, Any]:
    """Read virtual memory from an arbitrary process WITHOUT an attached
    debugger session through the persistent RSP reader.

    Looks up the target's EPROCESS, grabs its ``DirectoryTableBase``,
    temporarily selects that CR3 through QEMU's gdbstub, and reads
    ``length`` bytes at ``address``. One broker owns the single RSP client
    across calls and serializes concurrent MCP/CLI transactions.

    For in-session reads after ``kdbg_attach``, use ``kdbg_mem`` because the
    interactive daemon already owns the same gdbstub connection.

    Returns ``{pid, va, bytes}`` in the common envelope. Pair with
    ``kdbg_ps`` to find a PID first.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
        address: Virtual address, hex string (e.g. '0x7ff600001000').
        length: Number of bytes to read (capped at 1MB).
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_read_va"
        )
    if length <= 0:
        return _research_error("length must be > 0", operation="kdbg_read_va")
    if length > 1024 * 1024:
        return _research_error(
            f"length {length} too large - cap at 1MB", operation="kdbg_read_va"
        )
    try:
        va = int(address, 0)
    except ValueError:
        return _research_error(
            f"invalid address: {address!r}", operation="kdbg_read_va"
        )

    try:
        with _kdbg_debug_snapshot(cfg):
            store = _kdbg_get_store()
            cache = _KdbgWalkCache()
            target = _kdbg_find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                return _research_error(
                    f"pid {pid} not found", operation="kdbg_read_va"
                )
            data = _kdbg_read_virt_cr3(
                cfg.vm_name, target.directory_table_base, va, length, cache=cache,
            )
    except _KdbgHmpError as e:
        return _research_error(f"read failed: {e}", operation="kdbg_read_va")
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_read_va")
    return _research_ok({"pid": pid, "va": f"0x{va:x}", "bytes": data.hex()})
