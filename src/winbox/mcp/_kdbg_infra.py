"""kdbg infrastructure — start, stop, status, doctor, CET, symbols, base."""

from __future__ import annotations

from typing import Any

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import _get_state, _research_ok, _research_error

from winbox.config import Config
from winbox.vm import VMState
from winbox import __version__ as _winbox_version
from winbox.kdbg import (
    SymbolLoadError as _KdbgSymbolLoadError,
    SymbolStore as _KdbgStore,
    SymbolStoreError as _KdbgStoreError,
    load_nt as _kdbg_load_nt,
    resolve_nt_base as _kdbg_resolve_nt_base,
)
from winbox.kdbg.hmp import probe_port as _kdbg_probe, HmpError as _KdbgHmpError
from winbox.kdbg.debugger.reader import (
    reader_info as _kdbg_reader_info,
    stop_reader as _kdbg_stop_reader,
)
from winbox.kdbg.pe import PeError as _KdbgPeError
from winbox.kdbg.cet import (
    CetSafetyError as _KdbgCetSafetyError,
    format_status as _kdbg_format_cet_status,
    prepare as _kdbg_prepare_cet,
    query_status as _kdbg_query_cet_status,
    restore as _kdbg_restore_cet_policy,
)
from winbox.kdbg.doctor import collect_doctor as _kdbg_collect_doctor
from winbox.kdbg.catalog import (
    MCP_CATALOG_REVISION as _MCP_CATALOG_REVISION,
    MCP_TOOL_COUNT as _MCP_TOOL_COUNT,
)


def _kdbg_hmp(vm_name: str, command: str) -> tuple[int, str, str]:
    from winbox.kdbg.hmp import hmp as _hmp_call
    return _hmp_call(vm_name, command, mode="tuple")


def _kdbg_get_store() -> _KdbgStore:
    """The symbol store, with its nt base re-pointed if ASLR moved it."""
    from winbox.kdbg.symbols import ensure_nt_base_current

    cfg, _, _ = _get_state()
    store = _KdbgStore(cfg.symbols_dir)
    ensure_nt_base_current(cfg, store)
    return store


@mcp.tool()
def kdbg_start(port: int = 1234, any_interface: bool = False) -> dict[str, Any]:
    """Start the QEMU gdb stub for hypervisor-level kernel debug.

    This exposes a gdb remote-protocol endpoint on the Kali host (inside
    the QEMU process) — completely transparent to the guest. No
    KdDebuggerEnabled flag, no bcdedit, no guest-visible artifacts. An
    external gdb client can then attach with `target remote :<port>`
    and set hardware breakpoints at any guest virtual address (kernel
    or userland). Undo with kdbg_stop().

    Args:
        port: TCP port for the gdb stub (default 1234).
        any_interface: Bind to 0.0.0.0 instead of 127.0.0.1. Exposes
            full r/w on guest kernel memory + registers to the LAN —
            opt-in only. Default False (localhost).
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return _research_error(
            f"VM is not running (state: {vm.state().value})", operation="kdbg_start"
        )

    bind = "0.0.0.0" if any_interface else "127.0.0.1"

    active_reader = _kdbg_reader_info(cfg)
    if active_reader is not None:
        owned_port = active_reader.get("port", 1234)
        return _research_error(
            f"Persistent kdbg reader already owns the gdbstub on port "
            f"{owned_port}. Call kdbg_stop() first.", operation="kdbg_start"
        )

    if _kdbg_probe("127.0.0.1", port):
        return _research_error(
            f"Something is already listening on 127.0.0.1:{port}. "
            "Call kdbg_stop() first, or pick a different port.",
            operation="kdbg_start",
        )

    rc, out, err = _kdbg_hmp(cfg.vm_name, f"gdbserver tcp:{bind}:{port}")
    if rc != 0:
        return _research_error(
            f"Failed to start gdb stub: {err or out}", operation="kdbg_start"
        )
    if "Waiting for gdb connection" not in out:
        return _research_error(
            f"Unexpected HMP response: {out}", operation="kdbg_start"
        )

    return _research_ok({
        "listening": True, "bind": bind, "port": port,
        "lan_accessible": bool(any_interface),
        "gdb_command": (
            "gdb -ex 'set architecture i386:x86-64' "
            f"-ex 'target remote :{port}'"
        ),
    })


@mcp.tool()
def kdbg_stop() -> dict[str, Any]:
    """Stop the QEMU gdb stub. Any attached gdb session gets EOF."""
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return _research_error(
            f"VM is not running (state: {vm.state().value})", operation="kdbg_stop"
        )

    _kdbg_stop_reader(cfg)
    rc, out, err = _kdbg_hmp(cfg.vm_name, "gdbserver none")
    if rc != 0:
        return _research_error(
            f"Failed to stop gdb stub: {err or out}", operation="kdbg_stop"
        )
    return _research_ok({"stopped": True})


@mcp.tool()
def kdbg_status(port: int = 1234) -> dict[str, Any]:
    """Show whether the gdb stub is listening.

    Probes 127.0.0.1:<port> with a TCP connect. QEMU's stub only
    accepts one client at a time, so "listening but probe fails" is
    the usual signal that a gdb session is already attached.
    """
    cfg, vm, ga = _get_state()
    vm_state = vm.state()
    if vm_state != VMState.RUNNING:
        return _research_ok({
            "state": "vm_not_running", "vm_state": vm_state.value,
            "listening": False, "port": port,
        })

    active_reader = _kdbg_reader_info(cfg)
    if active_reader is not None:
        owned_port = active_reader.get("port", port)
        return _research_ok({
            "state": "connected", "listening": True, "host": "127.0.0.1",
            "port": owned_port, "owner": "persistent_reader",
        })

    if _kdbg_probe("127.0.0.1", port):
        return _research_ok({
            "state": "listening", "listening": True,
            "host": "127.0.0.1", "port": port,
        })
    return _research_ok({
        "state": "stopped", "listening": False,
        "host": "127.0.0.1", "port": port,
    })


@mcp.tool()
def kdbg_doctor(port: int = 1234) -> dict[str, Any]:
    """Fast, non-disruptive kdbg readiness report.

    Reports VM and guest-agent reachability, CET safety, cached nt symbol
    identity, gdbstub/reader ownership, and this MCP catalog revision.  It
    never attaches to the RSP socket or stops the guest.  Consequently,
    ``symbols.nt.live_base`` is honestly ``not_checked``: a walker or explicit
    base refresh performs that live RSP verification.
    """
    cfg, vm, ga = _get_state()
    try:
        return _research_ok(_kdbg_collect_doctor(
            cfg, vm, ga, port=port,
            catalog_revision=_MCP_CATALOG_REVISION,
            tool_count=_MCP_TOOL_COUNT,
            version=_winbox_version,
        ))
    except Exception as exc:
        return _research_error(exc, operation="kdbg_doctor")


@mcp.tool()
def kdbg_cet_status() -> dict[str, Any]:
    """Report whether Windows CET state is safe for QEMU GDB stop/resume.

    Repeated debug stops on affected QEMU/KVM versions can bugcheck Windows
    while UserShadowStack is active. This read-only check must report OFF
    before kdbg memory/walker/attach operations are allowed.
    """
    _, _, ga = _mcp_common._ensure_vm_ready()
    try:
        status = _kdbg_query_cet_status(ga)
    except _KdbgCetSafetyError as exc:
        return _research_error(exc, operation="kdbg_cet_status")
    return _research_ok({
        "safe_for_debug": bool(status.safe_for_debug),
        "summary": _kdbg_format_cet_status(status),
    })


@mcp.tool()
def kdbg_prepare(confirm: bool = False) -> dict[str, Any]:
    """Hide CET-SS from the VM for stable kdbg use; reboot required.

    This weakens a Windows exploit mitigation, so ``confirm`` must be true.
    The original raw Windows policy and libvirt CPU XML are backed up on the
    host and can be restored with ``kdbg_restore_cet``.
    """
    if not confirm:
        return _research_error(
            "refused: this disables Windows CET UserShadowStack and hides "
            "the VM cet-ss CPU feature; "
            "call again with confirm=true, then reboot the VM",
            operation="kdbg_prepare",
        )
    cfg, _, ga = _mcp_common._ensure_vm_ready()
    _kdbg_stop_reader(cfg)
    try:
        backup = _kdbg_prepare_cet(cfg, ga)
    except _KdbgCetSafetyError as exc:
        return _research_error(exc, operation="kdbg_prepare")
    if backup is None:
        return _research_ok({"changed": False, "safe_for_debug": True})
    return _research_ok({
        "changed": True, "backup": str(backup), "reboot_required": True,
    })


@mcp.tool()
def kdbg_restore_cet(confirm: bool = False) -> dict[str, Any]:
    """Restore the CET policy backed up by ``kdbg_prepare``; reboot required."""
    if not confirm:
        return _research_error(
            "refused: call again with confirm=true to restore the CET policy",
            operation="kdbg_restore_cet",
        )
    cfg, _, ga = _mcp_common._ensure_vm_ready()
    _kdbg_stop_reader(cfg)
    try:
        _kdbg_restore_cet_policy(cfg, ga)
    except _KdbgCetSafetyError as exc:
        return _research_error(exc, operation="kdbg_restore_cet")
    return _research_ok({"restored": True, "reboot_required": True})


@mcp.tool()
def kdbg_symbols_load() -> dict[str, Any]:
    """Load symbols + struct offsets for nt.

    Pulls ntoskrnl.exe from the running VM, fetches ntkrnlmp.pdb from
    Microsoft's symbol server, extracts public symbols and key struct
    layouts (EPROCESS/KPROCESS/KTHREAD/LDR_DATA_TABLE_ENTRY/etc),
    resolves the live load base via the IDT, and persists everything
    to ``~/.winbox/symbols/``.

    The map itself is never returned inline - use ``kdbg_sym`` and
    ``kdbg_struct`` for lookups.
    """
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    store = _kdbg_get_store()
    try:
        info = _kdbg_load_nt(cfg, ga, store)
    except (_KdbgSymbolLoadError, _KdbgStoreError, _KdbgPeError) as e:
        return _research_error(e, operation="kdbg_symbols_load")
    return _research_ok({
        "module": "nt", "build": info.build,
        "symbol_count": info.symbol_count, "type_count": info.type_count,
        "base": f"0x{info.base:x}" if info.base else None,
    })


@mcp.tool()
def kdbg_sym(
    name: str, search: bool = False, limit: int = 16, rva: bool = False,
) -> dict[str, Any]:
    """Resolve a kernel symbol. Use ``mod!sym`` to pick a module (default nt).

    By default returns the absolute virtual address. Pass ``rva=True`` to
    get the raw RVA (no base required). Pass ``search=True`` with a
    substring pattern to get the first ``limit`` matches.

    Args:
        name: Symbol name (e.g. 'NtCreateFile', 'nt!PsActiveProcessHead').
        search: If True, treat ``name`` as a substring pattern.
        limit: Max results when searching (default 16).
        rva: Return RVA instead of absolute VA.
    """
    from winbox.kdbg.format import format_sym

    store = _kdbg_get_store()
    try:
        lines = format_sym(store, name, search=search, limit=limit, rva=rva)
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_sym")
    if not lines:
        return _research_error(f"no matches for {name}", operation="kdbg_sym")
    return _research_ok({"query": name, "matches": lines})


@mcp.tool()
def kdbg_struct(
    type_name: str, field: str = "", module: str = "nt",
) -> dict[str, Any]:
    """Return a struct layout or a single field offset from the symbol store.

    Without ``field``, returns the whole struct as a compact list of
    ``name +0xoffset type`` lines. With ``field``, returns just
    ``off=0xN type=...`` for that one member.

    Args:
        type_name: Struct type name (e.g. '_EPROCESS').
        field: Optional field name to look up by itself.
        module: Module the type lives in (default 'nt').
    """
    from winbox.kdbg.format import format_struct

    store = _kdbg_get_store()
    try:
        lines = format_struct(store, type_name, field=field or None, module=module)
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_struct")
    return _research_ok({
        "module": module, "type": type_name, "field": field or None,
        "lines": lines,
    })


@mcp.tool()
def kdbg_base_refresh() -> dict[str, Any]:
    """Re-resolve and persist the nt load base from the live guest.

    ASLR re-randomizes the kernel base on every reboot. After a VM
    reboot the cached symbol map still has the old base — this call
    re-reads the IDT, computes the fresh base, and updates the store.
    """
    cfg, vm, _ = _get_state()
    state = vm.state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        return _research_error(
            f"VM is not running (state: {state.value})", operation="kdbg_base_refresh"
        )
    store = _kdbg_get_store()
    try:
        data = store.load("nt")
    except _KdbgStoreError as e:
        return _research_error(e, operation="kdbg_base_refresh")
    try:
        base = _kdbg_resolve_nt_base(cfg, data.get("symbols", {}))
    except Exception as e:
        return _research_error(
            f"could not resolve nt base: {e}", operation="kdbg_base_refresh"
        )
    store.set_base("nt", base)
    return _research_ok({"module": "nt", "base": f"0x{base:x}"})
