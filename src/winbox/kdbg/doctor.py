"""Cheap, non-disruptive kdbg readiness reporting."""

from __future__ import annotations

from typing import Any

from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, format_status, query_status
from winbox.kdbg.debugger.client import DaemonClient
from winbox.kdbg.debugger.reader import reader_info
from winbox.kdbg.hmp import probe_port
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.vm import GuestAgent, VM, VMState


def collect_doctor(
    cfg: Config,
    vm: VM,
    ga: GuestAgent,
    *,
    port: int = 1234,
    catalog_revision: str,
    tool_count: int,
    version: str,
) -> dict[str, Any]:
    """Return readiness facts without opening the QEMU RSP socket.

    A listener probe would attach to QEMU's GDB stub and halt the guest, so a
    doctor report deliberately relies on the existing non-connecting host
    probe.  Likewise, stored PDB identity is labelled cached: checking the
    currently loaded kernel base requires an RSP snapshot and belongs to a
    walker/explicit refresh rather than this quick health report.
    """
    state = vm.state()
    vm_running = state == VMState.RUNNING
    agent: dict[str, Any] = {"responding": None, "error": None}
    cet: dict[str, Any] = {
        "safe_for_debug": None,
        "summary": None,
        "error": None,
    }
    if vm_running:
        try:
            agent["responding"] = bool(ga.ping())
        except Exception as exc:  # doctor reports a broken transport, never hides it
            agent["responding"] = False
            agent["error"] = str(exc)
        if agent["responding"]:
            try:
                status = query_status(ga)
                cet["safe_for_debug"] = bool(status.safe_for_debug)
                cet["summary"] = format_status(status)
            except CetSafetyError as exc:
                cet["error"] = str(exc)
            except Exception as exc:
                cet["error"] = str(exc)

    symbols: dict[str, Any] = {
        "available": False,
        "build": None,
        "base": None,
        "symbol_count": 0,
        "type_count": 0,
        "identity": "not_loaded",
        "live_base": "not_checked",
        "error": None,
    }
    try:
        info = SymbolStore(cfg.symbols_dir).info("nt")
        symbols.update({
            "available": True,
            "build": info.build or None,
            "base": f"0x{info.base:016x}" if info.base else None,
            "symbol_count": info.symbol_count,
            "type_count": info.type_count,
            "identity": "cached_unverified",
        })
    except (OSError, ValueError, KeyError, SymbolStoreError) as exc:
        symbols["error"] = str(exc)

    reader = reader_info(cfg)
    daemon_attached = DaemonClient(cfg).session_alive()
    if reader is not None:
        debugger = {
            "state": "connected",
            "listening": True,
            "host": "127.0.0.1",
            "port": reader.get("port", port),
            "owner": "persistent_reader",
            "reader": reader,
            "interactive_session": False,
        }
    else:
        listening = vm_running and probe_port("127.0.0.1", port)
        debugger = {
            "state": "listening" if listening else "stopped",
            "listening": listening,
            "host": "127.0.0.1",
            "port": port,
            "owner": "interactive_session" if daemon_attached else None,
            "reader": None,
            "interactive_session": daemon_attached,
        }

    ready = bool(
        vm_running
        and agent["responding"]
        and cet["safe_for_debug"]
        and symbols["available"]
        and not debugger["interactive_session"]
    )
    return {
        "ready": ready,
        "vm": {"name": cfg.vm_name, "state": state.value, "running": vm_running},
        "guest_agent": agent,
        "cet": cet,
        "symbols": {"nt": symbols},
        "debugger": debugger,
        "mcp": {
            "schema": "winbox.mcp/1",
            "version": version,
            "catalog_revision": catalog_revision,
            "tool_count": tool_count,
        },
        "notes": [
            "symbol identity is cached until a walker or base-refresh takes a live RSP snapshot",
        ],
    }
