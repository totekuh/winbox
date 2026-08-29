"""Cheap, non-disruptive kdbg readiness reporting."""

from __future__ import annotations

from typing import Any

from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, format_status, query_status
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.debugger.client import DaemonClient
from winbox.kdbg.debugger.reader import reader_info
from winbox.kdbg.hmp import probe_port
from winbox.kdbg.provenance import runtime_provenance
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.capture import CaptureStore
from winbox.kdbg.telemetry import summary as operation_summary
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
    package_file: str = "",
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
    decomp = _decomp_capability(cfg)
    basic_blockers = _blockers(
        vm_running=vm_running,
        agent=agent,
        cet=cet,
        symbols=symbols,
        debugger=debugger,
    )
    thread_blockers = list(basic_blockers)
    if symbols["available"] and not symbols["type_count"]:
        thread_blockers.append("nt type layouts are unavailable")
    decomp_blockers = list(basic_blockers)
    if not decomp["available"]:
        decomp_blockers.append(str(decomp["reason"]))
    if not package_file:
        from winbox import __file__ as package_file
    return {
        "ready": ready,
        "research_ready": bool(ready and decomp["available"]),
        "vm": {"name": cfg.vm_name, "state": state.value, "running": vm_running},
        "guest_agent": agent,
        "cet": cet,
        "symbols": {"nt": symbols},
        "debugger": debugger,
        "decomp": decomp,
        "capabilities": {
            "snapshot_research": {
                "available": ready,
                "blockers": basic_blockers,
            },
            "thread_research": {
                "available": not thread_blockers,
                "blockers": thread_blockers,
            },
            "interactive_debugging": {
                "available": ready,
                "blockers": basic_blockers,
            },
            "live_decompilation": {
                "available": not decomp_blockers,
                "blockers": decomp_blockers,
                "cold_policy": "warm_required",
            },
            "offline_preparation": {
                "available": bool(symbols["available"] and decomp["available"]),
                "blockers": [
                    *([] if symbols["available"] else ["nt symbols are unavailable"]),
                    *([] if decomp["available"] else [str(decomp["reason"])]),
                ],
            },
        },
        "runtime": runtime_provenance(package_file, version),
        "operations": operation_summary(cfg),
        "captures": CaptureStore(cfg).inventory(),
        "mcp": {
            "schema": "winbox.mcp/1",
            "version": version,
            "catalog_revision": catalog_revision,
            "tool_count": tool_count,
        },
        "notes": [
            "symbol identity is cached until a walker or base-refresh takes a live RSP snapshot",
            "cold live decompilation is refused by default; prepare exact artifacts offline first",
        ],
    }


def _blockers(*, vm_running, agent, cet, symbols, debugger) -> list[str]:
    blockers: list[str] = []
    if not vm_running:
        blockers.append("VM is not running")
    if agent.get("responding") is not True:
        blockers.append("guest agent is not responding")
    if cet.get("safe_for_debug") is not True:
        blockers.append("CET safety is not confirmed")
    if not symbols.get("available"):
        blockers.append("nt symbols are unavailable")
    if debugger.get("interactive_session"):
        blockers.append("an interactive debugger session owns the gdbstub")
    return blockers


def _decomp_capability(cfg: Config) -> dict[str, Any]:
    """Read decompiler prerequisites without starting the JVM or container."""
    try:
        status = DecompClient(cfg).status(quick=True)
    except (DecompError, OSError, ValueError) as exc:
        return {
            "available": False,
            "reason": f"decompiler status unavailable: {exc}",
            "next_action": "kdbg_decomp_status",
            "status": None,
        }
    backend = str(status.get("backend") or "unknown")
    if backend == "docker":
        if not status.get("docker_available"):
            reason = "Docker CLI is unavailable"
            action = "install Docker and run kdbg_decomp_status"
        elif not status.get("image_installed"):
            reason = "managed PyGhidra image is not installed"
            action = "run kdbg_ghidra_install"
        elif status.get("error"):
            reason = str(status["error"])[:512]
            action = "inspect kdbg_decomp_status"
        else:
            reason = "ready"
            action = None
    elif backend == "host":
        if not status.get("pyghidra_available"):
            reason = "PyGhidra host runtime is unavailable"
            action = "install PyGhidra or configure WINBOX_PYGHIDRA_PYTHON"
        elif status.get("error"):
            reason = str(status["error"])[:512]
            action = "inspect kdbg_decomp_status"
        else:
            reason = "ready"
            action = None
    else:
        reason = str(status.get("error") or "unknown decompiler backend")[:512]
        action = "inspect kdbg_decomp_status"
    return {
        "available": reason == "ready",
        "reason": reason,
        "next_action": action,
        "backend": backend,
        "health": status.get("health"),
        "busy": bool(status.get("busy")),
        "admission": status.get("admission"),
    }
