"""Hypervisor-level debugger primitives — drives QEMU's gdbstub.

The persistent RSP reader supplies coherent stateless memory reads and
EPROCESS/PEB walkers; the session daemon adds the active side: breakpoints,
single-step, register writes, and run control. QMP/HMP only controls the
gdbserver lifecycle and other non-debugger VM operations.

The MVP target is invisible-to-the-OS user-mode debugging of XDR
components (Defender, CrowdStrike, etc.) where any in-guest debugger
would be detected and tampered with by the target's anti-debug
hooks. QEMU's gdbstub sits below the OS — the guest cannot see it
through any of the standard checks (DebugObject, DebugPort,
KdDebuggerEnabled, IsDebuggerPresent, NtQueryInformationProcess).
"""

from __future__ import annotations

import importlib

__all__ = [
    "ClientError",
    "DaemonClient",
    "DaemonError",
    "DaemonSession",
    "InstallError",
    "InstallReport",
    "RspClient",
    "RspError",
    "StopReply",
    "fork_daemon",
    "install_user_breakpoint",
    "lock_path",
    "masquerade_cr3_candidates",
    "session_path",
    "sock_path",
]


_EXPORT_MODULE = {
    "ClientError": "client",
    "DaemonClient": "client",
    "DaemonError": "daemon",
    "DaemonSession": "daemon",
    "fork_daemon": "daemon",
    "lock_path": "daemon",
    "masquerade_cr3_candidates": "daemon",
    "session_path": "daemon",
    "sock_path": "daemon",
    "InstallError": "install",
    "InstallReport": "install",
    "install_user_breakpoint": "install",
    "RspClient": "rsp",
    "RspError": "rsp",
    "StopReply": "rsp",
}


def __getattr__(name: str):
    """Load debugger layers lazily to keep the read transport acyclic.

    ``winbox.kdbg.memory`` imports the lightweight reader, whose package import
    must not eagerly import ``daemon`` (the daemon itself imports
    ``winbox.kdbg``).  Public imports keep their previous API through this
    module-level lazy resolver.
    """
    module_name = _EXPORT_MODULE.get(name)
    if module_name is None:
        raise AttributeError(name)
    module = importlib.import_module(f"winbox.kdbg.debugger.{module_name}")
    value = getattr(module, name)
    globals()[name] = value
    return value
