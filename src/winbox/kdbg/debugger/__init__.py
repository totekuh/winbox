"""Hypervisor-level debugger primitives — drives QEMU's gdbstub.

Layered on top of the read-only kdbg surface (HMP memory reads, PDB
symbol resolution, EPROCESS/PEB walkers). This package adds the
*active* side: breakpoints, single-step, register write, run control.

The MVP target is invisible-to-the-OS user-mode debugging of XDR
components (Defender, CrowdStrike, etc.) where any in-guest debugger
would be detected and tampered with by the target's anti-debug
hooks. QEMU's gdbstub sits below the OS — the guest cannot see it
through any of the standard checks (DebugObject, DebugPort,
KdDebuggerEnabled, IsDebuggerPresent, NtQueryInformationProcess).
"""

from __future__ import annotations

from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.debugger.daemon import (
    DaemonError,
    DaemonSession,
    fork_daemon,
    lock_path,
    session_path,
    sock_path,
)
from winbox.kdbg.debugger.install import (
    InstallError,
    InstallReport,
    install_user_breakpoint,
)
from winbox.kdbg.debugger.rsp import (
    RspClient,
    RspError,
    StopReply,
)

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
    "session_path",
    "sock_path",
]
