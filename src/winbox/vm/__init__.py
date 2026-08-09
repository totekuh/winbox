"""VM infrastructure — lifecycle, guest agent."""

from winbox.vm.lifecycle import VM, VMState, virsh_run
from winbox.vm.guest import (
    ExecResult,
    GuestAgent,
    GuestAgentError,
    GuestAgentUnreachable,
    GuestExecAbandoned,
    GuestExecTimeout,
)

__all__ = [
    "VM", "VMState", "virsh_run",
    "ExecResult", "GuestAgent", "GuestAgentError",
    "GuestAgentUnreachable", "GuestExecAbandoned", "GuestExecTimeout",
]
