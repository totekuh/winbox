"""VM infrastructure — lifecycle, guest agent."""

from winbox.vm.lifecycle import VM, VMState
from winbox.vm.guest import ExecResult, GuestAgent, GuestAgentError

__all__ = ["VM", "VMState", "ExecResult", "GuestAgent", "GuestAgentError"]
