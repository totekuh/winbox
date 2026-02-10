"""VM infrastructure — lifecycle, guest agent, SMB."""

from winbox.vm.lifecycle import VM, VMState
from winbox.vm.guest import ExecResult, GuestAgent, GuestAgentError
from winbox.vm import smb

__all__ = ["VM", "VMState", "ExecResult", "GuestAgent", "GuestAgentError", "smb"]
