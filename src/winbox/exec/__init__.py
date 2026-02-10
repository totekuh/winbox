"""Execution — command runner, interactive shell."""

from winbox.exec.executor import run_command, resolve_exe
from winbox.exec.shell import open_shell

__all__ = ["run_command", "resolve_exe", "open_shell"]
