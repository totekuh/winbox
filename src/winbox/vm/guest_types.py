"""Guest-agent types, exceptions, and standalone helpers."""

from __future__ import annotations

import base64
import binascii
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# How many foreign (stale-slot) results `exec` will discard before giving up.
# Each discarded read frees the offending entry inside the guest agent, so in
# practice one discard is enough; the cap only bounds a pathological case.
_MAX_STALE_DISCARDS = 3

# A PID the guest agent cannot hold a result for: its table only contains
# processes it spawned itself, and Windows PIDs are well under this.
_NEVER_SPAWNED_PID = 0xFFFFFFF0

# How many *consecutive* failed status polls are treated as a virtio-serial
# hiccup rather than a dead agent. A long-running command used to be aborted
# by the first one, even though the in-VM process was still running fine.
_MAX_TRANSIENT_ERRORS = 5

# How many times the unknown-PID probe retries before giving up. Only an
# answer from the agent settles it; a transport failure is not an answer.
_UNKNOWN_PID_PROBE_ATTEMPTS = 3

# How many times a guest-exec *launch* is retried on a pre-launch failure (the
# GA pipe-broker race, a libvirt transport hiccup, or a call that returns no
# PID). Every one of those means nothing ran, so retrying is idempotent-safe —
# unlike anything post-launch, which may re-run a non-idempotent command.
_LAUNCH_RETRIES = 3
_LAUNCH_RETRY_DELAY = 0.5

RUNEX_PATH = r"C:\Tools\RunEx.exe"
_LOCAL_COMPUTER_NAME = "WINBOX"
_RUNEX_EXCEPTION_MARKER = "[-] RunExException:"


def _validate_credentials(user: str | None, password: str | None) -> None:
    if (user is None) != (password is None):
        raise ValueError("--user and --password must be supplied together")


def _runex_args(
    user: str,
    password: str,
    path: str,
    args: list[str],
) -> list[str]:
    if "\\" in user:
        qualifier, local_user = user.split("\\", 1)
        if qualifier == "." or qualifier.casefold() == _LOCAL_COMPUTER_NAME.casefold():
            user = local_user
    return [user, password, "-P", "-p", "--", path, *args]


def _normalized_runex_exitcode(
    exitcode: int, stdout: str, stderr: str,
) -> int:
    """Compensate for RunEx v2.1 returning zero on its own exceptions."""
    if exitcode == 0 and _RUNEX_EXCEPTION_MARKER in stdout + stderr:
        return 1
    return exitcode


_UNREACHABLE_SIGNS = (
    "not connected",
    "not responding",
    "not available",
    "failed to connect",
    "domain is not running",
    "domain not found",
)


def _is_unreachable(virsh_stderr: str) -> bool:
    """True when virsh's error means the agent was never reached."""
    lowered = virsh_stderr.lower()
    return any(sign in lowered for sign in _UNREACHABLE_SIGNS)


@dataclass
class ExecResult:
    """Result of a guest-exec command."""

    exitcode: int
    stdout: str
    stderr: str


class GuestAgentError(RuntimeError):
    """A guest-agent operation failed.

    Subclasses ``RuntimeError`` to match the convention ``lifecycle.virsh_run``
    already sets for the same subprocess, so callers don't need
    ``except (RuntimeError, GuestAgentError)``.

    The subclasses below exist for one question callers actually have to
    answer: **did the command reach the guest?** Retrying something that
    already ran means running an installer or an exploit PoC twice; declining
    to retry something that never started turns a transient into a hard
    failure. That distinction cannot be recovered from the message text —
    libvirt renders its own timeouts as "operation timed out" too, which is
    exactly how string matching got it wrong.
    """


class GuestAgentUnreachable(GuestAgentError):
    """The agent could not be reached, or answered with something unusable.

    The command did **not** run: this is raised where the transport itself
    fails, before any guest process exists. Safe to retry.
    """


class GuestExecTimeout(GuestAgentError):
    """A command exceeded its own deadline and was killed.

    It **did** run — for the full timeout — and its process tree was
    taskkill'd. Retrying re-runs a half-completed operation.
    """

    def __init__(self, message: str, pid: int | None = None) -> None:
        super().__init__(message)
        self.pid = pid


class GuestExecAbandoned(GuestAgentError):
    """A command ran but its output could not be collected.

    Raised when the transport dies mid-poll (the process is killed and reaped
    on the way out) or when the agent kept handing back another command's
    result. Like a timeout, the guest-side work already happened.
    """

    def __init__(self, message: str, pid: int | None = None) -> None:
        super().__init__(message)
        self.pid = pid


_CLIXML_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")
_CLIXML_DOC = re.compile(r"#< CLIXML\r?\n(<Objs\b.*?</Objs>)", re.DOTALL)


def _decode_clixml_escapes(text: str) -> str:
    """Undo PowerShell's ``_xHHHH_`` character escaping (e.g. ``_x000D_`` -> CR)."""
    return _CLIXML_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _clixml_to_text(stderr: str) -> str:
    """Render PowerShell's CLIXML stderr as the plain text a console would show."""
    if not stderr or "#< CLIXML" not in stderr:
        return stderr

    def _render(match: re.Match) -> str:
        try:
            root = ET.fromstring(match.group(1))
        except ET.ParseError:
            return match.group(0)
        parts = [
            _decode_clixml_escapes(child.text or "")
            for child in root
            if child.tag.rsplit("}", 1)[-1] == "S"
        ]
        return "".join(parts)

    return _CLIXML_DOC.sub(_render, stderr).strip("\r\n")


def _strip_nonce(stdout: str, nonce: str) -> str:
    """Remove the identity-nonce line `exec` prepends to a command's stdout."""
    idx = stdout.find(nonce)
    if idx == -1:
        return stdout
    rest = stdout[idx + len(nonce):]
    if rest.startswith("\r\n"):
        return rest[2:]
    if rest.startswith("\n"):
        return rest[1:]
    return rest


def _decode_b64(data: str) -> str:
    """Decode base64 string, return empty string if input is empty."""
    if not data:
        return ""
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        logger.warning("Failed to decode base64 output from guest agent")
        return ""
