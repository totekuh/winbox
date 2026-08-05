"""QEMU Guest Agent interface over virtio-serial."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from winbox.config import Config

# How many foreign (stale-slot) results `exec` will discard before giving up.
# Each discarded read frees the offending entry inside the guest agent, so in
# practice one discard is enough; the cap only bounds a pathological case.
_MAX_STALE_DISCARDS = 3


@dataclass
class ExecResult:
    """Result of a guest-exec command."""

    exitcode: int
    stdout: str
    stderr: str


class GuestAgentError(Exception):
    pass


class GuestAgent:
    """Communicates with the Windows VM via QEMU Guest Agent (virtio-serial)."""

    def __init__(self, cfg: Config) -> None:
        self.vm_name = cfg.vm_name

    def _raw_command(self, payload: dict, timeout: int = 30) -> dict:
        """Send a raw command to the guest agent and return parsed JSON."""
        result = subprocess.run(
            [
                "virsh", "-c", "qemu:///system",
                "qemu-agent-command", self.vm_name,
                json.dumps(payload),
                "--timeout", str(timeout),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or f"(virsh exit code {result.returncode})"
            raise GuestAgentError(
                f"Guest agent command failed: {error_msg}"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise GuestAgentError(f"Invalid JSON from guest agent: {e}") from e

    def ping(self) -> bool:
        """Check if the guest agent is responding."""
        try:
            self._raw_command({"execute": "guest-ping"}, timeout=5)
            return True
        except GuestAgentError:
            return False

    def wait(self, timeout: int = 120, interval: int = 2) -> None:
        """Block until the guest agent responds or timeout."""
        deadline = time.monotonic() + timeout
        while not self.ping():
            if time.monotonic() >= deadline:
                raise GuestAgentError(
                    f"Guest agent not responding after {timeout}s"
                )
            time.sleep(interval)

    def exec_detached(self, command: str) -> int:
        """Fire a command in the guest and return immediately.

        Returns the guest PID. No output capture, no polling — the process
        runs in the background until it exits on its own.
        """
        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": "cmd.exe",
                "arg": ["/c", command],
                "capture-output": False,
            },
        }
        response = self._raw_command(payload)
        pid = response.get("return", {}).get("pid")
        if pid is None:
            raise GuestAgentError("Failed to start process — no PID returned")
        return pid

    def exec_background(self, command: str) -> int:
        """Start a command with output capture but don't poll for completion.

        Returns the guest PID immediately. Output stays buffered in the
        guest agent until retrieved via exec_status().
        """
        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": "cmd.exe",
                "arg": ["/c", command],
                "capture-output": True,
            },
        }
        response = self._raw_command(payload)
        pid = response.get("return", {}).get("pid")
        if pid is None:
            raise GuestAgentError("Failed to start process — no PID returned")
        return pid

    def _kill_and_reap(self, pid: int) -> None:
        """Kill a runaway process tree and free every slot it leaves behind.

        Two slots are involved and both matter: the timed-out command's own
        buffered result, and the one the ``taskkill`` itself registers. An
        unread slot lives in the guest agent forever and becomes the orphan a
        later command inherits when Windows recycles its PID.
        """
        try:
            response = self._raw_command({
                "execute": "guest-exec",
                "arguments": {
                    # /T so children die too — otherwise they keep the
                    # inherited stdout pipe open and the agent goes on
                    # buffering their output into the orphaned slot.
                    "path": "taskkill",
                    "arg": ["/PID", str(pid), "/T", "/F"],
                    "capture-output": False,
                },
            }, timeout=5)
            kill_pid = response.get("return", {}).get("pid")
            if kill_pid is not None:
                self.reap(kill_pid)
        except Exception:
            logger.debug("taskkill of PID %s failed", pid, exc_info=True)
        self.reap(pid)

    def reap(self, pid: int, *, attempts: int = 4, interval: float = 0.25) -> None:
        """Consume a finished guest-exec result so its slot is freed.

        The guest agent keys results by Windows PID and only frees an entry
        when a status read reports ``exited``. An entry nobody reads lives
        forever — and because Windows recycles PIDs aggressively (especially
        the short-lived ``cmd.exe`` PIDs every exec here burns), a later
        command can be handed the orphan's output instead of its own. Every
        path that abandons a PID should reap it. Best-effort by design:
        failure to reap is not worth failing the caller's operation over.
        """
        for _ in range(attempts):
            try:
                if self.exec_status(pid)["exited"]:
                    return
            except Exception:
                # Deliberately broad: reap runs on error paths, where letting
                # a cleanup failure replace the caller's real exception would
                # hide the actual problem.
                logger.debug("reap of PID %s failed", pid, exc_info=True)
                return
            time.sleep(interval)

    def exec_status(self, pid: int) -> dict:
        """Query the status of a previously started guest-exec process.

        Returns dict with keys: exited (bool), exitcode (int),
        stdout (str), stderr (str).
        """
        payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid},
        }
        response = self._raw_command(payload)
        ret = response.get("return", {})
        return {
            "exited": ret.get("exited", False),
            "exitcode": ret.get("exitcode", -1),
            "stdout": _decode_b64(ret.get("out-data", "")),
            "stderr": _decode_b64(ret.get("err-data", "")),
        }

    def exec(
        self,
        command: str,
        *,
        timeout: int = 300,
        poll_interval: float = 0.5,
    ) -> ExecResult:
        """Execute a command in the guest via cmd.exe and return the result.

        Uses guest-exec to launch cmd.exe /c <command>, polls for completion,
        and decodes the base64-encoded stdout/stderr.

        The result is verified to actually be this command's. The guest agent
        keys buffered results by Windows PID and returns the *first* matching
        entry, so an abandoned result whose PID has since been recycled will
        be handed to whichever command next lands on that PID — silently
        returning another process's output and exit code. To make that
        detectable, the command is prefixed with an ``echo`` of a per-call
        nonce; a completed result that doesn't carry the nonce is not ours,
        so it is discarded (the read frees the stale entry) and polling
        continues. The nonce is stripped before returning.
        """
        if poll_interval <= 0:
            poll_interval = 0.5

        nonce = f"__wbx{uuid.uuid4().hex[:16]}__"
        # `&&` (not `&`) so the nonce is written by a command that has already
        # exited before `command` starts — no interleaving with its output.
        # No space before `&&`: `echo x && y` would emit a trailing space.
        tagged = f"echo {nonce}&&{command}"

        # Start the process
        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": "cmd.exe",
                "arg": ["/c", tagged],
                "capture-output": True,
            },
        }
        response = self._raw_command(payload)
        pid = response.get("return", {}).get("pid")
        if pid is None:
            raise GuestAgentError("Failed to start process — no PID returned")

        # Poll for completion. Tolerate up to N consecutive transient
        # errors -- a brief virtio-serial hiccup mid-poll used to abort
        # a long-running command immediately, even though the in-VM
        # process was still chugging along just fine.
        status_payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid},
        }
        deadline = time.monotonic() + timeout
        consecutive_errors = 0
        max_transient_errors = 5
        stale_discards = 0
        while True:
            try:
                status = self._raw_command(status_payload)
                consecutive_errors = 0
            except GuestAgentError:
                consecutive_errors += 1
                if consecutive_errors > max_transient_errors:
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(poll_interval)
                continue
            ret = status.get("return", {})
            if ret.get("exited"):
                stdout = _decode_b64(ret.get("out-data", ""))
                if nonce in stdout:
                    break
                # Not our result: a stale entry parked on this recycled PID.
                # Reading it above freed it, so the next poll should find
                # ours. Bail out rather than loop forever if it keeps up.
                stale_discards += 1
                logger.warning(
                    "discarded a foreign guest-exec result on PID %s "
                    "(recycled PID collided with an abandoned result); "
                    "discard %d/%d",
                    pid, stale_discards, _MAX_STALE_DISCARDS,
                )
                if stale_discards >= _MAX_STALE_DISCARDS:
                    raise GuestAgentError(
                        f"Could not obtain this command's own output on PID "
                        f"{pid} after {stale_discards} foreign results"
                    )
                continue
            if time.monotonic() >= deadline:
                self._kill_and_reap(pid)
                raise GuestAgentError(
                    f"Command timed out after {timeout}s (PID {pid})"
                )
            time.sleep(poll_interval)

        # Decode output. Use -1 as the missing-exitcode sentinel to match
        # exec_status() — a real exit 1 should not be indistinguishable from
        # "guest-exec-status didn't include exitcode". Today neither callers
        # rely on the difference, but the inconsistency was already a footgun
        # noted in code review.
        exitcode = ret.get("exitcode", -1)
        stderr = _decode_b64(ret.get("err-data", ""))

        return ExecResult(
            exitcode=exitcode, stdout=_strip_nonce(stdout, nonce), stderr=stderr
        )

    def exec_argv(
        self,
        path: str,
        args: list[str],
        *,
        timeout: int = 300,
        poll_interval: float = 0.5,
    ) -> ExecResult:
        """Execute a command by passing path and args directly to guest-exec.

        Unlike exec(), this bypasses cmd.exe entirely — no shell interpretation
        of metacharacters. Use this for direct exe calls that don't need shell
        features (pipes, redirects, cd).
        """
        if poll_interval <= 0:
            poll_interval = 0.5

        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": path,
                "arg": list(args),
                "capture-output": True,
            },
        }
        response = self._raw_command(payload)
        pid = response.get("return", {}).get("pid")
        if pid is None:
            raise GuestAgentError("Failed to start process — no PID returned")

        status_payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid},
        }
        deadline = time.monotonic() + timeout
        while True:
            status = self._raw_command(status_payload)
            ret = status.get("return", {})
            if ret.get("exited"):
                break
            if time.monotonic() >= deadline:
                self._kill_and_reap(pid)
                raise GuestAgentError(
                    f"Command timed out after {timeout}s (PID {pid})"
                )
            time.sleep(poll_interval)

        # Use -1 as the missing-exitcode sentinel; matches exec() and
        # exec_status(). A real exit 1 should not be indistinguishable
        # from "guest-exec-status didn't include exitcode".
        exitcode = ret.get("exitcode", -1)
        stdout = _decode_b64(ret.get("out-data", ""))
        stderr = _decode_b64(ret.get("err-data", ""))

        return ExecResult(exitcode=exitcode, stdout=stdout, stderr=stderr)

    def exec_powershell(
        self,
        script: str,
        *,
        timeout: int = 600,
    ) -> ExecResult:
        """Execute a PowerShell command/script in the guest.

        Progress reporting is disabled first. With stderr redirected — which
        it always is here — PowerShell serializes its progress stream as a
        CLIXML document onto stderr, so cmdlets that report progress (notably
        the Defender module's "Preparing modules for first use") buried every
        result under hundreds of bytes of XML that callers then had to treat
        as if it were an error.
        """
        # Use -EncodedCommand to avoid shell quoting issues
        script = f"$ProgressPreference = 'SilentlyContinue'\n{script}"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        result = self.exec(cmd, timeout=timeout)
        return ExecResult(
            exitcode=result.exitcode,
            stdout=result.stdout,
            stderr=_strip_clixml_progress(result.stderr),
        )

    def exec_powershell_file(
        self,
        path: str,
        *,
        timeout: int = 600,
    ) -> ExecResult:
        """Execute a PowerShell script file in the guest.

        Goes through ``exec_argv`` rather than ``exec`` so the path never
        passes through cmd.exe. The guest agent escapes embedded quotes as
        ``\\"`` when it builds the Windows command line, and cmd.exe has no
        backslash-escape rule — so it forwarded them verbatim and PowerShell
        received a path with literal quote characters in it, failing with
        "Illegal characters in path". Passing argv directly sidesteps shell
        quoting altogether, which also means paths with spaces just work.
        """
        return self.exec_argv(
            "powershell.exe",
            ["-ExecutionPolicy", "Bypass", "-File", path],
            timeout=timeout,
        )

    def shutdown(self) -> None:
        """Initiate a graceful shutdown via the guest."""
        try:
            self.exec("shutdown /s /t 0", timeout=10)
        except GuestAgentError:
            pass  # Expected — VM shuts down before we get a response


def _strip_clixml_progress(stderr: str) -> str:
    """Drop a CLIXML payload from stderr when it carries only progress records.

    Belt-and-braces alongside ``$ProgressPreference``: some cmdlets emit
    progress regardless. Anything containing a real error record is returned
    untouched — losing an actual PowerShell error to cosmetics would be a far
    worse trade than leaving some XML in place.
    """
    if not stderr or not stderr.lstrip().startswith("#< CLIXML"):
        return stderr
    # Error records serialize as <S S="Error">; progress as <Obj S="progress">.
    if 'S="Error"' in stderr or 'S="Warning"' in stderr:
        return stderr
    return ""


def _strip_nonce(stdout: str, nonce: str) -> str:
    """Remove the identity-nonce line `exec` prepends to a command's stdout.

    Drops everything up to and including the newline that terminates the
    echoed nonce, so callers see exactly the output their command produced.
    """
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
