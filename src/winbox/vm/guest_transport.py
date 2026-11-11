"""Guest-agent base class: transport, launch, poll, and status machinery."""

from __future__ import annotations

import json
import logging
import subprocess
import time
from typing import TYPE_CHECKING

from winbox.vm.lifecycle import agent_channel_connected
from winbox.vm.guest_types import (
    _LAUNCH_RETRIES,
    _LAUNCH_RETRY_DELAY,
    _MAX_STALE_DISCARDS,
    _MAX_TRANSIENT_ERRORS,
    _NEVER_SPAWNED_PID,
    _UNKNOWN_PID_PROBE_ATTEMPTS,
    GuestAgentError,
    GuestAgentUnreachable,
    GuestExecAbandoned,
    GuestExecTimeout,
    _decode_b64,
    _is_unreachable,
    _normalized_runex_exitcode,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from winbox.config import Config


class GuestAgentBase:
    """Low-level guest-agent transport: command dispatch, launch, poll, reap."""

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
            message = f"Guest agent command failed: {error_msg}"
            if _is_unreachable(error_msg):
                raise GuestAgentUnreachable(message)
            raise GuestAgentError(message)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise GuestAgentUnreachable(f"Invalid JSON from guest agent: {e}") from e

    def ping(self) -> bool:
        """Whether the guest agent is ready to take a command."""
        if not agent_channel_connected(self.vm_name):
            return False
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

    def _start_guest_exec(self, payload: dict) -> int:
        """Launch a guest-exec, retrying only when the agent was never reached."""
        for attempt in range(_LAUNCH_RETRIES):
            try:
                response = self._raw_command(payload)
            except GuestAgentUnreachable as e:
                if attempt < _LAUNCH_RETRIES - 1:
                    logger.debug(
                        "guest-exec launch unreachable (attempt %d/%d), "
                        "retrying: %s", attempt + 1, _LAUNCH_RETRIES, e,
                    )
                    time.sleep(_LAUNCH_RETRY_DELAY)
                    continue
                raise
            pid = response.get("return", {}).get("pid")
            if pid is None:
                raise GuestAgentError("Failed to start process — no PID returned")
            return pid
        raise GuestAgentUnreachable("guest-exec launch exhausted retries")

    def _kill_and_reap(self, pid: int) -> None:
        """Kill a runaway process tree and free every slot it leaves behind."""
        try:
            response = self._raw_command({
                "execute": "guest-exec",
                "arguments": {
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
        """Consume a finished guest-exec result so its slot is freed."""
        for _ in range(attempts):
            try:
                if self.exec_status(pid)["exited"]:
                    return
            except Exception:
                logger.debug("reap of PID %s failed", pid, exc_info=True)
                return
            time.sleep(interval)

    def _poll_exec(
        self,
        pid: int,
        *,
        deadline: float,
        timeout: int,
        poll_interval: float,
        resolve,
    ) -> dict:
        """Poll ``guest-exec-status`` until this command's own result arrives."""
        status_payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid},
        }
        consecutive_errors = 0
        stale_discards = 0
        while True:
            try:
                status = self._raw_command(status_payload)
                consecutive_errors = 0
            except GuestAgentError as e:
                consecutive_errors += 1
                if (
                    consecutive_errors > _MAX_TRANSIENT_ERRORS
                    or time.monotonic() >= deadline
                ):
                    self._kill_and_reap(pid)
                    raise GuestExecAbandoned(
                        f"Lost contact with the guest agent while waiting on "
                        f"PID {pid}; the command had already started and has "
                        f"been killed: {e}",
                        pid=pid,
                    ) from e
                time.sleep(poll_interval)
                continue
            ret = status.get("return", {})
            if ret.get("exited"):
                try:
                    resolved = resolve(ret)
                except GuestAgentError as e:
                    self._kill_and_reap(pid)
                    raise GuestExecAbandoned(
                        f"Could not establish this command's identity on PID "
                        f"{pid}; it had already started and has been killed: "
                        f"{e}",
                        pid=pid,
                    ) from e
                if resolved is not None:
                    return resolved
                stale_discards += 1
                logger.warning(
                    "discarded a foreign guest-exec result on PID %s "
                    "(recycled PID collided with an abandoned result); "
                    "discard %d/%d",
                    pid, stale_discards, _MAX_STALE_DISCARDS,
                )
                if stale_discards >= _MAX_STALE_DISCARDS:
                    self._kill_and_reap(pid)
                    raise GuestExecAbandoned(
                        f"Could not obtain this command's own output on PID "
                        f"{pid} after {stale_discards} foreign results",
                        pid=pid,
                    )
                continue
            if time.monotonic() >= deadline:
                self._kill_and_reap(pid)
                raise GuestExecTimeout(
                    f"Command timed out after {timeout}s (PID {pid})", pid=pid
                )
            time.sleep(poll_interval)

    def _errors_on_unknown_pid(self) -> bool:
        """Does this agent report an *error* for a PID it has no entry for?"""
        last: GuestAgentUnreachable | None = None
        for attempt in range(_UNKNOWN_PID_PROBE_ATTEMPTS):
            try:
                self._raw_command({
                    "execute": "guest-exec-status",
                    "arguments": {"pid": _NEVER_SPAWNED_PID},
                }, timeout=5)
            except GuestAgentUnreachable as e:
                last = e
                if attempt < _UNKNOWN_PID_PROBE_ATTEMPTS - 1:
                    time.sleep(0.25)
                continue
            except GuestAgentError:
                return True
            return False
        raise GuestAgentUnreachable(
            f"Could not determine how the guest agent answers for an unknown "
            f"PID after {_UNKNOWN_PID_PROBE_ATTEMPTS} attempts: {last}"
        )

    def exec_status(self, pid: int) -> dict:
        """Query the status of a previously started guest-exec process."""
        payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid},
        }
        response = self._raw_command(payload)
        ret = response.get("return", {})
        stdout = _decode_b64(ret.get("out-data", ""))
        stderr = _decode_b64(ret.get("err-data", ""))
        exitcode = ret.get("exitcode", -1)
        return {
            "exited": ret.get("exited", False),
            "exitcode": _normalized_runex_exitcode(
                exitcode, stdout, stderr,
            ),
            "stdout": stdout,
            "stderr": stderr,
        }
