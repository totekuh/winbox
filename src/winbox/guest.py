"""QEMU Guest Agent interface over virtio-serial."""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from winbox.config import Config


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
                "virsh", "qemu-agent-command", self.vm_name,
                json.dumps(payload),
                "--timeout", str(timeout),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise GuestAgentError(
                f"Guest agent command failed: {result.stderr.strip()}"
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
        elapsed = 0
        while not self.ping():
            time.sleep(interval)
            elapsed += interval
            if elapsed >= timeout:
                raise GuestAgentError(
                    f"Guest agent not responding after {timeout}s"
                )

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
        """
        # Start the process
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

        # Poll for completion
        status_payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid},
        }
        elapsed = 0.0
        while True:
            status = self._raw_command(status_payload)
            ret = status.get("return", {})
            if ret.get("exited"):
                break
            time.sleep(poll_interval)
            elapsed += poll_interval
            if elapsed >= timeout:
                raise GuestAgentError(
                    f"Command timed out after {timeout}s (PID {pid})"
                )

        # Decode output
        exitcode = ret.get("exitcode", 1)
        stdout = _decode_b64(ret.get("out-data", ""))
        stderr = _decode_b64(ret.get("err-data", ""))

        return ExecResult(exitcode=exitcode, stdout=stdout, stderr=stderr)

    def exec_powershell(
        self,
        script: str,
        *,
        timeout: int = 600,
    ) -> ExecResult:
        """Execute a PowerShell command/script in the guest."""
        # Use -EncodedCommand to avoid shell quoting issues
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        return self.exec(cmd, timeout=timeout)

    def exec_powershell_file(
        self,
        path: str,
        *,
        timeout: int = 600,
    ) -> ExecResult:
        """Execute a PowerShell script file in the guest."""
        cmd = f'powershell -ExecutionPolicy Bypass -File "{path}"'
        return self.exec(cmd, timeout=timeout)

    def shutdown(self) -> None:
        """Initiate a graceful shutdown via the guest."""
        try:
            self.exec("shutdown /s /t 0", timeout=10)
        except GuestAgentError:
            pass  # Expected — VM shuts down before we get a response


def _decode_b64(data: str) -> str:
    """Decode base64 string, return empty string if input is empty."""
    if not data:
        return ""
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return ""
