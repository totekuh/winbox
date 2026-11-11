"""QEMU Guest Agent interface over virtio-serial."""

from __future__ import annotations

import base64
import time
import uuid
from typing import TYPE_CHECKING

from winbox.vm.guest_types import (  # noqa: F401 — re-exported
    ExecResult,
    GuestAgentError,
    GuestAgentUnreachable,
    GuestExecAbandoned,
    GuestExecTimeout,
    RUNEX_PATH,
    _LAUNCH_RETRIES,
    _LAUNCH_RETRY_DELAY,
    _MAX_STALE_DISCARDS,
    _MAX_TRANSIENT_ERRORS,
    _NEVER_SPAWNED_PID,
    _UNKNOWN_PID_PROBE_ATTEMPTS,
    _clixml_to_text,
    _decode_b64,
    _decode_clixml_escapes,
    _normalized_runex_exitcode,
    _runex_args,
    _strip_nonce,
    _validate_credentials,
)
from winbox.vm.guest_transport import GuestAgentBase

if TYPE_CHECKING:
    from winbox.config import Config


class GuestAgent(GuestAgentBase):
    """Communicates with the Windows VM via QEMU Guest Agent (virtio-serial)."""

    def exec_detached(
        self,
        command: str,
        *,
        user: str | None = None,
        password: str | None = None,
    ) -> int:
        """Fire a command in the guest and return immediately.

        Returns the guest PID. No output capture, no polling — the process
        runs in the background until it exits on its own.
        """
        _validate_credentials(user, password)
        path, args = "cmd.exe", ["/c", command]
        if user is not None:
            path = RUNEX_PATH
            args = _runex_args(
                user,
                password,
                "cmd.exe",
                ["/d", "/s", "/c", command],
            )
        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": path,
                "arg": args,
                "capture-output": False,
            },
        }
        return self._start_guest_exec(payload)

    def exec_background(
        self,
        command: str,
        *,
        user: str | None = None,
        password: str | None = None,
    ) -> int:
        """Start a command with output capture but don't poll for completion.

        Returns the guest PID immediately. Output stays buffered in the
        guest agent until retrieved via exec_status().
        """
        _validate_credentials(user, password)
        path, args = "cmd.exe", ["/c", command]
        if user is not None:
            path = RUNEX_PATH
            args = _runex_args(
                user,
                password,
                "cmd.exe",
                ["/d", "/s", "/c", command],
            )
        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": path,
                "arg": args,
                "capture-output": True,
            },
        }
        return self._start_guest_exec(payload)

    def exec(
        self,
        command: str,
        *,
        timeout: int = 300,
        poll_interval: float = 0.5,
        user: str | None = None,
        password: str | None = None,
    ) -> ExecResult:
        """Execute a command in the guest via cmd.exe and return the result."""
        _validate_credentials(user, password)
        if poll_interval <= 0:
            poll_interval = 0.5

        if user is not None:
            return self.exec_argv(
                RUNEX_PATH,
                _runex_args(
                    user,
                    password,
                    "cmd.exe",
                    ["/d", "/s", "/c", command],
                ),
                timeout=timeout,
                poll_interval=poll_interval,
            )

        nonce = f"__wbx{uuid.uuid4().hex[:16]}__"
        tagged = f"echo {nonce}&&{command}"

        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": "cmd.exe",
                "arg": ["/c", tagged],
                "capture-output": True,
            },
        }
        pid = self._start_guest_exec(payload)

        def resolve(ret: dict) -> dict | None:
            return ret if nonce in _decode_b64(ret.get("out-data", "")) else None

        deadline = time.monotonic() + timeout
        ret = self._poll_exec(
            pid, deadline=deadline, timeout=timeout,
            poll_interval=poll_interval, resolve=resolve,
        )
        stdout = _decode_b64(ret.get("out-data", ""))
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
        user: str | None = None,
        password: str | None = None,
    ) -> ExecResult:
        """Execute a command by passing path and args directly to guest-exec."""
        _validate_credentials(user, password)
        if poll_interval <= 0:
            poll_interval = 0.5

        launch_path, launch_args = path, list(args)
        if user is not None:
            launch_path = RUNEX_PATH
            launch_args = _runex_args(
                user,
                password,
                path,
                list(args),
            )
        payload = {
            "execute": "guest-exec",
            "arguments": {
                "path": launch_path,
                "arg": launch_args,
                "capture-output": True,
            },
        }
        pid = self._start_guest_exec(payload)

        first_poll = True

        def resolve(ret: dict) -> dict | None:
            nonlocal first_poll
            if not first_poll:
                return ret
            first_poll = False
            try:
                behind = self._raw_command({
                    "execute": "guest-exec-status",
                    "arguments": {"pid": pid},
                })
            except GuestAgentError:
                return ret
            behind_ret = behind.get("return", {})
            if behind_ret.get("exited"):
                return behind_ret
            if not self._errors_on_unknown_pid():
                return ret
            return None

        deadline = time.monotonic() + timeout
        ret = self._poll_exec(
            pid, deadline=deadline, timeout=timeout,
            poll_interval=poll_interval, resolve=resolve,
        )

        exitcode = ret.get("exitcode", -1)
        stdout = _decode_b64(ret.get("out-data", ""))
        stderr = _decode_b64(ret.get("err-data", ""))
        if user is not None or path.casefold() == RUNEX_PATH.casefold():
            exitcode = _normalized_runex_exitcode(
                exitcode, stdout, stderr,
            )

        return ExecResult(exitcode=exitcode, stdout=stdout, stderr=stderr)

    def exec_powershell(
        self,
        script: str,
        *,
        timeout: int = 600,
        user: str | None = None,
        password: str | None = None,
    ) -> ExecResult:
        """Execute a PowerShell command/script in the guest."""
        script = f"$ProgressPreference = 'SilentlyContinue'\n{script}"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        if user is None and password is None:
            result = self.exec(cmd, timeout=timeout)
        else:
            result = self.exec(
                cmd, timeout=timeout, user=user, password=password,
            )
        return ExecResult(
            exitcode=result.exitcode,
            stdout=result.stdout,
            stderr=_clixml_to_text(result.stderr),
        )

    def exec_powershell_file(
        self,
        path: str,
        *,
        timeout: int = 600,
        user: str | None = None,
        password: str | None = None,
    ) -> ExecResult:
        """Execute a PowerShell script file in the guest."""
        kwargs = {"timeout": timeout}
        if user is not None or password is not None:
            kwargs.update(user=user, password=password)
        return self.exec_argv(
            "powershell.exe",
            ["-ExecutionPolicy", "Bypass", "-File", path],
            **kwargs,
        )

    def exec_powershell_background(
        self,
        script: str,
        *,
        user: str | None = None,
        password: str | None = None,
    ) -> int:
        """Launch a PowerShell script fire-and-forget; return the guest PID."""
        script = f"$ProgressPreference = 'SilentlyContinue'\n{script}"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        kwargs = {}
        if user is not None or password is not None:
            kwargs.update(user=user, password=password)
        return self.exec_background(
            f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            **kwargs,
        )

    def shutdown(self) -> None:
        """Initiate a graceful shutdown via the guest."""
        try:
            self.exec("shutdown /s /t 0", timeout=10)
        except GuestAgentError:
            pass
