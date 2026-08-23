from __future__ import annotations

import fcntl
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from winbox.config import Config
from winbox.kdbg.debugger.continue_job import (
    ContinueJobError,
    _bounded_result,
    _write,
    cancel_continue,
    poll_continue,
    start_continue,
)


class _FakeDaemon:
    """Real Unix-socket protocol peer used by the detached worker process."""

    def __init__(self, root: Path, *, block_cont: bool = False) -> None:
        self.root = root
        self.block_cont = block_cont
        self.interrupted = threading.Event()
        self.stopped = threading.Event()
        self.ops: list[str] = []
        root.mkdir(parents=True, exist_ok=True)
        self.lock_handle = (root / "kdbg.lock").open("a+b")
        fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_EX)
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(root / "kdbg.sock"))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw += chunk
            request = json.loads(raw)
            op = request["op"]
            self.ops.append(op)
            if op == "status":
                result = {
                    "state": "halted", "halted": True,
                    "session_id": "session-live", "stop_id": 1,
                }
            elif op == "interrupt":
                self.interrupted.set()
                result = {"queued": True}
            elif op == "cont":
                if self.block_cont:
                    self.interrupted.wait(5)
                    result = {
                        "reason": "interrupt", "state": "halted",
                        "session_id": "session-live", "stop_id": 2,
                    }
                else:
                    result = {
                        "reason": "bp", "state": "halted", "rip": "0x1234",
                        "session_id": "session-live", "stop_id": 2,
                    }
            else:
                conn.sendall(json.dumps({"ok": False, "error": "bad op"}).encode() + b"\n")
                return
            conn.sendall(json.dumps({"ok": True, "result": result}).encode() + b"\n")

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=1)
        self.listener.close()
        fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_UN)
        self.lock_handle.close()


def _cfg(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    cfg.root_dir = tmp_path
    return cfg


def _wait_terminal(cfg, token, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = poll_continue(cfg, token=token)
        if not result["active"]:
            return result
        time.sleep(0.02)
    pytest.fail("continue worker did not publish a terminal state")


def test_detached_continue_completes_over_real_unix_protocol(tmp_path, monkeypatch):
    # token_urlsafe may legitimately begin with '-', which must not be parsed
    # as a subprocess option.
    monkeypatch.setattr(
        "winbox.kdbg.debugger.continue_job.secrets.token_urlsafe",
        lambda _size: "-leading-dash-token",
    )
    daemon = _FakeDaemon(tmp_path)
    cfg = _cfg(tmp_path)
    try:
        started = start_continue(cfg, timeout=5)
        assert started["state"] == "starting"
        final = _wait_terminal(cfg, started["token"])
    finally:
        daemon.close()

    assert final["state"] == "completed"
    assert final["token"] == "-leading-dash-token"
    assert final["result"]["reason"] == "bp"
    assert daemon.ops.count("status") == 2
    assert daemon.ops.count("cont") == 1
    assert json.loads((tmp_path / "kdbg.cont.json").read_text())["state"] == "completed"


def test_cancel_interrupts_real_detached_continue_and_survives_new_pollers(tmp_path):
    daemon = _FakeDaemon(tmp_path, block_cont=True)
    cfg = _cfg(tmp_path)
    try:
        started = start_continue(cfg, timeout=30)
        deadline = time.monotonic() + 3
        while "cont" not in daemon.ops and time.monotonic() < deadline:
            time.sleep(0.01)
        requested = cancel_continue(cfg, token=started["token"])
        # The detached worker can publish its terminal stop before cancel()
        # reacquires the state lock. Both observations are correct.
        assert requested["state"] in {"cancel_requested", "cancelled"}
        # poll_continue has no process-local state; this is the MCP-reload path.
        final = _wait_terminal(_cfg(tmp_path), started["token"])
    finally:
        daemon.close()

    assert final["state"] == "cancelled"
    assert final["result"]["reason"] == "interrupt"
    assert daemon.ops.count("interrupt") == 1


def test_concurrent_start_is_rejected_without_second_cont(tmp_path):
    daemon = _FakeDaemon(tmp_path, block_cont=True)
    cfg = _cfg(tmp_path)
    try:
        first = start_continue(cfg, timeout=30)
        with pytest.raises(ContinueJobError, match="already active"):
            start_continue(cfg, timeout=30)
        cancel_continue(cfg, token=first["token"])
        _wait_terminal(cfg, first["token"])
    finally:
        daemon.close()
    assert daemon.ops.count("cont") == 1


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, 86401])
def test_timeout_is_strictly_bounded_before_daemon_access(tmp_path, timeout):
    with pytest.raises(ContinueJobError, match="timeout"):
        start_continue(_cfg(tmp_path), timeout=timeout)


def test_poll_rejects_wrong_token_and_repairs_dead_worker(tmp_path):
    cfg = _cfg(tmp_path)
    _write(tmp_path, {
        "schema": "winbox.kdbg-cont/1", "token": "old-token",
        "state": "running", "created_at": time.time() - 60,
        "worker_pid": 999_999_999, "result": None, "error": None,
    })
    with pytest.raises(ContinueJobError, match="does not match"):
        poll_continue(cfg, token="wrong")
    repaired = poll_continue(cfg, token="old-token")
    assert repaired["state"] == "failed"
    assert repaired["retryable"] is True


@pytest.mark.parametrize("token", [0, False, None, "x" * 129])
def test_poll_rejects_malformed_tokens(tmp_path, token):
    with pytest.raises(ContinueJobError, match="invalid continue token"):
        poll_continue(_cfg(tmp_path), token=token)


def test_persisted_result_is_bounded_but_keeps_stop_coordinates():
    result = _bounded_result({
        "reason": "bp", "rip": "0x1234", "session_id": "s", "stop_id": 7,
        "hostile": "x" * (100 * 1024),
    })
    assert result["reason"] == "bp"
    assert result["rip"] == "0x1234"
    assert result["session_id"] == "s" and result["stop_id"] == 7
    assert result["truncated"] is True
    assert result["original_bytes"] > 100 * 1024
