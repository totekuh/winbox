from __future__ import annotations

import fcntl
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from winbox.config import Config
from winbox.kdbg.debugger.client import ClientError
from winbox.kdbg.debugger.continue_job import (
    ACTIVE_STATES,
    SCHEMA,
    ContinueJobError,
    _bounded_result,
    _read,
    _run_worker,
    _write,
    cancel_continue,
    poll_continue,
    start_continue,
    wait_continue,
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


# ── _run_worker unit tests ─────────────────────────────────────────────


def _seed_state(root, token="T1", state="starting", **extra):
    record = {
        "schema": SCHEMA, "token": token, "state": state,
        "created_at": time.time(), "updated_at": time.time(),
        "timeout": 10.0, "worker_pid": None, "daemon_session_id": "sess1",
        "start_stop_id": 1, "result": None, "error": None, "retryable": False,
    }
    record.update(extra)
    _write(root, record)
    return record


class _MockClient:
    def __init__(self, *, status_result=None, cont_result=None, cont_error=None):
        self._status = status_result or {"session_id": "sess1", "run_state": "halted"}
        self._cont = cont_result or {"stop_kind": "swbreak", "signal": 5}
        self._cont_error = cont_error

    def call(self, op, **kwargs):
        if op == "status":
            return self._status
        if op == "cont":
            if self._cont_error:
                raise self._cont_error
            return self._cont
        return {}


class TestRunWorker:

    def test_token_mismatch_before_run(self, tmp_path):
        _seed_state(tmp_path, token="AAAA")
        rc = _run_worker(tmp_path, "BBBB", 10.0, "sess1")
        assert rc == 2
        record = _read(tmp_path)
        assert record["state"] == "starting"

    def test_cont_succeeds(self, tmp_path, monkeypatch):
        import winbox.kdbg.debugger.continue_job as mod
        _seed_state(tmp_path, token="T1")
        monkeypatch.setattr(mod, "DaemonClient", lambda cfg: _MockClient())
        rc = _run_worker(tmp_path, "T1", 10.0, "sess1")
        assert rc == 0
        record = _read(tmp_path)
        assert record["state"] == "completed"
        assert record["result"]["stop_kind"] == "swbreak"
        assert record["error"] is None
        assert record["retryable"] is False

    def test_session_id_changed(self, tmp_path, monkeypatch):
        import winbox.kdbg.debugger.continue_job as mod
        _seed_state(tmp_path, token="T1")
        monkeypatch.setattr(
            mod, "DaemonClient",
            lambda cfg: _MockClient(status_result={"session_id": "different"}),
        )
        rc = _run_worker(tmp_path, "T1", 10.0, "sess1")
        assert rc == 0
        record = _read(tmp_path)
        assert record["state"] == "failed"
        assert "session changed" in record["error"]

    def test_client_error_on_cont(self, tmp_path, monkeypatch):
        import winbox.kdbg.debugger.continue_job as mod
        _seed_state(tmp_path, token="T1")
        monkeypatch.setattr(
            mod, "DaemonClient",
            lambda cfg: _MockClient(cont_error=ClientError("socket timeout")),
        )
        rc = _run_worker(tmp_path, "T1", 10.0, "sess1")
        assert rc == 0
        record = _read(tmp_path)
        assert record["state"] == "failed"
        assert "timeout" in record["error"]
        assert record["retryable"] is True

    def test_cancel_requested_becomes_cancelled(self, tmp_path, monkeypatch):
        import winbox.kdbg.debugger.continue_job as mod
        _seed_state(tmp_path, token="T1")
        real_read = mod._read
        call_count = [0]

        def patched_read(root):
            call_count[0] += 1
            record = real_read(root)
            if record and call_count[0] >= 2:
                record["state"] = "cancel_requested"
            return record

        monkeypatch.setattr(mod, "_read", patched_read)
        monkeypatch.setattr(mod, "DaemonClient", lambda cfg: _MockClient())
        rc = _run_worker(tmp_path, "T1", 10.0, "sess1")
        assert rc == 0
        record = real_read(tmp_path)
        assert record["state"] == "cancelled"
        assert record["result"]["stop_kind"] == "swbreak"

    def test_token_mismatch_after_run(self, tmp_path, monkeypatch):
        import winbox.kdbg.debugger.continue_job as mod
        _seed_state(tmp_path, token="T1")
        real_read = mod._read
        call_count = [0]

        def patched_read(root):
            call_count[0] += 1
            record = real_read(root)
            if record and call_count[0] >= 2:
                record["token"] = "STOLEN"
            return record

        monkeypatch.setattr(mod, "_read", patched_read)
        monkeypatch.setattr(mod, "DaemonClient", lambda cfg: _MockClient())
        rc = _run_worker(tmp_path, "T1", 10.0, "sess1")
        assert rc == 3


class TestWaitAndCancel:

    def test_wait_continue_immediate_terminal(self, tmp_path):
        cfg = _cfg(tmp_path)
        _seed_state(tmp_path, token="T1", state="completed",
                    result={"stop_kind": "swbreak"})
        result = wait_continue(cfg, token="T1", timeout=1.0)
        assert result["state"] == "completed"
        assert result["active"] is False

    def test_wait_continue_timeout(self, tmp_path):
        cfg = _cfg(tmp_path)
        _seed_state(tmp_path, token="T1", state="running", worker_pid=999_999_999)
        result = wait_continue(cfg, token="T1", timeout=0.15)
        assert result["state"] == "failed"

    def test_cancel_interrupt_failure_rolls_back(self, tmp_path, monkeypatch):
        import winbox.kdbg.debugger.continue_job as mod
        cfg = _cfg(tmp_path)
        _seed_state(tmp_path, token="T1", state="running",
                    worker_pid=999_999_999)
        monkeypatch.setattr(
            mod, "DaemonClient",
            lambda cfg: type("C", (), {
                "call": lambda self, op, **kw: (_ for _ in ()).throw(
                    ClientError("socket gone")
                ),
            })(),
        )
        monkeypatch.setattr(mod, "_worker_alive", lambda pid, token: True)
        with pytest.raises(ContinueJobError, match="socket gone"):
            cancel_continue(cfg, token="T1")
        record = _read(tmp_path)
        assert record["state"] == "running"
