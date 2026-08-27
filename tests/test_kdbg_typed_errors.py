from __future__ import annotations

import json
import hashlib
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from winbox.config import Config
from winbox.kdbg.debugger.client import ClientError, DaemonClient
from winbox.kdbg.debugger.protocol import reply_err
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.client import (
    cache_dir, lock_path, project_dir, session_path, socket_path,
)
from winbox.kdbg.decomp.worker import WorkerError, _error_info
from winbox.kdbg.errors import make_error_info, parse_error_info


def test_typed_reply_is_additive_for_legacy_clients():
    reply = reply_err(
        "plain legacy message", code="busy", retryable=True,
        details={"operation": "cont"},
    )
    assert reply["error"] == "plain legacy message"
    assert reply["error_info"] == {
        "schema": "winbox.error/1", "code": "busy",
        "message": "plain legacy message", "retryable": True,
        "details": {"operation": "cont"},
    }
    oversized = reply_err("x" * 5000, code="operation_failed")
    assert len(oversized["error"]) == 2048
    assert len(oversized["error_info"]["message"]) == 2048


def test_error_info_rejects_malformed_peer_and_bounds_untrusted_details():
    info = make_error_info(
        "m" * 5000, code="BAD CODE", details={
            "long": "x" * 5000,
            **{f"key-{index}": index for index in range(30)},
        },
    )
    assert info["code"] == "operation_failed"
    assert len(info["message"]) == 2048
    assert len(info["details"]) == 16
    assert len(info["details"]["long"]) == 512
    assert parse_error_info({"schema": "winbox.error/1", "code": "BAD"}) is None


def test_daemon_client_preserves_typed_error_without_prose_inference(
    monkeypatch, tmp_path,
):
    client = DaemonClient(Config(winbox_dir=tmp_path))
    monkeypatch.setattr(client, "session_alive", lambda: True)
    wire = json.dumps(reply_err(
        "message contains timeout and not found but is not retryable",
        code="policy_refused", retryable=False,
        details={"reason": "safe halt required"},
    )).encode() + b"\n"

    class FakeSocket:
        def __init__(self):
            self.sent = False
        def settimeout(self, _value): pass
        def connect(self, _path): pass
        def sendall(self, _payload): self.sent = True
        def recv(self, _size):
            if self.sent:
                self.sent = False
                return wire
            return b""
        def close(self): pass

    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: FakeSocket())
    with pytest.raises(ClientError) as captured:
        client.call("status")
    assert captured.value.code == "policy_refused"
    assert captured.value.retryable is False
    assert captured.value.details == {"reason": "safe halt required"}


def test_decomp_client_accepts_new_and_legacy_worker_errors(monkeypatch, tmp_path):
    monkeypatch.setenv("WINBOX_DECOMP_BACKEND", "host")
    client = DecompClient(Config(winbox_dir=tmp_path))
    monkeypatch.setattr(client, "worker_alive", lambda: True)
    monkeypatch.setattr(client, "active_backend", lambda: "host")
    from winbox.kdbg.decomp.client import WORKER_API
    monkeypatch.setattr(client, "active_worker_api", lambda: WORKER_API)

    def typed(payload, *, timeout):
        request_id = json.loads(payload)["request_id"]
        return {
            "ok": False, "request_id": request_id,
            "error": "old readable message",
            "error_info": make_error_info(
                "typed message with busy in prose", code="analysis_failed",
                details={"phase": "decompiling"},
            ),
        }

    monkeypatch.setattr(client, "_exchange", typed)
    with pytest.raises(DecompError) as captured:
        client.call("status", start=False)
    assert captured.value.code == "analysis_failed"
    assert captured.value.retryable is False
    assert captured.value.details == {"phase": "decompiling"}

    def legacy(payload, *, timeout):
        request_id = json.loads(payload)["request_id"]
        return {"ok": False, "request_id": request_id, "error": "legacy failure"}

    monkeypatch.setattr(client, "_exchange", legacy)
    with pytest.raises(DecompError) as legacy_error:
        client.call("status", start=False)
    assert legacy_error.value.code is None
    assert str(legacy_error.value) == "legacy failure"


def test_worker_error_contract_bounds_details():
    info = _error_info(WorkerError(
        "failed", code="analysis_failed", retryable=True,
        details={"phase": "x" * 1000, "nested": {"secret": "no"}},
    ))
    assert info["schema"] == "winbox.error/1"
    assert info["code"] == "analysis_failed"
    assert info["retryable"] is True
    assert len(info["details"]["phase"]) == 512
    assert "nested" not in info["details"]


def test_mcp_prefers_typed_code_over_misleading_message():
    from winbox.mcp import _research_error

    error = DecompError(
        "contains timeout busy stale and not found",
        code="analysis_failed", retryable=False,
        details={"phase": "decompiling", "huge": "z" * 5000},
    )
    reply = _research_error(error, operation="kdbg_decomp")
    assert reply["error"]["code"] == "analysis_failed"
    assert reply["error"]["retryable"] is False
    assert reply["error"]["details"]["phase"] == "decompiling"
    assert len(reply["error"]["details"]["huge"]) == 512


def test_cli_renders_stable_typed_error_code(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from winbox.cli import cli

    class RefusingClient:
        def call(self, *_args, **_kwargs):
            raise ClientError(
                "safe halt required", code="state_conflict",
                details={"state": "running"},
            )

    monkeypatch.setattr("winbox.cli.Config.load", lambda: Config(winbox_dir=tmp_path))
    monkeypatch.setattr("winbox.cli.kdbg._client", lambda _cfg: RefusingClient())
    result = CliRunner().invoke(cli, ["kdbg", "regs"])
    assert result.exit_code == 1
    assert "state_conflict: safe halt required" in result.output


def test_real_worker_publishes_heartbeat_and_typed_wire_error(monkeypatch, tmp_path):
    import winbox.kdbg.decomp.worker as worker_module

    monkeypatch.setenv("WINBOX_DECOMP_BACKEND", "host")
    monkeypatch.setenv("WINBOX_GHIDRA_PROJECT_DIR", str(tmp_path / "projects"))
    cfg = Config(winbox_dir=tmp_path / "state")
    command = [
        sys.executable, str(Path(worker_module.__file__).resolve()),
        "--socket", str(socket_path(cfg)), "--lock", str(lock_path(cfg)),
        "--session", str(session_path(cfg)), "--cache", str(cache_dir(cfg)),
        "--projects", str(project_dir()), "--max-open-programs", "2",
    ]
    process = subprocess.Popen(command)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if socket_path(cfg).exists() and session_path(cfg).exists():
                break
            time.sleep(0.02)
        assert socket_path(cfg).exists()
        status = DecompClient(cfg).status()
        assert status["health"] == "idle"
        assert status["responsive"] is True
        assert status["heartbeat_age_seconds"] < 5
        assert status["max_open_programs"] == 2

        request_id = "a" * 32
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(socket_path(cfg)))
            connection.sendall(json.dumps({
                "request_id": request_id, "op": "unknown", "args": {},
            }).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                raw += connection.recv(4096)
        reply = json.loads(raw)
        assert reply["error"].startswith("WorkerError:")
        assert reply["error_info"]["schema"] == "winbox.error/1"
        assert reply["error_info"]["code"] == "unknown_operation"

        secret_path = str(tmp_path / "caller-secret" / "missing.exe")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(socket_path(cfg)))
            connection.sendall(json.dumps({
                "request_id": "b" * 32, "op": "decompile", "args": {
                    "binary": secret_path, "binary_name": "missing.exe",
                    "sha256": "c" * 64, "rva": 0,
                },
            }).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                raw += connection.recv(4096)
        assert json.loads(raw)["error_info"]["code"] == "prerequisite_missing"
        failed_status = DecompClient(cfg).status()
        assert failed_status["last_failure"]["code"] == "prerequisite_missing"
        assert secret_path not in failed_status["last_failure"]["message"]
        assert "<binary>" in failed_status["last_failure"]["message"]

        DecompClient(cfg).call("shutdown", start=False, timeout=5)
        process.wait(timeout=5)
        assert not session_path(cfg).exists()
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_status_is_nonblocking_during_serialized_worker_phase(monkeypatch, tmp_path):
    import winbox.kdbg.decomp.worker as worker_module

    fake_modules = tmp_path / "fake-modules"
    fake_modules.mkdir()
    (fake_modules / "pyghidra.py").write_text(
        "import time\n"
        "def started(): return False\n"
        "def start(*args, **kwargs):\n"
        "    time.sleep(2)\n"
        "    raise RuntimeError('synthetic JVM failure')\n",
        encoding="utf-8",
    )
    projects = tmp_path / "projects"
    monkeypatch.setenv("WINBOX_DECOMP_BACKEND", "host")
    monkeypatch.setenv("WINBOX_PYGHIDRA_PYTHON", sys.executable)
    monkeypatch.setenv("WINBOX_GHIDRA_PROJECT_DIR", str(projects))
    cfg = Config(winbox_dir=tmp_path / "state")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(fake_modules) + os.pathsep + environment.get("PYTHONPATH", "")
    command = [
        sys.executable, str(Path(worker_module.__file__).resolve()),
        "--socket", str(socket_path(cfg)), "--lock", str(lock_path(cfg)),
        "--session", str(session_path(cfg)), "--cache", str(cache_dir(cfg)),
        "--projects", str(projects), "--max-open-programs", "2",
    ]
    process = subprocess.Popen(command, env=environment)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"exact input")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    request_id = "c" * 32
    reply = {}

    def request_analysis():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(socket_path(cfg)))
            connection.sendall(json.dumps({
                "request_id": request_id, "op": "decompile", "args": {
                    "binary": str(binary), "binary_name": "sample.exe",
                    "sha256": digest, "rva": 0,
                },
            }).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                raw += connection.recv(4096)
            reply.update(json.loads(raw))

    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not socket_path(cfg).exists():
            time.sleep(0.02)
        query = threading.Thread(target=request_analysis)
        query.start()
        observed = None
        while time.monotonic() < deadline:
            started = time.monotonic()
            status = DecompClient(cfg).status()
            status_latency = time.monotonic() - started
            current = status.get("current_operation") or {}
            if current.get("phase") == "starting_jvm":
                observed = (status, status_latency)
                break
            time.sleep(0.02)
        assert observed is not None
        status, status_latency = observed
        assert status_latency < 0.5
        assert status["health"] == "busy"
        assert status["responsive"] is True
        assert status["current_operation"]["progress"]["unit"] == "phases"

        marker = cache_dir(cfg) / "cancel" / request_id
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
        cancel_deadline = time.monotonic() + 1.5
        while time.monotonic() < cancel_deadline:
            status = DecompClient(cfg).status()
            if (status.get("current_operation") or {}).get("cancellation_state") == "requested":
                break
            time.sleep(0.05)
        assert status["current_operation"]["cancellation_state"] == "requested"
        query.join(timeout=5)
        assert not query.is_alive()
        assert reply["error_info"]["code"] == "operation_failed"
        DecompClient(cfg).call("shutdown", start=False, timeout=5)
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
