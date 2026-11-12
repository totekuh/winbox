"""Unix socket server and CLI entry point for the Ghidra worker."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import signal
import socket
import sys
import threading
import time
import traceback
from pathlib import Path

from winbox.kdbg.decomp.worker._common import (
    ANALYSIS_PROFILE,
    HEARTBEAT_INTERVAL,
    MAX_REQUEST,
    WORKER_API,
    WorkerError,
    _PHASE_PROGRESS,
    _TOTAL_PHASES,
    _error_info,
    _safe_binary_name,
)
from winbox.kdbg.decomp.worker._worker import Worker


def _read_request(conn: socket.socket) -> dict:
    data = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            raise WorkerError("connection closed before request newline")
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            data = data[:newline]
            break
        if len(data) > MAX_REQUEST:
            raise WorkerError(f"request exceeds {MAX_REQUEST} bytes")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError(f"invalid request JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("op"), str):
        raise WorkerError("request must contain a string op")
    args = value.get("args") or {}
    if not isinstance(args, dict):
        raise WorkerError("request args must be an object")
    request_id = value.get("request_id")
    if (
        not isinstance(request_id, str) or not 1 <= len(request_id) <= 64
        or any(c not in "0123456789abcdef" for c in request_id)
    ):
        raise WorkerError("request_id must be 1-64 lowercase hexadecimal characters")
    return {"op": value["op"], "args": args, "request_id": request_id}


def _write_session(path: Path, value: dict) -> None:
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _serve(args) -> int:
    os.umask(0o077)
    Path.home().mkdir(parents=True, exist_ok=True, mode=0o700)
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    args.projects.mkdir(parents=True, exist_ok=True)
    os.chmod(args.socket.parent, 0o700)
    os.chmod(args.projects, 0o700)
    lock_fd = os.open(args.lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock_fd)
        return 0
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    worker = Worker(
        args.cache, args.projects, args.ghidra_install_dir,
        max_open_programs=args.max_open_programs,
    )
    try:
        with contextlib.suppress(FileNotFoundError):
            args.socket.unlink()
        listener.bind(str(args.socket))
        os.chmod(args.socket, 0o600)
        listener.listen(16)
        listener.settimeout(0.5)
        session_state = {
            "schema": "winbox.decomp-worker-session/2",
            "pid": os.getpid(),
            "backend": args.backend,
            "worker_api": WORKER_API,
            "analysis_profile": ANALYSIS_PROFILE,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "socket": str(args.socket),
            "heartbeat_at": time.time(),
            "current_operation": None,
            "last_failure": None,
        }
        session_lock = threading.Lock()

        def publish_session() -> None:
            session_state["worker_state"] = {
                "jvm_started": worker.started,
                "ghidra_version": worker.ghidra_version,
                "open_programs": len(worker.programs),
                "max_open_programs": worker.max_open_programs,
            }
            _write_session(args.session, session_state)

        def report_phase(phase: str, details: dict) -> None:
            now = time.time()
            with session_lock:
                current = session_state.get("current_operation")
                if not isinstance(current, dict):
                    return
                current.update({
                    "phase": phase,
                    "phase_started_at": now,
                    "last_progress_at": now,
                    "progress": {
                        "completed": _PHASE_PROGRESS.get(phase, 0),
                        "total": _TOTAL_PHASES,
                        "unit": "phases",
                        "determinate": False,
                    },
                })
                for key in ("binary_name", "binary_sha256"):
                    value = details.get(key)
                    if isinstance(value, str) and value:
                        current[key] = value[:260 if key == "binary_name" else 64]
                session_state["heartbeat_at"] = now
                publish_session()

        worker.progress_callback = report_phase
        with session_lock:
            publish_session()

        heartbeat_stop = threading.Event()

        def heartbeat_loop() -> None:
            while not heartbeat_stop.wait(HEARTBEAT_INTERVAL):
                with session_lock:
                    now = time.time()
                    session_state["heartbeat_at"] = now
                    current = session_state.get("current_operation")
                    if isinstance(current, dict):
                        request_id = str(current.get("request_id") or "")
                        marker = args.cache / "cancel" / request_id
                        if request_id and marker.exists():
                            current["cancellation_state"] = "requested"
                    with contextlib.suppress(OSError):
                        publish_session()

        heartbeat_thread = threading.Thread(
            target=heartbeat_loop, name="winbox-decomp-heartbeat", daemon=True,
        )
        heartbeat_thread.start()

        def stop(_signum, _frame):
            worker.shutdown = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        while not worker.shutdown:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if worker.shutdown:
                    break
                raise
            with conn:
                request = None
                try:
                    conn.settimeout(5.0)
                    request = _read_request(conn)
                    request["args"]["_request_id"] = request["request_id"]
                    now = time.time()
                    with session_lock:
                        session_state["current_operation"] = {
                            "request_id": request["request_id"], "op": request["op"],
                            "phase": "accepted", "started_at": now,
                            "phase_started_at": now, "last_progress_at": now,
                            "cancellation_state": "not_requested",
                            "binary_sha256": str(
                                request["args"].get("sha256") or ""
                            )[:64],
                            "binary_name": str(
                                _safe_binary_name(request["args"].get("binary_name"))
                            ),
                            "progress": {
                                "completed": 0, "total": _TOTAL_PHASES,
                                "unit": "phases", "determinate": False,
                            },
                        }
                        session_state["last_failure"] = None
                        session_state["heartbeat_at"] = now
                        publish_session()
                    result = worker.handle(request["op"], request["args"])
                    reply = {
                        "ok": True, "result": result,
                        "request_id": request["request_id"],
                    }
                except Exception as exc:
                    traceback.print_exc(file=sys.stderr)
                    info = _error_info(exc)
                    legacy_error = f"{type(exc).__name__}: {exc}"[:2048]
                    reply = {
                        "ok": False, "error": legacy_error,
                        "error_info": info,
                        "request_id": request.get("request_id") if request else None,
                    }
                    with session_lock:
                        status_info = dict(info)
                        raw_binary = str(
                            (request or {}).get("args", {}).get("binary") or ""
                        )
                        if raw_binary:
                            message = str(status_info.get("message") or "")
                            candidates = {raw_binary}
                            with contextlib.suppress(OSError):
                                candidates.add(str(Path(raw_binary).expanduser().resolve()))
                            for candidate in candidates:
                                message = message.replace(candidate, "<binary>")
                            status_info["message"] = message
                        session_state["last_failure"] = status_info
                finally:
                    with session_lock:
                        session_state["current_operation"] = None
                        session_state["heartbeat_at"] = time.time()
                        with contextlib.suppress(OSError):
                            publish_session()
                encoded = json.dumps(reply, separators=(",", ":")).encode("utf-8") + b"\n"
                with contextlib.suppress(OSError):
                    conn.sendall(encoded)
    finally:
        if "heartbeat_stop" in locals():
            heartbeat_stop.set()
        if "heartbeat_thread" in locals():
            heartbeat_thread.join(timeout=2.0)
        worker.close()
        listener.close()
        with contextlib.suppress(FileNotFoundError):
            args.socket.unlink()
        with contextlib.suppress(FileNotFoundError):
            args.session.unlink()
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--projects", type=Path, required=True)
    parser.add_argument("--ghidra-install-dir")
    parser.add_argument("--backend", choices=("docker", "host"), default="host")
    parser.add_argument("--max-open-programs", type=int, default=1)
    return _serve(parser.parse_args())
