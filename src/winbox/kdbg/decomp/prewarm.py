"""Detached entry point for attach-time Ghidra prewarming."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import signal
import threading
import time
from pathlib import Path

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient
from winbox.kdbg.decomp.service import (
    PREPARE_JOB_SCHEMA,
    _process_start_ticks,
    _write_prepare_job,
    prepare_decomp,
)


_IDENTITY = re.compile(r"^[0-9a-f]{32}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--module", action="append", required=True)
    parser.add_argument("--analysis-timeout", type=int, default=900)
    parser.add_argument("--force-enrichment", action="store_true")
    args = parser.parse_args()
    if not _IDENTITY.fullmatch(args.token) or not _IDENTITY.fullmatch(args.nonce):
        parser.error("token and nonce must be 32 lowercase hexadecimal characters")
    cfg = Config(winbox_dir=args.state_root)
    path = args.state_root / "decomp" / "prepare-jobs" / f"{args.token}.json"
    cancel_path = path.with_suffix(".cancel")
    started = time.time()
    state = {
        "schema": PREPARE_JOB_SCHEMA,
        "token": args.token, "state": "running", "pid": os.getpid(),
        "nonce": args.nonce,
        "process_start_ticks": _process_start_ticks(os.getpid()),
        "modules": args.module[:256], "started_at": started,
        "heartbeat_at": started, "cancellation_state": "not_requested",
        "analysis_timeout": args.analysis_timeout,
        "force_enrichment": args.force_enrichment,
        "current_request_id": "", "current_module": "",
    }
    state_lock = threading.Lock()
    done = threading.Event()
    cancelled = threading.Event()
    cancel_forwarded = ""

    def publish(**updates) -> None:
        with state_lock:
            state.update(updates)
            snapshot = dict(state)
        _write_prepare_job(path, snapshot)

    def cancellation_marker_matches() -> bool:
        if cancel_path.is_symlink() or not cancel_path.is_file():
            return False
        try:
            if cancel_path.stat().st_size > 4096:
                return False
            marker = json.loads(cancel_path.read_text(encoding="utf-8"))
            return (
                marker.get("schema") == "winbox.decomp-prepare-cancel/1"
                and marker.get("token") == args.token
                and marker.get("nonce") == args.nonce
            )
        except (OSError, ValueError, TypeError):
            return False

    def monitor() -> None:
        nonlocal cancel_forwarded
        next_heartbeat = 0.0
        client = DecompClient(cfg)
        while not done.wait(0.1):
            if cancellation_marker_matches():
                cancelled.set()
            now = time.time()
            with state_lock:
                request_id = str(state.get("current_request_id") or "")
            if cancelled.is_set() and request_id and request_id != cancel_forwarded:
                with contextlib.suppress(Exception):
                    client.request_cancel(request_id)
                    cancel_forwarded = request_id
            if now >= next_heartbeat:
                publish(
                    state="cancelling" if cancelled.is_set() else "running",
                    cancellation_state=(
                        "requested" if cancelled.is_set() else "not_requested"
                    ),
                    heartbeat_at=now,
                )
                next_heartbeat = now + 1.0

    def progress(value: dict) -> None:
        publish(
            heartbeat_at=time.time(), current_module=value.get("module", ""),
            current_index=value.get("index"), total_modules=value.get("total"),
            current_request_id=value.get("request_id", ""),
            module_state=value.get("state", ""),
        )

    def request_shutdown(_signum, _frame) -> None:
        cancelled.set()

    previous_handlers = {
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
        signal.SIGINT: signal.getsignal(signal.SIGINT),
    }
    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    publish()
    watcher = threading.Thread(target=monitor, daemon=True)
    watcher.start()
    try:
        result = prepare_decomp(
            cfg, module=args.module, analysis_timeout=args.analysis_timeout,
            force_enrichment=args.force_enrichment,
            progress=progress, cancel_requested=cancelled.is_set,
        )
        final_state = (
            "cancelled" if cancelled.is_set()
            else "completed" if not result["failed"] else "partial"
        )
        done.set()
        publish(
            state=final_state, completed_at=time.time(), result=result,
            heartbeat_at=time.time(), current_request_id="",
            cancellation_state=(
                "completed" if cancelled.is_set() else "not_requested"
            ),
        )
    except BaseException as exc:
        done.set()
        publish(
            state="cancelled" if cancelled.is_set() else "failed",
            completed_at=time.time(), heartbeat_at=time.time(),
            current_request_id="",
            error={
                "code": str(getattr(exc, "code", None) or "operation_failed")[:64],
                "message": str(getattr(exc, "message", exc))[:2048],
            },
        )
    finally:
        done.set()
        watcher.join(timeout=2.0)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if cancel_path.is_file() and not cancel_path.is_symlink():
            with contextlib.suppress(OSError):
                cancel_path.unlink()
    return 0 if state["state"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
