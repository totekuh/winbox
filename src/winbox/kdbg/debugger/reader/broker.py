"""Server-side RSP broker process and reader-info queries."""

from __future__ import annotations

import fcntl
import json
import os
import select
import socket
import time
from contextlib import suppress
from typing import Any

from winbox.config import Config
from winbox.kdbg.admission import active_admission
from winbox.kdbg.debugger.protocol import ProtocolError, decode, encode, read_line
from winbox.kdbg.debugger.rsp import RspClient
from winbox.kdbg.debugger.reader.types import (
    ReaderError,
    SnapshotBudget,
    SnapshotBudgetError,
    _MAX_READ,
    _reply_err,
    _reply_ok,
    _runtime_dir,
    lock_path,
    session_path,
)
from winbox.kdbg.debugger.reader.local import _LocalRspSnapshot


class _ReaderBroker:
    def __init__(self, cfg: Config, rsp: RspClient, port: int):
        self.cfg = cfg
        self.rsp = rsp
        self.port = port
        self.shutdown_requested = False
        self.poisoned = False

    def _halt_snapshot(self) -> tuple:
        self.rsp.interrupt()
        stop = self.rsp.wait_for_stop(timeout=10.0)
        return stop, _LocalRspSnapshot(
            self.cfg.vm_name, self.rsp, stop,
            pagewalk=self.cfg.kdbg_pagewalk,
        )

    def serve(self, listener: socket.socket) -> None:
        listener.settimeout(0.5)
        while not self.shutdown_requested and not self.poisoned:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    conn.settimeout(30.0)
                    first = decode(read_line(conn))
                    if first.get("op") == "shutdown":
                        self.shutdown_requested = True
                        conn.sendall(encode(_reply_ok()))
                        continue
                    if first.get("op") != "begin":
                        conn.sendall(encode(_reply_err("expected begin or shutdown")))
                        continue
                    self._serve_snapshot_after_begin(conn, first)
                except (OSError, ProtocolError):
                    continue

    def _serve_snapshot_after_begin(self, conn: socket.socket, begin: dict[str, Any]) -> None:
        snapshot: _LocalRspSnapshot | None = None
        try:
            budget = SnapshotBudget.from_wire((begin.get("args") or {}).get("budget"))
            try:
                stop, snapshot = self._halt_snapshot()
            except BaseException as exc:
                with suppress(OSError):
                    conn.sendall(encode(_reply_err(
                        f"{type(exc).__name__}: {exc}"
                    )))
                self.shutdown_requested = True
                return
            started = time.monotonic()

            def budget_error(reason: str) -> SnapshotBudgetError:
                counters = snapshot.transport_counters()
                return SnapshotBudgetError(
                    reason, budget=budget,
                    read_count=counters["transport_read_count"],
                    bytes_read=counters["transport_bytes_read"],
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )

            def check_transport_fill(length: int) -> None:
                elapsed_ms = (time.monotonic() - started) * 1000
                counters = snapshot.transport_counters()
                if elapsed_ms >= budget.max_duration_ms:
                    raise budget_error("duration")
                if counters["transport_read_count"] >= budget.max_reads:
                    raise budget_error("read_count")
                if counters["transport_bytes_read"] + length > budget.max_bytes:
                    raise budget_error("bytes")

            conn.sendall(encode(_reply_ok({
                "stop": stop.raw,
                "current_cr3": f"0x{snapshot.current_cr3:x}",
                "cr3s": [f"0x{value:x}" for value in snapshot.cr3_candidates],
                "kernel_gs_bases": [
                    f"0x{value:x}" for value in snapshot.kernel_gs_bases
                ],
                "vcpu_kernel_gs_bases": [
                    {
                        "vcpu": vcpu,
                        "bases": [f"0x{value:x}" for value in bases],
                    }
                    for vcpu, bases in snapshot.vcpu_kernel_gs_bases
                ],
            })))
            while True:
                # Notice a shutdown (SIGTERM sets this) promptly even while a
                # client holds the snapshot open and idle. Returning here runs
                # the finally below, which restores registers and conts the VM
                # — so a stop_reader that escalates to SIGTERM gets a clean,
                # resumed guest instead of a SIGKILL that leaves it paused.
                if self.shutdown_requested:
                    return
                remaining = (budget.max_duration_ms / 1000) - (time.monotonic() - started)
                if remaining <= 0:
                    conn.sendall(encode(_reply_err(budget_error("duration"))))
                    return
                # Poll with select so the shutdown/budget checks run on a short
                # cadence without interrupting read_line mid-line (a recv
                # timeout there would drop its partial buffer and desync).
                try:
                    ready, _, _ = select.select([conn], [], [], min(0.5, remaining))
                except (OSError, InterruptedError):
                    return
                if not ready:
                    continue
                conn.settimeout(min(30.0, max(0.001, remaining)))
                try:
                    request = decode(read_line(conn))
                except TimeoutError:
                    with suppress(OSError):
                        conn.sendall(encode(_reply_err(budget_error("duration"))))
                    return
                op = request.get("op")
                args = request.get("args") or {}
                try:
                    if op == "read":
                        length = int(args["length"])
                        if not 0 <= length <= _MAX_READ:
                            raise ReaderError(f"invalid read length {length}")
                        cr3 = int(args["cr3"], 0)
                        address = int(args["addr"], 0)
                        if not snapshot.virtual_cache_hit(cr3, address, length):
                            check_transport_fill(length)
                        data = snapshot.read_virtual(
                            cr3, address, length,
                        )
                        conn.sendall(encode(_reply_ok({
                            "bytes": data.hex(), **snapshot.transport_counters(),
                        })))
                    elif op == "read_phys":
                        length = int(args["length"])
                        if not 0 <= length <= _MAX_READ:
                            raise ReaderError(f"invalid read length {length}")
                        check_transport_fill(length)
                        data = snapshot.read_physical(int(args["addr"], 0), length)
                        conn.sendall(encode(_reply_ok({
                            "bytes": data.hex(), **snapshot.transport_counters(),
                        })))
                    elif op == "end":
                        counters = snapshot.transport_counters()
                        snapshot.restore()
                        snapshot = None
                        try:
                            self.rsp.cont()
                        except BaseException:
                            self.poisoned = True
                            raise
                        conn.sendall(encode(_reply_ok({
                            **counters,
                            "budget": budget.public(),
                        })))
                        return
                    else:
                        conn.sendall(encode(_reply_err(f"unknown reader op {op!r}")))
                except BaseException as exc:
                    with suppress(OSError):
                        conn.sendall(encode(_reply_err(exc)))
                    if snapshot is not None and snapshot._poisoned:
                        self.poisoned = True
                        return
        finally:
            if snapshot is not None:
                try:
                    snapshot.restore()
                except BaseException:
                    self.poisoned = True
                if not self.poisoned:
                    try:
                        self.rsp.cont()
                    except BaseException:
                        self.poisoned = True


def _reader_alive(cfg: Config) -> bool:
    path = lock_path(cfg)
    if not path.exists():
        return False
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def reader_info(cfg: Config) -> dict[str, Any] | None:
    """Return verified live-broker metadata, or ``None`` when idle."""
    if not _reader_alive(cfg):
        return None
    admission = active_admission(_runtime_dir(cfg), "kdbg-snapshot")
    try:
        info = json.loads(session_path(cfg).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result = {"active": True}
        if admission is not None:
            result["snapshot"] = admission
        return result
    if not isinstance(info, dict):
        result = {"active": True}
        if admission is not None:
            result["snapshot"] = admission
        return result
    result = {"active": True, **info}
    if admission is not None:
        result["snapshot"] = admission
    return result
