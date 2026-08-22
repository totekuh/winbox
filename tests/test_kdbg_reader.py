"""Unit and Unix-socket integration tests for the persistent RSP reader."""

from __future__ import annotations

import socket
import struct
import threading
import time
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from winbox.config import Config
from winbox.kdbg.debugger.install import _CR3_OFFSET_IN_G
from winbox.kdbg.debugger.reader import (
    ReaderError,
    _LocalRspSnapshot,
    _ReaderBroker,
    _RemoteSnapshot,
    _active_snapshot,
    _bind_listener,
    debug_snapshot,
    reader_info,
)
from winbox.kdbg.debugger.rsp import RspError, StopReply


def _regs(*, cr3: int, gs: int = 0, kernel_gs: int = 0) -> bytes:
    blob = bytearray(608)
    struct.pack_into("<Q", blob, 128, 0xFFFFF80000100000)  # RIP
    struct.pack_into("<I", blob, 140, 0x10)                # CS
    struct.pack_into("<Q", blob, 172, gs)
    struct.pack_into("<Q", blob, 180, kernel_gs)
    struct.pack_into("<Q", blob, _CR3_OFFSET_IN_G, cr3)
    return bytes(blob)


class FakeRsp:
    def __init__(self, *, restore_reply: bytes = b"OK"):
        self.threads = ["01", "02"]
        self.selected = "01"
        self.regs = {
            "01": _regs(cr3=0x111000, gs=0x7FF600000000,
                        kernel_gs=0xFFFFF78000000000),
            "02": _regs(cr3=0x222000, gs=0xFFFFF78000001000,
                        kernel_gs=0x7FF700000000),
        }
        self.original = dict(self.regs)
        self.restore_reply = restore_reply
        self.writes: list[bytes] = []
        self.physical_modes: list[bool] = []
        self.reads: list[tuple[int, int, int, bool]] = []
        self.interrupts = 0
        self.continues = 0
        self.continue_error: BaseException | None = None

    def list_threads(self):
        return list(self.threads)

    def select_thread(self, thread):
        self.selected = thread

    def read_registers(self):
        return self.regs[self.selected]

    def read_cr3(self):
        return struct.unpack_from(
            "<Q", self.regs[self.selected], _CR3_OFFSET_IN_G,
        )[0]

    def write_registers(self, blob):
        self.writes.append(blob)
        # Let the final exact-original restore be rejected when requested.
        if blob == self.original[self.selected] and self.restore_reply != b"OK":
            return self.restore_reply
        self.regs[self.selected] = blob
        return b"OK"

    def set_physical_memory_mode(self, enabled):
        self.physical_modes.append(enabled)

    def read_memory(self, addr, length):
        cr3 = struct.unpack_from(
            "<Q", self.regs[self.selected], _CR3_OFFSET_IN_G,
        )[0]
        physical = bool(self.physical_modes and self.physical_modes[-1])
        self.reads.append((cr3, addr, length, physical))
        return bytes((addr + offset) & 0xFF for offset in range(length))

    def interrupt(self):
        self.interrupts += 1

    def wait_for_stop(self, timeout=None):
        return StopReply(2, "01", None, "T02thread:01;")

    def cont(self):
        if self.continue_error is not None:
            raise self.continue_error
        self.continues += 1


def test_local_snapshot_collects_all_cr3_and_kernel_gs_candidates():
    rsp = FakeRsp()
    snap = _LocalRspSnapshot(
        "vm", rsp, StopReply(2, "01", None, "T02thread:01;"),
    )
    assert snap.current_cr3 == 0x111000
    assert snap.cr3_candidates == (0x111000, 0x222000)
    assert snap.kernel_gs_bases == (
        0xFFFFF78000000000, 0xFFFFF78000001000,
    )


def test_local_snapshot_reuses_masqueraded_cr3_and_restores_exact_registers():
    rsp = FakeRsp()
    snap = _LocalRspSnapshot(
        "vm", rsp, StopReply(2, "01", None, "T02thread:01;"),
    )
    assert snap.read_virtual(0xABC000, 0x1000, 4) == b"\x00\x01\x02\x03"
    snap.read_virtual(0xABC000, 0x2000, 2)
    # One CR3 write for both same-address-space reads, then one restore.
    assert len(rsp.writes) == 1
    snap.restore()
    assert len(rsp.writes) == 2
    assert rsp.writes[-1] == rsp.original["01"]


def test_physical_read_always_returns_to_virtual_mode():
    rsp = FakeRsp()
    snap = _LocalRspSnapshot(
        "vm", rsp, StopReply(2, "01", None, "T02thread:01;"),
    )
    snap.read_physical(0x3000, 2)
    assert rsp.physical_modes == [True, False]
    assert rsp.reads[-1][-1] is True


def test_physical_read_failure_still_returns_to_virtual_mode():
    rsp = FakeRsp()
    snap = _LocalRspSnapshot(
        "vm", rsp, StopReply(2, "01", None, "T02thread:01;"),
    )
    rsp.read_memory = lambda addr, length: (_ for _ in ()).throw(
        RspError("physical read failed")
    )
    with pytest.raises(RspError, match="physical read failed"):
        snap.read_physical(0x3000, 2)
    assert rsp.physical_modes == [True, False]


def test_restore_rejection_poisons_snapshot():
    rsp = FakeRsp(restore_reply=b"E22")
    snap = _LocalRspSnapshot(
        "vm", rsp, StopReply(2, "01", None, "T02thread:01;"),
    )
    snap.read_virtual(0xABC000, 0x1000, 1)
    with pytest.raises(ReaderError, match="register restore"):
        snap.restore()
    assert snap._poisoned is True


@pytest.fixture
def broker(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    rsp = FakeRsp()
    listener = _bind_listener(cfg)
    server = _ReaderBroker(cfg, rsp, 1234)
    thread = threading.Thread(target=server.serve, args=(listener,), daemon=True)
    thread.start()
    try:
        yield cfg, rsp, server
    finally:
        # Poisoned brokers exit on their own. Give the serve loop a moment to
        # observe the flag before sending shutdown; otherwise teardown can
        # connect during that tiny race, queue a request behind a server that
        # has already decided to exit, and block forever waiting for a reply.
        thread.join(0.2)
        if thread.is_alive():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            try:
                sock.connect(str(tmp_path / ".winbox" / "kdbg-reader.sock"))
                from winbox.kdbg.debugger.reader import _request
                _request(sock, "shutdown")
            except (OSError, ReaderError):
                pass
            finally:
                sock.close()
        thread.join(2)
        listener.close()


def test_real_unix_broker_transaction_reads_and_restores(broker):
    cfg, rsp, _ = broker
    snap = _RemoteSnapshot.connect(cfg)
    assert snap.cr3_candidates == (0x111000, 0x222000)
    assert snap.read_virtual(0xABC000, 0x1234, 4) == b"4567"
    assert snap.read_physical(0x2001, 3) == b"\x01\x02\x03"
    snap.close()

    assert rsp.interrupts == 1
    assert rsp.continues == 1
    assert rsp.regs["01"] == rsp.original["01"]
    assert rsp.physical_modes[-1] is False


def test_broker_disconnect_before_end_restores_and_resumes(broker):
    cfg, rsp, _ = broker
    snap = _RemoteSnapshot.connect(cfg)
    snap.read_virtual(0xABC000, 0x1000, 1)
    snap._sock.close()  # simulate client crash; no end packet
    deadline = time.monotonic() + 2
    while rsp.continues == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert rsp.regs["01"] == rsp.original["01"]
    assert rsp.continues == 1


def test_read_failure_restores_and_next_transaction_succeeds(broker):
    cfg, rsp, _ = broker
    original_read = rsp.read_memory
    failures = 1

    def fail_once(addr, length):
        nonlocal failures
        if failures:
            failures -= 1
            raise RspError("transient read failure")
        return original_read(addr, length)

    rsp.read_memory = fail_once
    snap = _RemoteSnapshot.connect(cfg)
    with pytest.raises(ReaderError, match="transient read failure"):
        snap.read_virtual(0xABC000, 0x1000, 1)
    snap.close()
    assert rsp.regs["01"] == rsp.original["01"]
    assert rsp.continues == 1

    retry = _RemoteSnapshot.connect(cfg)
    assert retry.read_virtual(0xABC000, 0x1000, 2) == b"\x00\x01"
    retry.close()
    assert rsp.continues == 2


def test_overlapping_clients_are_strictly_serialized(broker):
    cfg, rsp, _ = broker
    first = _RemoteSnapshot.connect(cfg)
    started = threading.Event()
    connected = threading.Event()
    result: list[bytes] = []

    def second_client():
        started.set()
        second = _RemoteSnapshot.connect(cfg)
        connected.set()
        result.append(second.read_virtual(0xABC000, 0x2000, 2))
        second.close()

    thread = threading.Thread(target=second_client)
    thread.start()
    assert started.wait(1)
    assert not connected.wait(0.1), "second transaction overlapped the first"
    first.close()
    assert connected.wait(2)
    thread.join(2)

    assert not thread.is_alive()
    assert result == [b"\x00\x01"]
    assert rsp.interrupts == 2
    assert rsp.continues == 2


def test_remote_snapshot_close_is_idempotent(broker):
    cfg, rsp, _ = broker
    snap = _RemoteSnapshot.connect(cfg)
    snap.close()
    snap.close()
    assert rsp.continues == 1


def test_resume_failure_poisons_broker_after_explicit_end(broker):
    cfg, rsp, server = broker
    snap = _RemoteSnapshot.connect(cfg)
    rsp.continue_error = RspError("continue failed")
    with pytest.raises(ReaderError, match="continue failed"):
        snap.close()
    deadline = time.monotonic() + 2
    while not server.poisoned and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.poisoned is True
    assert rsp.regs["01"] == rsp.original["01"]
    assert rsp.continues == 0


def test_resume_failure_poisons_broker_after_client_disconnect(broker):
    cfg, rsp, server = broker
    snap = _RemoteSnapshot.connect(cfg)
    snap.read_virtual(0xABC000, 0x1000, 1)
    rsp.continue_error = RspError("continue failed")
    snap._sock.close()
    deadline = time.monotonic() + 2
    while not server.poisoned and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.poisoned is True
    assert rsp.regs["01"] == rsp.original["01"]
    assert rsp.continues == 0


def test_debug_snapshot_nesting_reuses_one_remote_transaction(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    fake = SimpleNamespace(vm_name=cfg.vm_name)
    calls = {"connect": 0, "close": 0}

    monkeypatch.setattr(
        "winbox.kdbg.debugger.reader.ensure_reader", lambda cfg, port=1234: None,
    )
    def connect(_cfg):
        calls["connect"] += 1
        fake.close = lambda: calls.__setitem__("close", calls["close"] + 1)
        return fake
    monkeypatch.setattr(
        "winbox.kdbg.debugger.reader._RemoteSnapshot.connect", connect,
    )

    with debug_snapshot(cfg) as outer:
        with debug_snapshot(cfg) as inner:
            assert inner is outer
            assert _active_snapshot.get() is outer
    assert calls == {"connect": 1, "close": 1}


def test_debug_snapshot_reconnects_once_after_stale_broker(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    fake = SimpleNamespace(vm_name=cfg.vm_name, close=lambda: None)
    calls = {"ensure": 0, "connect": 0, "stop": 0}

    def ensure(_cfg, port=1234):
        calls["ensure"] += 1

    def connect(_cfg):
        calls["connect"] += 1
        if calls["connect"] == 1:
            raise ReaderError("peer rebooted")
        return fake

    monkeypatch.setattr("winbox.kdbg.debugger.reader.ensure_reader", ensure)
    monkeypatch.setattr("winbox.kdbg.debugger.reader._RemoteSnapshot.connect", connect)
    monkeypatch.setattr(
        "winbox.kdbg.debugger.reader.stop_reader",
        lambda _cfg: calls.__setitem__("stop", calls["stop"] + 1),
    )

    with debug_snapshot(cfg) as snapshot:
        assert snapshot is fake
    assert calls == {"ensure": 2, "connect": 2, "stop": 1}


def test_rsp_errors_during_begin_do_not_claim_a_completed_snapshot(broker):
    cfg, rsp, _ = broker
    def fail_wait(timeout=None):
        raise RspError("peer rebooted")
    rsp.wait_for_stop = fail_wait
    with pytest.raises(ReaderError, match="peer rebooted"):
        _RemoteSnapshot.connect(cfg)


def test_reader_info_ignores_stale_session_file(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    from winbox.kdbg.debugger import reader
    reader.session_path(cfg).write_text('{"pid":123,"port":1234}')
    monkeypatch.setattr(reader, "_reader_alive", lambda cfg: False)
    assert reader_info(cfg) is None


def test_reader_info_returns_live_metadata(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    from winbox.kdbg.debugger import reader
    reader.session_path(cfg).write_text('{"pid":123,"port":4321}')
    monkeypatch.setattr(reader, "_reader_alive", lambda cfg: True)
    assert reader_info(cfg) == {"active": True, "pid": 123, "port": 4321}
