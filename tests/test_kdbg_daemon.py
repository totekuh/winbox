"""Daemon op-handler unit tests using a fake RspClient.

These don't touch the fork/socket/lock layer (covered separately by
the integration test). They exercise the in-process ``DaemonSession``
state machine and op_<verb> dispatch.
"""

from __future__ import annotations

import struct
from typing import Any

import pytest

from winbox.kdbg.debugger.daemon import (
    Breakpoint,
    DaemonSession,
    StopState,
    TargetInfo,
    _decode_regs,
    _looks_like_code_va,
)
from winbox.kdbg.debugger.protocol import OPS


_CR3_OFFSET = 204
_BLOB_LEN = 608


def _blob(*, rip=0xfffff80608628780, rsp=0xfffff80501234500,
          rcx=0xdeadbeef, cr3=0x1ae000) -> bytes:
    b = bytearray(_BLOB_LEN)
    struct.pack_into("<Q", b, 16, rcx)        # rcx
    struct.pack_into("<Q", b, 56, rsp)        # rsp
    struct.pack_into("<Q", b, 128, rip)       # rip
    struct.pack_into("<Q", b, _CR3_OFFSET, cr3)
    return bytes(b)


class FakeRsp:
    def __init__(self, regs_blob=None, threads=("01",)) -> None:
        self.regs_blob = regs_blob or _blob()
        self._threads = list(threads)
        self.bps_inserted: list[int] = []
        self.bps_removed: list[int] = []
        self.continued = 0
        self.stepped = 0
        self.interrupted = 0
        self.next_stop = None  # caller can prime this

    def list_threads(self) -> list[str]:
        return list(self._threads)

    def select_thread(self, t: str, *, op: str = "g") -> None:
        pass

    def read_registers(self) -> bytes:
        return self.regs_blob

    def read_cr3(self) -> int:
        return struct.unpack_from("<Q", self.regs_blob, _CR3_OFFSET)[0]

    def insert_breakpoint(self, addr: int, *, kind: int = 1, hardware: bool = False) -> None:
        self.bps_inserted.append(addr)

    def remove_breakpoint(self, addr: int, *, kind: int = 1, hardware: bool = False) -> None:
        self.bps_removed.append(addr)

    def cont(self) -> None:
        self.continued += 1

    def step(self, t: str | None = None) -> None:
        self.stepped += 1

    def interrupt(self) -> None:
        self.interrupted += 1

    def wait_for_stop(self, *, timeout: float | None = None):
        # Test will inject .next_stop before calling cont.
        if self.next_stop is None:
            from winbox.kdbg.debugger.rsp import StopReply
            return StopReply(signal=5, thread="01", stop_kind="swbreak", raw="T05")
        sr, self.next_stop = self.next_stop, None
        return sr

    def read_memory(self, va: int, length: int) -> bytes:
        return b"\x90" * length

    def _exchange(self, body: bytes, *, timeout=None) -> bytes:
        # used by op_mem for G-packet swap; just accept and update blob.
        if body.startswith(b"G"):
            self.regs_blob = bytes.fromhex(body[1:].decode("ascii"))
            return b"OK"
        return b"OK"

    def close(self) -> None:
        pass


class FakeStore:
    def __init__(self, syms=None) -> None:
        self._syms = dict(syms or {})

    def resolve(self, name: str) -> int:
        if name not in self._syms:
            from winbox.kdbg import SymbolStoreError
            raise SymbolStoreError(f"missing: {name}")
        return self._syms[name]

    def list_modules(self) -> list[str]:
        return ["nt"]

    def load(self, name: str) -> dict:
        return {
            "module": "nt", "build": "BEEF", "image": "ntkrnlmp.pdb",
            "base": 0xfffff80608000000,
            "symbols": {"NtCreateFile": 0x80000, "PsActiveProcessHead": 0xc263a0},
            "types": {},
        }


class FakeCfg:
    """Minimal Config stand-in. Daemon ops only read .vm_name."""
    vm_name = "winbox"


def _make_session(rsp=None, store=None, target=None) -> DaemonSession:
    return DaemonSession(
        cfg=FakeCfg(),
        rsp=rsp or FakeRsp(),
        target=target or TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe"),
        store=store or FakeStore({"notepad!Save": 0x7ff6e289eabc}),
    )


# ── op dispatch / unknown ops ───────────────────────────────────────────


def test_handle_op_returns_err_for_unknown():
    session = _make_session()
    reply = session.handle_op("not_a_real_op", {})
    assert reply["ok"] is False
    assert "unknown op" in reply["error"]


def test_handle_op_returns_err_for_bad_args():
    session = _make_session()
    reply = session.handle_op("bp_add", {"wrong_kw": "x"})
    assert reply["ok"] is False
    assert "bad args" in reply["error"]


# ── op_status ───────────────────────────────────────────────────────────


def test_status_reports_target_and_uptime():
    session = _make_session()
    reply = session.handle_op("status", {})
    assert reply["ok"]
    r = reply["result"]
    assert r["target"]["name"] == "notepad.exe"
    assert r["target"]["dtb"] == "0x4d6bb000"
    assert r["bps"] == 0
    assert "uptime_s" in r
    assert "daemon_pid" in r


# ── op_bp_add (kernel) ──────────────────────────────────────────────────


def test_bp_add_kernel_va_uses_plain_z0():
    """Kernel VA (canonical-high) shouldn't trigger CR3 masquerade."""
    rsp = FakeRsp()
    store = FakeStore({"nt!SwapContext": 0xfffff80608628520})
    session = _make_session(rsp=rsp, store=store)

    reply = session.handle_op("bp_add", {"target": "nt!SwapContext"})
    assert reply["ok"]
    assert reply["result"]["user_mode"] is False
    assert rsp.bps_inserted == [0xfffff80608628520]


# ── op_bp_add (user) — uses real install_user_breakpoint internally ────


def test_bp_add_user_va_uses_cr3_masquerade(monkeypatch):
    """User VA dispatches through install_user_breakpoint."""
    user_va = 0x7ff6e289a760

    # Stub install to avoid needing the full G-packet dance against FakeRsp
    from winbox.kdbg.debugger import daemon as daemon_mod
    from winbox.kdbg.debugger.install import InstallReport

    captured = {}

    def fake_install(cli, vm_name, store, *, target_dtb, user_va):
        captured["target_dtb"] = target_dtb
        captured["user_va"] = user_va
        return InstallReport(user_va=user_va, target_dtb=target_dtb, elapsed=0.005)

    monkeypatch.setattr(daemon_mod, "install_user_breakpoint", fake_install)

    rsp = FakeRsp()
    store = FakeStore({"notepad!NPWndProc": user_va})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "notepad!NPWndProc"})
    assert reply["ok"]
    assert reply["result"]["user_mode"] is True
    assert captured["target_dtb"] == 0x4d6bb000
    assert captured["user_va"] == user_va


# ── bp_list / bp_remove ─────────────────────────────────────────────────


def test_bp_list_reflects_added_bps():
    rsp = FakeRsp()
    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)
    session.handle_op("bp_add", {"target": "nt!Foo"})
    reply = session.handle_op("bp_list", {})
    assert reply["ok"]
    bps = reply["result"]["bps"]
    assert len(bps) == 1
    assert bps[0]["target"] == "nt!Foo"
    assert bps[0]["va"] == "0xfffff80608000000"


def test_bp_remove_drops_from_registry_and_calls_z0():
    rsp = FakeRsp()
    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)
    add_reply = session.handle_op("bp_add", {"target": "nt!Foo"})
    bp_id = add_reply["result"]["id"]
    rm_reply = session.handle_op("bp_remove", {"id": bp_id})
    assert rm_reply["ok"]
    assert rsp.bps_removed == [0xfffff80608000000]
    # registry empty
    list_reply = session.handle_op("bp_list", {})
    assert list_reply["result"]["bps"] == []


def test_bp_remove_unknown_id_errors():
    session = _make_session()
    reply = session.handle_op("bp_remove", {"id": 999})
    assert reply["ok"] is False
    assert "no bp with id" in reply["error"]


# ── interrupt / status fast paths ──────────────────────────────────────


def test_interrupt_queues_pending_flag():
    session = _make_session()
    assert session._interrupt_pending is False
    session.handle_op("interrupt", {})
    assert session._interrupt_pending is True


# ── regs decode roundtrip ──────────────────────────────────────────────


def test_decode_regs_extracts_known_offsets():
    blob = _blob(rip=0xdead, rsp=0xbeef, cr3=0xfeed)
    out = _decode_regs(blob)
    assert out["rip"] == "0x000000000000dead"
    assert out["rsp"] == "0x000000000000beef"
    assert out["cr3"] == "0x000000000000feed"


# ── _looks_like_code_va heuristic ──────────────────────────────────────


def test_code_va_heuristic_kernel_addresses():
    assert _looks_like_code_va(0xfffff80608628780)


def test_code_va_heuristic_user_addresses():
    assert _looks_like_code_va(0x7ff6e289a760)


def test_code_va_heuristic_rejects_zero_and_low():
    assert not _looks_like_code_va(0)
    assert not _looks_like_code_va(0x100)


# ── ops set is exactly the set the daemon implements ──────────────────


def test_ops_match_daemon_methods():
    session = _make_session()
    for op in OPS:
        assert hasattr(session, f"op_{op}"), f"DaemonSession.op_{op} missing"
