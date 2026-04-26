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


# ── op_write_mem ─────────────────────────────────────────────────────────


class _FakeRspWithWrite(FakeRsp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.writes: list[tuple[int, bytes]] = []

    def write_memory(self, va, data):
        self.writes.append((va, data))


def test_op_write_mem_decodes_hex_and_writes():
    rsp = _FakeRspWithWrite()
    session = _make_session(rsp=rsp)
    reply = session.handle_op("write_mem", {"va": "0x1000", "data": "deadbeef"})
    assert reply["ok"]
    assert reply["result"]["va"] == "0x1000"
    assert reply["result"]["length"] == 4
    assert rsp.writes == [(0x1000, b"\xde\xad\xbe\xef")]


def test_op_write_mem_rejects_non_hex_data():
    rsp = _FakeRspWithWrite()
    session = _make_session(rsp=rsp)
    reply = session.handle_op("write_mem", {"va": "0x1000", "data": "not_hex"})
    assert reply["ok"] is False
    assert "hex" in reply["error"].lower()


def test_op_write_mem_caps_at_64kib():
    rsp = _FakeRspWithWrite()
    session = _make_session(rsp=rsp)
    big = "00" * (64 * 1024 + 1)
    reply = session.handle_op("write_mem", {"va": "0x1000", "data": big})
    assert reply["ok"] is False
    assert "64" in reply["error"] or "cap" in reply["error"].lower()
    assert rsp.writes == []  # nothing written


def test_op_write_mem_empty_data_is_noop():
    rsp = _FakeRspWithWrite()
    session = _make_session(rsp=rsp)
    reply = session.handle_op("write_mem", {"va": "0x1000", "data": ""})
    assert reply["ok"]
    assert reply["result"]["length"] == 0
    assert rsp.writes == []


def test_op_write_mem_restores_cr3_even_on_failure():
    """If gdbstub rejects the M packet, original CR3 must still be restored."""
    rsp = _FakeRspWithWrite()
    # Track G-packet CR3 values directly since the daemon-test FakeRsp
    # doesn't carry a cr3_writes list — its _exchange just updates the
    # regs_blob in place. We track here by intercepting _exchange.
    cr3_writes: list[int] = []
    original_exchange = rsp._exchange

    def tracking_exchange(body, *, timeout=None):
        if body.startswith(b"G"):
            blob = bytes.fromhex(body[1:].decode("ascii"))
            cr3_writes.append(struct.unpack_from("<Q", blob, _CR3_OFFSET)[0])
        return original_exchange(body, timeout=timeout)

    rsp._exchange = tracking_exchange

    # Make write_memory fail (M packet)
    def fail_write(va, data):
        from winbox.kdbg.debugger.rsp import RspError
        raise RspError("M failed: E22")
    rsp.write_memory = fail_write

    session = _make_session(rsp=rsp)
    target_dtb = session.target.dtb
    initial_cr3 = struct.unpack_from("<Q", rsp.regs_blob, _CR3_OFFSET)[0]

    reply = session.handle_op("write_mem", {"va": "0x1000", "data": "00"})
    assert reply["ok"] is False

    # Two G writes: target_dtb (masquerade), then initial CR3 (restore in finally).
    assert len(cr3_writes) == 2
    assert cr3_writes[0] == target_dtb
    assert cr3_writes[1] == initial_cr3


# ── _validate_module_bases ───────────────────────────────────────────────


class _RspForValidation:
    """Minimal RspClient stand-in for stale-base detection unit tests.

    Returns canned bytes from a per-base lookup so we can simulate
    "module's base points at MZ" vs "module's base points at garbage".
    """

    def __init__(self, mappings: dict[int, bytes]) -> None:
        self.mappings = mappings  # base_va -> 2 bytes
        self.threads_returned = ["01"]
        self.regs_blob = _blob()

    def list_threads(self):
        return list(self.threads_returned)

    def select_thread(self, t, *, op="g"):
        pass

    def read_registers(self):
        return self.regs_blob

    def read_memory(self, va, length):
        # The validator passes the module's base as va; we look it up
        # in mappings. If not present, simulate "VA not mapped".
        if va in self.mappings:
            return self.mappings[va][:length]
        from winbox.kdbg.debugger.rsp import RspError
        raise RspError(f"m failed at 0x{va:x}: E22")

    def _exchange(self, body, *, timeout=None):
        return b"OK"  # G writes always accepted in this fake


class _StoreForValidation:
    def __init__(self, modules: dict[str, dict]) -> None:
        self._modules = modules

    def list_modules(self):
        return list(self._modules.keys())

    def load(self, name):
        return self._modules[name]


def test_validate_module_bases_passes_when_all_show_MZ():
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    rsp = _RspForValidation({0x7ff700000000: b"MZ", 0x7ff800000000: b"MZ"})
    store = _StoreForValidation({
        "notepad": {"base": 0x7ff700000000},
        "ntdll": {"base": 0x7ff800000000},
    })
    # Should not raise.
    _validate_module_bases(rsp, target_dtb=0x4d6bb000, store=store, target_name="notepad.exe")


def test_validate_module_bases_raises_on_stale():
    from winbox.kdbg.debugger.daemon import _validate_module_bases, DaemonError
    rsp = _RspForValidation({
        0x7ff700000000: b"MZ",       # notepad's base — valid
        0x7ff800000000: b"\x00\x00",  # ntdll's base — STALE (zeros, not MZ)
    })
    store = _StoreForValidation({
        "notepad": {"base": 0x7ff700000000},
        "ntdll": {"base": 0x7ff800000000},
    })
    with pytest.raises(DaemonError) as exc:
        _validate_module_bases(rsp, target_dtb=0x4d6bb000, store=store, target_name="notepad.exe")
    msg = str(exc.value)
    assert "stale" in msg.lower()
    assert "ntdll" in msg
    assert "0x7ff800000000" in msg
    assert "kdbg_user_symbols_load" in msg


def test_validate_module_bases_skips_nt_module():
    """The kernel module's base is validated by kdbg_base_refresh, not here."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    rsp = _RspForValidation({})  # no mappings
    store = _StoreForValidation({
        "nt": {"base": 0xfffff80608628000},  # would otherwise be flagged stale
    })
    # Should not raise — we skipped the nt entry.
    _validate_module_bases(rsp, target_dtb=0x1ae000, store=store, target_name="System")


def test_validate_module_bases_treats_unmapped_as_stale():
    from winbox.kdbg.debugger.daemon import _validate_module_bases, DaemonError
    rsp = _RspForValidation({})  # base not mapped at all
    store = _StoreForValidation({
        "notepad": {"base": 0x7ff700000000},
    })
    with pytest.raises(DaemonError, match="stale"):
        _validate_module_bases(rsp, target_dtb=0x4d6bb000, store=store, target_name="notepad.exe")


def test_validate_module_bases_skips_modules_with_no_base():
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    rsp = _RspForValidation({})
    store = _StoreForValidation({
        "kernelbase": {"base": None},  # loaded but base unset
        "user32": {"base": 0},
    })
    # Should not raise — both entries skipped.
    _validate_module_bases(rsp, target_dtb=0x4d6bb000, store=store, target_name="x.exe")
