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


def test_bp_add_soft_user_va_uses_cr3_masquerade(monkeypatch):
    """mode='soft' on a user VA still routes through install_user_breakpoint."""
    user_va = 0x7ff6e289a760

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
    reply = session.handle_op(
        "bp_add", {"target": "notepad!NPWndProc", "mode": "soft"},
    )
    assert reply["ok"]
    assert reply["result"]["user_mode"] is True
    assert reply["result"]["hw"] is False
    assert captured["target_dtb"] == 0x4d6bb000
    assert captured["user_va"] == user_va


# ── new mode= dispatching ───────────────────────────────────────────────


def test_bp_add_default_mode_is_hw():
    """No mode arg == hw bp via Z1, no CR3 masquerade for user VAs."""
    user_va = 0x7ff6e289a760
    rsp = FakeRsp()
    # Add hw-aware insert tracker
    hw_calls: list[dict] = []
    real_insert = rsp.insert_breakpoint
    def tracking_insert(addr, *, kind=1, hardware=False):
        hw_calls.append({"addr": addr, "hw": hardware})
        real_insert(addr, kind=kind, hardware=hardware)
    rsp.insert_breakpoint = tracking_insert

    store = FakeStore({"notepad!Foo": user_va})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "notepad!Foo"})
    assert reply["ok"]
    assert reply["result"]["hw"] is True
    assert hw_calls == [{"addr": user_va, "hw": True}]


def test_bp_add_hw_user_skips_install_user_breakpoint(monkeypatch):
    """mode=hw user VA must NOT invoke install_user_breakpoint
    (Z1 doesn't need CR3 masquerade)."""
    from winbox.kdbg.debugger import daemon as daemon_mod
    captured = {"called": False}
    def fake_install(*a, **kw):
        captured["called"] = True
        raise AssertionError("install_user_breakpoint should NOT be called for hw bps")
    monkeypatch.setattr(daemon_mod, "install_user_breakpoint", fake_install)

    rsp = FakeRsp()
    store = FakeStore({"notepad!Bar": 0x7ff6_e289_b000})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "notepad!Bar", "mode": "hw"})
    assert reply["ok"]
    assert captured["called"] is False


def test_bp_add_hw_kernel_uses_z1_directly():
    """Kernel hw bp = plain Z1 (kernel pages are in every CR3 anyway)."""
    rsp = FakeRsp()
    hw_calls: list[bool] = []
    real_insert = rsp.insert_breakpoint
    def tracking_insert(addr, *, kind=1, hardware=False):
        hw_calls.append(hardware)
        real_insert(addr, kind=kind, hardware=hardware)
    rsp.insert_breakpoint = tracking_insert

    store = FakeStore({"nt!SwapContext": 0xfffff80608628520})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "nt!SwapContext"})
    assert reply["ok"]
    assert reply["result"]["hw"] is True
    assert reply["result"]["user_mode"] is False
    assert hw_calls == [True]


def test_bp_add_hw_no_slots_clear_error():
    """When QEMU rejects Z1 (e.g. all 4 DRs in use), surface a remediation
    hint that mentions mode='soft'."""
    from winbox.kdbg.debugger.rsp import RspError
    rsp = FakeRsp()
    def reject_z1(addr, *, kind=1, hardware=False):
        if hardware:
            raise RspError(f"Z1 insert at 0x{addr:x} failed: b'E22'")
    rsp.insert_breakpoint = reject_z1

    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})
    assert reply["ok"] is False
    assert "soft" in reply["error"]
    assert "slot" in reply["error"].lower() or "budget" in reply["error"].lower()


def test_bp_add_auto_falls_back_to_soft_on_no_slots(monkeypatch):
    """mode=auto: Z1 fails -> Z0 path runs -> result has hw=False."""
    from winbox.kdbg.debugger.rsp import RspError
    rsp = FakeRsp()
    soft_installed: list[int] = []
    def half_reject(addr, *, kind=1, hardware=False):
        if hardware:
            raise RspError(f"Z1 insert at 0x{addr:x} failed: b'E22'")
        soft_installed.append(addr)
    rsp.insert_breakpoint = half_reject

    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "auto"})
    assert reply["ok"]
    assert reply["result"]["hw"] is False
    assert soft_installed == [0xfffff80608000000]


def test_bp_add_invalid_mode_errors():
    rsp = FakeRsp()
    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)
    reply = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "weird"})
    assert reply["ok"] is False
    assert "mode" in reply["error"]


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
    # target_pretty is included even for unmangled names (just equals target)
    assert "target_pretty" in bps[0]


def test_bp_list_includes_demangled_pretty_target():
    """bp_list now exposes a demangled target_pretty alongside the
    raw mangled target string."""
    import shutil as _shutil
    if _shutil.which("llvm-undname") is None:
        import pytest
        pytest.skip("llvm-undname not available on this host")

    rsp = FakeRsp()
    mangled = "?SaveFile@@YA_NPEAUHWND__@@_NPEBG@Z"
    store = FakeStore({f"notepad!{mangled}": 0x7ff7b04eeabc})
    session = _make_session(
        rsp=rsp, store=store,
        target=TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe"),
    )
    # Stub install to skip the actual gdbstub dance for user-mode bp.
    from winbox.kdbg.debugger import daemon as daemon_mod
    from winbox.kdbg.debugger.install import InstallReport
    original = daemon_mod.install_user_breakpoint
    daemon_mod.install_user_breakpoint = lambda *a, **kw: InstallReport(
        user_va=kw["user_va"], target_dtb=kw["target_dtb"], elapsed=0.001,
    )
    try:
        session.handle_op("bp_add", {"target": f"notepad!{mangled}"})
        reply = session.handle_op("bp_list", {})
    finally:
        daemon_mod.install_user_breakpoint = original

    bp = reply["result"]["bps"][0]
    assert bp["target"] == f"notepad!{mangled}"
    assert "SaveFile" in bp["target_pretty"]
    assert "?" not in bp["target_pretty"]  # demangled form has no leading '?'


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


def test_bp_remove_routes_to_correct_packet():
    """hw bp removal must send z1; soft bp removal must send z0."""
    rsp = FakeRsp()
    rm_calls: list[bool] = []
    real_remove = rsp.remove_breakpoint
    def tracking_remove(addr, *, kind=1, hardware=False):
        rm_calls.append(hardware)
        real_remove(addr, kind=kind, hardware=hardware)
    rsp.remove_breakpoint = tracking_remove

    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)

    # Install one hw, one soft (using auto path won't work since FakeRsp
    # always succeeds — explicit modes).
    hw_id = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})["result"]["id"]
    soft_id = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "soft"})["result"]["id"]

    session.handle_op("bp_remove", {"id": hw_id})
    session.handle_op("bp_remove", {"id": soft_id})

    # Removal calls in order: hw (True), soft (False)
    assert rm_calls == [True, False]


def test_bp_list_includes_hw_field():
    rsp = FakeRsp()
    store = FakeStore({"nt!Foo": 0xfffff80608000000, "nt!Bar": 0xfffff80608000100})
    session = _make_session(rsp=rsp, store=store)
    session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})
    session.handle_op("bp_add", {"target": "nt!Bar", "mode": "soft"})
    reply = session.handle_op("bp_list", {})
    bps = reply["result"]["bps"]
    assert len(bps) == 2
    # Both bps have hw field set correctly
    by_target = {b["target"]: b for b in bps}
    assert by_target["nt!Foo"]["hw"] is True
    assert by_target["nt!Bar"]["hw"] is False


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


# ── _best_symbol_for_va — module-range filtering ────────────────────────


class _MultiModuleStore:
    """Store stand-in with multiple modules at different bases + sizes."""

    def __init__(self, modules: dict[str, dict]) -> None:
        self._modules = modules

    def list_modules(self):
        return list(self._modules.keys())

    def load(self, name):
        return self._modules[name]


def test_best_symbol_for_va_filters_by_module_range():
    """A user32 VA must NOT match an ntdll-only symbol just because
    ntdll's symbol is the closest <= match overall."""
    store = _MultiModuleStore({
        "ntdll": {
            "base": 0x7fff_8a000000,
            "size_of_image": 0x200000,  # ntdll spans 0x8a000000..0x8a200000
            "symbols": {"RtlAllocate": 0x10000},  # at 0x7fff_8a010000
        },
        "user32": {
            "base": 0x7fff_8c000000,
            "size_of_image": 0x100000,  # user32 spans 0x8c000000..0x8c100000
            "symbols": {"DispatchMessageW": 0x5000},  # at 0x7fff_8c005000
        },
    })
    session = _make_session(store=store)

    # VA inside user32 — must match user32, NOT ntdll.
    sym = session._best_symbol_for_va(0x7fff_8c008000)
    assert sym is not None
    assert "user32" in sym
    assert "DispatchMessageW" in sym


def test_best_symbol_for_va_returns_none_when_no_module_covers():
    """Random VA outside every module range — explicit None, no
    wrong-module guess."""
    store = _MultiModuleStore({
        "ntdll": {
            "base": 0x7fff_8a000000,
            "size_of_image": 0x100000,
            "symbols": {"RtlFoo": 0x100},
        },
    })
    session = _make_session(store=store)
    assert session._best_symbol_for_va(0x1234_5678) is None


def test_best_symbol_for_va_uses_legacy_fallback_when_size_missing():
    """Old store entries without size_of_image fall back to a 16MB
    coarse range — better than no symbol at all for legacy data."""
    store = _MultiModuleStore({
        "legacy_mod": {
            "base": 0x7fff_8a000000,
            # size_of_image NOT set
            "symbols": {"OldSym": 0x1000},
        },
    })
    session = _make_session(store=store)
    # VA within 16MB of base
    sym = session._best_symbol_for_va(0x7fff_8a002000)
    assert sym is not None
    assert "legacy_mod" in sym
    assert "OldSym" in sym


def test_best_symbol_for_va_respects_legacy_fallback_upper_bound():
    """Past the 16MB legacy fallback, no match."""
    store = _MultiModuleStore({
        "legacy_mod": {
            "base": 0x7fff_8a000000,
            "symbols": {"OldSym": 0x100},
        },
    })
    session = _make_session(store=store)
    # 32 MB past base — outside the 16MB fallback
    far = 0x7fff_8a000000 + 32 * 1024 * 1024
    assert session._best_symbol_for_va(far) is None
