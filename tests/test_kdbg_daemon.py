"""Daemon op-handler unit tests using a fake RspClient.

These don't touch the fork/socket/lock layer (covered separately by
the integration test). They exercise the in-process ``DaemonSession``
state machine and op_<verb> dispatch.
"""

from __future__ import annotations

import struct
from typing import Any
from unittest.mock import MagicMock

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
          rcx=0xdeadbeef, cr3=0x1ae000,
          rax=0, rbx=0, rdx=0, rsi=0, rdi=0, rbp=0,
          r8=0, r9=0, r10=0, r11=0, r12=0, r13=0, r14=0, r15=0) -> bytes:
    b = bytearray(_BLOB_LEN)
    # Offsets match _decode_regs in daemon.py — i*8 for rax..r15.
    struct.pack_into("<Q", b, 0, rax)
    struct.pack_into("<Q", b, 8, rbx)
    struct.pack_into("<Q", b, 16, rcx)
    struct.pack_into("<Q", b, 24, rdx)
    struct.pack_into("<Q", b, 32, rsi)
    struct.pack_into("<Q", b, 40, rdi)
    struct.pack_into("<Q", b, 48, rbp)
    struct.pack_into("<Q", b, 56, rsp)
    struct.pack_into("<Q", b, 64, r8)
    struct.pack_into("<Q", b, 72, r9)
    struct.pack_into("<Q", b, 80, r10)
    struct.pack_into("<Q", b, 88, r11)
    struct.pack_into("<Q", b, 96, r12)
    struct.pack_into("<Q", b, 104, r13)
    struct.pack_into("<Q", b, 112, r14)
    struct.pack_into("<Q", b, 120, r15)
    struct.pack_into("<Q", b, 128, rip)
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


def test_interrupt_also_sends_real_break_to_rsp():
    """Regression: previously ``op_interrupt`` only set the pending
    flag, which was checked at the top of each cont-loop iteration.
    A cont stuck inside ``wait_for_stop`` against a target that wasn't
    firing would ignore the flag for the full 30s timeout. Now the op
    also calls ``rsp.interrupt()`` so the gdbstub receives \\x03 and
    surfaces a stop reply promptly."""
    rsp = FakeRsp()
    session = _make_session(rsp=rsp)
    session.handle_op("interrupt", {})
    assert rsp.interrupted == 1
    assert session._interrupt_pending is True


def test_interrupt_swallows_rsp_failure_without_raising():
    """If the RSP socket is dead the cont loop will surface its own
    error — interrupt itself shouldn't double-fault on the lightweight
    path (it bypasses _busy and runs from a separate connection)."""
    from winbox.kdbg.debugger.rsp import RspError

    class _BrokenRsp(FakeRsp):
        def interrupt(self) -> None:
            raise RspError("socket closed")
    rsp = _BrokenRsp()
    session = _make_session(rsp=rsp)
    reply = session.handle_op("interrupt", {})
    # No exception leaked; flag still set so the cont loop can pick up
    # cooperative interrupt if the socket recovers.
    assert reply["ok"] is True
    assert session._interrupt_pending is True


def test_op_step_recovers_from_wait_for_stop_timeout():
    """Regression: a step whose ``wait_for_stop`` timed out left
    ``self.stop`` unchanged and the gdbstub in indeterminate state
    (it might still owe us a stop reply). Now: force a halt, drain
    the recovery stop, and surface a clear RuntimeError so the next
    op runs against a known-halted stub."""
    from winbox.kdbg.debugger.rsp import RspError, StopReply

    class _StepTimeoutRsp(FakeRsp):
        def __init__(self):
            super().__init__()
            self._wait_calls = 0

        def wait_for_stop(self, *, timeout: float | None = None):
            self._wait_calls += 1
            if self._wait_calls == 1:
                # First call (post-step) times out.
                raise RspError("read timed out")
            # Recovery wait after our forced interrupt — succeeds.
            return StopReply(signal=2, thread="01", stop_kind=None, raw="T02")

    rsp = _StepTimeoutRsp()
    session = _make_session(rsp=rsp)
    # Pre-step state: capture a stop so op_step's halted check passes.
    from winbox.kdbg.debugger.daemon import StopState
    session.stop = StopState(
        vcpu="01", rip=0xffffffff80001000, cr3=0x1234000,
        signal=5, raw_regs=_blob(),
    )
    reply = session.handle_op("step", {})
    assert reply["ok"] is False
    assert "step did not complete" in reply["error"]
    # The recovery interrupt was sent.
    assert rsp.interrupted == 1
    # And the recovery stop was captured so the next op sees the halted state.
    assert session.stop is not None
    assert session.stop.signal == 2  # SIGINT from our forced halt


def test_op_step_propagates_non_timeout_rsp_error():
    """Step recovery only kicks in for timeouts. Other RspErrors should
    propagate so the op handler reports them (and doesn't pretend the
    stub is in a known state)."""
    from winbox.kdbg.debugger.rsp import RspError

    class _StepFailsRsp(FakeRsp):
        def wait_for_stop(self, *, timeout: float | None = None):
            raise RspError("connection closed by peer")

    rsp = _StepFailsRsp()
    session = _make_session(rsp=rsp)
    from winbox.kdbg.debugger.daemon import StopState
    session.stop = StopState(
        vcpu="01", rip=0xffffffff80001000, cr3=0x1234000,
        signal=5, raw_regs=_blob(),
    )
    reply = session.handle_op("step", {})
    assert reply["ok"] is False
    assert "connection closed" in reply["error"]
    # No recovery attempted — error is not a timeout.
    assert rsp.interrupted == 0


def test_op_step_double_timeout_message_admits_indeterminate_state():
    """Regression: when both the original step's wait AND the recovery
    halt's wait time out (genuine stub hang), the previous message
    claimed "stub recovered to halted state" — a lie. Operator
    following the message would assume the stub is consistent and run
    the next op against an actually-running stub. Now the message
    explicitly says "stub state is indeterminate, daemon may need
    restart"."""
    from winbox.kdbg.debugger.rsp import RspError

    class _DoubleTimeoutRsp(FakeRsp):
        def wait_for_stop(self, *, timeout: float | None = None):
            raise RspError("read timed out")

    rsp = _DoubleTimeoutRsp()
    session = _make_session(rsp=rsp)
    from winbox.kdbg.debugger.daemon import StopState
    pre_step_stop = StopState(
        vcpu="01", rip=0xffffffff80001000, cr3=0x1234000,
        signal=5, raw_regs=_blob(),
    )
    session.stop = pre_step_stop
    reply = session.handle_op("step", {})
    assert reply["ok"] is False
    # Old (lying) message had "stub recovered"; new message must admit
    # the truth.
    assert "indeterminate" in reply["error"]
    # Recovery interrupt was attempted exactly once.
    assert rsp.interrupted == 1
    # ``self.stop`` is the pre-step state since recovery didn't capture
    # anything new — operator can see the daemon hasn't claimed false
    # progress.
    assert session.stop is pre_step_stop


# ── KPTI / KVA Shadow CR3 filter ────────────────────────────────────────
#
# Live VM trace from a real Cortex audit session showed half the running
# processes have bit 12 already set in KPROCESS.DirectoryTableBase
# (cyserver=0x1225ad000, cytray=0x3ab25000, cysandbox=0x13ba73000), and
# the other half have it clear (lsass=0x1088d4000, explorer=0x138464000,
# System=0x1ae000). The first version of this fix used ``| 0x1000`` to
# derive the second CR3, which is a no-op when bit 12 is already set —
# so kernel-side bp hits in cyserver kept getting silent-continued.
# Tests below cover both polarities, plus the explicit user_dtb path.


def test_target_info_cr3_set_uses_explicit_user_dtb_when_known():
    """When KPROCESS.UserDirectoryTableBase was readable at attach,
    cr3_set returns both physical PML4s exactly — no XOR guessing."""
    t = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ac000,
    )
    assert t.cr3_set == (0x1225ad000, 0x1225ac000)


def test_target_info_cr3_set_falls_back_to_xor_when_user_dtb_missing():
    """Pre-KPTI struct or read failed -> user_dtb=0. Fall back to
    XOR-0x1000 of dtb. Must work for BOTH bit-12 polarities."""
    # bit 12 set: cyserver-style. XOR-0x1000 clears it.
    t1 = TargetInfo(pid=8000, dtb=0x1225ad000, name="cyserver.exe")
    assert t1.cr3_set == (0x1225ad000, 0x1225ac000)
    # bit 12 clear: lsass-style. XOR-0x1000 sets it.
    t2 = TargetInfo(pid=624, dtb=0x1088d4000, name="lsass.exe")
    assert t2.cr3_set == (0x1088d4000, 0x1088d5000)


def test_target_info_cr3_set_or_would_be_wrong_for_bit12_set_dtbs():
    """Regression: the original fix used ``| 0x1000`` which is a no-op
    when bit 12 is already set. cr3_set must NOT have that property."""
    t = TargetInfo(pid=8000, dtb=0x1225ad000, name="cyserver.exe")
    # The two CR3s must differ — otherwise we'd lose kernel-side hits
    # for any process whose primary dtb has bit 12 set.
    assert t.cr3_set[0] != t.cr3_set[1]


def test_op_cont_accepts_second_cr3_under_kpti():
    """Bp inside a driver fires with the kernel CR3 of the calling
    process. With UserDirectoryTableBase known, that's stored exactly;
    the daemon must accept it as in-target."""
    target = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ac000,
    )
    # Pretend the bp fired with the SECOND CR3 loaded (whichever side
    # of the user/kernel pair that is).
    rsp = FakeRsp(regs_blob=_blob(rip=0xfffff80700001234, cr3=0x1225ac000))
    session = _make_session(rsp=rsp, target=target)

    out = session.handle_op("cont", {"timeout": 1.0})
    result = out["result"]

    assert result["reason"] == "bp"
    assert result["in_target"] is True
    assert result["primary_cr3"] is False
    assert result["cr3"] == "0x1225ac000"


def test_op_cont_accepts_primary_cr3():
    target = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ac000,
    )
    rsp = FakeRsp(regs_blob=_blob(rip=0x7ff6e289a760, cr3=0x1225ad000))
    session = _make_session(rsp=rsp, target=target)

    out = session.handle_op("cont", {"timeout": 1.0})
    result = out["result"]

    assert result["reason"] == "bp"
    assert result["in_target"] is True
    assert result["primary_cr3"] is True


def test_op_cont_accepts_xor_fallback_when_user_dtb_unknown():
    """Walk gave us no UserDirectoryTableBase (older build / struct
    field absent). Fall back to dtb ^ 0x1000 and still catch the
    kernel-side hit, regardless of bit-12 polarity."""
    # bit 12 set in primary: cyserver shape. The 'other' CR3 is XOR.
    target = TargetInfo(pid=8000, dtb=0x1225ad000, name="cyserver.exe")
    rsp = FakeRsp(regs_blob=_blob(rip=0xfffff80700001234, cr3=0x1225ac000))
    session = _make_session(rsp=rsp, target=target)
    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["result"]["reason"] == "bp"
    assert out["result"]["in_target"] is True


def test_op_cont_silent_continues_unrelated_cr3():
    """Hits in another process's CR3 must NOT stop us. This is the
    whole point of CR3 filtering."""
    target = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ac000,
    )
    # Some unrelated process's CR3.
    rsp = FakeRsp(regs_blob=_blob(rip=0xfffff80700001234, cr3=0xdeadbeef000))
    session = _make_session(rsp=rsp, target=target)

    # cont loops forever silent-continuing on this fake — bound it
    # with a tight timeout and assert the loop exits via timeout, not
    # via a bp report.
    out = session.handle_op("cont", {"timeout": 0.5})
    result = out["result"]
    assert result["reason"] == "timeout"


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


class _StoreForValidation:
    def __init__(self, modules: dict[str, dict]) -> None:
        self._modules = modules

    def list_modules(self):
        return list(self._modules.keys())

    def load(self, name):
        return self._modules[name]


class _FakeUserModule:
    """Mimics walk.UserModuleRecord shape for tests."""
    def __init__(self, name: str, base: int) -> None:
        self.name = name
        self.base = base
        self.size = 0x100000
        self.full_path = f"C:\\Windows\\{name}"
        self.entry = 0


class _FakeTarget:
    """Mimics ProcessRecord for the validator's target arg."""
    def __init__(self, pid=4584, dtb=0x4d6bb000, name="notepad.exe", eprocess=0xffffe000_00100000) -> None:
        self.pid = pid
        self.directory_table_base = dtb
        self.name = name
        self.eprocess = eprocess


def _patch_validator(monkeypatch, loaded_modules):
    """Stub list_user_modules + ensure_types_loaded so _validate_module_bases
    sees ``loaded_modules`` as the target's PEB.Ldr contents.
    """
    from winbox.kdbg.debugger import daemon as daemon_mod
    monkeypatch.setattr(
        daemon_mod, "_validate_module_bases",
        daemon_mod._validate_module_bases,  # keep real impl
    )
    # Patch the inner imports
    import winbox.kdbg as kdbg_mod
    import winbox.kdbg.walk as walk_mod
    monkeypatch.setattr(walk_mod, "list_user_modules",
                        lambda vm, store, target, cache=None: loaded_modules)
    monkeypatch.setattr(kdbg_mod, "ensure_types_loaded",
                        lambda *a, **kw: None)


def test_validate_passes_when_cached_base_matches_loaded(monkeypatch):
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    _patch_validator(monkeypatch, [
        _FakeUserModule("notepad.exe", 0x7ff700000000),
        _FakeUserModule("ntdll.dll", 0x7ff800000000),
    ])
    store = _StoreForValidation({
        "notepad": {"base": 0x7ff700000000},
        "ntdll": {"base": 0x7ff800000000},
    })
    # Should not raise — bases match what's loaded.
    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)


def test_validate_raises_on_base_mismatch(monkeypatch):
    """Module loaded in target at a DIFFERENT base than cached → stale."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases, DaemonError
    _patch_validator(monkeypatch, [
        _FakeUserModule("ntdll.dll", 0x7ff_99999000),  # actual base
    ])
    store = _StoreForValidation({
        "ntdll": {"base": 0x7ff800000000},  # cached base — stale
    })
    with pytest.raises(DaemonError) as exc:
        _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)
    msg = str(exc.value)
    assert "stale" in msg.lower()
    assert "ntdll" in msg
    assert "0x7ff800000000" in msg
    assert "0x7ff99999000" in msg
    assert "kdbg_user_symbols_load" in msg


def test_validate_skips_modules_not_loaded_in_target(monkeypatch):
    """THE BUG FIX: cached store entries for modules not loaded in
    THIS target must be skipped (not flagged stale).

    Realistic case: notepad symbols cached during a previous notepad
    debug session; user now attaches to cyserver.exe. cyserver doesn't
    have notepad loaded, so the cached notepad entry is irrelevant —
    NOT stale.
    """
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    _patch_validator(monkeypatch, [
        # Target only has ntdll loaded — notepad isn't in this process.
        _FakeUserModule("ntdll.dll", 0x7ff800000000),
    ])
    store = _StoreForValidation({
        "notepad": {"base": 0x7ff700000000},  # not in target — should skip
        "ntdll": {"base": 0x7ff800000000},     # in target, base matches — pass
    })
    # Should NOT raise — notepad cached entry is irrelevant to this target.
    _validate_module_bases(
        FakeCfg(), MagicMock(),
        _FakeTarget(name="cyserver.exe"),
        store,
    )


def test_validate_nt_without_symbols_skipped(monkeypatch):
    """nt is checked via resolve_nt_base, but only if symbols are
    cached (resolve_nt_base needs KiDivideErrorFault). Store entry with
    just a base and no symbols is silently skipped — no live HMP probe."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    _patch_validator(monkeypatch, [])  # no user modules in target

    # Sentinel — fail loudly if resolve_nt_base ever gets called.
    import winbox.kdbg.symbols as sym_mod
    def boom(*a, **kw):
        raise AssertionError("resolve_nt_base must not run without nt symbols")
    monkeypatch.setattr(sym_mod, "resolve_nt_base", boom)

    store = _StoreForValidation({
        "nt": {"base": 0xfffff80608628000},  # no symbols → no live probe
    })
    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)


def test_validate_nt_passes_when_live_base_matches(monkeypatch):
    """nt cached base matches live IDT-derived base → no raise."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    _patch_validator(monkeypatch, [])

    cached_nt_base = 0xfffff80608628000
    import winbox.kdbg.symbols as sym_mod
    monkeypatch.setattr(
        sym_mod, "resolve_nt_base",
        lambda cfg, syms: cached_nt_base,  # matches cached
    )

    store = _StoreForValidation({
        "nt": {
            "base": cached_nt_base,
            "symbols": {"KiDivideErrorFault": 0x10000},
        },
    })
    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)


def test_validate_nt_raises_on_stale_kernel_base(monkeypatch):
    """THE FIX: cached nt base differs from live IDT-derived base
    (typical post-VM-reboot state) → raise DaemonError naming the
    `winbox kdbg base` + `kdbg symbols load -m nt` remediation."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases, DaemonError
    _patch_validator(monkeypatch, [])

    cached_nt_base = 0xfffff80608628000  # what the store thinks
    live_nt_base = 0xfffff806AAAAA000   # what IDT actually points at

    import winbox.kdbg.symbols as sym_mod
    monkeypatch.setattr(
        sym_mod, "resolve_nt_base",
        lambda cfg, syms: live_nt_base,
    )

    store = _StoreForValidation({
        "nt": {
            "base": cached_nt_base,
            "symbols": {"KiDivideErrorFault": 0x10000},
        },
    })
    with pytest.raises(DaemonError) as exc:
        _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)
    msg = str(exc.value)
    assert "stale nt base" in msg.lower()
    assert f"0x{cached_nt_base:x}" in msg
    assert f"0x{live_nt_base:x}" in msg
    assert "winbox kdbg base" in msg
    assert "symbols load -m nt" in msg


def test_validate_nt_resolve_failure_warns_and_continues(monkeypatch, capsys):
    """If resolve_nt_base raises an HMP / load error, log a warning
    and continue rather than block the attach. (User will get a
    clearer error if a concrete bp install hits the stale base later.)"""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    from winbox.kdbg.hmp import HmpError
    _patch_validator(monkeypatch, [])

    import winbox.kdbg.symbols as sym_mod
    def boom(cfg, syms):
        raise HmpError("HMP socket transient")
    monkeypatch.setattr(sym_mod, "resolve_nt_base", boom)

    store = _StoreForValidation({
        "nt": {
            "base": 0xfffff80608628000,
            "symbols": {"KiDivideErrorFault": 0x10000},
        },
    })
    # Should NOT raise.
    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)
    captured = capsys.readouterr()
    assert "could not validate nt base" in captured.err
    assert "HmpError" in captured.err


def test_validate_skips_modules_with_no_base(monkeypatch):
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    _patch_validator(monkeypatch, [])
    store = _StoreForValidation({
        "kernelbase": {"base": None},  # loaded but base unset
        "user32": {"base": 0},
    })
    # Should not raise — both entries skipped.
    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)


def test_validate_no_candidates_skips_peb_walk(monkeypatch):
    """If the store has no user-mode modules with bases, skip the
    PEB.Ldr walk entirely (it's an HMP-heavy operation we don't want
    to trigger if there's nothing to validate)."""
    from winbox.kdbg.debugger import daemon as daemon_mod
    walked = {"called": False}
    def tracking_walk(*a, **kw):
        walked["called"] = True
        return []
    import winbox.kdbg.walk as walk_mod
    monkeypatch.setattr(walk_mod, "list_user_modules", tracking_walk)

    store = _StoreForValidation({
        "nt": {"base": 0xfffff80608628000},  # kernel-only, gets skipped
    })
    daemon_mod._validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)
    assert walked["called"] is False


def test_validate_peb_walk_failure_skips_gracefully(monkeypatch, capsys):
    """If the PEB.Ldr walk fails (target has no PEB, store missing
    types, etc.), skip validation rather than block attach AND log a
    clear warning to stderr so the user knows checks were skipped."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    import winbox.kdbg as kdbg_mod
    import winbox.kdbg.walk as walk_mod
    monkeypatch.setattr(kdbg_mod, "ensure_types_loaded", lambda *a, **kw: None)
    def boom(*a, **kw):
        raise RuntimeError("walk failed")
    monkeypatch.setattr(walk_mod, "list_user_modules", boom)

    store = _StoreForValidation({
        "ntdll": {"base": 0x7ff800000000},
    })
    # Should NOT raise — graceful fallback.
    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)
    captured = capsys.readouterr()
    assert "PEB.Ldr walk failed" in captured.err
    assert "RuntimeError" in captured.err


def test_validate_peb_walk_unexpected_exception_reraises(monkeypatch):
    """THE FIX: previously _validate_module_bases caught bare Exception
    and silently skipped on every failure — including programming bugs.
    Now it catches only the expected set; anything else (TypeError,
    ValueError on a real bug, AssertionError, etc.) MUST propagate so
    the daemon dies loudly instead of installing bps against stale
    bases."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    import winbox.kdbg as kdbg_mod
    import winbox.kdbg.walk as walk_mod
    monkeypatch.setattr(kdbg_mod, "ensure_types_loaded", lambda *a, **kw: None)

    class WeirdBug(Exception):
        """Stand-in for an unrelated programming bug — not in the
        narrow expected set (HmpError/OSError/RuntimeError/LookupError/
        SymbolStoreError) so it must propagate."""

    def boom(*a, **kw):
        raise WeirdBug("real bug, not a transient failure")
    monkeypatch.setattr(walk_mod, "list_user_modules", boom)

    store = _StoreForValidation({
        "ntdll": {"base": 0x7ff800000000},
    })
    with pytest.raises(WeirdBug):
        _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)


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


# ── Conditional bps (predicate gate) ────────────────────────────────────


_KERNEL_VA = 0xfffff80608628780  # nt!something — kernel half, no CR3 dance
_TARGET_DTB = 0x4d6bb000          # matches default _make_session() target


class _ScriptedRsp(FakeRsp):
    """FakeRsp variant where ``read_registers`` and ``read_cr3`` step
    through a list of g-packet blobs — one per fire. Used to drive
    multi-fire op_cont scenarios for predicate skip+halt tests.

    Order of events per fire in op_cont: cont() → wait_for_stop() →
    read_cr3() → read_registers(). We advance on wait_for_stop so the
    blobs list is read in order: blobs[0] for fire 1, blobs[1] for
    fire 2, etc. After the script is exhausted the last blob is reused
    (a runaway loop just keeps re-reading it instead of IndexError).
    """

    def __init__(self, blobs: list[bytes]) -> None:
        super().__init__(regs_blob=blobs[0])
        self._blobs = list(blobs)
        self._fire_idx = 0  # which blob the upcoming reads will see

    def wait_for_stop(self, *, timeout: float | None = None):
        # Update regs_blob to the next scripted fire BEFORE the daemon
        # reads cr3/regs.
        if self._fire_idx < len(self._blobs):
            self.regs_blob = self._blobs[self._fire_idx]
            self._fire_idx += 1
        return super().wait_for_stop(timeout=timeout)


def _install_kernel_bp(session, *, condition=None) -> int:
    """Install a soft kernel bp at _KERNEL_VA (no CR3 masquerade) and
    return its bp_id. Soft mode keeps the test focused on the predicate
    gate, not the install path."""
    reply = session.handle_op(
        "bp_add",
        {"target": f"0x{_KERNEL_VA:x}", "mode": "soft", "condition": condition},
    )
    assert reply["ok"], reply
    return reply["result"]["id"]


def test_bp_add_bad_condition_rejected_before_install():
    rsp = FakeRsp()
    session = _make_session(rsp=rsp)
    reply = session.handle_op(
        "bp_add",
        {"target": f"0x{_KERNEL_VA:x}", "condition": "garbage **"},
    )
    assert reply["ok"] is False
    assert "condition" in reply["error"].lower()
    # And nothing was sent to gdbstub.
    assert rsp.bps_inserted == []


def test_bp_add_no_condition_unchanged_behavior():
    rsp = FakeRsp()
    session = _make_session(rsp=rsp)
    reply = session.handle_op(
        "bp_add",
        {"target": f"0x{_KERNEL_VA:x}", "mode": "soft"},
    )
    assert reply["ok"]
    bp = next(iter(session.bps.values()))
    assert bp.condition is None
    assert bp._predicate is None
    assert bp.predicate_hits == 0
    assert bp.predicate_skips == 0
    assert bp.predicate_errors == 0


def test_bp_list_includes_predicate_counters():
    session = _make_session()
    _install_kernel_bp(session, condition="rcx == 0xdeadbeef")
    out = session.handle_op("bp_list", {})
    bp = out["result"]["bps"][0]
    assert bp["condition"] == "rcx == 0xdeadbeef"
    assert bp["predicate_hit_count"] == 0
    assert bp["predicate_skip_count"] == 0
    assert bp["predicate_error_count"] == 0


def test_op_cont_predicate_skip_then_halt():
    """First fire: rcx mismatches predicate → silent-cont.
    Second fire: rcx matches → halt with reason='bp'."""
    blobs = [
        _blob(rip=_KERNEL_VA, rsp=0x1000, rcx=0x1, cr3=_TARGET_DTB),
        _blob(rip=_KERNEL_VA, rsp=0x1000, rcx=0xdeadbeef, cr3=_TARGET_DTB),
    ]
    rsp = _ScriptedRsp(blobs)
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="rcx == 0xdeadbeef")

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    result = out["result"]
    assert result["reason"] == "bp"
    assert result["rip"] == f"0x{_KERNEL_VA:x}"

    bp = next(iter(session.bps.values()))
    assert bp.predicate_skips == 1
    assert bp.predicate_hits == 1
    # cont() called twice: once after skip to advance, once at start.
    # Either way, > 0 is what matters — the skip path went through cont.
    assert rsp.continued >= 2


def test_op_cont_predicate_mem_deref_halts_when_match():
    """[rsp+0x18] == 0x226048 — only fires that satisfy the qword
    deref should halt."""
    blobs = [
        _blob(rip=_KERNEL_VA, rsp=0x2000, cr3=_TARGET_DTB),  # mismatch
        _blob(rip=_KERNEL_VA, rsp=0x2000, cr3=_TARGET_DTB),  # match
    ]
    rsp = _ScriptedRsp(blobs)
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="[rsp+0x18] == 0x226048")

    # Drive read_memory from the test: first fire sees a non-match,
    # second fire sees the magic value.
    fire_idx = {"n": 0}

    def scripted_read(va, length):
        assert va == 0x2000 + 0x18
        assert length == 8
        # First call → 0; second call → 0x226048.
        cur = fire_idx["n"]
        fire_idx["n"] += 1
        return (0 if cur == 0 else 0x226048).to_bytes(8, "little")

    rsp.read_memory = scripted_read

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    assert out["result"]["reason"] == "bp"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_skips == 1
    assert bp.predicate_hits == 1


def test_op_cont_predicate_mask_check():
    """(rax & 0x80000000) != 0 — halt only on negative status."""
    blobs = [
        _blob(rip=_KERNEL_VA, rax=0x00001234, cr3=_TARGET_DTB),  # mask 0
        _blob(rip=_KERNEL_VA, rax=0x80001234, cr3=_TARGET_DTB),  # mask set
    ]
    rsp = _ScriptedRsp(blobs)
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="(rax & 0x80000000) != 0")

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    assert out["result"]["reason"] == "bp"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_skips == 1
    assert bp.predicate_hits == 1


def test_op_cont_predicate_boolean_combo():
    """rcx == 0x4 && [rdx] != 0 — halt only when both true."""
    blobs = [
        # rcx mismatch (rdx irrelevant due to short-circuit)
        _blob(rip=_KERNEL_VA, rcx=0x5, rdx=0x3000, cr3=_TARGET_DTB),
        # rcx match, rdx points to zero qword → mismatch
        _blob(rip=_KERNEL_VA, rcx=0x4, rdx=0x3000, cr3=_TARGET_DTB),
        # rcx match, rdx points to nonzero qword → match
        _blob(rip=_KERNEL_VA, rcx=0x4, rdx=0x3000, cr3=_TARGET_DTB),
    ]
    rsp = _ScriptedRsp(blobs)
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="rcx == 0x4 && [rdx] != 0")

    fire_idx = {"n": 0}

    def scripted_read(va, length):
        # Only called when the && short-circuits to the rhs (fires 2+).
        assert va == 0x3000 and length == 8
        cur = fire_idx["n"]
        fire_idx["n"] += 1
        return (0 if cur == 0 else 0xc0de).to_bytes(8, "little")

    rsp.read_memory = scripted_read

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    assert out["result"]["reason"] == "bp"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_skips == 2
    assert bp.predicate_hits == 1
    # short-circuit: read_memory not called for the rcx-mismatch fire.
    assert fire_idx["n"] == 2


def test_op_cont_predicate_unmapped_va_reads_as_zero():
    """RspError from ``rsp.read_memory`` means the gdbstub rejected the
    read — typically an unmapped VA. Documented predicate semantic: such
    reads return 0 so checks like ``[rcx+N] != 0`` naturally false-out on
    dangling pointers without aborting the bp. No predicate_errors bump."""
    rsp = _ScriptedRsp([
        _blob(rip=_KERNEL_VA, rcx=0xdeadbeef, cr3=_TARGET_DTB),
    ])
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="[rcx] == 0")

    from winbox.kdbg.debugger.rsp import RspError

    def bad_read(va, length):
        raise RspError("E14")
    rsp.read_memory = bad_read

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    # [rcx] silently reads as 0 -> 0 == 0 -> true -> predicate_hits, halt.
    assert out["result"]["reason"] == "bp"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_hits == 1
    assert bp.predicate_errors == 0


def test_op_cont_predicate_oserror_does_not_crash_daemon():
    """Regression: previously, an OSError from rsp.read_memory (e.g.
    socket reset mid-cont) leaked past the predicate evaluator and out
    of op_cont as an uncaught OSError, taking down the daemon socket
    handler. After the MemRead.eval wrap fix, it must surface as a
    clean reason='predicate_error' halt with the counter bumped."""
    rsp = _ScriptedRsp([
        _blob(rip=_KERNEL_VA, rcx=0xdeadbeef, cr3=_TARGET_DTB),
    ])
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="[rcx] == 0")

    def bad_read(va, length):
        raise OSError("connection reset by peer")
    rsp.read_memory = bad_read

    out = session.handle_op("cont", {"timeout": 1.0})
    # The daemon must reply normally — not raise OSError out of handle_op.
    assert out["ok"], out
    assert out["result"]["reason"] == "predicate_error"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_errors == 1


def test_op_cont_predicate_value_error_does_not_crash_daemon():
    """Same shape as the OSError test but for ValueError (e.g. bad
    m-packet response parsing inside the rsp layer)."""
    rsp = _ScriptedRsp([
        _blob(rip=_KERNEL_VA, rcx=0xdeadbeef, cr3=_TARGET_DTB),
    ])
    session = _make_session(rsp=rsp)
    _install_kernel_bp(session, condition="[rcx] == 0")

    def bad_read(va, length):
        raise ValueError("malformed m-packet response")
    rsp.read_memory = bad_read

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    assert out["result"]["reason"] == "predicate_error"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_errors == 1


def test_bp_remove_clears_va_index():
    rsp = FakeRsp()
    session = _make_session(rsp=rsp)
    reply = session.handle_op(
        "bp_add",
        {"target": f"0x{_KERNEL_VA:x}", "mode": "soft", "condition": "rcx == 1"},
    )
    bp_id = reply["result"]["id"]
    assert _KERNEL_VA in session._bp_by_va
    session.handle_op("bp_remove", {"id": bp_id})
    assert _KERNEL_VA not in session._bp_by_va


# ── Bug fixes: CR3 restore failure poisons session ──────────────────────


class _FailingRestoreRsp(_FakeRspWithWrite):
    """FakeRsp that lets the masquerade G-swap succeed but the
    restore G-packet fail with a non-OK reply.

    op_mem/op_write_mem do exactly two G exchanges per call: swap then
    restore. We let the first through and reject the second.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._g_count = 0
        self.restore_response = b"E22"

    def _exchange(self, body, *, timeout=None):
        if body.startswith(b"G"):
            self._g_count += 1
            if self._g_count == 2:
                # Second G is the restore — reject it.
                return self.restore_response
            # First G (swap) — accept and update regs as the parent does.
            self.regs_blob = bytes.fromhex(body[1:].decode("ascii"))
            return b"OK"
        return b"OK"


def test_op_mem_failed_restore_sets_cr3_corrupted_and_refuses_subsequent_ops():
    """If the restore G-packet is rejected, the daemon must mark itself
    poisoned and refuse every following op (except status) — resuming
    with a masqueraded CR3 BSODs the guest."""
    rsp = _FailingRestoreRsp()
    session = _make_session(rsp=rsp)
    reply = session.handle_op("mem", {"va": "0x1000", "length": 8})
    assert reply["ok"] is False
    assert "poison" in reply["error"].lower() or "cr3" in reply["error"].lower()
    assert session._cr3_corrupted is True

    # Subsequent op (anything but status) — short-circuits with the
    # poison error, never touches gdbstub.
    g_count_before = rsp._g_count
    follow = session.handle_op("regs", {})
    assert follow["ok"] is False
    assert "poison" in follow["error"].lower()
    assert rsp._g_count == g_count_before  # gdbstub untouched

    # status still works (introspection only).
    st = session.handle_op("status", {})
    assert st["ok"] is True


def test_op_write_mem_failed_restore_also_poisons():
    """Same poison rule applies to op_write_mem's CR3 dance."""
    rsp = _FailingRestoreRsp()
    session = _make_session(rsp=rsp)
    reply = session.handle_op("write_mem", {"va": "0x1000", "data": "deadbeef"})
    assert reply["ok"] is False
    assert session._cr3_corrupted is True


# ── Bug fix #2: shutdown removes hw bps via z1 ──────────────────────────


def test_shutdown_removes_hw_bps_with_hardware_flag():
    """Hardware bps installed via Z1 must be removed via z1 — passing
    no hardware flag (default False) sends z0 which is a no-op for hw
    bps in QEMU, leaking DR0..3 across detach."""
    rsp = FakeRsp()
    rm_calls: list[dict] = []
    real_remove = rsp.remove_breakpoint

    def tracking_remove(addr, *, kind=1, hardware=False):
        rm_calls.append({"addr": addr, "hw": hardware})
        real_remove(addr, kind=kind, hardware=hardware)

    rsp.remove_breakpoint = tracking_remove

    store = FakeStore({"nt!Foo": 0xfffff80608000000, "nt!Bar": 0xfffff80608000100})
    session = _make_session(rsp=rsp, store=store)
    session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})
    session.handle_op("bp_add", {"target": "nt!Bar", "mode": "soft"})

    # shutdown() calls _sock.close() — give it a sock attribute.
    rsp._sock = MagicMock()

    session.shutdown()

    by_addr = {c["addr"]: c["hw"] for c in rm_calls}
    assert by_addr[0xfffff80608000000] is True   # hw bp -> z1
    assert by_addr[0xfffff80608000100] is False  # soft bp -> z0


# ── Bug fix #3: shutdown skips cont when CR3 corrupted ──────────────────


def test_shutdown_skips_cont_when_cr3_corrupted():
    """Mid-dance corruption means the firing vCPU still holds a
    masqueraded CR3. shutdown must NOT issue cont — that would resume
    the guest with the wrong page tables and BSOD it."""
    rsp = FakeRsp()
    rsp._sock = MagicMock()
    session = _make_session(rsp=rsp)
    session._cr3_corrupted = True

    # Pre-existing bp — shutdown should not even try to remove it
    # (removing requires touching the gdbstub) and definitely should
    # not cont.
    import time as _t
    session.bps[0] = Breakpoint(
        bp_id=0, va=0xfffff80608000000, target="nt!Foo",
        user_mode=False, hw=False, installed_at=_t.monotonic(),
    )

    session.shutdown()

    assert rsp.continued == 0
    assert rsp.bps_removed == []


def test_shutdown_returns_quickly_when_not_busy():
    """shutdown waits up to ~2s for an in-flight op to clear self._busy
    before yanking the socket. When not busy, it returns quickly."""
    import time as _t
    rsp = FakeRsp()
    rsp._sock = MagicMock()
    session = _make_session(rsp=rsp)
    session._busy = False

    t0 = _t.monotonic()
    session.shutdown()
    elapsed = _t.monotonic() - t0
    # Not busy → returns quickly (well under the 2s budget; cont path
    # adds a 0.1s sleep so we allow some headroom).
    assert elapsed < 0.5


# ── Bug fix #4: op_mem prefers self.stop.vcpu over threads[0] ───────────


def test_op_mem_uses_stop_vcpu_when_set():
    """op_mem must prefer self.stop.vcpu over threads[0] — the firing
    vCPU is the one the bp/step machinery is already manipulating."""
    rsp = FakeRsp(threads=("01", "03", "07"))
    selected: list[str] = []
    real_select = rsp.select_thread

    def tracking_select(t, *, op="g"):
        selected.append(t)
        real_select(t, op=op)

    rsp.select_thread = tracking_select

    session = _make_session(rsp=rsp)
    # Pretend a stop happened on vCPU 03 (NOT threads[0] which is "01").
    session.stop = StopState(
        vcpu="03", rip=0xfffff80608628780, cr3=0x4d6bb000, signal=5,
        raw_regs=_blob(),
    )

    reply = session.handle_op("mem", {"va": "0x1000", "length": 8})
    assert reply["ok"]
    # The op_mem path must have selected vCPU 03, not 01.
    assert "03" in selected
    assert "01" not in selected


def test_op_mem_falls_back_to_threads0_pre_stop():
    """When no stop is recorded, op_mem falls back to threads[0]."""
    rsp = FakeRsp(threads=("05", "06"))
    selected: list[str] = []
    real_select = rsp.select_thread

    def tracking_select(t, *, op="g"):
        selected.append(t)
        real_select(t, op=op)

    rsp.select_thread = tracking_select

    session = _make_session(rsp=rsp)
    assert session.stop is None  # pre-stop

    reply = session.handle_op("mem", {"va": "0x1000", "length": 8})
    assert reply["ok"]
    assert "05" in selected


def test_op_write_mem_uses_stop_vcpu_when_set():
    """Same vCPU preference applies to op_write_mem."""
    rsp = _FakeRspWithWrite(threads=("01", "03", "07"))
    selected: list[str] = []
    real_select = rsp.select_thread

    def tracking_select(t, *, op="g"):
        selected.append(t)
        real_select(t, op=op)

    rsp.select_thread = tracking_select

    session = _make_session(rsp=rsp)
    session.stop = StopState(
        vcpu="07", rip=0xfffff80608628780, cr3=0x4d6bb000, signal=5,
        raw_regs=_blob(),
    )

    reply = session.handle_op("write_mem", {"va": "0x1000", "data": "00"})
    assert reply["ok"]
    assert "07" in selected
    assert "01" not in selected


# ── Bug fix #5: op_bp_remove keeps registry intact on RspError ──────────


def test_op_bp_remove_leaves_registry_intact_on_rsp_error():
    """If z-packet remove fails, the bp may still be live in QEMU.
    Untracking would leave a phantom: future fires hit the linear-scan
    fallback in op_cont with no predicate context. Keep both registry
    entries in place so the user can retry."""
    from winbox.kdbg.debugger.rsp import RspError
    rsp = FakeRsp()

    def failing_remove(addr, *, kind=1, hardware=False):
        raise RspError("z0 failed: E14")

    rsp.remove_breakpoint = failing_remove

    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)
    add = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "soft"})
    bp_id = add["result"]["id"]
    va = 0xfffff80608000000

    # Sanity: tracked before remove.
    assert bp_id in session.bps
    assert session._bp_by_va.get(va) == bp_id

    # Remove fails — error surfaces.
    rm = session.handle_op("bp_remove", {"id": bp_id})
    assert rm["ok"] is False
    err = rm["error"].lower()
    assert "retry" in err or "still tracked" in err

    # Both registry entries STILL there (the bug fix).
    assert bp_id in session.bps
    assert session._bp_by_va.get(va) == bp_id

    # Retrying with a now-working remove must succeed and clean up.
    rsp.remove_breakpoint = lambda addr, *, kind=1, hardware=False: None
    rm2 = session.handle_op("bp_remove", {"id": bp_id})
    assert rm2["ok"] is True
    assert bp_id not in session.bps
    assert va not in session._bp_by_va
