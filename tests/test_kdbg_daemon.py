"""Daemon op-handler unit tests using a fake RspClient.

These don't touch the fork/socket/lock layer (covered separately by
the integration test). They exercise the in-process ``DaemonSession``
state machine and op_<verb> dispatch.
"""

from __future__ import annotations

import struct
import time
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
          rcx=0xdeadbeef, cr3=0x1ae000, cs=0x10,
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
    struct.pack_into("<I", b, 140, cs)
    struct.pack_into("<Q", b, _CR3_OFFSET, cr3)
    return bytes(b)


class FakeRsp:
    def __init__(self, regs_blob=None, threads=("01",)) -> None:
        self.regs_blob = regs_blob or _blob()
        self._threads = list(threads)
        self.bps_inserted: list = []
        self.bps_removed: list = []
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

    def insert_breakpoint(self, addr: int, *, kind: int = 1,
                          hardware: bool = False, wp_type: str | None = None) -> None:
        self.bps_inserted.append((addr, kind, hardware, wp_type))

    def remove_breakpoint(self, addr: int, *, kind: int = 1,
                          hardware: bool = False, wp_type: str | None = None) -> None:
        self.bps_removed.append((addr, kind, hardware, wp_type))

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


def test_stop_epoch_invalidates_stale_reads_after_new_stop():
    session = _make_session()
    from winbox.kdbg.debugger.rsp import StopReply

    session._capture_stop(StopReply(5, "01", "swbreak", "T05"))
    old_session, old_stop = session.session_id, session.stop_id
    session._capture_stop(StopReply(5, "01", "swbreak", "T05"))

    reply = session.handle_op("mem", {
        "va": "0x1000", "length": 1,
        "session_id": old_session, "stop_id": old_stop,
    })
    assert reply["ok"] is False
    assert "stale debugger stop" in reply["error"]


def test_resume_clears_stop_evidence_and_status_reports_running():
    session = _make_session()
    session.stop = StopState(
        vcpu="01", rip=0x1000, cr3=0x4d6bb000, signal=5,
        raw_regs=_blob(rip=0x1000),
    )
    session.run_state = "halted"
    session.stop_id = 9

    session._begin_resume()

    status = session.op_status()
    assert status["state"] == "running"
    assert status["halted"] is False
    assert status["stop_id"] is None
    assert session.handle_op("regs", {})["ok"] is False


def test_decomp_snapshot_resolves_module_rva_atomically(monkeypatch):
    from types import SimpleNamespace

    session = _make_session()
    session.stop = StopState(
        vcpu="01", rip=0x1010, cr3=0x4d6bb000, signal=5, raw_regs=_blob()
    )
    session.run_state = "halted"
    session.stop_id = 3
    user = [SimpleNamespace(
        name="sample.exe", base=0x7FF600000000, size=0x5000,
        entry=0x1234, full_path=r"C:\sample.exe",
    )]
    monkeypatch.setattr(
        session, "_live_modules", lambda kind: user if kind == "user" else []
    )

    result = session.op_decomp_snapshot(module="sample", rva="0x120")

    assert result["runtime_va"] == "0x7ff600000120"
    assert result["module"]["rva"] == "0x120"
    assert result["stop_id"] == 3


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"module": "sample"}, "together"),
        ({"rva": "0x10"}, "together"),
        ({"module": "sample", "rva": "-1"}, "outside"),
        ({"module": "sample", "rva": "0x100000000"}, "outside"),
        ({"va": "0x10", "module": "sample", "rva": "0x10"}, "mutually"),
    ],
)
def test_decomp_snapshot_rejects_ambiguous_or_invalid_coordinates(kwargs, message):
    session = _make_session()
    session.stop = StopState(
        vcpu="01", rip=0x1010, cr3=0x4d6bb000, signal=5, raw_regs=_blob()
    )
    session.run_state = "halted"
    reply = session.handle_op("decomp_snapshot", kwargs)
    assert reply["ok"] is False
    assert message in reply["error"]


def test_context_is_bounded_and_epoch_consistent():
    session = _make_session(store=FakeStore({"nt!Here": 0xfffff80608628780}))
    session.stop = StopState(
        vcpu="01", rip=0xfffff80608628780, cr3=0x1ae000,
        signal=5, raw_regs=_blob(),
    )
    session.run_state = "halted"
    session.stop_id = 4

    result = session.op_context(
        disasm_count=3, stack_qwords=2, bt_depth=1,
        memory=[{"va": "0x2000", "length": 8}],
    )

    assert result["schema"] == "winbox.kdbg-context/1"
    assert result["stop_epoch"]["stop_id"] == 4
    assert len(result["assembly"]) == 3
    assert len(result["stack"]["qwords"]) == 2
    assert result["memory"] == [{"va": "0x2000", "bytes": "90" * 8}]


def test_context_allows_zero_components_without_leaking_one_frame():
    session = _make_session()
    session.stop = StopState(
        vcpu="01", rip=0x1000, cr3=0x4d6bb000, signal=5, raw_regs=_blob()
    )
    session.run_state = "halted"
    result = session.op_context(disasm_count=0, stack_qwords=0, bt_depth=0)
    assert result["assembly"] == []
    assert result["stack"]["qwords"] == []
    assert result["backtrace"]["frames"] == []


def test_context_preserves_other_evidence_when_code_and_stack_are_unreadable():
    from winbox.kdbg.debugger.rsp import RspError

    class UnreadableRsp(FakeRsp):
        def read_memory(self, va, length):
            raise RspError("E14")

    session = _make_session(rsp=UnreadableRsp())
    session.stop = StopState(
        vcpu="01", rip=0x1000, cr3=0x4d6bb000, signal=5,
        raw_regs=_blob(rip=0x1000),
    )
    session.run_state = "halted"

    result = session.op_context(disasm_count=2, stack_qwords=2, bt_depth=2)

    assert result["registers"]["rip"].endswith("1000")
    assert "assembly_error" in result
    assert "stack_error" in result
    assert result["assembly"] == []
    assert result["stack"]["qwords"] == []
    assert result["backtrace"]["frames"] == []


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"disasm_count": 33}, "between"),
        ({"stack_qwords": True}, "integer"),
        ({"memory": [{"va": "0", "length": 1}] * 5}, "at most 4"),
        ({"memory": [{"va": "0", "length": 257}]}, "between"),
        ({"memory": [{"length": 8}]}, "requires va"),
    ],
)
def test_context_rejects_oversized_or_ambiguous_inputs(kwargs, message):
    session = _make_session()
    session.stop = StopState(
        vcpu="01", rip=0x1000, cr3=0x4d6bb000, signal=5, raw_regs=_blob()
    )
    session.run_state = "halted"
    reply = session.handle_op("context", kwargs)
    assert reply["ok"] is False
    assert message in reply["error"]


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
    assert rsp.bps_inserted == [(0xfffff80608628520, 1, True, None)]


# ── op_bp_add (user) — uses real install_user_breakpoint internally ────


def test_bp_add_soft_user_va_uses_cr3_masquerade(monkeypatch):
    """mode='soft' on a user VA still routes through install_user_breakpoint."""
    user_va = 0x7ff6e289a760

    from winbox.kdbg.debugger import daemon as daemon_mod
    from winbox.kdbg.debugger.install import InstallReport

    captured = {}

    def fake_install(cli, vm_name, store, *, cr3_candidates, user_va):
        captured["cr3_candidates"] = cr3_candidates
        captured["user_va"] = user_va
        return InstallReport(user_va=user_va, target_dtb=cr3_candidates[0], elapsed=0.005)

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
    # Default _make_session target has no user_dtb -> single candidate.
    assert captured["cr3_candidates"] == (0x4d6bb000,)
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


def test_bp_add_auto_mode_rejected():
    """mode='auto' is no longer accepted — breakpoints must carry type explicitly."""
    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(store=store)
    reply = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "auto"})
    assert reply["ok"] is False
    assert "explicitly" in reply["error"]


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
        user_va=kw["user_va"], target_dtb=kw["cr3_candidates"][0], elapsed=0.001,
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
    assert rsp.bps_removed == [(0xfffff80608000000, 1, True, None)]
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
    def tracking_remove(addr, *, kind=1, hardware=False, wp_type=None):
        rm_calls.append(hardware)
        real_remove(addr, kind=kind, hardware=hardware, wp_type=wp_type)
    rsp.remove_breakpoint = tracking_remove

    store = FakeStore({"nt!Foo": 0xfffff80608000000})
    session = _make_session(rsp=rsp, store=store)

    # Install one hw, one soft.
    hw_id = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})["result"]["id"]
    soft_id = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "soft"})["result"]["id"]

    session.handle_op("bp_remove", {"id": hw_id})
    session.handle_op("bp_remove", {"id": soft_id})

    # Removal calls in order: hw (True), soft (False)
    assert rm_calls == [True, False]


def _track_masquerade(rsp):
    """Wire ``rsp`` to record every G-packet CR3 write and the CR3 in
    effect at each remove_breakpoint call. Returns (cr3_writes,
    remove_cr3) lists that fill in as ops run."""
    cr3_writes: list[int] = []
    remove_cr3: list[int] = []
    orig_exchange = rsp._exchange

    def tracking_exchange(body, *, timeout=None):
        if body.startswith(b"G"):
            blob = bytes.fromhex(body[1:].decode("ascii"))
            cr3_writes.append(struct.unpack_from("<Q", blob, _CR3_OFFSET)[0])
        return orig_exchange(body, timeout=timeout)

    rsp._exchange = tracking_exchange

    orig_remove = rsp.remove_breakpoint

    def tracking_remove(addr, *, kind=1, hardware=False, wp_type=None):
        remove_cr3.append(struct.unpack_from("<Q", rsp.regs_blob, _CR3_OFFSET)[0])
        orig_remove(addr, kind=kind, hardware=hardware, wp_type=wp_type)

    rsp.remove_breakpoint = tracking_remove
    return cr3_writes, remove_cr3


def test_bp_remove_user_soft_masquerades_cr3():
    """A user-mode software bp was patched into target's physical page
    under a CR3 masquerade; its z0 removal must re-enter the same
    masquerade so QEMU clears the byte in target's address space, not
    the current (kernel-side) vCPU's — otherwise target's 0xCC stays."""
    import time as _t
    user_va = 0x7ff6e289a760
    rsp = FakeRsp()  # regs_blob default cr3 = 0x1ae000 (a non-target CR3)
    target = TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe")
    cr3_writes, remove_cr3 = _track_masquerade(rsp)

    session = _make_session(rsp=rsp, target=target)
    # Simulate a kernel-side stop: the current vCPU CR3 is not target's.
    session.stop = StopState(
        vcpu="01", rip=0xfffff80600001000, cr3=0x1ae000, signal=5,
        raw_regs=_blob(cr3=0x1ae000),
    )
    session.bps[0] = Breakpoint(
        bp_id=0, va=user_va, target="notepad!NPWndProc",
        user_mode=True, hw=False, installed_at=_t.monotonic(),
    )
    session._bp_by_va[user_va] = 0

    reply = session.handle_op("bp_remove", {"id": 0})
    assert reply["ok"], reply
    assert session.bps == {}
    # Swap to target.dtb, then restore original 0x1ae000.
    assert cr3_writes == [0x4d6bb000, 0x1ae000]
    # The z0 removal happened while masqueraded as target.dtb.
    assert remove_cr3 == [0x4d6bb000]
    assert rsp.bps_removed == [(user_va, 1, False, None)]


def test_shutdown_user_soft_bp_removed_under_masquerade():
    """shutdown's bp sweep must masquerade for user-mode soft bps too,
    for the same reason op_bp_remove does."""
    import time as _t
    user_va = 0x7ff6e289a760
    rsp = FakeRsp()
    rsp._sock = MagicMock()
    target = TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe")
    cr3_writes, remove_cr3 = _track_masquerade(rsp)

    session = _make_session(rsp=rsp, target=target)
    session.bps[0] = Breakpoint(
        bp_id=0, va=user_va, target="notepad!NPWndProc",
        user_mode=True, hw=False, installed_at=_t.monotonic(),
    )

    session.shutdown()

    assert remove_cr3 == [0x4d6bb000]  # removed under target's CR3
    # swap-in target.dtb then restore initial CR3 present in the writes.
    assert cr3_writes[0] == 0x4d6bb000


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


# ── installed_cr3 (bug #21) ────────────────────────────────────────────


def test_bp_add_user_soft_stores_installed_cr3(monkeypatch):
    """op_bp_add must persist the CR3 that install_user_breakpoint
    actually used so removal can skip candidate iteration."""
    from winbox.kdbg.debugger import daemon as _daemon_mod
    from winbox.kdbg.debugger.install import InstallReport

    rsp = FakeRsp()
    store = FakeStore({"notepad!NPWndProc": 0x7ff6e289a760})
    session = _make_session(rsp=rsp, store=store)

    fake_report = InstallReport(
        user_va=0x7ff6e289a760,
        target_dtb=0xDEAD,
        elapsed=0.001,
    )
    monkeypatch.setattr(
        _daemon_mod, "install_user_breakpoint",
        lambda *a, **kw: fake_report,
    )

    reply = session.handle_op(
        "bp_add", {"target": "notepad!NPWndProc", "mode": "soft"},
    )
    assert reply["ok"], reply
    bp_id = reply["result"]["id"]
    assert session.bps[bp_id].installed_cr3 == 0xDEAD


def test_bp_remove_user_soft_uses_installed_cr3():
    """When installed_cr3 is set, removal must use _cr3_masquerade with
    that exact CR3 instead of iterating candidates via
    _cr3_masqueraded_call."""
    import time as _t

    user_va = 0x7ff6e289a760
    rsp = FakeRsp()
    target = TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe")
    cr3_writes, remove_cr3 = _track_masquerade(rsp)

    session = _make_session(rsp=rsp, target=target)
    session.stop = StopState(
        vcpu="01", rip=0xfffff80600001000, cr3=0x1ae000, signal=5,
        raw_regs=_blob(cr3=0x1ae000),
    )
    session.bps[0] = Breakpoint(
        bp_id=0, va=user_va, target="notepad!NPWndProc",
        user_mode=True, hw=False, installed_at=_t.monotonic(),
        installed_cr3=0xBEEF,
    )
    session._bp_by_va[user_va] = 0

    # _cr3_masqueraded_call iterates candidates; we should NOT enter
    # it. Track whether it was called.
    masqueraded_call_used = []
    orig = session._cr3_masqueraded_call
    def spy(*a, **kw):
        masqueraded_call_used.append(True)
        return orig(*a, **kw)
    session._cr3_masqueraded_call = spy

    reply = session.handle_op("bp_remove", {"id": 0})
    assert reply["ok"], reply

    # Must have used installed_cr3 (0xBEEF) directly, not the
    # candidate-iteration path.
    assert masqueraded_call_used == [], (
        "_cr3_masqueraded_call should not be called when installed_cr3 is set"
    )
    # Swap to 0xBEEF, then restore original 0x1ae000.
    assert cr3_writes == [0xBEEF, 0x1ae000]
    assert remove_cr3 == [0xBEEF]


def test_bp_remove_user_soft_falls_back_without_installed_cr3():
    """When installed_cr3 is 0 (not recorded), removal must fall back
    to _cr3_masqueraded_call which iterates all candidates."""
    import time as _t

    user_va = 0x7ff6e289a760
    rsp = FakeRsp()
    target = TargetInfo(pid=4584, dtb=0x4d6bb000, name="notepad.exe")
    cr3_writes, _ = _track_masquerade(rsp)

    session = _make_session(rsp=rsp, target=target)
    session.stop = StopState(
        vcpu="01", rip=0xfffff80600001000, cr3=0x1ae000, signal=5,
        raw_regs=_blob(cr3=0x1ae000),
    )
    session.bps[0] = Breakpoint(
        bp_id=0, va=user_va, target="notepad!NPWndProc",
        user_mode=True, hw=False, installed_at=_t.monotonic(),
        installed_cr3=0,  # not recorded
    )
    session._bp_by_va[user_va] = 0

    masqueraded_call_used = []
    orig = session._cr3_masqueraded_call
    def spy(*a, **kw):
        masqueraded_call_used.append(True)
        return orig(*a, **kw)
    session._cr3_masqueraded_call = spy

    reply = session.handle_op("bp_remove", {"id": 0})
    assert reply["ok"], reply

    # Must have used _cr3_masqueraded_call (candidate iteration).
    assert masqueraded_call_used == [True]
    # Candidate iteration uses target.dtb (0x4d6bb000).
    assert cr3_writes[0] == 0x4d6bb000


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


def test_cont_timeout_captures_halt_state():
    """After cont timeout, self.stop must reflect the interrupt halt."""
    from winbox.kdbg.debugger.rsp import RspError, StopReply

    class TimeoutRsp(FakeRsp):
        def wait_for_stop(self, *, timeout=None):
            return StopReply(signal=2, thread="01", stop_kind="", raw="T02")

    rsp = TimeoutRsp(regs_blob=_blob())
    session = _make_session(rsp=rsp)
    session._wait_for_stop_serving = lambda remaining: (_ for _ in ()).throw(
        RspError("read timed out"))

    result = session.op_cont(timeout=1.0)
    assert result["reason"] == "timeout"
    assert session.stop is not None
    assert "rip" in result


def test_cont_timeout_interrupt_failure_leaves_stop_none():
    """If the post-timeout interrupt fails, stop stays None (graceful)."""
    from winbox.kdbg.debugger.rsp import RspError

    class BrokenInterruptRsp(FakeRsp):
        def interrupt(self):
            raise RspError("socket dead")

    session = _make_session(rsp=BrokenInterruptRsp())
    session._wait_for_stop_serving = lambda remaining: (_ for _ in ()).throw(
        RspError("read timed out"))

    result = session.op_cont(timeout=1.0)
    assert result["reason"] == "timeout"
    assert session.stop is None


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
    # Stop-derived evidence is cleared before resume and stays unavailable
    # when recovery cannot prove a new halt.
    assert session.stop is None
    assert session.op_status()["state"] == "indeterminate"


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


def test_masquerade_candidates_includes_verified_user_dtb():
    t = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ac000,
    )
    assert t.masquerade_candidates == (0x1225ad000, 0x1225ac000)


def test_masquerade_candidates_excludes_xor_guess_when_user_dtb_missing():
    """Unlike cr3_set, masquerade_candidates must NOT offer the XOR
    guess as a fallback — that guess is only safe as a passive
    membership check, not as a value to actively write into CR3 and
    walk page tables through."""
    t = TargetInfo(pid=8000, dtb=0x1225ad000, name="cyserver.exe")
    assert t.masquerade_candidates == (0x1225ad000,)
    assert t.cr3_set == (0x1225ad000, 0x1225ac000)  # cr3_set still offers it


def test_masquerade_candidates_dedupes_equal_halves():
    """A build that reports user_dtb == dtb must not yield the same CR3 twice —
    it would double the RSP round-trips and list the value twice in an
    exhausted-candidates error, reading as if two distinct halves were tried."""
    t = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ad000,
    )
    assert t.masquerade_candidates == (0x1225ad000,)


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


def test_op_cont_silent_continue_does_not_inflate_bp_hits():
    """A bp on shared code (e.g. ntdll!NtCreateFile) fires from every
    process on the box, not just the target. Fires that get
    silent-continued because their CR3 isn't the target's must not
    bump ``hits`` — that field is documented as counting only
    in-target fires."""
    import time as _t

    target = TargetInfo(
        pid=8000, dtb=0x1225ad000, name="cyserver.exe",
        user_dtb=0x1225ac000,
    )
    va = 0xfffff80700001234
    # Some unrelated process's CR3 hits the same shared VA.
    rsp = FakeRsp(regs_blob=_blob(rip=va, cr3=0xdeadbeef000))
    session = _make_session(rsp=rsp, target=target)
    session.bps[0] = Breakpoint(
        bp_id=0, va=va, target="nt!Shared",
        user_mode=False, hw=False, installed_at=_t.monotonic(),
    )

    session.handle_op("cont", {"timeout": 0.5})

    assert session.bps[0].hits == 0


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


# ── KPTI CR3-half retry (op_mem / op_write_mem) ─────────────────────────


class _FakeRspTwoCr3(FakeRsp):
    """Memory ops succeed only while masqueraded as ``real_cr3`` — fail
    with ``RspError`` under any other CR3. Models a KPTI target where a
    VA is mapped under only one of the process's two CR3 halves.
    Records every G-packet CR3 write in ``cr3_writes`` (the base
    FakeRsp doesn't keep one — this one adds it for retry-order
    assertions)."""

    def __init__(self, *args, real_cr3: int, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.real_cr3 = real_cr3
        self.cr3_writes: list[int] = []
        self.writes: list[tuple[int, bytes]] = []

    def _current_cr3(self) -> int:
        return struct.unpack_from("<Q", self.regs_blob, _CR3_OFFSET)[0]

    def _exchange(self, body, *, timeout=None) -> bytes:
        if body.startswith(b"G"):
            blob = bytes.fromhex(body[1:].decode("ascii"))
            self.regs_blob = blob
            self.cr3_writes.append(struct.unpack_from("<Q", blob, _CR3_OFFSET)[0])
            return b"OK"
        return b"OK"

    def read_memory(self, va, length):
        from winbox.kdbg.debugger.rsp import RspError
        if self._current_cr3() != self.real_cr3:
            raise RspError(f"m failed at 0x{va:x}: not mapped under this CR3")
        return b"\x90" * length

    def write_memory(self, va, data):
        from winbox.kdbg.debugger.rsp import RspError
        if self._current_cr3() != self.real_cr3:
            raise RspError(f"M failed at 0x{va:x}: not mapped under this CR3")
        self.writes.append((va, data))


def test_op_mem_retries_second_cr3_when_primary_fails_and_user_dtb_known():
    """Primary dtb doesn't map the VA (KPTI half mismatch), but the
    verified user_dtb does — op_mem should succeed via the fallback
    instead of failing outright."""
    primary_dtb = 0x4d6bb000
    user_dtb = 0x4d6bc000
    rsp = _FakeRspTwoCr3(real_cr3=user_dtb)
    target = TargetInfo(pid=4584, dtb=primary_dtb, name="notepad.exe", user_dtb=user_dtb)
    session = _make_session(rsp=rsp, target=target)

    reply = session.handle_op("mem", {"va": "0x1000", "length": 8})
    assert reply["ok"], reply
    assert reply["result"]["bytes"] == "90" * 8
    # Primary tried first (and failed), second candidate succeeded.
    assert rsp.cr3_writes[0] == primary_dtb
    assert user_dtb in rsp.cr3_writes


def test_op_mem_does_not_retry_xor_guess_when_user_dtb_unknown():
    """Without a verified user_dtb, op_mem must NOT fall back to the
    cr3_set XOR guess — that guess is only safe as a passive membership
    check (op_cont), not as a value to actively masquerade into CR3 and
    walk page tables through. A miss here should fail cleanly, not
    silently walk through a guessed physical page."""
    primary_dtb = 0x4d6bb000
    guess = primary_dtb ^ 0x1000  # what cr3_set's fallback would offer
    rsp = _FakeRspTwoCr3(real_cr3=guess)  # only the guess would "work"
    target = TargetInfo(pid=4584, dtb=primary_dtb, name="notepad.exe")  # user_dtb=0
    session = _make_session(rsp=rsp, target=target)

    reply = session.handle_op("mem", {"va": "0x1000", "length": 8})
    assert reply["ok"] is False
    # Only the primary was ever tried — no XOR-guess retry attempted.
    assert rsp.cr3_writes.count(primary_dtb) >= 1
    assert guess not in rsp.cr3_writes


def test_op_write_mem_retries_second_cr3_when_primary_fails_and_user_dtb_known():
    primary_dtb = 0x4d6bb000
    user_dtb = 0x4d6bc000
    rsp = _FakeRspTwoCr3(real_cr3=user_dtb)
    target = TargetInfo(pid=4584, dtb=primary_dtb, name="notepad.exe", user_dtb=user_dtb)
    session = _make_session(rsp=rsp, target=target)

    reply = session.handle_op("write_mem", {"va": "0x1000", "data": "deadbeef"})
    assert reply["ok"], reply
    assert rsp.writes == [(0x1000, b"\xde\xad\xbe\xef")]
    assert rsp.cr3_writes[0] == primary_dtb
    assert user_dtb in rsp.cr3_writes


# ── _validate_module_bases ───────────────────────────────────────────────


class _StoreForValidation:
    def __init__(self, modules: dict[str, dict], *, set_base_fails=False) -> None:
        self._modules = modules
        self.rebased: list[tuple[str, int]] = []
        self._set_base_fails = set_base_fails

    def list_modules(self):
        return list(self._modules.keys())

    def load(self, name):
        return self._modules[name]

    def set_base(self, name, base):
        if self._set_base_fails:
            raise OSError("store is read-only")
        self.rebased.append((name, base))
        self._modules.setdefault(name, {})["base"] = base


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


def test_validate_refreshes_a_stale_user_module_base(monkeypatch):
    """ASLR relocates images every boot, but the symbols stay valid — only
    the base each RVA is added to changed, and the live value is already in
    hand. Raising here made every post-reboot attach fail on a repair the
    daemon could just do."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
    _patch_validator(monkeypatch, [
        _FakeUserModule("ntdll.dll", 0x7ff_99999000),  # actual base
    ])
    store = _StoreForValidation({
        "ntdll": {"base": 0x7ff800000000},  # cached base — stale
    })

    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)

    assert store.rebased == [("ntdll", 0x7ff_99999000)]


def test_validate_raises_when_it_cannot_refresh(monkeypatch):
    """Only an unrepairable store is worth blocking the attach for."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases, DaemonError
    _patch_validator(monkeypatch, [
        _FakeUserModule("ntdll.dll", 0x7ff_99999000),
    ])
    store = _StoreForValidation(
        {"ntdll": {"base": 0x7ff800000000}}, set_base_fails=True
    )

    with pytest.raises(DaemonError) as exc:
        _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)

    msg = str(exc.value)
    assert "ntdll" in msg
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


def test_validate_refreshes_a_stale_nt_base(monkeypatch, capsys):
    """The post-VM-reboot state: cached nt base differs from the live
    IDT-derived one. ASLR moved the kernel, but every RVA in the store is
    still correct — so re-pointing the base is the entire repair, and the two
    commands the old error named did exactly that and nothing more."""
    from winbox.kdbg.debugger.daemon import _validate_module_bases
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

    _validate_module_bases(FakeCfg(), MagicMock(), _FakeTarget(), store)

    assert store.rebased == [("nt", live_nt_base)]
    # Say what happened — a silent rebase would hide a genuinely surprising
    # event (the guest rebooted under an attached debugger).
    err = capsys.readouterr().err
    assert f"0x{cached_nt_base:x}" in err
    assert f"0x{live_nt_base:x}" in err


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


def _record_g_cr3s(rsp) -> list[int]:
    """Return a list populated with every CR3 written by a G packet."""
    writes: list[int] = []
    original = rsp._exchange

    def tracking_exchange(body, *, timeout=None):
        if body.startswith(b"G"):
            blob = bytes.fromhex(body[1:].decode("ascii"))
            writes.append(struct.unpack_from("<Q", blob, _CR3_OFFSET)[0])
        return original(body, timeout=timeout)

    rsp._exchange = tracking_exchange
    return writes


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
    cr3_writes = _record_g_cr3s(rsp)
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
    # Only the two fires that actually reached [rdx] masqueraded.  The
    # runtime-short-circuited first fire kept the zero-G-packet fast path.
    assert len(cr3_writes) == 4


def test_op_cont_batches_independent_and_nested_predicate_reads():
    """Independent derefs and a dependent poi() chain share one swap."""
    regs = _blob(
        rip=_KERNEL_VA, rcx=0x1000, rdx=0x3000, cr3=_TARGET_DTB,
    )
    rsp = _ScriptedRsp([regs])
    cr3_writes = _record_g_cr3s(rsp)
    session = _make_session(rsp=rsp)
    _install_kernel_bp(
        session,
        condition="poi(poi(rcx)+0x8) == 0x1234 && [rdx] == 0x55",
    )

    memory = {
        0x1000: 0x2000,
        0x2008: 0x1234,
        0x3000: 0x55,
    }
    reads: list[int] = []

    def read_memory(va, length):
        reads.append(va)
        return memory[va].to_bytes(length, "little")

    rsp.read_memory = read_memory
    out = session.handle_op("cont", {"timeout": 1.0})

    assert out["ok"], out
    assert out["result"]["reason"] == "bp"
    assert reads == [0x1000, 0x2008, 0x3000]
    # One swap and one restore for all three data-dependent reads.  The old
    # path emitted six G packets (swap+restore around each read).
    assert cr3_writes == [_TARGET_DTB, _TARGET_DTB]


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


def test_op_cont_predicate_mem_deref_retries_second_cr3_when_user_dtb_known():
    """A predicate deref unmapped under the primary CR3 but mapped
    under the verified user_dtb must still evaluate against the real
    value — not silently read as 0 just because the first candidate
    missed. Same retry path as op_mem, exercised through the predicate
    reader instead."""
    user_dtb = 0x4d6bc000
    rsp = _ScriptedRsp([_blob(rip=_KERNEL_VA, rsp=0x2000, cr3=_TARGET_DTB)])
    target = TargetInfo(pid=4584, dtb=_TARGET_DTB, name="notepad.exe", user_dtb=user_dtb)
    session = _make_session(rsp=rsp, target=target)
    cr3_writes = _record_g_cr3s(rsp)
    _install_kernel_bp(session, condition="[rsp+0x18] == 0x226048")

    from winbox.kdbg.debugger.rsp import RspError

    def scripted_read(va, length):
        assert va == 0x2000 + 0x18
        assert length == 8
        current_cr3 = struct.unpack_from("<Q", rsp.regs_blob, _CR3_OFFSET)[0]
        if current_cr3 != user_dtb:
            raise RspError("E14")  # primary CR3 doesn't map this VA
        return (0x226048).to_bytes(8, "little")

    rsp.read_memory = scripted_read

    out = session.handle_op("cont", {"timeout": 1.0})
    assert out["ok"], out
    assert out["result"]["reason"] == "bp"
    bp = next(iter(session.bps.values()))
    # Retried through to the real value and matched — not a false
    # positive from the unmapped-reads-as-zero fallback.
    assert bp.predicate_hits == 1
    assert bp.predicate_errors == 0
    # Primary attempt + restore, then verified user-DTB attempt + restore.
    assert cr3_writes == [_TARGET_DTB, _TARGET_DTB, user_dtb, _TARGET_DTB]


def test_batched_predicate_falls_back_for_mixed_cr3_mappings():
    """A mixed kernel/user expression may require a different CR3 per read.

    Neither candidate can evaluate the whole expression alone.  The batch
    attempts must therefore fall back to the old per-read selection and still
    produce the correct truth value.
    """
    user_dtb = 0x4d6bc000
    regs = _blob(
        rip=_KERNEL_VA, rcx=0xfffff80000100000,
        rdx=0x0000000000200000, cr3=_TARGET_DTB,
    )
    rsp = _ScriptedRsp([regs])
    target = TargetInfo(
        pid=4584, dtb=_TARGET_DTB, name="notepad.exe", user_dtb=user_dtb,
    )
    session = _make_session(rsp=rsp, target=target)
    _install_kernel_bp(session, condition="[rcx] == 0xaa && [rdx] == 0xbb")

    def read_memory(va, length):
        current_cr3 = struct.unpack_from("<Q", rsp.regs_blob, _CR3_OFFSET)[0]
        if va == 0xfffff80000100000 and current_cr3 == _TARGET_DTB:
            return (0xaa).to_bytes(length, "little")
        if va == 0x200000 and current_cr3 == user_dtb:
            return (0xbb).to_bytes(length, "little")
        from winbox.kdbg.debugger.rsp import RspError
        raise RspError("E14")

    rsp.read_memory = read_memory
    out = session.handle_op("cont", {"timeout": 1.0})

    assert out["ok"], out
    assert out["result"]["reason"] == "bp"
    bp = next(iter(session.bps.values()))
    assert bp.predicate_hits == 1
    assert bp.predicate_read_errors == 0


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


def test_batched_predicate_failed_restore_poisons_without_retrying():
    """A failed batch restore is fatal, never a reason to try another CR3."""
    user_dtb = 0x4d6bc000
    rsp = _FailingRestoreRsp(
        regs_blob=_blob(
            rip=_KERNEL_VA, rcx=0x1000, rdx=0x2000, cr3=_TARGET_DTB,
        )
    )
    target = TargetInfo(
        pid=4584, dtb=_TARGET_DTB, name="notepad.exe", user_dtb=user_dtb,
    )
    session = _make_session(rsp=rsp, target=target)
    _install_kernel_bp(session, condition="[rcx] == 0x90 && [rdx] == 0x90")

    reply = session.handle_op("cont", {"timeout": 1.0})

    assert reply["ok"] is False
    assert session._cr3_corrupted is True
    # Exactly swap + failed restore.  The verified second candidate must not
    # be attempted after a poisoning restore failure.
    assert rsp._g_count == 2


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


class TestBreakpointFailureExplanations:
    """Neither mechanism installs on both images: HVCI blocks the software
    path on Windows 11, and the 4-slot DR budget has been seen exhausted on
    Server 2022. The messages have to say which wall you hit, because the
    remedy is the opposite mode in each case."""

    def test_hw_timeout_does_not_blame_the_slot_budget_alone(self):
        from winbox.kdbg.debugger.daemon import _hw_bp_failure
        from winbox.kdbg.debugger.rsp import RspError

        msg = _hw_bp_failure(RspError("read timed out"))

        assert "timed out" in msg
        assert "stopped answering" in msg
        # Slots are still a possibility, just not asserted as the cause.
        assert "may" in msg
        assert "soft" in msg

    def test_hw_refusal_points_at_the_slot_budget(self):
        from winbox.kdbg.debugger.daemon import _hw_bp_failure
        from winbox.kdbg.debugger.rsp import RspError

        msg = _hw_bp_failure(RspError("E22"))

        assert "DR0..3" in msg
        assert "soft" in msg

    def test_soft_kernel_timeout_names_hvci(self):
        """The Windows 11 case. "read timed out" alone gave no way to know a
        software breakpoint structurally cannot work on that guest."""
        from winbox.kdbg.debugger.daemon import _soft_bp_failure
        from winbox.kdbg.debugger.rsp import RspError

        msg = _soft_bp_failure(RspError("read timed out"), is_user=False)

        assert "HVCI" in msg
        assert "0xCC" in msg
        assert "hw" in msg

    def test_soft_user_mode_does_not_blame_hvci(self):
        """HVCI guards kernel code pages; a user-mode bp failing is something
        else, and saying HVCI would send the user down a dead end."""
        from winbox.kdbg.debugger.daemon import _soft_bp_failure
        from winbox.kdbg.debugger.rsp import RspError

        msg = _soft_bp_failure(RspError("read timed out"), is_user=True)

        assert "HVCI" not in msg


# ── op_stack ────────────────────────────────────────────────────────────


def test_op_stack_returns_offset_labeled_qwords():
    rsp_val = 0xfffff80501234500
    blob = _blob(rsp=rsp_val, cr3=0x1ae000)
    stack_bytes = (b"\xef\xbe\xad\xde\x00\x00\x00\x00"
                   b"\xbe\xba\xfe\xca\x00\x00\x00\x00")

    class StackRsp(FakeRsp):
        def read_memory(self, va, length):
            return stack_bytes[:length]

    session = _make_session(rsp=StackRsp(regs_blob=blob))
    session.stop = StopState(vcpu="01", rip=0x1000, cr3=0x1ae000,
                             signal=5, raw_regs=blob)
    result = session.op_stack(n=2)
    assert result["rsp"] == f"0x{rsp_val:x}"
    assert len(result["qwords"]) == 2
    assert result["qwords"][0]["offset"] == "rsp+0x00"
    assert result["qwords"][0]["va"] == f"0x{rsp_val:x}"
    assert result["qwords"][0]["value"] == "0x00000000deadbeef"
    assert result["qwords"][1]["offset"] == "rsp+0x08"
    assert result["qwords"][1]["va"] == f"0x{rsp_val + 8:x}"
    assert result["qwords"][1]["value"] == "0x00000000cafebabe"


def test_op_stack_requires_halt():
    session = _make_session()
    with pytest.raises(RuntimeError, match="not halted"):
        session.op_stack()


# ── step_over ──────────────────────────────────────────────────────────


class TestStepOver:

    def _halted_session(self, rsp=None, rip=0xfffff80608628780):
        session = _make_session(rsp=rsp or FakeRsp())
        blob = _blob(rip=rip, cr3=0x1ae000)
        session.stop = StopState(
            vcpu="01", rip=rip, cr3=0x1ae000, signal=5, raw_regs=blob,
        )
        session._hw_bp_verified = True
        return session

    def test_step_over_call_plants_temp_bp(self):
        """call rel32 (E8 xx xx xx xx) should plant temp bp at RIP+5."""
        from winbox.kdbg.debugger.rsp import StopReply

        call_rip = 0xfffff80608628780
        next_rip = call_rip + 5  # E8 + 4-byte rel32

        class CallRsp(FakeRsp):
            def __init__(self):
                super().__init__()
                self._temp_bp_va = None
                self._returned = False

            def read_memory(self, va, length):
                if va == call_rip:
                    # E8 00 10 00 00 = call rel32 (offset 0x1000)
                    return b"\xe8\x00\x10\x00\x00" + b"\x90" * 10
                return b"\x90" * length

            def insert_breakpoint(self, addr, *, kind=1, hardware=False):
                self.bps_inserted.append(addr)
                if hardware and addr == next_rip:
                    self._temp_bp_va = addr

            def remove_breakpoint(self, addr, *, kind=1, hardware=False):
                self.bps_removed.append(addr)

            def cont(self):
                self.continued += 1

            def wait_for_stop(self, *, timeout=None):
                return StopReply(signal=5, thread="01",
                                stop_kind="hwbreak", raw="T05")

            def read_registers(self):
                return _blob(rip=next_rip, cr3=0x1ae000)

        rsp = CallRsp()
        session = self._halted_session(rsp=rsp, rip=call_rip)
        result = session.op_step_over()

        assert result["reason"] == "step_over"
        assert result["stepped_over"] == "call"
        assert next_rip in rsp.bps_inserted
        assert next_rip in rsp.bps_removed

    def test_step_over_non_call_falls_back_to_step(self):
        """Non-call instruction (e.g., nop) falls back to regular step."""
        from winbox.kdbg.debugger.rsp import StopReply

        nop_rip = 0xfffff80608628780

        class NopRsp(FakeRsp):
            def read_memory(self, va, length):
                if va == nop_rip:
                    return b"\x90" * 15  # nop sled
                return b"\x90" * length

            def step(self, t=None):
                self.stepped += 1

            def wait_for_stop(self, *, timeout=None):
                return StopReply(signal=5, thread="01",
                                stop_kind="hwbreak", raw="T05")

        rsp = NopRsp()
        session = self._halted_session(rsp=rsp, rip=nop_rip)
        result = session.op_step_over()

        assert result["reason"] == "step"
        assert rsp.stepped > 0

    def test_step_over_requires_halt(self):
        session = _make_session()
        with pytest.raises(RuntimeError, match="not halted"):
            session.op_step_over()

    def test_step_over_syscall(self):
        """syscall (0F 05) should be stepped over too."""
        from winbox.kdbg.debugger.rsp import StopReply

        sc_rip = 0xfffff80608628780
        next_rip = sc_rip + 2  # 0F 05 = 2 bytes

        class SyscallRsp(FakeRsp):
            def read_memory(self, va, length):
                if va == sc_rip:
                    return b"\x0f\x05" + b"\x90" * 13
                return b"\x90" * length

            def insert_breakpoint(self, addr, *, kind=1, hardware=False):
                self.bps_inserted.append(addr)

            def remove_breakpoint(self, addr, *, kind=1, hardware=False):
                self.bps_removed.append(addr)

            def cont(self):
                self.continued += 1

            def wait_for_stop(self, *, timeout=None):
                return StopReply(signal=5, thread="01",
                                stop_kind="hwbreak", raw="T05")

            def read_registers(self):
                return _blob(rip=next_rip, cr3=0x1ae000)

        rsp = SyscallRsp()
        session = self._halted_session(rsp=rsp, rip=sc_rip)
        result = session.op_step_over()

        assert result["reason"] == "step_over"
        assert result["stepped_over"] == "syscall"
        assert next_rip in rsp.bps_inserted
        assert next_rip in rsp.bps_removed

    def test_step_over_dr_slot_exhaustion(self):
        """Temp bp install failure gives clear error about DR slots."""
        from winbox.kdbg.debugger.rsp import RspError

        call_rip = 0xfffff80608628780

        class NoSlotsRsp(FakeRsp):
            def read_memory(self, va, length):
                if va == call_rip:
                    return b"\xe8\x00\x10\x00\x00" + b"\x90" * 10
                return b"\x90" * length

            def insert_breakpoint(self, addr, *, kind=1, hardware=False):
                raise RspError("E22")

        rsp = NoSlotsRsp()
        session = self._halted_session(rsp=rsp, rip=call_rip)
        with pytest.raises(RuntimeError, match="Free a DR slot"):
            session.op_step_over()


# ── step_out ───────────────────────────────────────────────────────────


class TestStepOut:

    def _halted_session(self, rsp=None, rip=0xfffff80608628780,
                        rsp_val=0xfffff80501234500):
        session = _make_session(rsp=rsp or FakeRsp())
        blob = _blob(rip=rip, rsp=rsp_val, cr3=0x1ae000)
        session.stop = StopState(
            vcpu="01", rip=rip, cr3=0x1ae000, signal=5, raw_regs=blob,
        )
        return session

    def test_step_out_plants_bp_at_return_address(self):
        from winbox.kdbg.debugger.rsp import StopReply

        rsp_val = 0xfffff80501234500
        ret_addr = 0xfffff80608628800

        class StepOutRsp(FakeRsp):
            def read_memory(self, va, length):
                if va == rsp_val:
                    return struct.pack("<Q", ret_addr)
                return b"\x90" * length

            def insert_breakpoint(self, addr, *, kind=1, hardware=False):
                self.bps_inserted.append(addr)

            def remove_breakpoint(self, addr, *, kind=1, hardware=False):
                self.bps_removed.append(addr)

            def cont(self):
                self.continued += 1

            def wait_for_stop(self, *, timeout=None):
                return StopReply(signal=5, thread="01",
                                stop_kind="hwbreak", raw="T05")

            def read_registers(self):
                return _blob(rip=ret_addr, cr3=0x1ae000)

        rsp = StepOutRsp()
        session = self._halted_session(rsp=rsp, rsp_val=rsp_val)
        result = session.op_step_out()

        assert result["reason"] == "step_out"
        assert ret_addr in rsp.bps_inserted
        assert ret_addr in rsp.bps_removed

    def test_step_out_requires_halt(self):
        session = _make_session()
        with pytest.raises(RuntimeError, match="not halted"):
            session.op_step_out()

    def test_step_out_zero_return_address_rejected(self):
        class ZeroRetRsp(FakeRsp):
            def read_memory(self, va, length):
                return b"\x00" * length

        rsp = ZeroRetRsp()
        session = self._halted_session(rsp=rsp)
        with pytest.raises(RuntimeError, match="return address.*is 0"):
            session.op_step_out()

    def test_step_out_dr_slot_exhaustion(self):
        from winbox.kdbg.debugger.rsp import RspError

        class NoSlotsRetRsp(FakeRsp):
            def read_memory(self, va, length):
                return struct.pack("<Q", 0xfffff80608628800)

            def insert_breakpoint(self, addr, *, kind=1, hardware=False):
                raise RspError("E22")

        rsp = NoSlotsRetRsp()
        session = self._halted_session(rsp=rsp)
        with pytest.raises(RuntimeError, match="Free a DR slot"):
            session.op_step_out()


# ── Item #18: register layout validation ───────────────────────────────


class TestRegisterLayoutValidation:

    def test_valid_blob_passes(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout
        blob = _blob(rip=0xfffff80608628780, cr3=0x1ae000)
        _validate_register_layout(blob)  # should not raise

    def test_short_blob_rejected(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout, DaemonError
        with pytest.raises(DaemonError, match="too short"):
            _validate_register_layout(b"\x00" * 100)

    def test_non_canonical_rip_rejected(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout, DaemonError
        blob = _blob(rip=0x8000000000001000)  # bit 47 set but not sign-extended
        with pytest.raises(DaemonError, match="not canonical"):
            _validate_register_layout(blob)

    def test_zero_cr3_rejected(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout, DaemonError
        blob = _blob(cr3=0)
        with pytest.raises(DaemonError, match="implausible"):
            _validate_register_layout(blob)

    def test_cr3_above_phys_cap_rejected(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout, DaemonError
        blob = _blob(cr3=(1 << 52))
        with pytest.raises(DaemonError, match="implausible"):
            _validate_register_layout(blob)

    def test_bad_cs_rejected(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout, DaemonError
        blob = bytearray(_blob())
        struct.pack_into("<I", blob, 140, 0xFF)  # bogus CS
        with pytest.raises(DaemonError, match="not a recognized"):
            _validate_register_layout(bytes(blob))

    def test_kernel_rip_passes(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout
        blob = _blob(rip=0xFFFFF80608628780)  # canonical-high
        _validate_register_layout(blob)

    def test_user_rip_passes(self):
        from winbox.kdbg.debugger.daemon import _validate_register_layout
        blob = _blob(rip=0x7FF6E289EABC)  # canonical-low
        _validate_register_layout(blob)


# ── Item #28: auto-retry on "empty stop reply" ─────────────────────────


class TestEmptyStopReplyRetry:
    """fork_daemon should auto-restart the gdbstub and reconnect when
    query_halt_reason raises RspError('empty stop reply')."""

    def test_retry_loop_constants_exist(self):
        """The retry constant is defined in fork_daemon's body.
        We verify indirectly by checking the source."""
        import inspect
        from winbox.kdbg.debugger import daemon
        src = inspect.getsource(daemon.fork_daemon)
        assert "_MAX_ATTACH_ATTEMPTS" in src
        assert "empty stop reply" in src

    def test_rsp_error_non_empty_stop_reply_is_not_retried(self):
        """RspError that is NOT "empty stop reply" should propagate
        without triggering the retry path."""
        from winbox.kdbg.debugger.rsp import RspError

        # The retry logic checks 'if "empty stop reply" not in str(err)'
        err = RspError("connection closed by peer")
        assert "empty stop reply" not in str(err)

    def test_rsp_error_empty_stop_reply_matches(self):
        """The exact error string must match the retry guard."""
        from winbox.kdbg.debugger.rsp import RspError

        err = RspError("empty stop reply")
        assert "empty stop reply" in str(err)


# ── Item #29: safe close on PID-not-found ──────────────────────────────


class TestPidNotFoundSafeClose:
    """When target_pid is not in the process list, fork_daemon should
    resume the VM and close the socket safely (no D-packet)."""

    def test_source_does_not_call_rsp_close(self):
        """The PID-not-found path must NOT call rsp.close() anymore —
        it uses the raw _sock.close() pattern from shutdown()."""
        import inspect
        from winbox.kdbg.debugger import daemon

        src = inspect.getsource(daemon.fork_daemon)
        # Find the pid-not-found block
        idx = src.index("target_rec is None")
        # Get the block until os._exit(1) after it
        block_end = src.index("os._exit(1)", idx)
        block = src[idx:block_end]
        # Strip comments before checking — the comment explaining *why*
        # rsp.close() is wrong mentions it by name.
        code_lines = [
            ln for ln in block.splitlines()
            if not ln.strip().startswith("#")
        ]
        code_only = "\n".join(code_lines)
        assert "rsp.close()" not in code_only, "rsp.close() must not be used in PID-not-found"
        assert "rsp._sock.close()" in code_only, "raw _sock.close() should be used"
        assert "rsp.cont()" in code_only, "cont() must be called before close"

    def test_source_checks_ga_channel(self):
        """The PID-not-found path should check agent_channel_connected
        and include a warning if the channel is down."""
        import inspect
        from winbox.kdbg.debugger import daemon

        src = inspect.getsource(daemon.fork_daemon)
        idx = src.index("target_rec is None")
        block_end = src.index("os._exit(1)", idx)
        block = src[idx:block_end]
        assert "agent_channel_connected" in block


# ── Item #30 Part A: hw bp verification probe ──────────────────────────


class TestHwBpPassiveVerification:
    """hw bp verification is now passive — set _hw_bp_verified when any
    hw bp fires during op_cont, regardless of CR3."""

    def test_hw_bp_verified_on_non_target_fire(self):
        """A hw bp fire in wrong CR3 should still set _hw_bp_verified."""
        from winbox.kdbg.debugger.rsp import StopReply

        bp_va = 0xfffff80608628780
        wrong_cr3 = 0xAAAAA000

        class WrongCR3Rsp(FakeRsp):
            def __init__(self):
                super().__init__(regs_blob=_blob(rip=bp_va, cr3=wrong_cr3))

            def wait_for_stop(self, *, timeout=None):
                return StopReply(signal=5, thread="01",
                                stop_kind="hwbreak", raw="T05")

            def read_registers(self):
                return _blob(rip=bp_va, cr3=wrong_cr3)

        rsp = WrongCR3Rsp()
        store = FakeStore({"nt!Foo": bp_va})
        session = _make_session(rsp=rsp, store=store)
        session._hw_bp_verified = False

        session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})
        assert session._hw_bp_verified is False  # not verified yet

        session.stop = StopState(vcpu="01", rip=0x1000, cr3=0x4d6bb000,
                                 signal=5, raw_regs=_blob(cr3=0x4d6bb000))
        session.handle_op("cont", {"timeout": 1})

        assert session._hw_bp_verified is True

    def test_hw_bp_not_verified_for_soft_bp(self):
        """A soft bp fire should NOT set _hw_bp_verified."""
        from winbox.kdbg.debugger.rsp import StopReply

        bp_va = 0xfffff80608628780
        target_cr3 = 0x4d6bb000

        class TargetRsp(FakeRsp):
            def __init__(self):
                super().__init__(regs_blob=_blob(rip=bp_va, cr3=target_cr3))

            def wait_for_stop(self, *, timeout=None):
                return StopReply(signal=5, thread="01",
                                stop_kind="swbreak", raw="T05")

            def read_registers(self):
                return _blob(rip=bp_va, cr3=target_cr3)

        rsp = TargetRsp()
        store = FakeStore({"nt!Foo": bp_va})
        session = _make_session(rsp=rsp, store=store)
        session._hw_bp_verified = False

        session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})

        session.stop = StopState(vcpu="01", rip=0x1000, cr3=target_cr3,
                                 signal=5, raw_regs=_blob(cr3=target_cr3))

        # Manually set the bp as soft for this test
        session.bps[0].hw = False

        session.handle_op("cont", {"timeout": 1})
        assert session._hw_bp_verified is False

    def test_no_probe_warning_on_bp_add(self):
        """bp_add should NOT include hw_probe_warning anymore."""
        store = FakeStore({"nt!Foo": 0xfffff80608000000})
        session = _make_session(store=store)
        reply = session.handle_op("bp_add", {"target": "nt!Foo", "mode": "hw"})
        assert reply["ok"]
        assert "hw_probe_warning" not in reply["result"]


# ── Item #30 Part B: unfired hw bp warnings ────────────────────────────


class TestUnfiredHwBpWarnings:
    """op_cont should warn about hw bps with hits==0 after long runs."""

    def test_unfired_warning_after_long_cont(self):
        """A hw bp with 0 hits after 5+ seconds should appear in warnings."""
        session = _make_session()
        # Manually set up a hw bp with 0 hits
        bp = Breakpoint(
            bp_id=0, va=0xfffff80608628780, target="nt!Foo",
            user_mode=False, hw=True, installed_at=time.monotonic(),
        )
        session.bps[0] = bp
        session._bp_by_va[bp.va] = 0

        result = session._unfired_hw_bp_warnings(elapsed=10.0)
        assert "unfired_hw_bps" in result
        assert len(result["unfired_hw_bps"]) == 1
        assert result["unfired_hw_bps"][0]["id"] == 0

    def test_no_warning_for_short_cont(self):
        """Under 5 seconds, no warning even if bp has 0 hits."""
        session = _make_session()
        bp = Breakpoint(
            bp_id=0, va=0xfffff80608628780, target="nt!Foo",
            user_mode=False, hw=True, installed_at=time.monotonic(),
        )
        session.bps[0] = bp

        result = session._unfired_hw_bp_warnings(elapsed=3.0)
        assert result == {}

    def test_no_warning_when_bp_has_hits(self):
        """A hw bp with hits > 0 should not show in warnings."""
        session = _make_session()
        bp = Breakpoint(
            bp_id=0, va=0xfffff80608628780, target="nt!Foo",
            user_mode=False, hw=True, installed_at=time.monotonic(),
            hits=3,
        )
        session.bps[0] = bp

        result = session._unfired_hw_bp_warnings(elapsed=10.0)
        assert result == {}

    def test_no_warning_for_soft_bp(self):
        """Software bps should not appear in unfired hw bp warnings."""
        session = _make_session()
        bp = Breakpoint(
            bp_id=0, va=0xfffff80608628780, target="nt!Foo",
            user_mode=False, hw=False, installed_at=time.monotonic(),
        )
        session.bps[0] = bp

        result = session._unfired_hw_bp_warnings(elapsed=10.0)
        assert result == {}

    def test_multiple_unfired_bps(self):
        """All unfired hw bps should be listed."""
        session = _make_session()
        for i in range(3):
            bp = Breakpoint(
                bp_id=i, va=0xfffff80608628780 + i,
                target=f"nt!Func{i}",
                user_mode=False, hw=True,
                installed_at=time.monotonic(),
            )
            session.bps[i] = bp

        # Give one of them hits
        session.bps[1].hits = 5

        result = session._unfired_hw_bp_warnings(elapsed=10.0)
        assert "unfired_hw_bps" in result
        ids = [bp["id"] for bp in result["unfired_hw_bps"]]
        assert 0 in ids
        assert 1 not in ids  # has hits
        assert 2 in ids


# ── Watchpoint tests (item 14) ────────────────────────────────────────

_KERNEL_VA_WP = 0xfffff80608628780


class TestWatchpointAdd:
    def test_write_watchpoint_sends_z2(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!SomeVar": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        reply = session.handle_op(
            "bp_add", {"target": "nt!SomeVar", "wp_type": "write", "wp_size": 4},
        )
        assert reply["ok"]
        r = reply["result"]
        assert r["wp_type"] == "write"
        assert r["wp_size"] == 4
        assert r["hw"] is True
        assert rsp.bps_inserted == [(_KERNEL_VA_WP, 4, False, "write")]

    def test_read_watchpoint_sends_z3(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!SomeVar": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        reply = session.handle_op(
            "bp_add", {"target": "nt!SomeVar", "wp_type": "read", "wp_size": 8},
        )
        assert reply["ok"]
        assert rsp.bps_inserted == [(_KERNEL_VA_WP, 8, False, "read")]

    def test_access_watchpoint_sends_z4(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!SomeVar": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        reply = session.handle_op(
            "bp_add", {"target": "nt!SomeVar", "wp_type": "access", "wp_size": 2},
        )
        assert reply["ok"]
        assert rsp.bps_inserted == [(_KERNEL_VA_WP, 2, False, "access")]

    def test_invalid_wp_type_rejected(self):
        session = _make_session(store=FakeStore({"nt!X": _KERNEL_VA_WP}))
        reply = session.handle_op(
            "bp_add", {"target": "nt!X", "wp_type": "execute"},
        )
        assert reply["ok"] is False
        assert "wp_type" in reply["error"]

    def test_invalid_wp_size_rejected(self):
        session = _make_session(store=FakeStore({"nt!X": _KERNEL_VA_WP}))
        reply = session.handle_op(
            "bp_add", {"target": "nt!X", "wp_type": "write", "wp_size": 3},
        )
        assert reply["ok"] is False
        assert "wp_size" in reply["error"]

    def test_watchpoint_with_condition(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        reply = session.handle_op(
            "bp_add", {
                "target": "nt!X", "wp_type": "write", "wp_size": 4,
                "condition": "rax == 0x42",
            },
        )
        assert reply["ok"]
        assert reply["result"]["condition"] == "rax == 0x42"


class TestWatchpointRemove:
    def test_remove_sends_correct_z_packet(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        add_reply = session.handle_op(
            "bp_add", {"target": "nt!X", "wp_type": "write", "wp_size": 4},
        )
        bp_id = add_reply["result"]["id"]
        rm_reply = session.handle_op("bp_remove", {"id": bp_id})
        assert rm_reply["ok"]
        assert rsp.bps_removed == [(_KERNEL_VA_WP, 4, False, "write")]

    def test_remove_clears_registry(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        add_reply = session.handle_op(
            "bp_add", {"target": "nt!X", "wp_type": "access", "wp_size": 8},
        )
        bp_id = add_reply["result"]["id"]
        session.handle_op("bp_remove", {"id": bp_id})
        assert session.bps == {}


class TestWatchpointList:
    def test_list_includes_wp_fields(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.handle_op(
            "bp_add", {"target": "nt!X", "wp_type": "write", "wp_size": 4},
        )
        reply = session.handle_op("bp_list", {})
        assert reply["ok"]
        bps = reply["result"]["bps"]
        assert len(bps) == 1
        assert bps[0]["wp_type"] == "write"
        assert bps[0]["wp_size"] == 4

    def test_exec_bp_has_no_wp_fields(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.handle_op("bp_add", {"target": "nt!X", "mode": "hw"})
        reply = session.handle_op("bp_list", {})
        bps = reply["result"]["bps"]
        assert "wp_type" not in bps[0]
        assert "wp_size" not in bps[0]


# ── Scriptable breakpoint actions (item 47) ───────────────────────────


class TestBpActions:
    def test_bp_add_with_actions(self, tmp_path):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg.root_dir = tmp_path
        reply = session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rcx", "rdx"]},
        )
        assert reply["ok"]
        r = reply["result"]
        assert r["actions"] == ["rcx", "rdx"]
        assert "trace_path" in r

    def test_bp_add_truncates_trace_from_previous_daemon_session(self, tmp_path):
        """bp ids restart at zero, but their runtime files outlive daemons."""
        stale = tmp_path / "bp0.trace.jsonl"
        stale.write_text('{"hit": 999, "values": {"stale": "yes"}}\n')
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg

        reply = session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rax"]},
        )

        assert reply["ok"], reply
        assert stale.read_text() == ""
        bp = list(session.bps.values())[0]
        session._execute_actions(
            bp, _blob(rax=0x42, rip=_KERNEL_VA_WP, cr3=0x1ae000),
        )
        trace = session.handle_op("bp_trace", {"id": bp.bp_id})["result"]
        assert trace["total"] == bp.trace_count == 1
        assert trace["entries"][0]["hit"] == 0

    def test_trace_initialisation_failure_happens_before_bp_install(
        self, tmp_path, monkeypatch,
    ):
        from pathlib import Path

        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg

        def fail_write(self, *args, **kwargs):
            raise OSError("read-only filesystem")

        monkeypatch.setattr(Path, "write_text", fail_write)
        reply = session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rax"]},
        )

        assert not reply["ok"]
        assert "initialise action trace" in reply["error"]
        assert rsp.bps_inserted == []
        assert session.bps == {}

    def test_bp_add_invalid_action_rejected(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        reply = session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rcx", "garbage **"]},
        )
        assert not reply["ok"]
        assert "action[1]" in reply["error"]

    def test_bp_list_includes_action_info(self, tmp_path):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg.root_dir = tmp_path
        session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rax"]},
        )
        reply = session.handle_op("bp_list", {})
        bp = reply["result"]["bps"][0]
        assert bp["actions"] == ["rax"]
        assert bp["trace_count"] == 0

    def test_execute_actions_logs_and_continues(self, tmp_path):
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg
        session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rax"]},
        )
        bp = list(session.bps.values())[0]
        regs = _blob(rax=0x42, rip=_KERNEL_VA_WP, cr3=0x1ae000)
        session._execute_actions(bp, regs)
        assert bp.trace_count == 1
        import json
        trace = json.loads(open(bp.trace_path).readline())
        assert trace["values"]["rax"] == "0x42"

    def test_multiple_memory_actions_share_one_masquerade(self, tmp_path):
        """All independent actions and nested poi reads use one G pair."""
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        cr3_writes = _record_g_cr3s(rsp)
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg
        session.handle_op(
            "bp_add",
            {
                "target": "nt!X",
                "actions": ["[rcx]", "poi(poi(rdx)+0x8)", "[r8]"],
            },
        )
        bp = list(session.bps.values())[0]
        regs = _blob(
            rcx=0x1000, rdx=0x2000, r8=0x3000,
            rip=_KERNEL_VA_WP, cr3=0x1ae000,
        )
        memory = {
            0x1000: 0x11,
            0x2000: 0x2800,
            0x2808: 0x22,
            0x3000: 0x33,
        }
        rsp.read_memory = lambda va, n: memory[va].to_bytes(n, "little")

        session._execute_actions(bp, regs)

        import json
        trace = json.loads(open(bp.trace_path).readline())
        assert trace["values"] == {
            "[rcx]": "0x11",
            "poi(poi(rdx)+0x8)": "0x22",
            "[r8]": "0x33",
        }
        assert cr3_writes == [session.target.dtb, 0x1ae000]

    def test_typed_scalars_and_buffer_captures_share_one_masquerade(self, tmp_path):
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        cr3_writes = _record_g_cr3s(rsp)
        session = _make_session(
            rsp=rsp, store=FakeStore({"nt!X": _KERNEL_VA_WP}),
        )
        session.cfg = cfg
        added = session.handle_op("bp_add", {
            "target": "nt!X",
            "condition": "byte(rcx) == 0x41 && dword(rdx) == 0x44332211",
            "actions": [
                "word(r8)", "bytes(r9,4)", "ascii(r10,4)", "utf16(r11,4)",
            ],
        })
        assert added["ok"], added
        bp = session.bps[added["result"]["id"]]
        regs = _blob(
            rcx=0x1000, rdx=0x2000, r8=0x3000, r9=0x4000,
            r10=0x5000, r11=0x6000, rip=_KERNEL_VA_WP, cr3=0x1ae000,
        )
        memory = {
            0x1000: b"A", 0x2000: bytes.fromhex("11223344"),
            0x3000: bytes.fromhex("3412"), 0x4000: bytes.fromhex("deadbeef"),
            0x5000: b"A\x01B\x7f", 0x6000: b"O\x00K\x00",
        }

        def read_memory(va, length):
            return memory[va][:length]

        rsp.read_memory = read_memory
        truthy, values = session._evaluate_breakpoint_expressions(
            bp, regs, vcpu="01",
        )
        assert truthy is True
        assert values == {
            "word(r8)": "0x1234",
            "bytes(r9,4)": "hex:deadbeef",
            "ascii(r10,4)": "ascii:A.B.",
            "utf16(r11,4)": "utf16:OK",
        }
        session._append_action_trace(bp, regs, values)
        assert bp.capture_bytes == 12
        trace = session.handle_op("bp_trace", {"id": bp.bp_id, "tail": 1})
        assert trace["ok"], trace
        assert trace["result"]["entries"][0]["values"] == values
        assert cr3_writes == [session.target.dtb, 0x1ae000]

    def test_capture_conditions_and_oversized_hit_are_rejected_at_install(self, tmp_path):
        session = _make_session(
            rsp=FakeRsp(), store=FakeStore({"nt!X": _KERNEL_VA_WP}),
        )
        session.cfg.root_dir = tmp_path
        condition = session.handle_op("bp_add", {
            "target": "nt!X", "condition": "bytes(rcx,8)",
        })
        assert not condition["ok"]
        assert "action-only" in condition["error"]
        oversized = session.handle_op("bp_add", {
            "target": "nt!X", "actions": ["bytes(rcx,256)"] * 5,
        })
        assert not oversized["ok"]
        assert "cap is 1024" in oversized["error"]
        too_many = session.handle_op("bp_add", {
            "target": "nt!X", "actions": ["rax"] * 17,
        })
        assert not too_many["ok"]
        assert "at most 16" in too_many["error"]
        malformed = session.handle_op("bp_add", {
            "target": "nt!X", "actions": ["rax", 7],
        })
        assert not malformed["ok"]
        assert "expression must be a string" in malformed["error"]
        empty_wrong_type = session.handle_op("bp_add", {
            "target": "nt!X", "actions": "",
        })
        assert not empty_wrong_type["ok"]
        assert "actions must be a list" in empty_wrong_type["error"]

    def test_capture_trace_budget_stops_future_reads_explicitly(
        self, tmp_path, monkeypatch,
    ):
        import winbox.kdbg.debugger.daemon as daemon_module

        monkeypatch.setattr(daemon_module, "MAX_CAPTURE_BYTES_PER_TRACE", 8)
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        reads = []
        rsp.read_memory = lambda va, n: reads.append((va, n)) or b"ABCD"[:n]
        session = _make_session(
            rsp=rsp, store=FakeStore({"nt!X": _KERNEL_VA_WP}),
        )
        session.cfg = cfg
        added = session.handle_op("bp_add", {
            "target": "nt!X", "actions": ["bytes(rcx,4)"],
        })["result"]
        bp = session.bps[added["id"]]
        regs = _blob(rcx=0x1000, rip=_KERNEL_VA_WP, cr3=0x1ae000)

        session._execute_actions(bp, regs)
        session._execute_actions(bp, regs)
        session._execute_actions(bp, regs)

        import json
        entries = [json.loads(line) for line in open(bp.trace_path)]
        assert [entry["values"]["bytes(rcx,4)"] for entry in entries] == [
            "hex:41424344", "hex:41424344",
            "error: capture trace byte budget exhausted (8 bytes)",
        ]
        assert reads == [(0x1000, 4), (0x1000, 4)]
        assert bp.capture_bytes == 8
        assert bp.capture_limit_reached is True

    def test_condition_and_actions_share_one_masquerade(self, tmp_path):
        """The hot path batches a matching predicate with all its actions."""
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        cr3_writes = _record_g_cr3s(rsp)
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg
        session.handle_op(
            "bp_add",
            {
                "target": "nt!X",
                "condition": "[rcx] == 0x11",
                "actions": ["[rdx]", "poi(r8)"],
            },
        )
        bp = list(session.bps.values())[0]
        regs = _blob(
            rcx=0x1000, rdx=0x2000, r8=0x3000,
            rip=_KERNEL_VA_WP, cr3=0x1ae000,
        )
        memory = {0x1000: 0x11, 0x2000: 0x22, 0x3000: 0x33}
        rsp.read_memory = lambda va, n: memory[va].to_bytes(n, "little")

        truthy, values = session._evaluate_breakpoint_expressions(
            bp, regs, vcpu="01",
        )

        assert truthy is True
        assert values == {"[rdx]": "0x22", "poi(r8)": "0x33"}
        assert cr3_writes == [session.target.dtb, 0x1ae000]

    def test_candidate_retry_does_not_duplicate_trace_entry(self, tmp_path):
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        user_dtb = 0x4d6bc000
        rsp = FakeRsp()
        target = TargetInfo(
            pid=4584, dtb=_TARGET_DTB, name="notepad.exe", user_dtb=user_dtb,
        )
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store, target=target)
        session.cfg = cfg
        session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["[rcx]"]},
        )
        bp = list(session.bps.values())[0]
        regs = _blob(rcx=0x1000, rip=_KERNEL_VA_WP, cr3=0x1ae000)

        def read_memory(va, n):
            current_cr3 = struct.unpack_from("<Q", rsp.regs_blob, _CR3_OFFSET)[0]
            if current_cr3 != user_dtb:
                from winbox.kdbg.debugger.rsp import RspError
                raise RspError("E14")
            return (0x44).to_bytes(n, "little")

        rsp.read_memory = read_memory
        session._execute_actions(bp, regs)

        assert bp.trace_count == 1
        assert len(open(bp.trace_path).readlines()) == 1

    def test_false_condition_skips_memory_actions_without_any_swap(self, tmp_path):
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        cr3_writes = _record_g_cr3s(rsp)
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg
        session.handle_op(
            "bp_add",
            {
                "target": "nt!X",
                "condition": "rcx == 1",
                "actions": ["[rdx]"],
            },
        )
        bp = list(session.bps.values())[0]
        truthy, values = session._evaluate_breakpoint_expressions(
            bp, _blob(rcx=0, rdx=0x2000), vcpu="01",
        )

        assert truthy is False
        assert values is None
        assert cr3_writes == []

    def test_bp_trace_returns_entries(self, tmp_path):
        cfg = FakeCfg()
        cfg.root_dir = tmp_path
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.cfg = cfg
        session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rcx"]},
        )
        bp = list(session.bps.values())[0]
        regs = _blob(rcx=0xDEAD, rip=_KERNEL_VA_WP, cr3=0x1ae000)
        session._execute_actions(bp, regs)
        session._execute_actions(bp, regs)
        trace_reply = session.handle_op("bp_trace", {"id": bp.bp_id})
        assert trace_reply["ok"]
        assert trace_reply["result"]["total"] == 2
        assert len(trace_reply["result"]["entries"]) == 2

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            ({"tail": 0}, "tail must be between"),
            ({"tail": 201}, "tail must be between"),
            ({"limit": 0}, "limit must be between"),
            ({"top": 21}, "top must be between"),
            ({"from_hit": -1}, "from_hit must be"),
            ({"from_hit": True}, "from_hit must be"),
            ({"errors_only": "yes"}, "errors_only must be"),
            ({"summary": 1}, "summary must be"),
        ],
    )
    def test_bp_trace_rejects_unbounded_or_wrong_typed_queries(
        self, tmp_path, args, message,
    ):
        session = _make_session(
            rsp=FakeRsp(), store=FakeStore({"nt!X": _KERNEL_VA_WP}),
        )
        session.cfg.root_dir = tmp_path
        added = session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rax"]},
        )["result"]

        reply = session.handle_op("bp_trace", {"id": added["id"], **args})

        assert not reply["ok"]
        assert message in reply["error"]

    def test_bp_trace_missing_file_is_explicit(self, tmp_path):
        session = _make_session(
            rsp=FakeRsp(), store=FakeStore({"nt!X": _KERNEL_VA_WP}),
        )
        session.cfg.root_dir = tmp_path
        added = session.handle_op(
            "bp_add", {"target": "nt!X", "actions": ["rax"]},
        )["result"]
        bp = session.bps[added["id"]]
        bp.trace_count = 3
        open(bp.trace_path, "w").close()
        from pathlib import Path
        Path(bp.trace_path).unlink()

        reply = session.handle_op("bp_trace", {"id": added["id"]})

        assert reply["ok"]
        assert reply["result"]["read_error"] == "trace file unavailable"
        assert reply["result"]["total"] == 3
        assert reply["result"]["truncated"] is True

    def test_bp_no_actions_halts_normally(self):
        rsp = FakeRsp()
        store = FakeStore({"nt!X": _KERNEL_VA_WP})
        session = _make_session(rsp=rsp, store=store)
        session.handle_op("bp_add", {"target": "nt!X"})
        bp = list(session.bps.values())[0]
        assert bp.actions == []
        assert bp._action_asts == []
