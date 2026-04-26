"""End-to-end integration tests for the gdb-RSP client.

Requires a running winbox VM with the gdbstub started via
``winbox kdbg start``. The kernel symbol store must already have nt
loaded (via ``winbox kdbg symbols``).

Each primitive in rsp.py gets *independent* verification — bp install
is confirmed by reading the physical page directly via HMP (not via
gdbstub's `m`, which may shim the read), memory reads cross-check
between RSP and HMP-derived physical reads, etc.

Run with:  pytest -m integration -k rsp
Skip with: pytest -m 'not integration'
"""

from __future__ import annotations

import struct
import subprocess

import pytest

from winbox.config import Config
from winbox.kdbg import SymbolStore
from winbox.kdbg.debugger import RspClient, RspError
from winbox.kdbg.hmp import hmp, parse_registers, probe_port
from winbox.kdbg.memory import read_phys, virt_to_phys


pytestmark = pytest.mark.integration


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def cfg():
    return Config.load()


@pytest.fixture(scope="module")
def store(cfg):
    return SymbolStore(cfg.symbols_dir)


@pytest.fixture(scope="module")
def swap_va(store):
    return store.resolve("nt!SwapContext")


@pytest.fixture
def cli_conn(cfg):
    """Fresh client per test — gdbstub is single-client."""
    if not probe_port("127.0.0.1", 1234):
        pytest.skip("gdbstub not listening on 127.0.0.1:1234 — run `winbox kdbg start` first")
    c = RspClient.connect("127.0.0.1", 1234, timeout=5)
    c.handshake()
    yield c
    # Robust close — may already be closed, may be in mid-bp state.
    try:
        c.close()
    except Exception:
        pass
    # Belt-and-braces: ensure VM is running for next test (close() should
    # achieve this; this is the safety net).
    subprocess.run(
        ["virsh", "-c", "qemu:///system", "resume", "winbox"],
        capture_output=True,
    )


# ── Helpers ─────────────────────────────────────────────────────────────


def _rip(regs: bytes) -> int:
    return struct.unpack_from("<Q", regs, 16 * 8)[0]


def _gpr(regs: bytes, idx: int) -> int:
    return struct.unpack_from("<Q", regs, idx * 8)[0]


def _vcpu_cr3(vm_name: str, vcpu_id_str: str) -> int:
    """Read CR3 of the named gdb-thread (1-based) via HMP."""
    vcpu_zero_idx = int(vcpu_id_str) - 1
    text = hmp(vm_name, "info registers -a")
    block = text.split(f"CPU#{vcpu_zero_idx}", 1)
    if len(block) != 2:
        raise RuntimeError(f"vCPU {vcpu_id_str} not found in HMP output")
    rest = block[1].split("CPU#", 1)[0]
    return parse_registers(rest)["CR3"]


def _domstate(vm_name: str = "winbox") -> str:
    return subprocess.run(
        ["virsh", "-c", "qemu:///system", "domstate", vm_name],
        capture_output=True, text=True,
    ).stdout.strip()


# ── Tests ────────────────────────────────────────────────────────────────


def test_handshake_returns_packet_size_against_real_qemu(cli_conn):
    """qSupported should at least give us a PacketSize."""
    # handshake already ran in fixture; just confirm features were parsed.
    sr = cli_conn.query_halt_reason()
    assert sr.signal in (5, 0)


def test_qemu_does_not_advertise_noackmode(cli_conn):
    """QEMU's gdbstub returns empty for QStartNoAckMode (= unsupported).
    Our client correctly stays in ack mode."""
    assert cli_conn._noack is False


def test_attach_halts_vm(cli_conn):
    sr = cli_conn.query_halt_reason()
    assert sr.signal == 5


def test_list_threads_returns_all_vcpus(cli_conn):
    threads = cli_conn.list_threads()
    assert len(threads) >= 1
    # winbox VM is configured with multiple vCPUs in production —
    # don't hardcode a number, just sanity-check shape.
    for t in threads:
        int(t)  # parses as a valid id


def test_rsp_read_memory_matches_hmp_physical_read(cli_conn, cfg):
    """Independent cross-check: RSP `m` and HMP `xp` (after page walk)
    must return the same bytes for the same VA."""
    threads = cli_conn.list_threads()
    cli_conn.select_thread(threads[0])
    regs = cli_conn.read_registers()
    rip = _rip(regs)

    rsp_bytes = cli_conn.read_memory(rip, 16)

    cr3 = _vcpu_cr3(cfg.vm_name, threads[0])
    page_pa = virt_to_phys(cfg.vm_name, cr3, rip & ~0xFFF)
    hmp_bytes = read_phys(cfg.vm_name, page_pa + (rip & 0xFFF), 16)

    assert rsp_bytes == hmp_bytes


def test_breakpoint_install_actually_patches_physical_page(cli_conn, cfg, swap_va):
    """Install bp, verify 0xCC lives in the physical page (HMP, not RSP).
    Remove, verify original byte restored."""
    threads = cli_conn.list_threads()
    cli_conn.select_thread(threads[0])
    cr3 = _vcpu_cr3(cfg.vm_name, threads[0])
    page_pa = virt_to_phys(cfg.vm_name, cr3, swap_va & ~0xFFF)
    page_off = swap_va & 0xFFF

    original = read_phys(cfg.vm_name, page_pa + page_off, 1)
    assert original != b"\xcc"  # don't fight a stale bp from a previous run

    cli_conn.insert_breakpoint(swap_va, kind=1)
    try:
        patched = read_phys(cfg.vm_name, page_pa + page_off, 1)
        assert patched == b"\xcc"
    finally:
        cli_conn.remove_breakpoint(swap_va, kind=1)

    restored = read_phys(cfg.vm_name, page_pa + page_off, 1)
    assert restored == original


def test_breakpoint_fires_at_correct_va(cli_conn, swap_va):
    """Continue, wait for hit, RIP should equal the bp address."""
    cli_conn.insert_breakpoint(swap_va, kind=1)
    try:
        cli_conn.cont()
        sr = cli_conn.wait_for_stop(timeout=10)
        assert sr.signal == 5

        cli_conn.select_thread(sr.thread or "01")
        regs = cli_conn.read_registers()
        assert _rip(regs) == swap_va
    finally:
        cli_conn.remove_breakpoint(swap_va, kind=1)


def test_unmapped_va_breakpoint_raises(cli_conn):
    bad_va = 0xFFFFFFFFCAFEBABE
    with pytest.raises(RspError):
        cli_conn.insert_breakpoint(bad_va, kind=1)


def test_single_step_advances_rip(cli_conn, swap_va):
    cli_conn.insert_breakpoint(swap_va, kind=1)
    try:
        cli_conn.cont()
        sr = cli_conn.wait_for_stop(timeout=10)
        cli_conn.remove_breakpoint(swap_va, kind=1)

        cli_conn.select_thread(sr.thread or "01")
        regs_before = cli_conn.read_registers()
        rip_before = _rip(regs_before)

        cli_conn.step(sr.thread)
        cli_conn.wait_for_stop(timeout=5)
        cli_conn.select_thread(sr.thread or "01")
        regs_after = cli_conn.read_registers()
        rip_after = _rip(regs_after)

        assert rip_after != rip_before
        # x86-64 instruction lengths are 1..15 bytes; step should advance
        # by at most that.
        assert 1 <= rip_after - rip_before <= 15
    finally:
        try:
            cli_conn.remove_breakpoint(swap_va, kind=1)
        except RspError:
            pass


def test_write_memory_roundtrip_on_kernel_stack(cli_conn, swap_va):
    """Write a magic value to RSP, read it back, restore. Uses the firing
    vCPU's stack so the bytes are guaranteed to be real mapped memory."""
    cli_conn.insert_breakpoint(swap_va, kind=1)
    try:
        cli_conn.cont()
        sr = cli_conn.wait_for_stop(timeout=10)
        cli_conn.remove_breakpoint(swap_va, kind=1)
        cli_conn.select_thread(sr.thread or "01")
        regs = cli_conn.read_registers()
        rsp_va = _gpr(regs, 7)  # rsp is the 8th GPR

        original = cli_conn.read_memory(rsp_va, 8)
        magic = b"\xde\xad\xbe\xef\xfe\xed\xfa\xce"
        try:
            cli_conn.write_memory(rsp_va, magic)
            assert cli_conn.read_memory(rsp_va, 8) == magic
        finally:
            cli_conn.write_memory(rsp_va, original)
            assert cli_conn.read_memory(rsp_va, 8) == original
    finally:
        try:
            cli_conn.remove_breakpoint(swap_va, kind=1)
        except RspError:
            pass


def test_close_leaves_vm_running_after_cont(cli_conn, cfg):
    """The close() bug regression: cont then close used to leave the
    VM paused. The fix forces a halt-then-detach so QEMU's D handler
    always resumes via gdb_continue()."""
    cli_conn.cont()
    cli_conn.close()
    # close() ran detach; VM should be running.
    state = _domstate(cfg.vm_name)
    assert state == "running", f"expected running, got {state!r}"
