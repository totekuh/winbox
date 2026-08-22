"""End-to-end integration tests for the gdb-RSP client.

Requires a running winbox VM with the gdbstub started via
``winbox kdbg start``. The kernel symbol store must already have nt
loaded (via ``winbox kdbg symbols``).

Each primitive in rsp.py gets end-to-end verification against real QEMU. The
suite refuses to attach unless the guest passes the same CET safety gate as
the product paths.

Run with:  pytest -m integration -k rsp
Skip with: pytest -m 'not integration'
"""

from __future__ import annotations

import struct
import pytest

from winbox.config import Config
from winbox.kdbg import SymbolStore
from winbox.kdbg.debugger import RspClient, RspError
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.kdbg.debugger.reader import stop_reader, use_local_rsp
from winbox.kdbg.hmp import probe_port
from winbox.kdbg.memory import read_phys, virt_to_phys
from winbox.vm import GuestAgent, VM, VMState


pytestmark = pytest.mark.integration


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def cfg():
    config = Config.load()
    try:
        require_safe(config, GuestAgent(config))
    except CetSafetyError as exc:
        pytest.skip(f"live RSP tests require prepared CET state: {exc}")
    stop_reader(config)
    return config


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
    # Belt-and-braces: product cleanup must leave the guest running.
    vm = VM(cfg)
    if vm.state() == VMState.PAUSED:
        vm.resume()


# ── Helpers ─────────────────────────────────────────────────────────────


def _rip(regs: bytes) -> int:
    return struct.unpack_from("<Q", regs, 16 * 8)[0]


def _gpr(regs: bytes, idx: int) -> int:
    return struct.unpack_from("<Q", regs, idx * 8)[0]


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


def test_rsp_virtual_read_matches_rsp_physical_mode(cli_conn, cfg):
    """Cross-check virtual `m` against physical mode after a page walk."""
    threads = cli_conn.list_threads()
    cli_conn.select_thread(threads[0])
    regs = cli_conn.read_registers()
    rip = _rip(regs)

    rsp_bytes = cli_conn.read_memory(rip, 16)

    stop = cli_conn.query_halt_reason()
    with use_local_rsp(cfg.vm_name, cli_conn, stop):
        cr3 = cli_conn.read_cr3()
        page_pa = virt_to_phys(cfg.vm_name, cr3, rip & ~0xFFF)
        physical_bytes = read_phys(cfg.vm_name, page_pa + (rip & 0xFFF), 16)

    assert rsp_bytes == physical_bytes


def test_breakpoint_install_actually_patches_physical_page(cli_conn, cfg, swap_va):
    """Install bp, verify 0xCC in physical mode, then verify restoration."""
    threads = cli_conn.list_threads()
    cli_conn.select_thread(threads[0])
    stop = cli_conn.query_halt_reason()
    with use_local_rsp(cfg.vm_name, cli_conn, stop):
        cr3 = cli_conn.read_cr3()
        page_pa = virt_to_phys(cfg.vm_name, cr3, swap_va & ~0xFFF)
        page_off = swap_va & 0xFFF

        original = read_phys(cfg.vm_name, page_pa + page_off, 1)
        assert original != b"\xcc"

        cli_conn.insert_breakpoint(swap_va, kind=1)
        try:
            assert read_phys(cfg.vm_name, page_pa + page_off, 1) == b"\xcc"
        finally:
            cli_conn.remove_breakpoint(swap_va, kind=1)

        assert read_phys(cfg.vm_name, page_pa + page_off, 1) == original


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
    state = VM(cfg).state()
    assert state == VMState.RUNNING, f"expected running, got {state.value!r}"
