"""Live integration test for install_user_breakpoint via CR3 masquerade.

Requires:
  - VM running with notepad.exe started
  - gdbstub started (winbox kdbg start)
  - nt symbols loaded (winbox kdbg symbols)
  - ntdll symbols loaded (winbox kdbg user-symbols <pid> ntdll)

Run:   pytest -m integration -k install_integration
"""

from __future__ import annotations

import struct
import subprocess

import pytest

from winbox.config import Config
from winbox.kdbg import SymbolStore
from winbox.kdbg.debugger import RspClient, install_user_breakpoint
from winbox.kdbg.hmp import probe_port
from winbox.kdbg.walk import list_processes


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def cfg():
    return Config.load()


@pytest.fixture(scope="module")
def store(cfg):
    return SymbolStore(cfg.symbols_dir)


@pytest.fixture
def cli_conn(cfg):
    if not probe_port("127.0.0.1", 1234):
        pytest.skip("gdbstub not listening — run `winbox kdbg start`")
    c = RspClient.connect("127.0.0.1", 1234, timeout=5)
    c.handshake()
    yield c
    try:
        c.close()
    except Exception:
        pass
    subprocess.run(
        ["virsh", "-c", "qemu:///system", "resume", "winbox"],
        capture_output=True,
    )


def _find_notepad(cfg, store):
    procs = list_processes(cfg.vm_name, store)
    return next((p for p in procs if p.name == "notepad.exe"), None)


# ── tests ────────────────────────────────────────────────────────────────


def test_install_into_notepad_shared_section(cli_conn, cfg, store):
    """Install bp at ntdll!NtClose using notepad's CR3.
    Verify Z0 succeeded — fires for any process calling NtClose."""
    notepad = _find_notepad(cfg, store)
    if notepad is None:
        pytest.skip("no notepad.exe running in VM")

    try:
        nt_close = store.resolve("ntdll!NtClose")
    except Exception:
        pytest.skip("ntdll symbols not loaded")

    cli_conn.query_halt_reason()
    report = install_user_breakpoint(
        cli_conn, cfg.vm_name, store,
        target_dtb=notepad.directory_table_base,
        user_va=nt_close,
    )
    try:
        assert report.user_va == nt_close
        assert report.target_dtb == notepad.directory_table_base
        # CR3 swap is fast — sub-second always
        assert report.elapsed < 1.0

        # Verify CR3 was restored (firing vCPU's CR3 should be back to whatever
        # it was at attach — definitely NOT notepad's DTB right now since
        # notepad isn't actively scheduled on vCPU 1).
        post = struct.unpack_from("<Q", cli_conn.read_registers(), 204)[0]
        assert post != notepad.directory_table_base, (
            f"CR3 restore didn't happen: still 0x{post:x}"
        )
    finally:
        try:
            cli_conn.remove_breakpoint(nt_close, kind=1)
        except Exception:
            pass


def test_install_into_notepad_private_text(cli_conn, cfg, store):
    """The actual Day 3 payoff: install bp on notepad's OWN code (NPWndProc).
    Only notepad fires this — silent-cont noise from other processes is
    structurally impossible because the VA isn't even mapped elsewhere."""
    notepad = _find_notepad(cfg, store)
    if notepad is None:
        pytest.skip("no notepad.exe running in VM")

    try:
        npwndproc = store.resolve("notepad!?NPWndProc@@YA_JPEAUHWND__@@I_K_J@Z")
    except Exception:
        pytest.skip("notepad symbols not loaded — run `winbox kdbg user-symbols <pid> notepad.exe`")

    cli_conn.query_halt_reason()
    report = install_user_breakpoint(
        cli_conn, cfg.vm_name, store,
        target_dtb=notepad.directory_table_base,
        user_va=npwndproc,
    )
    try:
        assert report.user_va == npwndproc
        # Install was via masquerade → very fast, no SwapContext dance
        assert report.elapsed < 1.0

        # Try to install another bp at a clearly unmapped private VA —
        # this proves Z0 IS doing CR3-aware translation. notepad's heap
        # is mapped at high addresses; an arbitrary cookie VA won't be.
        cookie_va = 0x7FFEDEADBEEF0000
        from winbox.kdbg.debugger import RspError, InstallError
        with pytest.raises(InstallError):
            install_user_breakpoint(
                cli_conn, cfg.vm_name, store,
                target_dtb=notepad.directory_table_base,
                user_va=cookie_va,
            )
    finally:
        try:
            cli_conn.remove_breakpoint(npwndproc, kind=1)
        except Exception:
            pass
