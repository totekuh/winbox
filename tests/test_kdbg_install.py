"""Unit tests for install_user_breakpoint via CR3-masquerade.

The install primitive's core logic is:
1. Read regs (capture original CR3)
2. Write target_dtb to vCPU's CR3 via G packet
3. Verify CR3 was actually updated
4. Z0 at user_va
5. Restore original CR3 via G packet (always — finally clause)

These tests use a fake RspClient to verify the protocol-level
sequence regardless of any live VM. The CR3-masquerade really
working against QEMU is covered by test_kdbg_install_integration.
"""

from __future__ import annotations

import struct

import pytest

from winbox.kdbg.debugger.install import (
    InstallError,
    InstallReport,
    install_user_breakpoint,
)


# CR3 location verified against QEMU x86-64 g-packet (offset 204).
_CR3_OFFSET = 204
_REG_BLOB_LEN = 608  # full QEMU x86-64 register dump


def _make_blob(cr3: int = 0x1AE000) -> bytes:
    """Build a fake register blob with CR3 at the right offset."""
    blob = bytearray(_REG_BLOB_LEN)
    struct.pack_into("<Q", blob, _CR3_OFFSET, cr3)
    return bytes(blob)


class FakeRsp:
    """Minimal RspClient stand-in driven by a script of expected exchanges."""

    def __init__(self, threads=("01", "02")) -> None:
        self._threads = list(threads)
        self.selected_thread: str | None = None
        # Internal "vCPU register file" — what reads see, what G writes update.
        self.regs_blob: bytes = _make_blob()
        # Track Z0/z0 calls
        self.bps_installed: list[int] = []
        self.bps_removed: list[int] = []
        # Recorded G writes (CR3 values seen)
        self.cr3_writes: list[int] = []
        # Hooks for failure injection
        self.fail_z0_at: int | None = None
        self.fail_g_response: bytes | None = None

    def list_threads(self):
        return list(self._threads)

    def select_thread(self, t: str, *, op: str = "g") -> None:
        self.selected_thread = t

    def read_registers(self) -> bytes:
        return self.regs_blob

    def insert_breakpoint(self, addr: int, *, kind: int = 1, hardware: bool = False) -> None:
        if self.fail_z0_at is not None and addr == self.fail_z0_at:
            from winbox.kdbg.debugger.rsp import RspError
            raise RspError(f"Z0 insert at 0x{addr:x} failed: b'E22'")
        self.bps_installed.append(addr)

    def remove_breakpoint(self, addr: int, *, kind: int = 1, hardware: bool = False) -> None:
        self.bps_removed.append(addr)

    def _exchange(self, body: bytes, *, timeout=None) -> bytes:
        # Only G is invoked from install(); accept hex-encoded blob, parse CR3 out.
        if body.startswith(b"G"):
            hex_payload = body[1:]
            blob = bytes.fromhex(hex_payload.decode("ascii"))
            cr3 = struct.unpack_from("<Q", blob, _CR3_OFFSET)[0]
            self.cr3_writes.append(cr3)
            self.regs_blob = blob
            if self.fail_g_response is not None:
                resp = self.fail_g_response
                self.fail_g_response = None
                return resp
            return b"OK"
        raise AssertionError(f"unexpected packet: {body!r}")


# Used by install_user_breakpoint when it instantiates RspClient methods.
@pytest.fixture
def fake_cli():
    return FakeRsp()


# ── Happy path ──────────────────────────────────────────────────────────


def test_install_writes_target_dtb_then_restores(fake_cli):
    """Two G-packets total: one to swap in target_dtb, one to restore."""
    target_dtb = 0x4D6BB000
    user_va = 0x7FF6E289A760

    report = install_user_breakpoint(
        fake_cli, "vm", store=None,
        target_dtb=target_dtb,
        user_va=user_va,
    )

    assert isinstance(report, InstallReport)
    assert report.user_va == user_va
    assert report.target_dtb == target_dtb

    # Two G writes: target swap then original restore.
    assert fake_cli.cr3_writes == [target_dtb, 0x1AE000]
    # Z0 at user_va happened (and was not removed by install — caller's job).
    assert fake_cli.bps_installed == [user_va]
    assert fake_cli.bps_removed == []


def test_install_selects_first_vcpu(fake_cli):
    install_user_breakpoint(
        fake_cli, "vm", store=None,
        target_dtb=0x4D6BB000, user_va=0x7FF6E289A760,
    )
    assert fake_cli.selected_thread == "01"


# ── Failure paths ───────────────────────────────────────────────────────


def test_install_restores_cr3_when_z0_fails(fake_cli):
    """If Z0 errors (cold page → E22), CR3 must still be restored."""
    fake_cli.fail_z0_at = 0xCAFEBABE

    with pytest.raises(InstallError, match="not paged in"):
        install_user_breakpoint(
            fake_cli, "vm", store=None,
            target_dtb=0x4D6BB000,
            user_va=0xCAFEBABE,
        )

    # Critical invariant: even on failure, the second G call restored.
    assert len(fake_cli.cr3_writes) == 2
    assert fake_cli.cr3_writes[-1] == 0x1AE000
    assert fake_cli.bps_installed == []


def test_install_raises_when_g_packet_rejected(fake_cli):
    """If QEMU rejects the masquerade write, surface a clear error."""
    fake_cli.fail_g_response = b"E01"

    with pytest.raises(InstallError, match="rejected"):
        install_user_breakpoint(
            fake_cli, "vm", store=None,
            target_dtb=0x4D6BB000, user_va=0x7FF6E289A760,
        )

    # The failed G doesn't change regs_blob, so verify never tries to install
    # the bp (and there's nothing to restore).
    assert fake_cli.bps_installed == []


def test_install_raises_when_no_threads(fake_cli):
    fake_cli._threads = []
    with pytest.raises(InstallError, match="no threads"):
        install_user_breakpoint(
            fake_cli, "vm", store=None,
            target_dtb=0x4D6BB000, user_va=0x7FF6E289A760,
        )


def test_install_verifies_cr3_actually_changed(monkeypatch):
    """If QEMU silently ignores the CR3 write, install must detect that
    and raise — otherwise we'd patch the WRONG physical page."""
    cli = FakeRsp()

    # Subclass: G accepts but doesn't actually mutate regs_blob's CR3.
    original_exchange = cli._exchange

    def silent_g(body, *, timeout=None):
        if body.startswith(b"G"):
            cli.cr3_writes.append(
                struct.unpack_from("<Q", bytes.fromhex(body[1:].decode("ascii")), _CR3_OFFSET)[0]
            )
            return b"OK"  # accept, but don't change state
        return original_exchange(body, timeout=timeout)

    cli._exchange = silent_g

    with pytest.raises(InstallError, match="didn't take effect"):
        install_user_breakpoint(
            cli, "vm", store=None,
            target_dtb=0x4D6BB000, user_va=0x7FF6E289A760,
        )


def test_install_restore_failure_raises_install_error():
    """If the CR3 RESTORE G-packet is rejected, install_user_breakpoint
    must raise InstallError rather than silently swallow — otherwise
    the firing vCPU is left holding target_dtb in its register file
    and the next resume BSODs the guest."""
    cli = FakeRsp()
    target_dtb = 0x4D6BB000
    user_va = 0x7FF6E289A760

    # Track G calls; reject the second (the restore).
    g_count = {"n": 0}
    original_exchange = cli._exchange

    def reject_restore(body, *, timeout=None):
        if body.startswith(b"G"):
            g_count["n"] += 1
            if g_count["n"] == 2:
                # Second G is the restore — non-OK reply.
                cr3 = struct.unpack_from(
                    "<Q",
                    bytes.fromhex(body[1:].decode("ascii")),
                    _CR3_OFFSET,
                )[0]
                cli.cr3_writes.append(cr3)
                return b"E22"
            return original_exchange(body, timeout=timeout)
        return original_exchange(body, timeout=timeout)

    cli._exchange = reject_restore

    with pytest.raises(InstallError, match="poisoned"):
        install_user_breakpoint(
            cli, "vm", store=None,
            target_dtb=target_dtb, user_va=user_va,
        )

    # Two G writes total: swap and restore. Both attempted (the install
    # didn't bail before getting to restore).
    assert g_count["n"] == 2
