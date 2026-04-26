"""Install a software breakpoint at a USER virtual address.

Why this is non-trivial: QEMU's gdbstub ``Z0,va,1`` packet
translates ``va`` through the *currently selected vCPU's* CR3 to
find the physical page to patch. User VAs are only meaningful in
their owning process's address space, so we need the install to
happen with target's CR3 in effect.

The technique we use is **CR3 masquerade via G-packet**:

1. Halt VM (gdbstub auto-halts on attach)
2. Save the firing vCPU's current CR3
3. Write target_dtb into that vCPU's register file via the gdb ``G``
   packet (write all registers). QEMU honors the write — subsequent
   gdbstub VA translations on this vCPU use the new CR3.
4. Send ``Z0,user_va,1``. The gdbstub walks target's page tables,
   finds the correct physical page, patches 0xCC.
5. Restore the original CR3 via another ``G`` packet.
6. Resume.

Because the VM is halted throughout, no guest code ever runs in
the wrong CR3 — the masquerade is purely a debugger-side bookkeeping
trick. The 0xCC bp persists in the physical page; from then on,
every vCPU executing that page hits it (whether in target's CR3 or
any other process where the page is mapped).

This works for **all** user VAs:
* Shared sections (ntdll, kernel32, etc.) — many CR3s map the same
  PA, all fire the bp
* Private code (target's .text, heap, JIT'd RWX) — only target's
  CR3 maps the PA, only target fires the bp

It bypasses the SwapContext-piggyback dance entirely, dodging the
all-stop saturation problem (where high-frequency processes
monopolize bp fires and idle targets like notepad never get caught).

Critical: the CR3 restore MUST happen before any continue. Resuming
with the wrong CR3 in place would make the vCPU execute kernel
code with target's page tables — guaranteed BSOD. Every code path
restores in a finally clause; a script crash at most leaves the VM
halted (recoverable), never resumes with wrong CR3.

Invariants:

* **Server 2022 default has KPTI/KVA-shadow OFF**, so target_dtb
  (= ``EPROCESS.DirectoryTableBase``) is the actual user CR3.
  KPTI builds may need ``KPROCESS.UserDirectoryTableBase``.
* The user VA must be paged in. Cold VAs error with QEMU E22.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from winbox.kdbg.hmp import hmp, parse_registers

if TYPE_CHECKING:
    from winbox.kdbg.debugger.rsp import RspClient
    from winbox.kdbg.store import SymbolStore


# CR3 location inside QEMU's x86-64 g-packet register blob (verified
# against QEMU 8.x/9.x stub by searching the live g-packet for the
# known CR3 value). See RspClient._CR3_OFFSET for the read shortcut.
_CR3_OFFSET_IN_G = 204


class InstallError(RuntimeError):
    """Raised when the install dance can't place the bp."""


@dataclass
class InstallReport:
    user_va: int
    target_dtb: int
    elapsed: float


# ── Diagnostic HMP helper (unused by install but useful in tests/CLI) ─


def _vcpu_cr3(vm_name: str, vcpu_one_based: str) -> int:
    """Read CR3 of a specific vCPU via HMP — slow but doesn't disturb gdbstub state."""
    idx = int(vcpu_one_based) - 1
    text = hmp(vm_name, "info registers -a")
    parts = text.split(f"CPU#{idx}", 1)
    if len(parts) != 2:
        raise InstallError(f"vCPU {vcpu_one_based} not found in HMP output")
    rest = parts[1].split("CPU#", 1)[0]
    regs = parse_registers(rest)
    cr3 = regs.get("CR3")
    if cr3 is None:
        raise InstallError(f"CR3 missing from HMP regs for vCPU {vcpu_one_based}")
    return cr3


# ── core install primitive ──────────────────────────────────────────────


def install_user_breakpoint(
    cli: "RspClient",
    vm_name: str,
    store: "SymbolStore",
    *,
    target_dtb: int,
    user_va: int,
    timeout: float = 10.0,
) -> InstallReport:
    """Place a software bp at ``user_va`` in target's address space.

    Caller MUST have an attached, halted gdbstub. On success the user
    bp is installed; the VM remains halted ready for the caller to
    ``cont()`` and wait for the user bp to fire. Caller is responsible
    for removing the user bp later (``cli.remove_breakpoint(user_va)``).

    Raises ``InstallError`` on protocol failure or if the user VA
    isn't paged in target's address space.
    """
    # ``timeout`` is currently informational — no inner loops to bound.
    # Kept in the signature so callers can express intent and so we
    # can add bounded retry logic later without a breaking change.
    _ = timeout

    start = time.monotonic()

    # Pick a vCPU to masquerade. Default: the one currently selected
    # via Hg from the caller, or vCPU 1 if nothing was selected. Any
    # vCPU works since we're masquerading via debug interface, not
    # actually running code.
    threads = cli.list_threads()
    if not threads:
        raise InstallError("gdbstub returned no threads (vCPUs)")
    vcpu = threads[0]
    cli.select_thread(vcpu)

    # Snapshot the full register blob so we can restore CR3 cleanly.
    regs = cli.read_registers()
    original_cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]

    swapped = False
    try:
        # Write target_dtb at offset _CR3_OFFSET_IN_G; leave every other
        # byte unchanged. ``G`` packet with a fresh hex blob.
        masquerade = bytearray(regs)
        struct.pack_into("<Q", masquerade, _CR3_OFFSET_IN_G, target_dtb)
        body = b"G" + bytes(masquerade).hex().encode("ascii")
        resp = cli._exchange(body)
        if resp != b"OK":
            raise InstallError(f"G-packet (set CR3) rejected: {resp!r}")
        swapped = True

        # Sanity check QEMU actually applied it.
        verify = struct.unpack_from(
            "<Q", cli.read_registers(), _CR3_OFFSET_IN_G,
        )[0]
        if verify != target_dtb:
            raise InstallError(
                f"CR3 write didn't take effect: wrote 0x{target_dtb:x}, "
                f"reads back 0x{verify:x}"
            )

        # Now Z0 translates user_va via target's page tables.
        try:
            cli.insert_breakpoint(user_va, kind=1)
        except Exception as e:
            raise InstallError(
                f"Z0 at user_va=0x{user_va:x} failed (user CR3 active — VA "
                f"likely not paged in): {e}"
            ) from e

        return InstallReport(
            user_va=user_va,
            target_dtb=target_dtb,
            elapsed=time.monotonic() - start,
        )
    finally:
        # Restore CR3 unconditionally. If we leave target_dtb in vCPU's
        # register file and resume, the vCPU runs kernel code with the
        # wrong page tables = instant BSOD.
        if swapped:
            try:
                restore = bytearray(regs)  # ``regs`` already has original CR3
                struct.pack_into("<Q", restore, _CR3_OFFSET_IN_G, original_cr3)
                cli._exchange(b"G" + bytes(restore).hex().encode("ascii"))
            except Exception:
                # Couldn't restore via gdbstub — caller's only recourse
                # is to halt the VM externally before resume. We surface
                # the original install error if any (re-raised by the
                # outer try) so the user knows.
                pass
