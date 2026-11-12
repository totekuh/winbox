"""Module-private helper functions for the daemon subpackage."""

from __future__ import annotations

import struct
import sys

from winbox.kdbg.debugger.daemon._types import DaemonError
from winbox.kdbg.debugger.install import _CR3_OFFSET_IN_G
from winbox.kdbg.debugger.rsp import RspClient, RspError


_GPR_NAMES = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def _validate_register_layout(blob: bytes) -> None:
    """Sanity-check the g-packet register layout at connect time.

    If QEMU changes the register XML (different offsets for RIP, CR3, CS),
    every read, bp fire, and CR3 filter silently misdecodes. Checking once
    at attach is cheap and catches the problem before it causes damage.
    """
    if len(blob) < 220:
        raise DaemonError(
            f"g-packet too short ({len(blob)} bytes, need >=220); "
            "register layout may be incompatible"
        )
    rip = struct.unpack_from("<Q", blob, 128)[0]
    cs = struct.unpack_from("<I", blob, 140)[0]
    cr3 = struct.unpack_from("<Q", blob, _CR3_OFFSET_IN_G)[0]

    high = rip >> 47
    if high not in (0, 0x1FFFF):
        raise DaemonError(
            f"RIP 0x{rip:x} from g-packet offset 128 is not canonical — "
            "register layout may be wrong for this QEMU build"
        )
    if cs not in (0x10, 0x33, 0x08, 0x23, 0x2b, 0x1b):
        raise DaemonError(
            f"CS 0x{cs:x} from g-packet offset 140 is not a recognized "
            "x86-64 selector — register layout may be wrong"
        )
    if cr3 == 0 or cr3 >= (1 << 52):
        raise DaemonError(
            f"CR3 0x{cr3:x} from g-packet offset {_CR3_OFFSET_IN_G} is "
            "implausible — register layout may be wrong"
        )


def _decode_regs(blob: bytes) -> dict[str, str]:
    """Format a g-packet blob as a flat string-keyed dict."""
    out: dict[str, str] = {}
    for i, name in enumerate(_GPR_NAMES):
        out[name] = "0x{:016x}".format(struct.unpack_from("<Q", blob, i * 8)[0])
    out["rip"] = "0x{:016x}".format(struct.unpack_from("<Q", blob, 128)[0])
    out["eflags"] = "0x{:08x}".format(struct.unpack_from("<I", blob, 136)[0])
    out["cs"] = "0x{:04x}".format(struct.unpack_from("<I", blob, 140)[0])
    out["cr0"] = "0x{:016x}".format(struct.unpack_from("<Q", blob, 188)[0])
    out["cr2"] = "0x{:016x}".format(struct.unpack_from("<Q", blob, 196)[0])
    out["cr3"] = "0x{:016x}".format(struct.unpack_from("<Q", blob, 204)[0])
    out["cr4"] = "0x{:016x}".format(struct.unpack_from("<Q", blob, 212)[0])
    return out


def _looks_like_code_va(va: int) -> bool:
    """Heuristic: kernel-half OR low user-mode (0x7ff..) but not stack/heap."""
    if va == 0:
        return False
    high = va >> 47
    if high == 0x1FFFF:
        return True
    if high == 0 and va > 0x10000:
        return True
    return False


def _read_target_bytes(rsp: RspClient, target_dtb: int, va: int, length: int) -> bytes:
    """One-shot CR3-masquerade read. Used by attach-time stale-base
    detection — borrows the same primitive op_mem uses but doesn't
    need a DaemonSession yet."""
    threads = rsp.list_threads()
    if not threads:
        raise DaemonError("gdbstub returned no threads (vCPUs)")
    rsp.select_thread(threads[0])
    regs = rsp.read_registers()
    original_cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
    try:
        mod = bytearray(regs)
        struct.pack_into("<Q", mod, _CR3_OFFSET_IN_G, target_dtb)
        resp = rsp._exchange(b"G" + bytes(mod).hex().encode("ascii"))
        if resp != b"OK":
            raise DaemonError(f"G-packet rejected during base validation: {resp!r}")
        return rsp.read_memory(va, length)
    finally:
        restore = bytearray(regs)
        struct.pack_into("<Q", restore, _CR3_OFFSET_IN_G, original_cr3)
        try:
            resp = rsp._exchange(b"G" + bytes(restore).hex().encode("ascii"))
        except Exception as e:  # noqa: BLE001
            print(
                f"[kdbg-daemon] FATAL: CR3 restore raised {type(e).__name__}: "
                f"{e} during base validation; vCPU still holds masqueraded "
                f"CR3 0x{target_dtb:x} — DO NOT resume the guest",
                file=sys.stderr, flush=True,
            )
            raise DaemonError(
                "CR3 restore failed during base validation; daemon poisoned"
            ) from e
        else:
            if resp != b"OK":
                print(
                    f"[kdbg-daemon] FATAL: CR3 restore G-packet rejected "
                    f"({resp!r}) during base validation; vCPU still holds "
                    f"masqueraded CR3 0x{target_dtb:x} — DO NOT resume",
                    file=sys.stderr, flush=True,
                )
                raise DaemonError(
                    "CR3 restore failed during base validation; daemon poisoned"
                )


def _normalize_module_name(name: str) -> str:
    """Strip common PE suffixes for matching across naming conventions."""
    n = name.lower().rsplit(".", 1)[0]
    return n


def _stored_module_identity(name: str, data: dict) -> tuple[str, str]:
    """Return a loader basename and architecture for one store entry."""
    architecture = str(data.get("architecture") or "").lower()
    stem = name
    if architecture not in {"x86", "x64"}:
        architecture = "x86" if name.lower().endswith("_x86") else "x64"
    if architecture == "x86" and stem.lower().endswith("_x86"):
        stem = stem[:-4]
    return _normalize_module_name(stem), architecture


def _looks_like_timeout(err: Exception) -> bool:
    """A stalled gdbstub read, as opposed to the stub refusing outright."""
    text = str(err).lower()
    return "timed out" in text or "timeout" in text


def _hw_bp_failure(err: Exception) -> str:
    """Explain a failed hardware breakpoint without inventing a cause."""
    if _looks_like_timeout(err):
        return (
            f"hw bp install timed out: {err}. The stub stopped answering "
            f"rather than refusing — the guest may be busy, or all four "
            f"DR0..3 slots (per-vCPU) may already be taken. Check `kdbg bps`, "
            f"Use mode='soft' for a software breakpoint instead."
        )
    return (
        f"hw bp install failed: {err}. The 4-slot DR0..3 budget is the usual "
        f"cause; check `kdbg bps`. mode='soft' uses a software breakpoint "
        f"instead — unlimited, but PatchGuard-visible and hash-detectable."
    )


def _soft_bp_failure(err: Exception, *, is_user: bool) -> str:
    """Explain a failed software breakpoint."""
    parts = [f"soft bp install failed: {err}."]
    if not is_user and _looks_like_timeout(err):
        parts.append(
            "A software breakpoint patches 0xCC into the kernel code page, "
            "which HVCI exists to prevent — and HVCI is on by default on "
            "Windows 11. If this guest is a client SKU, hardware breakpoints "
            "(mode='hw') are the only ones that will install."
        )
    return " ".join(parts)
