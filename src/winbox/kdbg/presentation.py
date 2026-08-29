"""Stable, explicit presentation of Windows thread metadata."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Keep this deliberately short and exact. Unknown statuses retain their raw
# signed value and normalized unsigned hexadecimal representation; guessing a
# Win32 error name from an arbitrary NTSTATUS is worse than no name at all.
_NTSTATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0x00000001: "STATUS_WAIT_0",
    0x00000080: "STATUS_ABANDONED",
    0x000000C0: "STATUS_USER_APC",
    0x00000101: "STATUS_ALERTED",
    0x00000102: "STATUS_TIMEOUT",
    0x00000103: "STATUS_PENDING",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000004B: "STATUS_THREAD_IS_TERMINATING",
    0xC000010A: "STATUS_PROCESS_IS_TERMINATING",
    0xC0000120: "STATUS_CANCELLED",
}

KERNEL_STACK_SEMANTICS = "KTHREAD.KernelStack field; not a saved RSP"


def filetime_utc(value: int | None) -> str | None:
    """Convert a nonzero Windows FILETIME to canonical UTC, or return null.

    A zero FILETIME is an unavailable/absent kernel field, not a useful date
    in 1601.  Out-of-range or malformed values stay explicit ``null`` while
    callers retain the original raw integer alongside it.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return converted.isoformat(timespec="microseconds").replace("+00:00", "Z")


def ntstatus_hex(value: int | None) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return f"0x{value & 0xFFFFFFFF:08x}"


def ntstatus_name(value: int | None) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return _NTSTATUS_NAMES.get(value & 0xFFFFFFFF)


def pointer_or_none(value: int | None) -> str | None:
    """Render a pointer only when the kernel actually supplied one."""
    if not isinstance(value, int) or isinstance(value, bool) or value == 0:
        return None
    return f"0x{value:016x}"


def thread_presentation_fields(thread: Any) -> dict[str, Any]:
    """New additive fields shared by the CLI and MCP thread contracts."""
    return {
        "create_time_filetime": thread.create_time,
        "create_time_utc": filetime_utc(thread.create_time),
        "exit_status_ntstatus": ntstatus_hex(thread.exit_status),
        "exit_status_name": ntstatus_name(thread.exit_status),
        # Existing top-level pointer strings remain intact for schema
        # compatibility. This typed view supplies null for unavailable zero
        # pointers, and prevents the KTHREAD field from being misread as an
        # arbitrary thread's saved register value.
        "pointer_values": {
            "teb": pointer_or_none(thread.teb),
            "kernel_stack": pointer_or_none(thread.kernel_stack),
            "stack_limit": pointer_or_none(thread.stack_limit),
            "stack_base": pointer_or_none(thread.stack_base),
            "start_address": pointer_or_none(thread.start_address),
            "win32_start_address": pointer_or_none(thread.win32_start_address),
        },
        "kernel_stack_semantics": KERNEL_STACK_SEMANTICS,
    }
