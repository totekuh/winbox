"""Offline diff between two kdbg capture artifacts."""

from __future__ import annotations

from typing import Any

from winbox.kdbg.capture import SCHEMA, CaptureError, CaptureIdentityError

DIFF_SCHEMA = "winbox.kdbg-capture-diff/1"
MAX_DIFF_ROWS = 1024


def _identity(capture: dict[str, Any]) -> tuple[Any, Any, Any]:
    boot = capture.get("boot_identity") if isinstance(capture.get("boot_identity"), dict) else {}
    nt = boot.get("nt") if isinstance(boot.get("nt"), dict) else {}
    system = boot.get("system") if isinstance(boot.get("system"), dict) else None
    return capture.get("vm_name"), nt.get("build"), system.get("create_time") if system else None


def _diff_sets(left: list[dict[str, Any]], right: list[dict[str, Any]], key: str, *, limit: int) -> dict[str, Any]:
    before = {str(row.get(key)): row for row in left if isinstance(row, dict) and row.get(key) is not None}
    after = {str(row.get(key)): row for row in right if isinstance(row, dict) and row.get(key) is not None}
    created = [after[key] for key in sorted(set(after) - set(before))][:limit]
    removed = [before[key] for key in sorted(set(before) - set(after))][:limit]
    changed = [
        {"key": key, "before": before[key], "after": after[key]}
        for key in sorted(set(before) & set(after)) if before[key] != after[key]
    ][:limit]
    return {"created": created, "removed": removed, "changed": changed}


def diff_captures(
    left: dict[str, Any], right: dict[str, Any], *, limit: int = 128,
    allow_identity_mismatch: bool = False,
) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_DIFF_ROWS:
        raise CaptureError(f"limit must be between 1 and {MAX_DIFF_ROWS}")
    if left.get("schema") != SCHEMA or right.get("schema") != SCHEMA:
        raise CaptureError("both inputs must be kdbg capture artifacts")
    left_id, right_id = _identity(left), _identity(right)
    if not allow_identity_mismatch and left_id != right_id:
        raise CaptureIdentityError("capture VM, nt build, or captured boot identity differs; refuse unsafe comparison")
    before = left.get("capture") if isinstance(left.get("capture"), dict) else {}
    after = right.get("capture") if isinstance(right.get("capture"), dict) else {}
    if before.get("profile") != after.get("profile"):
        raise CaptureIdentityError("capture profiles differ")
    result: dict[str, Any] = {
        "schema": DIFF_SCHEMA,
        "profile": before.get("profile"),
        "identity_match": left_id == right_id,
        "left_captured_at": left.get("captured_at"),
        "right_captured_at": right.get("captured_at"),
        "limit": limit,
    }
    if before.get("profile") == "process":
        result["threads"] = _diff_sets(
            before.get("threads", {}).get("records", []), after.get("threads", {}).get("records", []),
            "ethread", limit=limit,
        )
        result["modules"] = _diff_sets(
            before.get("modules", {}).get("user", []), after.get("modules", {}).get("user", []),
            "base", limit=limit,
        )
        result["executable_vads"] = _diff_sets(
            before.get("executable_vads", {}).get("records", []), after.get("executable_vads", {}).get("records", []),
            "start", limit=limit,
        )
    else:
        result["processes"] = _diff_sets(before.get("processes", []), after.get("processes", []), "eprocess", limit=limit)
        result["kernel_modules"] = _diff_sets(before.get("kernel_modules", []), after.get("kernel_modules", []), "base", limit=limit)
    return result
