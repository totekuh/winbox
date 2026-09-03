"""Durable, opt-in module-relative breakpoint intents.

The store preserves symbolic ``module+0xoffset`` requests, never resolved
virtual addresses.  A later attach may explicitly snapshot these records and
hand them to the daemon, which resolves them against that attach's frozen
module manifest before touching the gdbstub.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

from winbox.config import Config
from winbox.kdbg.debugger.predicate import (
    CaptureRead,
    PredicateSyntaxError,
    parse as parse_predicate,
)
from winbox.kdbg.debugger.protocol import WATCHPOINT_SIZES, WATCHPOINT_TYPES


SCHEMA = "winbox.kdbg-breakpoint-intents/1"
MAX_INTENTS = 256
MAX_ACTIONS = 16
MAX_CAPTURE_BYTES_PER_HIT = 1024
MAX_STORE_BYTES = 1 << 20
_TARGET_RE = re.compile(
    r"^(?P<module>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})\+"
    r"(?P<offset>0x[0-9a-fA-F]+)$"
)


class BreakpointIntentError(RuntimeError):
    code = "breakpoint_intent_error"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z",
    )


def normalize_target(target: object) -> str:
    """Return the canonical symbolic target accepted by the intent store."""
    if not isinstance(target, str):
        raise BreakpointIntentError("intent target must be a string")
    if len(target) > 260:
        raise BreakpointIntentError("intent target exceeds 260 characters")
    match = _TARGET_RE.fullmatch(target.strip())
    if match is None:
        raise BreakpointIntentError(
            "intent target must use module+0xoffset syntax"
        )
    offset = int(match.group("offset"), 16)
    if offset >= 1 << 64:
        raise BreakpointIntentError("intent offset exceeds uint64")
    return f"{match.group('module').casefold()}+0x{offset:x}"


def normalize_spec(
    target: object,
    *,
    mode: object = "hw",
    condition: object = None,
    wp_type: object = None,
    wp_size: object = 1,
    actions: object = None,
) -> dict[str, Any]:
    """Validate one serializable intent using the live breakpoint grammar."""
    canonical_target = normalize_target(target)
    if not isinstance(mode, str) or mode not in ("hw", "soft"):
        raise BreakpointIntentError("intent mode must be 'hw' or 'soft'")

    if isinstance(condition, str) and not condition.strip():
        condition = None
    if condition is not None:
        if not isinstance(condition, str):
            raise BreakpointIntentError("intent condition must be a string or null")
        try:
            parse_predicate(condition)
        except PredicateSyntaxError as exc:
            raise BreakpointIntentError(f"bad intent condition: {exc}") from exc

    if isinstance(wp_type, str) and not wp_type.strip():
        wp_type = None
    if wp_type is not None and (
        not isinstance(wp_type, str) or wp_type not in WATCHPOINT_TYPES
    ):
        raise BreakpointIntentError(
            "intent wp_type must be 'write', 'read', 'access', or null"
        )
    if isinstance(wp_size, bool) or not isinstance(wp_size, int):
        raise BreakpointIntentError("intent wp_size must be 1, 2, 4, or 8")
    if wp_type is not None and wp_size not in WATCHPOINT_SIZES:
        raise BreakpointIntentError("intent wp_size must be 1, 2, 4, or 8")
    if wp_type is None:
        wp_size = 1

    if actions is None:
        action_list: list[str] = []
    elif isinstance(actions, Sequence) and not isinstance(actions, (str, bytes)):
        action_list = list(actions)
    else:
        raise BreakpointIntentError("intent actions must be a list of strings")
    if len(action_list) > MAX_ACTIONS:
        raise BreakpointIntentError(
            f"intent actions may contain at most {MAX_ACTIONS} expressions"
        )
    capture_bytes = 0
    for index, expression in enumerate(action_list):
        if not isinstance(expression, str):
            raise BreakpointIntentError(
                f"bad intent action[{index}]: expression must be a string"
            )
        try:
            parsed = parse_predicate(expression, allow_capture=True)
        except PredicateSyntaxError as exc:
            raise BreakpointIntentError(
                f"bad intent action[{index}]: {exc}"
            ) from exc
        if isinstance(parsed, CaptureRead):
            capture_bytes += parsed.capture_length
    if capture_bytes > MAX_CAPTURE_BYTES_PER_HIT:
        raise BreakpointIntentError(
            f"intent action captures request {capture_bytes} bytes per hit; "
            f"cap is {MAX_CAPTURE_BYTES_PER_HIT}"
        )

    return {
        "target": canonical_target,
        "mode": mode,
        "condition": condition,
        "wp_type": wp_type,
        "wp_size": wp_size,
        "actions": action_list,
    }


class BreakpointIntentStore:
    """Atomic mode-0600 store scoped to one winbox configuration root."""

    def __init__(self, cfg: Config) -> None:
        self.root = cfg.winbox_dir / "kdbg"
        self.path = self.root / "breakpoint-intents.json"
        self.lock_path = self.root / "breakpoint-intents.lock"

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            os.chmod(self.root, 0o700)
            with self.lock_path.open("a+b") as handle:
                os.chmod(self.lock_path, 0o600)
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise BreakpointIntentError(f"could not lock intent store: {exc}") from exc

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "revision": 0,
            "next_id": 0,
            "updated_at": None,
            "intents": [],
        }

    def _load_unlocked(self) -> dict[str, Any]:
        try:
            stat = self.path.lstat()
        except FileNotFoundError:
            return self._empty()
        except OSError as exc:
            raise BreakpointIntentError(f"could not stat intent store: {exc}") from exc
        if self.path.is_symlink() or not self.path.is_file():
            raise BreakpointIntentError("intent store is not a regular file")
        if stat.st_size > MAX_STORE_BYTES:
            raise BreakpointIntentError("intent store exceeds its 1 MiB bound")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BreakpointIntentError(f"could not read intent store: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
            raise BreakpointIntentError("intent store has an unsupported or corrupt schema")
        intents = payload.get("intents")
        revision = payload.get("revision")
        next_id = payload.get("next_id")
        if (
            not isinstance(intents, list)
            or len(intents) > MAX_INTENTS
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
            or isinstance(next_id, bool)
            or not isinstance(next_id, int)
            or next_id < 0
        ):
            raise BreakpointIntentError("intent store metadata is corrupt")
        normalized: list[dict[str, Any]] = []
        seen: set[int] = set()
        for raw in intents:
            if not isinstance(raw, dict):
                raise BreakpointIntentError("intent store contains a non-object record")
            intent_id = raw.get("id")
            if (
                isinstance(intent_id, bool)
                or not isinstance(intent_id, int)
                or intent_id < 0
                or intent_id in seen
            ):
                raise BreakpointIntentError("intent store contains an invalid or duplicate id")
            seen.add(intent_id)
            spec = normalize_spec(
                raw.get("target"), mode=raw.get("mode"),
                condition=raw.get("condition"), wp_type=raw.get("wp_type"),
                wp_size=raw.get("wp_size"), actions=raw.get("actions"),
            )
            normalized.append({
                "id": intent_id,
                **spec,
                "created_at": str(raw.get("created_at") or ""),
            })
        if seen and next_id <= max(seen):
            raise BreakpointIntentError("intent store next_id is corrupt")
        return {
            "schema": SCHEMA,
            "revision": revision,
            "next_id": next_id,
            "updated_at": payload.get("updated_at"),
            "intents": normalized,
        }

    def _write_unlocked(self, payload: dict[str, Any]) -> None:
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".breakpoint-intents.", suffix=".tmp", dir=self.root,
            )
        except OSError as exc:
            raise BreakpointIntentError(f"could not create intent store: {exc}") from exc
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            if isinstance(exc, BreakpointIntentError):
                raise
            raise BreakpointIntentError(f"could not write intent store: {exc}") from exc

    @staticmethod
    def _public(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "revision": payload["revision"],
            "updated_at": payload["updated_at"],
            "count": len(payload["intents"]),
            "intents": payload["intents"],
        }

    def inventory(self) -> dict[str, Any]:
        with self._exclusive():
            return self._public(self._load_unlocked())

    def add(
        self,
        target: object,
        *,
        mode: object = "hw",
        condition: object = None,
        wp_type: object = None,
        wp_size: object = 1,
        actions: object = None,
    ) -> dict[str, Any]:
        spec = normalize_spec(
            target, mode=mode, condition=condition, wp_type=wp_type,
            wp_size=wp_size, actions=actions,
        )
        with self._exclusive():
            payload = self._load_unlocked()
            if len(payload["intents"]) >= MAX_INTENTS:
                raise BreakpointIntentError(f"intent store is capped at {MAX_INTENTS} records")
            if any(
                all(existing.get(key) == value for key, value in spec.items())
                for existing in payload["intents"]
            ):
                raise BreakpointIntentError("an identical breakpoint intent already exists")
            record = {
                "id": payload["next_id"],
                **spec,
                "created_at": _utc_now(),
            }
            payload["next_id"] += 1
            payload["revision"] += 1
            payload["updated_at"] = _utc_now()
            payload["intents"].append(record)
            self._write_unlocked(payload)
            return record

    def remove(self, intent_id: object) -> dict[str, Any]:
        if isinstance(intent_id, bool) or not isinstance(intent_id, int) or intent_id < 0:
            raise BreakpointIntentError("intent id must be a non-negative integer")
        with self._exclusive():
            payload = self._load_unlocked()
            index = next(
                (i for i, item in enumerate(payload["intents"]) if item["id"] == intent_id),
                None,
            )
            if index is None:
                raise BreakpointIntentError(f"breakpoint intent {intent_id} was not found")
            removed = payload["intents"].pop(index)
            payload["revision"] += 1
            payload["updated_at"] = _utc_now()
            self._write_unlocked(payload)
            return {"removed": removed, "remaining": len(payload["intents"])}
