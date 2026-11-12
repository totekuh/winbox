"""Breakpoint management mixin — bp_add, bp_list, bp_trace, bp_remove."""

from __future__ import annotations

import re
import sys
import time
from contextlib import suppress
from typing import Any

from winbox.kdbg import SymbolStoreError
from winbox.kdbg.debugger.install import (
    InstallError,
    install_user_breakpoint,
)
from winbox.kdbg.debugger.predicate import (
    CaptureRead,
    PredicateSyntaxError,
    parse as parse_predicate,
)
from winbox.kdbg.debugger.protocol import WATCHPOINT_SIZES, WATCHPOINT_TYPES
from winbox.kdbg.debugger.rsp import RspError
from winbox.kdbg.debugger.trace import (
    MAX_SUMMARY_TOP,
    MAX_TRACE_RESULTS,
    query_trace,
)
from winbox.kdbg.debugger.daemon._types import (
    Breakpoint,
    MAX_BREAKPOINT_ACTIONS,
    MAX_CAPTURE_BYTES_PER_HIT,
    MAX_CAPTURE_BYTES_PER_TRACE,
    _MODULE_OFFSET_TARGET,
    _runtime_dir,
)
from winbox.kdbg.debugger.daemon._helpers import (
    _hw_bp_failure,
    _soft_bp_failure,
)


class _BreakpointMixin:

    _VALID_WP_TYPES = frozenset(WATCHPOINT_TYPES)
    _VALID_WP_SIZES = frozenset(WATCHPOINT_SIZES)

    def op_bp_add(
        self,
        target: str,
        mode: str = "hw",
        condition: str | None = None,
        wp_type: str | None = None,
        wp_size: int = 1,
        actions: list | None = None,
    ) -> dict[str, Any]:
        """Install a breakpoint or watchpoint at sym/VA."""
        if isinstance(condition, str) and not condition.strip():
            condition = None
        if isinstance(wp_type, str) and not wp_type.strip():
            wp_type = None

        if wp_type is not None:
            if wp_type not in self._VALID_WP_TYPES:
                raise ValueError(
                    f"wp_type must be 'write', 'read', or 'access'; "
                    f"got {wp_type!r}"
                )
            wp_size = int(wp_size)
            if wp_size not in self._VALID_WP_SIZES:
                raise ValueError(
                    f"wp_size must be 1, 2, 4, or 8; got {wp_size}"
                )

        predicate_ast = None
        if condition is not None:
            try:
                predicate_ast = parse_predicate(condition)
            except PredicateSyntaxError as e:
                raise RuntimeError(f"bad condition: {e}") from e

        action_list = [] if actions is None else actions
        if not isinstance(action_list, list):
            raise RuntimeError("actions must be a list of expression strings")
        if len(action_list) > MAX_BREAKPOINT_ACTIONS:
            raise RuntimeError(
                f"actions may contain at most {MAX_BREAKPOINT_ACTIONS} expressions"
            )
        action_asts = []
        for i, expr in enumerate(action_list):
            if not isinstance(expr, str):
                raise RuntimeError(f"bad action[{i}]: expression must be a string")
            try:
                action_asts.append(parse_predicate(expr, allow_capture=True))
            except PredicateSyntaxError as e:
                raise RuntimeError(f"bad action[{i}]: {e}") from e
        capture_bytes_per_hit = sum(
            ast.capture_length for ast in action_asts
            if isinstance(ast, CaptureRead)
        )
        if capture_bytes_per_hit > MAX_CAPTURE_BYTES_PER_HIT:
            raise RuntimeError(
                f"action captures request {capture_bytes_per_hit} bytes per hit; "
                f"cap is {MAX_CAPTURE_BYTES_PER_HIT}"
            )

        va, target = self._resolve_target(target)
        is_user = (va >> 47) != 0x1FFFF

        _trace = ""
        if action_list:
            trace_path = _runtime_dir(self.cfg) / (
                f"bp{self._next_bp_id}.trace.jsonl"
            )
            try:
                trace_path.write_text("", encoding="utf-8")
            except OSError as e:
                raise RuntimeError(f"could not initialise action trace: {e}") from e
            _trace = str(trace_path)

        # ── Watchpoint path ────────────────────────────────────────────
        if wp_type is not None:
            t0 = time.monotonic()
            try:
                self.rsp.insert_breakpoint(
                    va, kind=wp_size, wp_type=wp_type,
                )
            except RspError as e:
                raise RuntimeError(_hw_bp_failure(e)) from e
            elapsed_ms = (time.monotonic() - t0) * 1000.0

            bp_id = self._next_bp_id
            self._next_bp_id += 1
            bp = Breakpoint(
                bp_id=bp_id,
                va=va,
                target=target,
                user_mode=is_user,
                hw=True,
                installed_at=time.monotonic(),
                wp_type=wp_type,
                wp_size=wp_size,
                condition=condition,
                _predicate=predicate_ast,
                actions=action_list,
                _action_asts=action_asts,
                trace_path=_trace,
                capture_bytes_per_hit=capture_bytes_per_hit,
            )
            self.bps[bp_id] = bp
            self._bp_by_va[va] = bp_id
            result = {
                "id": bp_id,
                "va": f"0x{va:x}",
                "target": target,
                "user_mode": is_user,
                "hw": True,
                "wp_type": wp_type,
                "wp_size": wp_size,
                "condition": condition,
                "elapsed_ms": round(elapsed_ms, 2),
            }
            if action_list:
                result["actions"] = action_list
                result["trace_path"] = _trace
            return result

        # ── Execution breakpoint path ─────────────────────────────────
        if mode not in ("hw", "soft"):
            raise ValueError(
                f"mode must be 'hw' or 'soft'; got {mode!r}. "
                f"Breakpoints must carry their type explicitly — "
                f"no silent fallback."
            )

        installed_hw = False
        elapsed_ms = 0.0

        if mode == "hw":
            t0 = time.monotonic()
            try:
                self.rsp.insert_breakpoint(va, kind=1, hardware=True)
                installed_hw = True
                elapsed_ms = (time.monotonic() - t0) * 1000.0
            except RspError as e:
                raise RuntimeError(_hw_bp_failure(e)) from e
        else:
            t0 = time.monotonic()
            try:
                if is_user:
                    report = install_user_breakpoint(
                        self.rsp, self.cfg.vm_name, self.store,
                        cr3_candidates=self.target.masquerade_candidates,
                        user_va=va,
                    )
                    elapsed_ms = report.elapsed * 1000.0
                    self._last_selected_vcpu = None
                else:
                    self.rsp.insert_breakpoint(va, kind=1)
                    elapsed_ms = (time.monotonic() - t0) * 1000.0
            except (RspError, InstallError) as e:
                raise RuntimeError(
                    _soft_bp_failure(e, is_user=is_user)
                ) from e

        bp_id = self._next_bp_id
        self._next_bp_id += 1
        _installed_cr3 = 0
        if is_user and not installed_hw:
            _installed_cr3 = report.target_dtb  # type: ignore[union-attr]
        bp = Breakpoint(
            bp_id=bp_id,
            va=va,
            target=target,
            user_mode=is_user,
            hw=installed_hw,
            installed_at=time.monotonic(),
            installed_cr3=_installed_cr3,
            condition=condition,
            _predicate=predicate_ast,
            actions=action_list,
            _action_asts=action_asts,
            trace_path=_trace,
            capture_bytes_per_hit=capture_bytes_per_hit,
        )
        self.bps[bp_id] = bp
        self._bp_by_va[va] = bp_id
        result = {
            "id": bp_id,
            "va": f"0x{va:x}",
            "target": target,
            "user_mode": is_user,
            "hw": installed_hw,
            "condition": condition,
            "elapsed_ms": round(elapsed_ms, 2),
        }
        if action_list:
            result["actions"] = action_list
            result["trace_path"] = _trace
        return result

    def op_bp_list(self) -> dict[str, Any]:
        from winbox.kdbg.demangle import pretty_symbol
        entries = []
        for b in self.bps.values():
            entry = {
                "id": b.bp_id,
                "va": f"0x{b.va:x}",
                "target": b.target,
                "target_pretty": pretty_symbol(b.target),
                "user_mode": b.user_mode,
                "hw": b.hw,
                "hits": b.hits,
                "condition": b.condition,
                "predicate_hit_count": b.predicate_hits,
                "predicate_skip_count": b.predicate_skips,
                "predicate_error_count": b.predicate_errors,
                "predicate_read_error_count": b.predicate_read_errors,
                "age_s": round(time.monotonic() - b.installed_at, 2),
            }
            if b.wp_type is not None:
                entry["wp_type"] = b.wp_type
                entry["wp_size"] = b.wp_size
            if b.actions:
                entry["actions"] = b.actions
                entry["trace_count"] = b.trace_count
                entry["trace_path"] = b.trace_path
                entry["capture_bytes"] = b.capture_bytes
                entry["capture_bytes_per_hit"] = b.capture_bytes_per_hit
                entry["capture_bytes_limit"] = MAX_CAPTURE_BYTES_PER_TRACE
                entry["capture_limit_reached"] = b.capture_limit_reached
            entries.append(entry)
        return {"bps": entries}

    def op_bp_trace(  # noqa: A002
        self,
        id: int,
        tail: int = 20,
        from_hit: int | None = None,
        limit: int = 20,
        expression: str | None = None,
        value: str | int | None = None,
        errors_only: bool = False,
        summary: bool = False,
        top: int = 10,
    ) -> dict[str, Any]:
        """Run a bounded query over an action breakpoint's JSONL trace."""
        bp = self.bps.get(id)
        if bp is None:
            raise ValueError(f"no bp with id {id}")

        def _bounded_int(name: str, raw: Any, maximum: int) -> int:
            if isinstance(raw, bool):
                raise ValueError(f"{name} must be an integer")
            try:
                parsed = int(raw)
            except (TypeError, ValueError) as e:
                raise ValueError(f"{name} must be an integer") from e
            if not 1 <= parsed <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")
            return parsed

        tail = _bounded_int("tail", tail, MAX_TRACE_RESULTS)
        limit = _bounded_int("limit", limit, MAX_TRACE_RESULTS)
        top = _bounded_int("top", top, MAX_SUMMARY_TOP)
        if from_hit is not None:
            if isinstance(from_hit, bool):
                raise ValueError("from_hit must be a non-negative integer")
            try:
                from_hit = int(from_hit)
            except (TypeError, ValueError) as e:
                raise ValueError("from_hit must be a non-negative integer") from e
            if from_hit < 0:
                raise ValueError("from_hit must be a non-negative integer")
        if expression is not None:
            if not isinstance(expression, str):
                raise ValueError("expression must be a string")
            expression = expression.strip() or None
        if isinstance(value, bool):
            raise ValueError("value must be a string or integer")
        if value is not None and not isinstance(value, (str, int)):
            raise ValueError("value must be a string or integer")
        value = str(value) if value is not None else None
        if not isinstance(errors_only, bool):
            raise ValueError("errors_only must be a boolean")
        if not isinstance(summary, bool):
            raise ValueError("summary must be a boolean")

        if not bp.trace_path:
            return {
                "id": id, "entries": [], "total": 0, "returned": 0,
                "truncated": False, "scan_complete": True,
                "malformed_lines": 0, "result_bytes_truncated": False,
                "oversized_entries": 0,
            }
        try:
            result = query_trace(
                bp.trace_path,
                total=bp.trace_count,
                tail=tail,
                from_hit=from_hit,
                limit=limit,
                expression=expression,
                value=value,
                errors_only=errors_only,
                summary=summary,
                top=top,
            )
        except OSError:
            return {
                "id": id, "entries": [], "total": bp.trace_count,
                "returned": 0, "truncated": bp.trace_count > 0,
                "scan_complete": False, "malformed_lines": 0,
                "result_bytes_truncated": False, "oversized_entries": 0,
                "read_error": "trace file unavailable",
            }
        return {"id": id, **result}

    def _remove_bp_via_stub(self, bp: Breakpoint) -> None:
        """Send the z-packet that clears ``bp`` from the gdbstub."""
        if bp.wp_type is not None:
            self.rsp.remove_breakpoint(
                bp.va, kind=bp.wp_size, wp_type=bp.wp_type,
            )
        elif bp.user_mode and not bp.hw:
            vcpu = self._pick_vcpu()
            self._select_thread(vcpu)
            regs = self.rsp.read_registers()
            if bp.installed_cr3:
                with self._cr3_masquerade(vcpu, regs, cr3=bp.installed_cr3):
                    self.rsp.remove_breakpoint(bp.va, kind=1, hardware=False)
            else:
                self._cr3_masqueraded_call(
                    vcpu, regs,
                    lambda: self.rsp.remove_breakpoint(bp.va, kind=1, hardware=False),
                )
        else:
            self.rsp.remove_breakpoint(bp.va, kind=1, hardware=bp.hw)

    def op_bp_remove(self, id: int) -> dict[str, Any]:  # noqa: A002 — wire name
        bp = self.bps.get(id)
        if bp is None:
            raise ValueError(f"no bp with id {id}")
        try:
            self._remove_bp_via_stub(bp)
        except RspError as e:
            packet = "z1" if bp.hw else "z0"
            print(
                f"[kdbg-daemon] {packet} remove failed for bp {id} at "
                f"0x{bp.va:x}: {e}; bp left tracked, retry bp_remove",
                file=sys.stderr, flush=True,
            )
            raise RuntimeError(
                f"{packet} failed: {e}; bp still tracked, retry bp_remove"
            ) from e
        del self.bps[id]
        if self._bp_by_va.get(bp.va) == id:
            del self._bp_by_va[bp.va]
        return {"removed": id, "va": f"0x{bp.va:x}", "hw": bp.hw}

    def _resolve_target(self, target: str) -> tuple[int, str]:
        """Resolve a symbol, VA, or staged ``module+offset`` breakpoint."""
        if not isinstance(target, str):
            raise RuntimeError("target must be a string")
        target = target.strip()
        match = _MODULE_OFFSET_TARGET.fullmatch(target)
        if match:
            if self.module_manifest is None:
                raise RuntimeError(
                    "module+offset requires an attached session with a staged "
                    "user-module manifest"
                )
            requested = match.group("module").casefold()
            requested_stem = requested.rsplit(".", 1)[0]

            def forms(name: str) -> set[str]:
                folded = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].casefold()
                return {folded, folded.rsplit(".", 1)[0]}

            matches = [
                item for item in self.module_manifest.modules
                if requested in forms(item.name) or requested_stem in forms(item.name)
            ]
            if not matches:
                raise RuntimeError(
                    f"module+offset target {target!r} is not in this session's "
                    "staged module manifest"
                )
            if len(matches) != 1:
                choices = ", ".join(
                    f"{item.name}@{item.architecture}" for item in matches[:8]
                )
                raise RuntimeError(
                    f"module+offset target {target!r} is ambiguous in the staged "
                    f"module manifest: {choices}"
                )
            item = matches[0]
            offset = int(match.group("offset"), 16)
            if offset >= item.size:
                raise RuntimeError(
                    f"module+offset target {target!r} lies outside {item.name} "
                    f"(size 0x{item.size:x})"
                )
            va = item.base + offset
            if not 0 <= va < (1 << 64):
                raise RuntimeError(f"module+offset target {target!r} overflows uint64")
            return va, f"{item.name}+0x{offset:x}"
        if "!" in target:
            try:
                return self.store.resolve(target), target
            except SymbolStoreError as e:
                raise RuntimeError(f"symbol: {e}") from e
        try:
            return int(target, 0), target
        except ValueError as e:
            raise RuntimeError(
                f"not a hex VA, module!symbol, or staged module+0xoffset: {target!r}"
            ) from e
