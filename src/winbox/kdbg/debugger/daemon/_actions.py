"""Action/trace evaluation, stop summary, symbol resolution."""

from __future__ import annotations

import struct
import time
from typing import Any

from winbox.kdbg.debugger.daemon._types import (
    Breakpoint,
    CR3RestoreError,
    _CandidateReadFailed,
    _MemoryReadNeeded,
    MAX_CAPTURE_BYTES_PER_TRACE,
)
from winbox.kdbg.debugger.predicate import (
    CaptureRead,
    CaptureValue,
    PredicateRuntimeError,
)
from winbox.kdbg.debugger.rsp import RspError


class _ActionMixin:
    """Breakpoint action evaluation, trace recording, stop summary."""

    def _mem_qword_reader(
        self,
        fired_regs: bytes,
        bp: Breakpoint | None = None,
        *,
        vcpu: str | None = None,
    ):
        """Build a closure for typed scalars and bounded raw captures."""
        rsp = self.rsp
        session = self
        vcpu_hint = vcpu or (
            self.stop.vcpu if self.stop is not None else self._pick_vcpu()
        )
        _UNMAPPED_SIGNS = (b"E14", b"E0E", b"E08", b"failed")

        def _read(addr: int, width: int = 8, *, raw: bool = False):
            if width < 1 or width > 256:
                raise PredicateRuntimeError(f"invalid predicate read width: {width}")
            try:
                data = session._cr3_masqueraded_call(
                    vcpu_hint, fired_regs, lambda: rsp.read_memory(addr, width)
                )
            except RspError as e:
                err_str = str(e).encode()
                if any(sign in err_str for sign in _UNMAPPED_SIGNS):
                    if bp is not None:
                        bp.predicate_read_errors += 1
                    return 0
                raise PredicateRuntimeError(
                    f"predicate read at 0x{addr:x} failed (transport): {e}"
                ) from e
            except CR3RestoreError:
                raise
            except RuntimeError as e:
                if "G-packet" in str(e):
                    raise PredicateRuntimeError(str(e)) from e
                raise
            if len(data) != width:
                raise PredicateRuntimeError(
                    f"short mem read at 0x{addr:x}: got {len(data)}/{width} bytes"
                )
            return data if raw else int.from_bytes(data, "little")

        return _read

    def _evaluate_with_batched_reads(
        self,
        fired_regs: bytes,
        evaluate,
        *,
        bp: Breakpoint | None = None,
        vcpu: str | None = None,
    ):
        """Evaluate expressions with all successful reads under one CR3 swap."""
        def _probe_read(_addr: int, _width: int = 8, *, raw: bool = False):
            raise _MemoryReadNeeded()

        try:
            return evaluate(_probe_read)
        except _MemoryReadNeeded:
            pass

        vcpu_hint = vcpu or (
            self.stop.vcpu if self.stop is not None else self._pick_vcpu()
        )
        rsp = self.rsp

        def _direct_read(addr: int, width: int = 8, *, raw: bool = False):
            if width < 1 or width > 256:
                raise PredicateRuntimeError(f"invalid predicate read width: {width}")
            try:
                data = rsp.read_memory(addr, width)
            except RspError as e:
                raise _CandidateReadFailed(e)
            if len(data) != width:
                raise PredicateRuntimeError(
                    f"short mem read at 0x{addr:x}: got {len(data)}/{width} bytes"
                )
            return data if raw else int.from_bytes(data, "little")

        for candidate in self.target.masquerade_candidates:
            try:
                with self._cr3_masquerade(vcpu_hint, fired_regs, cr3=candidate):
                    return evaluate(_direct_read)
            except _CandidateReadFailed:
                continue

        return evaluate(self._mem_qword_reader(fired_regs, bp=bp, vcpu=vcpu_hint))

    @staticmethod
    def _evaluate_action_values(bp: Breakpoint, regs: bytes, mem) -> dict[str, str]:
        values: dict[str, str] = {}
        for expr_str, ast in zip(bp.actions, bp._action_asts):
            if isinstance(ast, CaptureRead) and (
                bp.capture_bytes + bp.capture_bytes_per_hit
                > MAX_CAPTURE_BYTES_PER_TRACE
            ):
                values[expr_str] = (
                    "error: capture trace byte budget exhausted "
                    f"({MAX_CAPTURE_BYTES_PER_TRACE} bytes)"
                )
                continue
            try:
                val = ast.eval(regs, mem)
                if isinstance(val, CaptureValue):
                    if val.kind == "bytes":
                        rendered = "hex:" + val.data.hex()
                    elif val.kind == "ascii":
                        rendered = "ascii:" + "".join(
                            chr(byte) if 32 <= byte < 127 else "."
                            for byte in val.data
                        )
                    else:
                        rendered = "utf16:" + val.data.decode(
                            "utf-16-le", errors="replace"
                        ).rstrip("\x00")
                    values[expr_str] = rendered
                else:
                    values[expr_str] = f"0x{val:x}"
            except Exception as e:
                values[expr_str] = f"error: {e}"
        return values

    def _evaluate_breakpoint_expressions(
        self,
        bp: Breakpoint,
        regs: bytes,
        *,
        vcpu: str,
    ) -> tuple[bool, dict[str, str] | None]:
        """Evaluate a fire's predicate and actions as one coherent batch."""
        def _evaluate(mem):
            truthy = True
            if bp._predicate is not None:
                truthy = bool(bp._predicate.eval(regs, mem))
            if not truthy or not bp._action_asts:
                return truthy, None
            return truthy, self._evaluate_action_values(bp, regs, mem)

        return self._evaluate_with_batched_reads(
            regs, _evaluate, bp=bp, vcpu=vcpu,
        )

    def _unfired_hw_bp_warnings(self, elapsed: float) -> dict[str, Any]:
        """Passive check for hw bps that never fired after a long cont."""
        if elapsed < 5.0:
            return {}
        unfired = [
            {
                "id": b.bp_id,
                "va": f"0x{b.va:x}",
                "target": b.target,
            }
            for b in self.bps.values()
            if b.hw and b.hits == 0
        ]
        if not unfired:
            return {}
        return {"unfired_hw_bps": unfired}

    def _stop_summary(self) -> dict[str, Any]:
        if self.stop is None:
            return {}
        bp_hit = next((b for b in self.bps.values() if b.va == self.stop.rip), None)
        return {
            "state": "halted",
            "vcpu": self.stop.vcpu,
            "rip": f"0x{self.stop.rip:x}",
            "cr3": f"0x{self.stop.cr3:x}",
            "in_target": self.stop.cr3 in self.target.cr3_set,
            "primary_cr3": self.stop.cr3 == self.target.dtb,
            "bp_id": bp_hit.bp_id if bp_hit else None,
            "bp_target": bp_hit.target if bp_hit else None,
            "session_id": self.session_id,
            "stop_id": self.stop_id,
        }

    def _bump_bp_hits(self, va: int, *, in_target: bool) -> None:
        if not in_target:
            return
        for b in self.bps.values():
            if b.va == va:
                b.hits += 1
                return

    def _append_action_trace(
        self,
        bp: Breakpoint,
        regs: bytes,
        values: dict[str, str],
    ) -> None:
        """Append one already-evaluated action result to the trace."""
        import json as _json
        rip = struct.unpack_from("<Q", regs, 128)[0]
        entry = {
            "hit": bp.trace_count,
            "rip": f"0x{rip:x}",
            "values": values,
        }
        bp.trace_count += 1
        if bp.capture_bytes_per_hit:
            if bp.capture_bytes + bp.capture_bytes_per_hit <= MAX_CAPTURE_BYTES_PER_TRACE:
                bp.capture_bytes += bp.capture_bytes_per_hit
            else:
                bp.capture_limit_reached = True
            if bp.capture_bytes >= MAX_CAPTURE_BYTES_PER_TRACE:
                bp.capture_limit_reached = True
        if bp.trace_path:
            try:
                with open(bp.trace_path, "a") as f:
                    f.write(_json.dumps(entry) + "\n")
            except OSError:
                pass

    def _execute_actions(
        self,
        bp: Breakpoint,
        regs: bytes,
        *,
        vcpu: str | None = None,
    ) -> None:
        """Evaluate actions as one batch and append their trace entry."""
        values = self._evaluate_with_batched_reads(
            regs,
            lambda mem: self._evaluate_action_values(bp, regs, mem),
            bp=bp,
            vcpu=vcpu,
        )
        self._append_action_trace(bp, regs, values)

    def _best_symbol_for_va(self, va: int) -> str | None:
        from winbox.kdbg.format import symbolicate_va
        return symbolicate_va(self.store, va)
