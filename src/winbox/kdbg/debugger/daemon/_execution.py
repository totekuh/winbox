"""Run-control mixin — cont, step, step_over, step_out, interrupt."""

from __future__ import annotations

import struct
import time
from contextlib import suppress
from typing import Any

from winbox.kdbg.debugger.install import _CR3_OFFSET_IN_G
from winbox.kdbg.debugger.predicate import PredicateRuntimeError
from winbox.kdbg.debugger.rsp import RspError
from winbox.kdbg.debugger.daemon._helpers import _decode_regs


class _ExecutionMixin:

    def op_cont(self, timeout: float = 30.0) -> dict[str, Any]:
        """Resume; block until next stop in any of target's CR3s."""
        accepted_cr3s = self.target.cr3_set
        _cont_start = time.monotonic()
        deadline = _cont_start + max(0.5, float(timeout))
        # An async continue-job cancel (an armed interrupt, see op_interrupt)
        # may have reached the daemon in the window between the worker
        # reporting "running" and this op starting, while the VM was still
        # halted from the attach. The VM was never resumed, so honor the
        # interrupt against the current stop instead of resuming and running
        # to the full timeout — otherwise the job never cancels.
        if (self._interrupt_pending
                and self.run_state == "halted" and self.stop is not None):
            self._interrupt_pending = False
            result = {"reason": "interrupt", **self._stop_summary()}
            result.update(self._unfired_hw_bp_warnings(0.0))
            return result
        self._interrupt_pending = False
        while True:
            if self._interrupt_pending:
                self.rsp.interrupt()
                sr = self.rsp.wait_for_stop(timeout=2.0)
                self._capture_stop(sr)
                result = {"reason": "interrupt", **self._stop_summary()}
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result = {"reason": "timeout"}
                if self.run_state == "halted" and self.stop is not None:
                    result.update(self._stop_summary())
                    result["target_liveness"] = self._probe_target_liveness()
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result

            self._begin_resume()
            try:
                self.rsp.cont()
            except Exception:
                self._mark_indeterminate()
                raise
            try:
                sr = self._wait_for_stop_serving(remaining)
            except RspError as e:
                if "timed out" in str(e).lower():
                    try:
                        self.rsp.interrupt()
                        sr = self.rsp.wait_for_stop(timeout=2.0)
                        self._capture_stop(sr)
                    except RspError:
                        self._mark_indeterminate()
                    result = {"reason": "timeout", **self._stop_summary()}
                    if self.run_state == "halted" and self.stop is not None:
                        result["target_liveness"] = self._probe_target_liveness()
                    result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                    return result
                self._mark_indeterminate()
                raise RuntimeError(f"cont/wait failed: {e}") from e

            if self._interrupt_pending:
                self._interrupt_pending = False
                self._capture_stop(sr)
                result = {"reason": "interrupt", **self._stop_summary()}
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result

            if sr.signal != 5:
                self._capture_stop(sr)
                result = {"reason": "signal", **self._stop_summary()}
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result

            firing_vcpu = self._stop_vcpu(sr)
            if self._last_selected_vcpu != firing_vcpu:
                self._select_thread(firing_vcpu)
            regs = self.rsp.read_registers()
            cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
            rip = struct.unpack_from("<Q", regs, 128)[0]

            if cr3 not in accepted_cr3s:
                self._bump_bp_hits(rip, in_target=False)
                if not self._hw_bp_verified:
                    hit_bp = self.bps.get(self._bp_by_va.get(rip, -1))
                    if hit_bp is not None and hit_bp.hw:
                        self._hw_bp_verified = True
                self._capture_stop_with_regs(sr, regs, vcpu=firing_vcpu)
                if time.monotonic() >= deadline:
                    result = {"reason": "timeout", **self._stop_summary()}
                    result["target_liveness"] = self._probe_target_liveness()
                    result.update(self._unfired_hw_bp_warnings(
                        time.monotonic() - _cont_start
                    ))
                    return result
                continue

            bp = self.bps.get(self._bp_by_va.get(rip, -1))

            action_values: dict[str, str] | None = None
            if bp is not None and (bp._predicate is not None or bp._action_asts):
                try:
                    truthy, action_values = self._evaluate_breakpoint_expressions(
                        bp, regs, vcpu=firing_vcpu,
                    )
                except PredicateRuntimeError as e:
                    bp.predicate_errors += 1
                    bp.hits += 1
                    self._capture_stop_with_regs(sr, regs, vcpu=firing_vcpu)
                    return {
                        "reason": "predicate_error",
                        "error": str(e),
                        **self._stop_summary(),
                    }
                if bp._predicate is not None and not truthy:
                    bp.predicate_skips += 1
                    bp.hits += 1
                    self._capture_stop_with_regs(sr, regs, vcpu=firing_vcpu)
                    if time.monotonic() >= deadline:
                        result = {"reason": "timeout", **self._stop_summary()}
                        result["target_liveness"] = self._probe_target_liveness()
                        result.update(self._unfired_hw_bp_warnings(
                            time.monotonic() - _cont_start
                        ))
                        return result
                    continue
                if bp._predicate is not None:
                    bp.predicate_hits += 1

            self._capture_stop_with_regs(sr, regs, vcpu=firing_vcpu)
            if bp is not None:
                bp.hits += 1
                if bp.hw and not self._hw_bp_verified:
                    self._hw_bp_verified = True
            else:
                self._bump_bp_hits(rip, in_target=True)

            if bp is not None and bp._action_asts:
                self._append_action_trace(bp, regs, action_values or {})
                if time.monotonic() >= deadline:
                    result = {"reason": "timeout", **self._stop_summary()}
                    result["target_liveness"] = self._probe_target_liveness()
                    result.update(self._unfired_hw_bp_warnings(
                        time.monotonic() - _cont_start
                    ))
                    return result
                continue

            result = {"reason": "bp", **self._stop_summary()}
            result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
            return result

    def op_step(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        vcpu = self.stop.vcpu
        suspended_bp = self.bps.get(self._bp_by_va.get(self.stop.rip, -1))
        if suspended_bp is not None and (
            not suspended_bp.hw or suspended_bp.wp_type is not None
        ):
            suspended_bp = None
        if suspended_bp is not None:
            self.rsp.remove_breakpoint(
                suspended_bp.va, kind=1, hardware=True,
            )

        def restore_suspended_bp() -> None:
            if suspended_bp is None:
                return
            try:
                self.rsp.insert_breakpoint(
                    suspended_bp.va, kind=1, hardware=True,
                )
            except Exception:
                self.bps.pop(suspended_bp.bp_id, None)
                self._bp_by_va.pop(suspended_bp.va, None)
                raise

        def forget_suspended_bp() -> None:
            if suspended_bp is not None:
                self.bps.pop(suspended_bp.bp_id, None)
                self._bp_by_va.pop(suspended_bp.va, None)

        self._begin_resume()
        try:
            self.rsp.step(vcpu)
        except Exception:
            forget_suspended_bp()
            self._mark_indeterminate()
            raise
        try:
            sr = self.rsp.wait_for_stop(timeout=5.0)
        except RspError as e:
            if "timed out" not in str(e).lower():
                forget_suspended_bp()
                self._mark_indeterminate()
                raise
            recovered = False
            try:
                self.rsp.interrupt()
                sr_recovery = self.rsp.wait_for_stop(timeout=2.0)
                self._capture_stop(sr_recovery)
            except Exception:
                forget_suspended_bp()
                self._mark_indeterminate()
            else:
                restore_suspended_bp()
                recovered = True
            if recovered:
                raise RuntimeError(
                    "step did not complete within 5s; stub recovered to halted state"
                ) from e
            raise RuntimeError(
                "step did not complete within 5s and recovery halt failed; "
                "stub state is indeterminate, daemon may need restart"
            ) from e
        try:
            self._select_thread(self._stop_vcpu(sr, fallback=vcpu))
            self._capture_stop(sr)
        except Exception:
            try:
                restore_suspended_bp()
            except Exception:
                pass
            self._mark_indeterminate()
            raise
        restore_suspended_bp()
        return {"reason": "step", **self._stop_summary()}

    _STEP_OVER_MNEMONICS = frozenset({"call", "syscall", "sysenter"})

    def _run_to(self, target_rip: int, *, timeout: float, reason: str,
                label: str) -> dict[str, Any]:
        """Plant temp hw bp at target_rip, cont until hit, remove."""
        try:
            self.rsp.insert_breakpoint(target_rip, kind=1, hardware=True)
        except RspError as e:
            raise RuntimeError(
                f"{reason} needs a temp hw bp at 0x{target_rip:x} but "
                f"install failed: {e}. Free a DR slot with bp_remove."
            ) from e

        try:
            deadline = time.monotonic() + max(1.0, float(timeout))
            self._begin_resume()
            try:
                self.rsp.cont()
            except Exception:
                self._mark_indeterminate()
                raise
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.rsp.interrupt()
                    try:
                        sr = self.rsp.wait_for_stop(timeout=2.0)
                        self._capture_stop(sr)
                    except RspError:
                        self._mark_indeterminate()
                    suffix = (
                        "VM re-halted" if self.run_state == "halted"
                        else "recovery halt failed; state is indeterminate"
                    )
                    raise RuntimeError(
                        f"{reason} timed out ({timeout}s) waiting to reach "
                        f"0x{target_rip:x}; {suffix}"
                    )
                try:
                    sr = self.rsp.wait_for_stop(timeout=remaining)
                except RspError as e:
                    if "timed out" in str(e).lower():
                        continue
                    self._mark_indeterminate()
                    raise
                regs = self.rsp.read_registers()
                hit_rip = struct.unpack_from("<Q", regs, 128)[0]
                if hit_rip == target_rip:
                    self._capture_stop(sr)
                    break
                self._begin_resume()
                try:
                    self.rsp.cont()
                except Exception:
                    self._mark_indeterminate()
                    raise
        finally:
            with suppress(RspError):
                self.rsp.remove_breakpoint(target_rip, kind=1, hardware=True)

        return {"reason": reason, **({label: True} if label else {}),
                **self._stop_summary()}

    def op_step_over(self, timeout: float = 10) -> dict[str, Any]:
        """Step over a call/syscall: temp bp at next instruction, cont, remove."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")

        rip = self.stop.rip
        raw = self.rsp.read_memory(rip, 15)

        try:
            import capstone
            mode = capstone.CS_MODE_32 if self._is_x86_stop() else capstone.CS_MODE_64
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            insn = next(md.disasm(raw, rip), None)
        except ImportError:
            raise RuntimeError("capstone not installed; step_over needs it for disasm")

        if insn is None:
            raise RuntimeError(f"could not decode instruction at 0x{rip:x}")

        if insn.mnemonic not in self._STEP_OVER_MNEMONICS:
            return self.op_step()

        next_rip = rip + insn.size
        result = self._run_to(next_rip, timeout=timeout,
                              reason="step_over", label="")
        result["stepped_over"] = insn.mnemonic
        return result

    def op_step_out(self, timeout: float = 10) -> dict[str, Any]:
        """Step out of the current function: temp bp at return address, cont."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        rsp_va = struct.unpack_from("<Q", self.stop.raw_regs, 7 * 8)[0]
        width = 4 if self._is_x86_stop() else 8
        ret_bytes = self.rsp.read_memory(rsp_va, width)
        ret_addr = int.from_bytes(ret_bytes, "little")
        if ret_addr == 0:
            raise RuntimeError("return address at [rsp] is 0 — stack may be corrupt")
        return self._run_to(ret_addr, timeout=timeout,
                            reason="step_out", label="")

    def op_interrupt(self, arm: bool = False) -> dict[str, Any]:
        """Halt a running VM via raw ``\\x03`` on the RSP socket.

        ``arm`` marks an async continue-job cancellation. Such a cancel can
        reach the daemon while the VM is still halted — in the window between
        the cont worker reporting "running" and its ``cont`` op actually
        starting. Clearing ``_interrupt_pending`` there would let the imminent
        ``cont`` resume and run to its full timeout, so the job would never
        cancel. With ``arm`` we leave the flag set instead; ``op_cont`` honors
        it the moment it starts (its pre-resume check) and returns a prompt
        ``interrupt`` stop. Interactive ``interrupt`` (``arm=False``) keeps the
        plain already-halted behavior.
        """
        if self.run_state == "halted" and self.stop is not None:
            self._interrupt_pending = bool(arm)
            return {
                "queued": bool(arm),
                "already_halted": True,
                **self._stop_summary(),
            }

        if self._busy:
            self._interrupt_pending = True
            with suppress(RspError, OSError):
                self.rsp.interrupt()
            return {"queued": True}

        self._interrupt_pending = False
        try:
            self.rsp.interrupt()
            sr = self.rsp.wait_for_stop(timeout=2.0)
            self._capture_stop(sr)
        except Exception:
            self._mark_indeterminate()
            raise
        return {
            "queued": False,
            "recovered": True,
            **self._stop_summary(),
        }

    def op_regs(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError(
                f"registers unavailable while target state is {self.run_state}"
            )
        return _decode_regs(self.stop.raw_regs)
