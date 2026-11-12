"""DaemonSession — core class composing all mixin clusters."""

from __future__ import annotations

import os
import secrets
import struct
import sys
import time
from contextlib import contextmanager, suppress
from typing import Any

from winbox.config import Config
from winbox.kdbg import SymbolStore, SymbolStoreError
from winbox.kdbg.debugger.install import _CR3_OFFSET_IN_G
from winbox.kdbg.debugger.protocol import OPS, reply_err, reply_ok
from winbox.kdbg.debugger.rsp import RspClient, RspError
from winbox.kdbg.staging import UserModuleManifest

from winbox.kdbg.debugger.daemon._types import (
    Breakpoint,
    CR3RestoreError,
    StopState,
    TargetInfo,
    _MODULE_OFFSET_TARGET,
)
from winbox.kdbg.debugger.daemon._helpers import _decode_regs
from winbox.kdbg.debugger.daemon._breakpoints import _BreakpointMixin
from winbox.kdbg.debugger.daemon._execution import _ExecutionMixin
from winbox.kdbg.debugger.daemon._memory import _MemoryMixin
from winbox.kdbg.debugger.daemon._unwind import _UnwindMixin
from winbox.kdbg.debugger.daemon._unwind_x86 import _UnwindX86Mixin
from winbox.kdbg.debugger.daemon._context import _ContextMixin
from winbox.kdbg.debugger.daemon._actions import _ActionMixin
from winbox.kdbg.debugger.daemon._serve import _ServeMixin

import socket


class DaemonSession(
    _BreakpointMixin,
    _ExecutionMixin,
    _MemoryMixin,
    _UnwindMixin,
    _UnwindX86Mixin,
    _ContextMixin,
    _ActionMixin,
    _ServeMixin,
):
    """Long-lived debugger session. One target, one gdb connection."""

    # Public for tests; tests can subclass to inject FakeRsp.
    BUSY_REPLY = reply_err(
        "BUSY: another op in progress", code="busy", retryable=True,
    )
    SHUTDOWN_REPLY = reply_err(
        "daemon shutting down", code="daemon_shutting_down", retryable=True,
    )
    _RUNNING_OPS = frozenset({
        "status", "interrupt", "bp_list", "bp_trace", "detach",
    })
    _INDETERMINATE_OPS = frozenset({"status", "interrupt", "detach"})
    _POISONED_OPS = frozenset({"status", "detach"})

    def __init__(
        self,
        cfg: Config,
        rsp: RspClient,
        target: TargetInfo,
        store: SymbolStore,
        module_manifest: UserModuleManifest | None = None,
    ) -> None:
        self.cfg = cfg
        self.rsp = rsp
        self.target = target
        self.store = store
        self.module_manifest = module_manifest
        self.breakpoint_intents: dict[str, Any] | None = None

        self.bps: dict[int, Breakpoint] = {}
        self._bp_by_va: dict[int, int] = {}
        self._next_bp_id = 0
        self.stop: StopState | None = None
        self.session_id = secrets.token_hex(16)
        self.stop_id = 0
        self.run_state = "indeterminate"
        self.attach_time = time.monotonic()
        self._last_target_liveness: dict[str, Any] = {
            "state": "unknown", "checked": False,
            "identity": "create_time" if target.create_time else "eprocess",
        }

        self._busy = False
        self._interrupt_pending = False
        self._cr3_corrupted = False
        self._last_selected_vcpu: str | None = None
        self._hw_bp_verified: bool = False
        self._serving = False
        self._listen_sock: socket.socket | None = None

    # ── op dispatch ─────────────────────────────────────────────────────

    def handle_op(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        """Route a parsed request to its op_<name> method."""
        if op not in OPS:
            return reply_err(
                f"unknown op: {op!r}", code="unknown_operation",
                details={"operation": op},
            )
        method = getattr(self, f"op_{op}", None)
        if method is None:
            return reply_err(
                f"op not implemented: {op!r}", code="unsupported_operation",
                details={"operation": op},
            )
        state_error = self._operation_state_error(op)
        if state_error is not None:
            code = "cr3_poisoned" if self._cr3_corrupted else "state_conflict"
            reply = reply_err(
                state_error,
                code=code,
                retryable=not self._cr3_corrupted,
                details={
                    "operation": op,
                    "state": self.run_state,
                    "allowed_operations": sorted(self._allowed_operations()),
                },
            )
            reply.update({
                "code": code,
                "state": self.run_state,
                "allowed_operations": sorted(self._allowed_operations()),
            })
            return reply
        try:
            result = method(**args)
        except TypeError as e:
            return reply_err(
                f"bad args for {op!r}: {e}", code="invalid_argument",
                details={"operation": op},
            )
        except ValueError as e:
            return reply_err(
                f"{type(e).__name__}: {e}", code="invalid_argument",
                details={"operation": op},
            )
        except TimeoutError as e:
            return reply_err(
                f"{type(e).__name__}: {e}", code="timeout", retryable=True,
                details={"operation": op},
            )
        except CR3RestoreError as e:
            return reply_err(
                f"{type(e).__name__}: {e}", code="cr3_poisoned",
                details={"operation": op, "state": self.run_state},
            )
        except Exception as e:  # noqa: BLE001 — surface any op-level failure
            return reply_err(
                f"{type(e).__name__}: {e}", code="operation_failed",
                details={"operation": op, "exception_type": type(e).__name__},
            )
        if isinstance(result, dict):
            return reply_ok(result)
        return reply_ok({"value": result})

    def _allowed_operations(self) -> frozenset[str]:
        """Return the operation set that is safe in the current state."""
        if self._cr3_corrupted:
            return self._POISONED_OPS
        if self.run_state == "halted" and self.stop is not None:
            return OPS
        if self.run_state == "running":
            return self._RUNNING_OPS
        return self._INDETERMINATE_OPS

    def _operation_state_error(self, op: str) -> str | None:
        if op in self._allowed_operations():
            return None
        if self._cr3_corrupted:
            return (
                "daemon poisoned: CR3 restore previously failed; only status "
                "and poison-safe detach are allowed (the VM must not resume)"
            )
        return (
            f"operation {op!r} unavailable while target state is "
            f"{self.run_state}; use status, interrupt recovery, or detach"
        )

    # ── CR3 masquerade plumbing ─────────────────────────────────────────

    @contextmanager
    def _cr3_masquerade(self, vcpu: str, regs: bytes, *, cr3: int):
        """Context manager: enter ``cr3`` on ``vcpu``, restore on exit."""
        original_cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
        target_dtb = cr3

        try:
            mod = bytearray(regs)
            struct.pack_into("<Q", mod, _CR3_OFFSET_IN_G, target_dtb)
            resp = self.rsp._exchange(b"G" + bytes(mod).hex().encode("ascii"))
            if resp != b"OK":
                raise RuntimeError(f"G-packet (CR3 swap) rejected: {resp!r}")
            yield
        finally:
            restore = bytearray(regs)
            struct.pack_into("<Q", restore, _CR3_OFFSET_IN_G, original_cr3)
            try:
                resp = self.rsp._exchange(
                    b"G" + bytes(restore).hex().encode("ascii"),
                )
                if resp != b"OK":
                    self._cr3_corrupted = True
                    print(
                        f"[kdbg-daemon] FATAL: CR3 restore G-packet rejected "
                        f"({resp!r}); session poisoned, vCPU {vcpu} still "
                        f"holds masqueraded CR3 0x{target_dtb:x}",
                        file=sys.stderr, flush=True,
                    )
                    raise CR3RestoreError(
                        "CR3 restore failed; daemon poisoned"
                    )
            except CR3RestoreError:
                raise
            except Exception as e:  # noqa: BLE001
                self._cr3_corrupted = True
                print(
                    f"[kdbg-daemon] FATAL: CR3 restore raised {type(e).__name__}: "
                    f"{e}; session poisoned, vCPU {vcpu} still holds "
                    f"masqueraded CR3 0x{target_dtb:x}",
                    file=sys.stderr, flush=True,
                )
                raise CR3RestoreError(
                    "CR3 restore failed; daemon poisoned"
                ) from e

    def _cr3_masqueraded_call(self, vcpu: str, regs: bytes, fn):
        """Run ``fn()`` under each masquerade candidate, stop at first success."""
        last_error: RspError | None = None
        for candidate in self.target.masquerade_candidates:
            try:
                with self._cr3_masquerade(vcpu, regs, cr3=candidate):
                    return fn()
            except RspError as e:
                last_error = e
                continue
        raise last_error

    # ── status ops ──────────────────────────────────────────────────────

    def op_status(self) -> dict[str, Any]:
        resume_safe = (
            not self._cr3_corrupted
            and self.run_state == "halted"
            and self.stop is not None
        )
        result = {
            "target": {
                "pid": self.target.pid,
                "dtb": f"0x{self.target.dtb:x}",
                "name": self.target.name,
                "eprocess": f"0x{self.target.eprocess:x}",
                "create_time": (
                    f"0x{self.target.create_time:x}" if self.target.create_time else None
                ),
            },
            "bps": len(self.bps),
            "state": self.run_state,
            "halted": self.run_state == "halted" and self.stop is not None,
            "session_id": self.session_id,
            "stop_id": self.stop_id if self.run_state == "halted" else None,
            "last_stop_id": self.stop_id,
            "uptime_s": time.monotonic() - self.attach_time,
            "daemon_pid": os.getpid(),
            "cr3_poisoned": self._cr3_corrupted,
            "resume_safe": resume_safe,
            "allowed_operations": sorted(self._allowed_operations()),
            "target_liveness": self._last_target_liveness,
        }
        if self._cr3_corrupted:
            result["recovery"] = (
                "detach leaves the VM paused; restore the original CR3 "
                "manually or restore a snapshot before resuming"
            )
        elif self.run_state == "indeterminate":
            result["recovery"] = (
                "use interrupt to establish a fresh halted stop before "
                "issuing debugger operations"
            )
        if self.module_manifest is not None:
            result["auto_stage"] = self.module_manifest.summary()
        if self.breakpoint_intents is not None:
            result["breakpoint_intents"] = self.breakpoint_intents
        return result

    def op_target_status(self) -> dict[str, Any]:
        """Probe the captured process identity without rebinding a reused PID."""
        return self._probe_target_liveness()

    # ── vCPU / register helpers ─────────────────────────────────────────

    def op_regs(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError(
                f"registers unavailable while target state is {self.run_state}"
            )
        return _decode_regs(self.stop.raw_regs)

    def _require_stop_epoch(
        self, session_id: str | None = None, stop_id: int | None = None
    ) -> StopState:
        if self.run_state != "halted" or self.stop is None:
            raise RuntimeError(f"target is not halted (state={self.run_state})")
        if session_id is not None and session_id != self.session_id:
            raise RuntimeError("stale debugger session")
        if stop_id is not None and int(stop_id) != self.stop_id:
            raise RuntimeError(
                f"stale debugger stop: expected {stop_id}, current {self.stop_id}"
            )
        return self.stop

    def _pick_vcpu(self) -> str:
        """Pick the vCPU to perform a CR3 masquerade against."""
        if self.stop is not None:
            return self.stop.vcpu
        threads = self.rsp.list_threads()
        if not threads:
            raise RuntimeError("no vCPUs returned by gdbstub")
        return threads[0]

    def _select_thread(self, vcpu: str) -> None:
        """Select ``vcpu`` for Hg and keep ``_last_selected_vcpu`` in sync."""
        self.rsp.select_thread(vcpu)
        self._last_selected_vcpu = vcpu

    # ── stop capture helpers ────────────────────────────────────────────

    def _read_rip(self) -> int:
        regs = self.rsp.read_registers()
        return struct.unpack_from("<Q", regs, 16 * 8)[0]

    def _capture_stop(self, sr) -> None:
        vcpu = self._stop_vcpu(sr)
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()
        self._capture_stop_with_regs(sr, regs, vcpu=vcpu)

    def _capture_stop_with_regs(self, sr, regs: bytes, *, vcpu: str | None = None) -> None:
        """Same as _capture_stop but reuses an already-fetched regs blob."""
        if vcpu is None:
            vcpu = self._stop_vcpu(sr)
            self._select_thread(vcpu)
        self.stop = StopState(
            vcpu=vcpu,
            rip=struct.unpack_from("<Q", regs, 16 * 8)[0],
            cr3=struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0],
            signal=sr.signal,
            raw_regs=regs,
        )
        self.stop_id += 1
        self.run_state = "halted"

    def _stop_vcpu(self, sr, *, fallback: str | None = None) -> str:
        """Resolve a stop to one concrete vCPU without SMP guessing."""
        vcpu = sr.thread or fallback
        if vcpu is None:
            try:
                vcpu = self.rsp.current_thread()
            except RspError as exc:
                raise RuntimeError(
                    "stop reply omitted its vCPU and qC could not resolve it"
                ) from exc
        try:
            int(vcpu, 16)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid vCPU id in stop reply: {vcpu!r}") from exc
        return str(vcpu)

    def _begin_resume(self) -> None:
        """Invalidate stop-derived evidence before a resume packet is sent."""
        self.stop = None
        self.run_state = "running"

    def _mark_indeterminate(self) -> None:
        self.stop = None
        self.run_state = "indeterminate"

    # ── detach / cleanup ────────────────────────────────────────────────

    def op_detach(self) -> dict[str, Any]:
        """Shut down without ever resuming an unsafe or unknown state."""
        self._cleanup_breakpoints_for_shutdown()
        resume_safe = (
            not self._cr3_corrupted
            and self.run_state == "halted"
            and self.stop is not None
        )
        self._shutdown_requested = True
        result = {
            "shutting_down": True,
            "cr3_poisoned": self._cr3_corrupted,
            "resume_safe": resume_safe,
            "vm_will_resume": resume_safe,
            "vm_will_remain_paused": self._cr3_corrupted,
        }
        if self._cr3_corrupted:
            result["recovery"] = (
                "CR3 restore failed: detach will leave the VM paused; "
                "restore the original CR3 manually or restore a snapshot"
            )
        elif not resume_safe:
            result["recovery"] = (
                f"target state is {self.run_state}; automatic resume is disabled"
            )
        return result

    def _cleanup_breakpoints_for_shutdown(self) -> None:
        """Best-effort cleanup, permitted only at a proven clean halt."""
        if (
            self._cr3_corrupted
            or self.run_state != "halted"
            or self.stop is None
        ):
            return
        for bp in list(self.bps.values()):
            if self._cr3_corrupted:
                break
            with suppress(Exception):
                self._remove_bp_via_stub(bp)
        self.bps.clear()
        self._bp_by_va.clear()

    # ── target resolution ───────────────────────────────────────────────

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
