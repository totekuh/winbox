"""kdbg session daemon — holds a live gdb connection and serves ops.

Lifecycle:

    parent (winbox kdbg attach <pid>)
      ├─ pipe()
      ├─ fork()
      │    parent: read 1 status line from pipe; print, exit
      │    child : detach (setsid, close fds), become daemon ⤵
      ├─ fcntl LOCK_EX on ~/.winbox/kdbg.lock
      │    on fail -> write "ERR: another session active" to pipe, exit
      ├─ open RspClient to gdbstub
      ├─ load SymbolStore, look up target dtb
      ├─ bind ~/.winbox/kdbg.sock, listen
      ├─ install signal handlers (TERM/INT/USR1)
      ├─ write "OK" to pipe, close it
      └─ serve_forever()

The lock is the source of truth for "is a session live?" — fcntl
LOCK_EX is automatically released by the kernel on process death, so
stale-lock recovery is free. The .session.json file is for
introspection only (CLI clients can read it before connecting).

Single-threaded serve loop: one op at a time. A long-running op
(``cont``) pumps the listen socket itself while it waits (see
``_wait_for_stop_serving``), so clients are still answered: heavy ops
get an immediate ``BUSY`` reply and the lightweight ops (``status``,
``interrupt``) are executed for real. That pump is what lets
``winbox kdbg interrupt`` break an in-flight ``cont`` — the accept()
in ``serve`` is unreachable for the whole duration of the op, so
without it a second client just sits in the listen backlog until its
own socket timeout fires.

SIGUSR1 sets the same interrupt-pending flag and is kept as a
last-resort path for an operator holding only the daemon pid; nothing
in winbox sends it.
"""

from __future__ import annotations

import fcntl
import json
import os
import select
import secrets
import signal
import socket
import struct
import sys
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg import SymbolStore, SymbolStoreError
from winbox.kdbg.debugger.install import (
    InstallError,
    install_user_breakpoint,
    _CR3_OFFSET_IN_G,  # for read-via-CR3-masquerade memory reads
)
from winbox.kdbg.debugger.predicate import (
    CaptureRead,
    CaptureValue,
    PredicateRuntimeError,
    PredicateSyntaxError,
    parse as parse_predicate,
)
from winbox.kdbg.debugger.protocol import (
    OPS,
    ProtocolError,
    decode,
    encode,
    read_line,
    reply_err,
    reply_ok,
)
from winbox.kdbg.debugger.rsp import RspClient, RspError
from winbox.kdbg.debugger.trace import (
    MAX_SUMMARY_TOP,
    MAX_TRACE_RESULTS,
    query_trace,
)
from winbox.kdbg.staging import UserModuleManifest


# ── Filesystem layout ───────────────────────────────────────────────────


def _runtime_dir(cfg: Config) -> Path:
    """Where lock/sock/session/log live. Reuses cfg's root for portability."""
    p = cfg.root_dir if hasattr(cfg, "root_dir") else cfg.winbox_dir
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    return p


def lock_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg.lock"


def sock_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg.sock"


def session_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg.session.json"


def log_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg.log"


# ── Session state ───────────────────────────────────────────────────────

MAX_BREAKPOINT_ACTIONS = 16
MAX_CAPTURE_BYTES_PER_HIT = 1024
MAX_CAPTURE_BYTES_PER_TRACE = 16 * 1024 * 1024


@dataclass
class Breakpoint:
    """One installed bp tracked by the daemon."""

    bp_id: int
    va: int
    target: str           # the user-supplied "module!sym" or hex string
    user_mode: bool       # True if VA is in user-half of address space
    hw: bool              # True if installed via Z1 (hardware DR), False if Z0 (software 0xCC)
    installed_at: float   # monotonic timestamp
    installed_cr3: int = 0   # CR3 used by install_user_breakpoint; 0 = not applicable
    hits: int = 0
    # Conditional-bp state. ``condition`` is the raw user string for
    # display; ``_predicate`` is the parsed AST evaluated on each fire
    # (None means unconditional — original behaviour). Counters track
    # how the predicate decided each in-target fire.
    wp_type: str | None = None  # None = exec bp; "write"/"read"/"access" = watchpoint
    wp_size: int = 0            # watched region size (1/2/4/8); 0 for exec bps
    condition: str | None = None
    _predicate: Any = field(default=None, repr=False)
    predicate_hits: int = 0
    predicate_skips: int = 0
    predicate_errors: int = 0
    predicate_read_errors: int = 0
    actions: list = field(default_factory=list)
    _action_asts: list = field(default_factory=list, repr=False)
    trace_count: int = 0
    trace_path: str = ""
    capture_bytes_per_hit: int = 0
    capture_bytes: int = 0
    capture_limit_reached: bool = False


@dataclass
class StopState:
    """Latest debugger halt info (returned by ops that need it)."""

    vcpu: str             # gdb thread id, e.g. "01"
    rip: int
    cr3: int
    signal: int
    raw_regs: bytes       # full g-packet blob — kept so re-reads are cheap


def masquerade_cr3_candidates(dtb: int, user_dtb: int) -> tuple[int, ...]:
    """CR3 values safe to *write* into a vCPU for masquerade reads/writes.

    The single source of truth for this rule — used by ``TargetInfo``, the
    ``kdbg_user_bp`` CLI, and ``install_user_breakpoint``. Keep it one function:
    the invariant is safety-critical (never actively write a *guessed* CR3), so
    it must not drift between call sites.

    Unlike ``cr3_set``, this never includes the ``dtb ^ 0x1000`` guess.
    ``cr3_set`` only ever compares against a CR3 QEMU already reports (a passive
    membership check — a wrong guess just fails to match). Masquerade actively
    writes a candidate into CR3 and walks page tables through it; a wrong guess
    there could resolve to some *other* valid-looking physical page and silently
    read, write, or patch the wrong process's memory instead of failing cleanly.

    So: only ``dtb`` when ``user_dtb`` is unknown (0), or both when ``user_dtb``
    was actually read from ``KPROCESS`` — and never the same value twice (a build
    that reports ``user_dtb == dtb`` must not double the RSP round-trips or list
    the same CR3 twice in an exhausted-candidates error).
    """
    if user_dtb and user_dtb != dtb:
        return (dtb, user_dtb)
    return (dtb,)


@dataclass
class TargetInfo:
    pid: int
    dtb: int
    name: str
    user_dtb: int = 0  # KPROCESS.UserDirectoryTableBase if present (KVA
                       # Shadow / KPTI builds). 0 means "field absent or
                       # read failed; we only know one CR3".
    eprocess: int = 0  # VA of the EPROCESS struct (for PEB.Ldr walks)

    @property
    def cr3_set(self) -> tuple[int, ...]:
        """All CR3 values that mean "this is our target".

        On KVA Shadow / KPTI builds Windows keeps two separate PML4
        physical pages per process — one mapped during user-mode
        execution, one during kernel-mode. ``KPROCESS.DirectoryTableBase``
        and ``KPROCESS.UserDirectoryTableBase`` point at them. The
        names are historically ambiguous about which is which (the
        ``install.py`` comment hedges and field semantics have shifted
        across builds), so we don't try to label them — we just accept
        either as "in target".

        Fallback: if ``user_dtb == 0`` (pre-KPTI struct or read
        failed), assume the kernel/user pair is allocator-adjacent
        and accept ``dtb ^ 0x1000`` too. This is empirical
        (nt!MmAllocateContiguousPages tends to allocate them
        consecutively) — not a documented contract — but it's a
        better fallback than single-CR3 filtering. ``^`` not ``|``
        because some processes' DirectoryTableBase already has bit
        12 set, in which case ``|`` is a no-op (the bug we're
        fixing).
        """
        if self.user_dtb:
            return (self.dtb, self.user_dtb)
        return (self.dtb, self.dtb ^ 0x1000)

    @property
    def directory_table_base(self) -> int:
        return self.dtb

    @property
    def user_directory_table_base(self) -> int:
        return self.user_dtb

    @property
    def masquerade_candidates(self) -> tuple[int, ...]:
        """CR3 values safe to *write* into a vCPU for masquerade reads/writes.

        Thin accessor over the shared rule — see ``masquerade_cr3_candidates``.
        """
        return masquerade_cr3_candidates(self.dtb, self.user_dtb)


# ── Daemon process ──────────────────────────────────────────────────────


class DaemonError(RuntimeError):
    pass


class CR3RestoreError(RuntimeError):
    """Raised when restoring the firing vCPU's CR3 via G-packet fails.

    This is a session-poisoning event. After it fires, the daemon
    cannot safely resume the VM (resuming with a masqueraded CR3 is
    a guaranteed BSOD), so the session goes into a hard-locked state
    where every subsequent op refuses to touch the gdbstub.
    """


class _MemoryReadNeeded(BaseException):
    """Internal probe signal: expression evaluation reached its first read.

    This deliberately derives from ``BaseException`` so the predicate AST and
    per-action error isolation (both of which catch ``Exception``) cannot turn
    the signal into a user-visible predicate/action error.  The batched
    evaluator catches it immediately and re-runs the pure expression while a
    CR3 masquerade is active.
    """


class _CandidateReadFailed(BaseException):
    """Internal signal that one CR3 candidate could not map a read."""

    def __init__(self, error: RspError) -> None:
        self.error = error


class DaemonSession:
    """Long-lived debugger session. One target, one gdb connection."""

    # Public for tests; tests can subclass to inject FakeRsp.
    BUSY_REPLY = reply_err("BUSY: another op in progress")
    SHUTDOWN_REPLY = reply_err("daemon shutting down")

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

        self.bps: dict[int, Breakpoint] = {}
        # va -> bp_id index for O(1) lookup on the cont/predicate hot
        # path. Populated/cleaned in op_bp_add / op_bp_remove. If two
        # bps share a VA (shouldn't happen in normal use) only the
        # latest is indexed; the others still appear in self.bps.
        self._bp_by_va: dict[int, int] = {}
        self._next_bp_id = 0
        self.stop: StopState | None = None
        self.session_id = secrets.token_hex(16)
        self.stop_id = 0
        self.run_state = "indeterminate"
        self.attach_time = time.monotonic()

        # Set when an op accesses gdb so other ops can detect "in flight".
        self._busy = False

        # Set by signal handler when SIGUSR1 arrives — a hint to the cont
        # loop to break out.
        self._interrupt_pending = False

        # Set when a CR3-masquerade restore G-packet fails. Once true,
        # the daemon refuses every subsequent op that would touch the
        # gdbstub — resuming with a masqueraded CR3 instant-BSODs the
        # guest. Only path out is process restart (the _CR3Masquerade
        # context manager sets this on restore failure).
        self._cr3_corrupted = False

        # Last vCPU we sent Hg for. Cache to skip redundant select_thread
        # calls in the cont hot path; reset on shutdown / detach.
        self._last_selected_vcpu: str | None = None

        # Item #30: one-time hw breakpoint verification probe.
        # Set True after the first hw bp in the session triggers a probe
        # (or after probing is skipped). Prevents repeated probes.
        self._hw_bp_verified: bool = False

        self._serving = False
        self._listen_sock: socket.socket | None = None

    # ── op dispatch ─────────────────────────────────────────────────────

    def handle_op(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        """Route a parsed request to its op_<name> method."""
        if op not in OPS:
            return reply_err(f"unknown op: {op!r}")
        method = getattr(self, f"op_{op}", None)
        if method is None:
            return reply_err(f"op not implemented: {op!r}")
        # If a previous CR3 masquerade left the firing vCPU's CR3 in
        # an unrestored state, refuse anything that could resume the
        # guest or talk to the gdbstub. Status/interrupt are safe-ish
        # but we lock them out too — the operator should detach + restart.
        if self._cr3_corrupted and op != "status":
            return reply_err(
                "daemon poisoned: CR3 restore previously failed; "
                "detach and restart the kdbg session"
            )
        try:
            result = method(**args)
        except TypeError as e:
            return reply_err(f"bad args for {op!r}: {e}")
        except Exception as e:  # noqa: BLE001 — surface any op-level failure
            return reply_err(f"{type(e).__name__}: {e}")
        if isinstance(result, dict):
            return reply_ok(result)
        return reply_ok({"value": result})

    # ── CR3 masquerade plumbing ─────────────────────────────────────────

    @contextmanager
    def _cr3_masquerade(self, vcpu: str, regs: bytes, *, cr3: int):
        """Context manager: enter ``cr3`` on ``vcpu``, restore on exit.

        Centralises the four-step dance that op_mem / op_write_mem /
        _mem_qword_reader all used to repeat with a ``with suppress(Exception)``
        on the restore. Suppressing the restore failure was a silent BSOD
        bomb — if we leave a masqueraded CR3 in the firing vCPU's register
        file and resume, the vCPU runs kernel code with the wrong page
        tables.

        On restore failure: set ``self._cr3_corrupted`` so every
        subsequent op short-circuits with a clear error, log to stderr,
        and re-raise as ``CR3RestoreError``. Caller's ``finally`` then
        propagates instead of silently swallowing.

        ``vcpu`` must already be selected via ``rsp.select_thread``.
        ``regs`` is the full g-packet blob captured before masquerade
        (used to extract original CR3 and as the template for restore).
        ``cr3`` is the value to masquerade as — callers that need to try
        more than one candidate (see ``_cr3_masqueraded_call``) enter
        this context once per candidate rather than this context picking
        one itself.
        """
        original_cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
        target_dtb = cr3

        # Swap in target_dtb INSIDE the try so the finally always attempts
        # a restore. If the swap _exchange writes the G-packet (CR3 applied
        # in QEMU) but then the reply read fails, we must still put the
        # original CR3 back — otherwise the vCPU resumes kernel code under
        # target's page tables and BSODs. Mirrors _read_target_bytes.
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
                # Network/protocol error during restore — same poison state.
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
        """Run ``fn()`` under each of ``self.target.masquerade_candidates``
        in turn, stopping at the first that doesn't raise ``RspError``.

        On builds with a verified ``user_dtb``, the captured ``dtb`` may
        be the wrong CR3 half for a given VA (KVA-Shadow/KPTI splits
        user/kernel page tables). A single-candidate target (``user_dtb``
        unknown) behaves exactly as before — one attempt, no retry.

        Only ``RspError`` from ``fn()`` triggers a retry — that's the
        gdbstub telling us the VA didn't map under this CR3. A
        ``RuntimeError`` from ``_cr3_masquerade`` itself (G-swap
        rejected) or a ``CR3RestoreError`` (restore failed, session
        poisoned) propagate immediately: neither is "wrong CR3 half",
        and retrying against another candidate wouldn't fix either.
        """
        last_error: RspError | None = None
        for candidate in self.target.masquerade_candidates:
            try:
                with self._cr3_masquerade(vcpu, regs, cr3=candidate):
                    return fn()
            except RspError as e:
                last_error = e
                continue
        raise last_error

    # ── ops ─────────────────────────────────────────────────────────────

    def op_status(self) -> dict[str, Any]:
        result = {
            "target": {
                "pid": self.target.pid,
                "dtb": f"0x{self.target.dtb:x}",
                "name": self.target.name,
            },
            "bps": len(self.bps),
            "state": self.run_state,
            "halted": self.run_state == "halted" and self.stop is not None,
            "session_id": self.session_id,
            "stop_id": self.stop_id if self.run_state == "halted" else None,
            "last_stop_id": self.stop_id,
            "uptime_s": time.monotonic() - self.attach_time,
            "daemon_pid": os.getpid(),
        }
        if self.module_manifest is not None:
            result["auto_stage"] = self.module_manifest.summary()
        return result

    _VALID_WP_TYPES = frozenset({"write", "read", "access"})
    _VALID_WP_SIZES = frozenset({1, 2, 4, 8})

    def op_bp_add(
        self,
        target: str,
        mode: str = "hw",
        condition: str | None = None,
        wp_type: str | None = None,
        wp_size: int = 1,
        actions: list | None = None,
    ) -> dict[str, Any]:
        """Install a breakpoint or watchpoint at sym/VA.

        ``mode`` selects the execution-bp mechanism (``"hw"`` or
        ``"soft"``). Ignored when ``wp_type`` is set.

        ``actions`` is a list of expression strings (same grammar as
        ``condition``). On each in-target fire that passes the predicate,
        every expression is evaluated and the results are appended to a
        trace file. The bp auto-continues instead of halting — turning it
        into a lightweight tracer. Use ``bp_trace`` to read the log.

        ``wp_type`` installs a watchpoint instead of an execution bp:
        ``"write"`` (Z2), ``"read"`` (Z3), ``"access"`` (Z4). Uses a
        hardware debug register — shares the 4-slot DR0..3 pool with
        hw execution breakpoints.

        ``wp_size`` is the watched region in bytes (1/2/4/8). Only
        meaningful for watchpoints; ignored for execution bps.
        """
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

        va = self._resolve_target(target)
        is_user = (va >> 47) != 0x1FFFF

        # Breakpoint ids restart at zero with every daemon session, while the
        # runtime directory persists.  Reusing bp0.trace.jsonl without
        # truncating it mixes old-session entries into the new trace and makes
        # ``total`` disagree with ``trace_count``.  Initialise the file before
        # touching the gdbstub: a permissions/disk error then cannot leave an
        # installed breakpoint that was never added to ``self.bps``.
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

        # ── Execution breakpoint path (unchanged) ─────────────────────
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
        """Send the z-packet that clears ``bp`` from the gdbstub.

        Route by how the bp was installed:

        * User-mode *software* bp — was patched into target's physical
          page under a CR3 masquerade (``install_user_breakpoint``). QEMU's
          z0 removal re-translates ``bp.va`` through the *currently
          selected* vCPU's CR3, which after a kernel-side stop is NOT
          target's. Without re-masquerading, QEMU restores the saved byte
          in the wrong address space and leaves target's 0xCC in place — an
          INT3 with no debugger attached once the guest resumes. Remove
          under the same masquerade dance (and candidate retry) used to
          install.
        * Kernel-mode software bp — kernel pages are present in every CR3,
          so a plain z0 translates correctly regardless of current CR3.
        * Hardware bp — z1 clears a DR match; no VA translation happens,
          so no masquerade is needed.

        Raises ``RspError`` (removal rejected under every candidate CR3)
        or ``CR3RestoreError`` (restore failed, session poisoned) — same
        contract as the memory-op masquerade path.
        """
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
            # Route to the right packet (z0 vs z1) based on how it was
            # installed; user-mode soft bps re-enter the CR3 masquerade so
            # QEMU clears the byte in target's address space, not the
            # current vCPU's. Mismatching is a no-op or error in QEMU.
            self._remove_bp_via_stub(bp)
        except RspError as e:
            # Don't drop from registry on failure. If the z-packet
            # didn't actually clear the bp in QEMU, untracking it
            # locally would leave a phantom: future fires would hit
            # the linear-scan fallback in op_cont with no predicate
            # context, and the user would have no way to retry the
            # removal. Surface the error and keep both entries in
            # place so a subsequent bp_remove can try again.
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

    def op_cont(self, timeout: float = 30.0) -> dict[str, Any]:
        """Resume; block until next stop in any of target's CR3s.
        Silent-cont everything else (typical when a bp hit is in
        shared code that another process tripped).

        Under KVA Shadow each process has two CR3 values (user-mode
        and kernel-mode PML4s); a bp set in driver code fires with
        the kernel one loaded. ``target.cr3_set`` returns both when
        ``KPROCESS.UserDirectoryTableBase`` was readable at attach,
        else falls back to ``(dtb, dtb ^ 0x1000)``.
        """
        accepted_cr3s = self.target.cr3_set
        _cont_start = time.monotonic()
        deadline = _cont_start + max(0.5, float(timeout))
        # Drop a flag left over from an interrupt issued while nothing was
        # running — honouring it would make this cont return immediately
        # without ever resuming the guest. An interrupt that arrives *during*
        # this cont is delivered by the pump in _wait_for_stop_serving and
        # consumed below, so it is no longer at risk of being swallowed here.
        self._interrupt_pending = False
        while True:
            if self._interrupt_pending:
                # User-asked interrupt during cont — break out.
                self.rsp.interrupt()
                sr = self.rsp.wait_for_stop(timeout=2.0)
                self._capture_stop(sr)
                result = {"reason": "interrupt", **self._stop_summary()}
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result = {"reason": "timeout"}
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
                    # Wall-clock budget exhausted in wait_for_stop —
                    # interrupt the running VM so we end in a halted
                    # state and return cleanly.
                    try:
                        self.rsp.interrupt()
                        sr = self.rsp.wait_for_stop(timeout=2.0)
                        self._capture_stop(sr)
                    except RspError:
                        self._mark_indeterminate()
                    result = {"reason": "timeout", **self._stop_summary()}
                    result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                    return result
                self._mark_indeterminate()
                raise RuntimeError(f"cont/wait failed: {e}") from e

            if self._interrupt_pending:
                # An interrupt was served mid-wait and its \x03 is what
                # halted us (QEMU reports SIGINT, not SIGTRAP). Consume the
                # flag here so it can't leak into the next cont, and label
                # the stop for what the operator asked for.
                self._interrupt_pending = False
                self._capture_stop(sr)
                result = {"reason": "interrupt", **self._stop_summary()}
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result

            if sr.signal != 5:
                # Not a bp — surface anyway, caller decides.
                self._capture_stop(sr)
                result = {"reason": "signal", **self._stop_summary()}
                result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
                return result

            # ONE g-packet per fire — extract cr3 + rip from the same
            # blob. The previous shape (select_thread, read_cr3,
            # optional _read_rip, then read_registers) was three to four
            # RSP round-trips per silent-cont iteration, which made
            # high-frequency conditional bps (an EDR IOCTL dispatcher
            # firing thousands of times per second) starve the VM —
            # most of the wall-clock was spent on RSP traffic, the
            # guest barely advanced between halts.
            #
            # Skip the Hg if the firing vCPU is the one we already
            # selected last iteration. On -smp 1 (default) this elides
            # an entire round-trip per fire.
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
                continue

            # Predicate gate. Reuse the regs blob we already read so
            # the per-fire cost stays at one g-packet plus any mem
            # derefs the predicate explicitly triggers.
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
                continue

            result = {"reason": "bp", **self._stop_summary()}
            result.update(self._unfired_hw_bp_warnings(time.monotonic() - _cont_start))
            return result

    def op_step(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        vcpu = self.stop.vcpu
        # QEMU checks an execution hardware breakpoint before executing the
        # instruction.  Leaving Z1 installed while issuing vCont;s therefore
        # traps at the same RIP forever.  Suspend only the exact firing exec
        # breakpoint; watchpoints and software INT3 handling have different
        # semantics and are not affected by this pre-execution retrigger.
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
                # Do not advertise a breakpoint that is no longer installed.
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
            # A failed exchange does not tell us whether QEMU accepted the
            # resume packet.  Do not issue another breakpoint command against
            # a possibly-running stub or claim the removed breakpoint exists.
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
            # Step didn't complete in the budget. The stub may still owe
            # us a stop reply (single-step trap pending in QEMU), or be
            # genuinely hung. Force a halt to drag the stub back into a
            # known state, drain whatever it sends, and surface a clear
            # error so the next op runs against a consistent stub
            # instead of indeterminate state.
            recovered = False
            try:
                self.rsp.interrupt()
                sr_recovery = self.rsp.wait_for_stop(timeout=2.0)
                self._capture_stop(sr_recovery)
            except Exception:
                # Recovery interrupt+wait also failed → genuine hang.
                forget_suspended_bp()
                self._mark_indeterminate()
            else:
                # The target is definitely halted, so breakpoint restoration
                # is safe.  Its helper drops bookkeeping if reinsertion fails.
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
            # We received a stop reply, but cannot safely expose evidence from
            # a half-captured stop.  Best-effort restore while QEMU is halted;
            # regardless of that outcome, mark the debugger state unknown.
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
        """Step over a call/syscall: temp bp at next instruction, cont, remove.

        If the current instruction is not a call/syscall, falls back to a
        regular single-step. Uses a hardware breakpoint for the temp bp
        (PatchGuard-safe); fails if all 4 DR slots are taken.
        """
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
        """Step out of the current function: temp bp at return address, cont.

        Reads [rsp] to get the return address, plants a temp hw bp there,
        and continues until it fires. Requires a free DR slot.
        """
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

    def op_interrupt(self) -> dict[str, Any]:
        """Halt a running VM via raw ``\\x03`` on the RSP socket, in
        addition to setting the cooperative interrupt-pending flag.

        ``op_interrupt`` is a lightweight op (bypasses ``_busy``), so it
        runs on a separate connection while ``op_cont`` is blocked in
        ``wait_for_stop`` on a different connection — that connection is
        accepted by ``_pump_client`` from inside the cont wait, since the
        serve loop's own accept() is unreachable until the op finishes.
        The flag alone is
        only checked at the top of each cont-loop iteration — a stuck
        cont that isn't firing bps wouldn't notice for the full 30s
        default timeout. Sending ``\\x03`` directly punts a stop reply
        onto the wire so ``wait_for_stop`` returns promptly.

        Sockets are full-duplex; ``rsp.interrupt`` only writes (no read,
        no rsp-state mutation) so it's safe to call concurrently with
        a cont-loop's read on the same RspClient.
        """
        self._interrupt_pending = True
        # Best-effort — if the rsp socket is dead the cont loop is
        # already going to surface its own error. Don't double-fault.
        with suppress(RspError, OSError):
            self.rsp.interrupt()
        return {"queued": True}

    def op_regs(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError(
                f"registers unavailable while target state is {self.run_state}"
            )
        return _decode_regs(self.stop.raw_regs)

    def _require_stop_epoch(
        self, session_id: str | None = None, stop_id: int | None = None
    ) -> StopState:
        # Test/custom embedders historically seed ``stop`` directly. Treat
        # that as the initial halted state; resume paths always clear it.
        if self.run_state == "indeterminate" and self.stop is not None:
            self.run_state = "halted"
        if (
            self.run_state == "indeterminate"
            and self.stop is None
            and session_id is None
            and stop_id is None
        ):
            # Backward-compatible unpinned memory access before the daemon's
            # initial stop has been recorded. Epoch-pinned callers never use
            # this path.
            return None  # type: ignore[return-value]
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
        """Pick the vCPU to perform a CR3 masquerade against.

        Prefer the firing vCPU recorded in ``self.stop`` — that's the
        one whose register file the bp/step machinery is already
        manipulating, and using a different vCPU here would mean
        masquerading CR3 on a thread that may be running guest code
        and crash it on resume.

        Fall back to the first thread the gdbstub reports if no stop
        is recorded (typically only on the first op after attach,
        before any cont/step has captured a stop).
        """
        if self.stop is not None:
            return self.stop.vcpu
        threads = self.rsp.list_threads()
        if not threads:
            raise RuntimeError("no vCPUs returned by gdbstub")
        return threads[0]

    def _select_thread(self, vcpu: str) -> None:
        """Select ``vcpu`` for Hg and keep ``_last_selected_vcpu`` in sync.

        The cont hot path (``op_cont``) skips a redundant ``select_thread``
        when the firing vCPU already matches this cache. That is only safe
        if the cache is the single source of truth for the stub's current
        Hg selection — so EVERY select must route through here (op_step,
        op_mem, op_write_mem, _capture_stop*, bp_remove), or op_cont would
        read the wrong vCPU's g-packet on an SMP guest. Selection made by
        code we don't own (install_user_breakpoint) invalidates the cache
        to None at its call site instead.
        """
        self.rsp.select_thread(vcpu)
        self._last_selected_vcpu = vcpu

    def op_mem(
        self,
        va: int | str,
        length: int = 64,
        session_id: str | None = None,
        stop_id: int | None = None,
    ) -> dict[str, Any]:
        """Read `length` bytes at `va` in target's CR3. Uses the same
        CR3-masquerade trick as bp install: temporarily writes target
        DTB into the firing vCPU's CR3 register, reads via gdb `m`,
        restores. Way faster than HMP page walks (~1ms vs ~40ms)."""
        self._require_stop_epoch(session_id, stop_id)
        if isinstance(va, str):
            va = int(va, 0)
        length = max(0, min(int(length), 64 * 1024))
        if length == 0:
            return {"va": f"0x{va:x}", "bytes": ""}

        # Pick the firing vCPU (or fall back to threads[0] pre-stop)
        # and snapshot its CR3 via the masquerade context.
        vcpu = self._pick_vcpu()
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()

        if self.stop is not None and self.stop.cr3 in self.target.cr3_set:
            # At an in-target stop the selected CPU already owns the exact
            # live address space.  Besides avoiding two full G packets, this
            # is required for WoW64 compatibility-mode stops: rewriting an
            # otherwise-identical x86-64 register blob through QEMU's G
            # handler can lose hidden segment/mode state and make subsequent
            # virtual reads resolve against nonsense mappings.
            data = self.rsp.read_memory(va, length)
        else:
            data = self._cr3_masqueraded_call(
                vcpu, regs, lambda: self.rsp.read_memory(va, length)
            )

        return {"va": f"0x{va:x}", "bytes": data.hex()}

    def op_write_mem(self, va: int | str, data: str) -> dict[str, Any]:
        """Write hex-encoded ``data`` at ``va`` in target's address space.

        Mirror of op_mem: temporarily masquerades the firing vCPU's CR3
        as target_dtb, sends gdb ``M`` packet, restores. Use for fault
        injection, fuzzing, faking returns, etc. Capped at 64 KiB.

        Args:
            va: Virtual address in target's address space (int or hex string).
            data: Hex-encoded bytes to write (e.g. ``"deadbeef"`` writes 4 bytes).

        Returns ``{va, length}`` on success.
        """
        if isinstance(va, str):
            va = int(va, 0)
        try:
            payload = bytes.fromhex(data)
        except ValueError as e:
            raise RuntimeError(f"data must be hex-encoded: {e}") from e
        if not payload:
            return {"va": f"0x{va:x}", "length": 0}
        if len(payload) > 64 * 1024:
            raise RuntimeError(f"write capped at 64 KiB; got {len(payload)} bytes")

        vcpu = self._pick_vcpu()
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()

        # gdb ``M addr,len:hex`` writes payload bytes at addr. As with reads,
        # never rewrite the full register block at an already in-target WoW64
        # stop; QEMU can lose compatibility-mode state in its G handler.
        if self.stop is not None and self.stop.cr3 in self.target.cr3_set:
            self.rsp.write_memory(va, payload)
        else:
            self._cr3_masqueraded_call(
                vcpu, regs, lambda: self.rsp.write_memory(va, payload)
            )

        return {"va": f"0x{va:x}", "length": len(payload)}

    def op_stack(self, n: int = 16) -> dict[str, Any]:
        """N architecture-sized stack words with RSP-relative labels."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        n = max(1, min(int(n), 256))
        rsp_va = struct.unpack_from("<Q", self.stop.raw_regs, 7 * 8)[0]
        width = 4 if self._is_x86_stop() else 8
        result = self.op_mem(rsp_va, n * width)
        raw = bytes.fromhex(result["bytes"])
        stack_register = "esp" if width == 4 else "rsp"
        entries = [
            {
                "offset": f"{stack_register}+0x{i:02x}",
                "va": f"0x{rsp_va + i:x}",
                "value": f"0x{int.from_bytes(raw[i:i + width], 'little'):0{width * 2}x}",
            }
            for i in range(0, n * width, width)
        ]
        output = {
            "rsp": f"0x{rsp_va:x}",
            "sp": f"0x{rsp_va:x}",
            "stack_register": stack_register,
            "architecture": "x86" if width == 4 else "x64",
            "word_size": width,
            "entries": entries,
        }
        output["dwords" if width == 4 else "qwords"] = entries
        return output

    def op_bt(self, depth: int = 8) -> dict[str, Any]:
        """Unwind x64 PE metadata or a WoW64 x86 hybrid call chain."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        depth = max(1, min(int(depth), 64))
        return self._unwind_backtrace(depth)

    def _unwind_backtrace(
        self,
        depth: int,
        *,
        x64_context: Any | None = None,
        allow_transition: bool = True,
    ) -> dict[str, Any]:
        """Epoch-stable, bounded live-image unwind implementation."""
        if x64_context is None and self._is_x86_stop():
            return self._unwind_x86_backtrace(depth)
        from winbox.kdbg.unwind import PeX64Unwinder, UnwindError

        stop = self._require_stop_epoch()
        epoch = {"session_id": self.session_id, "stop_id": self.stop_id}
        if x64_context is None:
            registers = {
                name: struct.unpack_from("<Q", stop.raw_regs, index * 8)[0]
                for index, name in enumerate(_GPR_NAMES)
            }
            rip = stop.rip
            rsp = registers["rsp"]
        else:
            registers = dict(x64_context.registers)
            rip = int(x64_context.rip)
            rsp = int(x64_context.rsp)
        initial_rsp = rsp

        # Read through a page cache so a typical frame costs no more than one
        # live read for xdata and one for its stack page.  Every underlying
        # read is stop-epoch pinned.
        pages: dict[int, bytes] = {}

        def live_read(va: int, length: int) -> bytes:
            if length < 0 or length > 16 * 1024 * 1024:
                raise UnwindError(f"live unwind read out of bounds: {length}")
            output = bytearray()
            while length:
                page = va & ~0xFFF
                offset = va - page
                take = min(length, 0x1000 - offset)
                if page not in pages:
                    pages[page] = bytes.fromhex(
                        self.op_mem(page, 0x1000, **epoch)["bytes"]
                    )
                chunk = pages[page][offset:offset + take]
                if len(chunk) != take:
                    raise UnwindError(f"short live page at 0x{page:x}")
                output.extend(chunk)
                va += take
                length -= take
            return bytes(output)

        def verified_static_reader(module):
            """Use a cached PE only after matching it to the live image."""
            from winbox.kdbg.decomp.identity import (
                IdentityError,
                parse_live_pe,
                parse_static_pe,
                sha256_file,
                validate_identity,
            )

            if self.module_manifest is not None:
                manifest_entry = self.module_manifest.by_base(
                    module.base, getattr(module, "architecture", "x64"),
                )
                if manifest_entry is None:
                    raise UnwindError(
                        f"{module.name} has no exact attach-manifest artifact"
                    )
                raw_path = manifest_entry.pe_path
                expected_sha = manifest_entry.pe_sha256
                artifact_source = "attach-manifest"
            else:
                stem = str(module.name).rsplit(".", 1)[0].lower()
                if stem.startswith("ntoskrnl") or stem.startswith("ntkrnl"):
                    store_name = "nt"
                else:
                    store_name = stem
                    if getattr(module, "architecture", "x64") == "x86":
                        store_name += "_x86"
                record = self.store.load(store_name)
                raw_path = record.get("pe_path")
                expected_sha = record.get("pe_sha256")
                artifact_source = "symbol-store"
            if not raw_path or not expected_sha:
                raise UnwindError(
                    f"live unwind metadata is unavailable and {module.name} "
                    "has no hash-bound exact PE"
                )
            path = Path(raw_path).resolve(strict=True)
            digest = sha256_file(path)
            if digest.lower() != str(expected_sha).lower():
                raise UnwindError(f"cached PE hash mismatch for {module.name}")
            static = parse_static_pe(path)
            identity_warning = None
            try:
                live = parse_live_pe(live_read, module.base)
            except IdentityError as exc:
                # Windows may decommit the page containing the RSDS record
                # along with other discardable image data.  Header identity
                # (machine, timestamp, SizeOfImage) remains independently
                # verifiable and still fails closed on any mismatch.
                live = parse_live_pe(live_read, module.base, include_pdb=False)
                identity_warning = f"live CodeView unavailable: {exc}"
            confidence = validate_identity(
                live, static, module_name=module.name,
                live_module_size=module.size,
            )
            first_section = min(
                (section.virtual_address for section in static.sections),
                default=0x1000,
            )

            def read_static(va: int, length: int) -> bytes:
                rva = va - module.base
                if rva < 0 or length < 0 or rva + length > static.image_size:
                    raise UnwindError("static unwind read lies outside image")
                if rva < first_section:
                    if rva + length > first_section:
                        raise UnwindError("static unwind read crosses PE headers")
                    with path.open("rb") as handle:
                        handle.seek(rva)
                        data = handle.read(length)
                else:
                    selected = next(
                        (section for section in static.sections
                         if section.file_offset(rva) is not None),
                        None,
                    )
                    if selected is None:
                        raise UnwindError(f"RVA 0x{rva:x} has no static bytes")
                    offset = selected.file_offset(rva)
                    assert offset is not None
                    available = selected.raw_offset + selected.raw_size - offset
                    if length > available:
                        raise UnwindError("static unwind read crosses section data")
                    with path.open("rb") as handle:
                        handle.seek(offset)
                        data = handle.read(length)
                if len(data) != length:
                    raise UnwindError(f"short cached PE read: {len(data)}/{length}")
                return data

            return read_static, confidence, identity_warning, artifact_source

        try:
            # A saved user trap can only unwind through user frames. Avoid a
            # kernel loader walk here: that walk may need CR3 masquerading,
            # and QEMU cannot safely round-trip a compatibility-mode G packet.
            kernel_modules = (
                [] if x64_context is not None else [
                    (module, "kernel") for module in self._live_modules("kernel")
                ]
            )
            modules = kernel_modules + [
                (module, "user") for module in self._unwind_user_modules()
            ]
        except Exception as exc:
            return {
                "rsp": f"0x{rsp:x}", "method": "windows-x64-pdata",
                "complete": False, "error": f"module inventory failed: {exc}",
                "frames": [],
            }

        unwinders: dict[tuple[int, int], tuple[PeX64Unwinder, str]] = {}
        frames: list[dict[str, Any]] = []
        visited: set[tuple[int, int]] = set()
        error: str | None = None
        complete = False
        for frame_index in range(depth):
            if rip == 0:
                complete = True
                break
            key = (rip, rsp)
            if key in visited:
                error = "unwind loop detected"
                break
            visited.add(key)
            matches = [
                (module, kind) for module, kind in modules
                if module.base <= rip < module.base + module.size
            ]
            if not matches:
                error = f"0x{rip:x} is outside every live module"
                break
            module, kind = min(matches, key=lambda item: item[0].size)
            frame = {
                "index": frame_index,
                "addr": f"0x{rip:x}",
                "rsp": f"0x{rsp:x}",
                "sym": self._best_symbol_for_va(rip),
                "module": module.name,
                "rva": f"0x{rip - module.base:x}",
                "architecture": getattr(module, "architecture", "x64"),
            }
            frames.append(frame)
            if getattr(module, "architecture", "x64") != "x64":
                error = "x86 WoW64 stack unwinding is not supported by the x64 unwinder"
                break
            try:
                cache_key = (module.base, module.size)
                cached = unwinders.get(cache_key)
                if cached is None:
                    try:
                        unwinder = PeX64Unwinder(
                            module.base, module.size, live_read,
                        )
                        metadata_source = "live-image"
                    except (UnwindError, RuntimeError) as live_exc:
                        static_read, confidence, identity_warning, artifact_source = (
                            verified_static_reader(module)
                        )
                        unwinder = PeX64Unwinder(
                            module.base, module.size, static_read,
                        )
                        metadata_source = (
                            f"verified-static:{confidence}:{artifact_source}"
                        )
                        frame["live_metadata_error"] = str(live_exc)
                        if identity_warning:
                            frame["identity_warning"] = identity_warning
                    unwinders[cache_key] = (unwinder, metadata_source)
                else:
                    unwinder, metadata_source = cached
                step = unwinder.unwind(rip, rsp, registers, live_read)
                frame["unwind"] = "leaf" if step.leaf else "pdata"
                frame["metadata"] = metadata_source
                if step.operations:
                    frame["operations"] = list(step.operations)
            except (UnwindError, RuntimeError) as exc:
                error = f"{module.name}+0x{rip - module.base:x}: {exc}"
                break
            if step.rsp <= rsp or step.rsp - initial_rsp > 16 * 1024 * 1024:
                error = f"implausible caller RSP 0x{step.rsp:x}"
                break
            rip, rsp, registers = step.rip, step.rsp, step.registers
        else:
            complete = False
            error = f"depth limit {depth} reached"

        result: dict[str, Any] = {
            "rsp": f"0x{initial_rsp:x}",
            "method": "windows-x64-pdata",
            "complete": complete,
            "frames": frames,
        }
        if error:
            result["error"] = error
        if (
            allow_transition and self.module_manifest is not None
            and len(frames) < depth
        ):
            self._stitch_wow64_x86(
                result, depth=depth, live_read=live_read,
            )
        return result

    def _is_x86_stop(self) -> bool:
        """True for the Windows WoW64 compatibility-mode code selector."""
        if self.stop is None or len(self.stop.raw_regs) < 144:
            return False
        cs = struct.unpack_from("<I", self.stop.raw_regs, 140)[0] & 0xFFFF
        return cs == 0x23

    def _stitch_wow64_x86(
        self, result: dict[str, Any], *, depth: int, live_read,
    ) -> None:
        """Append a validated saved x86 chain at an active native bridge stop."""
        frames = result.get("frames") or []
        if not any(
            _normalize_module_name(str(frame.get("module", ""))) == "wow64cpu"
            for frame in frames
        ):
            return
        assert self.module_manifest is not None
        bridge_entries = [
            entry for entry in self.module_manifest.modules
            if entry.architecture == "x64"
            and _normalize_module_name(entry.name) == "wow64cpu"
        ]
        if len(bridge_entries) != 1:
            result["transition_error"] = (
                "attach manifest does not contain one exact x64 wow64cpu.dll"
            )
            return
        bridge = bridge_entries[0]
        try:
            from winbox.kdbg.decomp.identity import sha256_file
            from winbox.kdbg.wow64_transition import (
                Wow64TransitionError,
                derive_transition_layout,
                recover_x86_context,
            )

            path = Path(bridge.pe_path).resolve(strict=True)
            if sha256_file(path).lower() != bridge.pe_sha256.lower():
                raise Wow64TransitionError("exact wow64cpu PE hash changed after attach")
            if not bridge.store_build:
                raise Wow64TransitionError("exact wow64cpu PDB was not enriched")
            record = self.store.load_build(bridge.store_name, bridge.store_build)
            if (
                str(record.get("pe_sha256") or "").lower()
                != bridge.pe_sha256.lower()
            ):
                raise Wow64TransitionError("wow64cpu PDB record is not bound to PE")
            layout = derive_transition_layout(path, record.get("symbols") or {})
            x86_ranges = [
                (entry.base, entry.base + entry.size)
                for entry in self.module_manifest.modules
                if entry.architecture == "x86"
            ]
            context = recover_x86_context(
                layout, self._require_stop_epoch().raw_regs, live_read,
                lambda address: any(start <= address < end for start, end in x86_ranges),
            )
            remaining = depth - len(frames)
            x86_result = self._unwind_x86_context(
                context.eip, context.esp, context.ebp, context.ebx,
                remaining, live_read,
            )
            x86_frames = x86_result.get("frames") or []
            if not x86_frames:
                raise Wow64TransitionError(
                    x86_result.get("error") or "saved x86 unwind returned no frames"
                )
        except Exception as exc:
            result["transition_error"] = f"{type(exc).__name__}: {exc}"
            return

        native_error = result.pop("error", None)
        first_x86_index = len(frames)
        for frame in x86_frames:
            copied = dict(frame)
            copied["index"] = len(frames)
            if copied["index"] == first_x86_index:
                copied["boundary"] = "wow64-x64-to-x86"
            frames.append(copied)
        result["method"] = "windows-wow64-mixed"
        result["architecture"] = "mixed-x64-x86"
        result["complete"] = bool(x86_result.get("complete"))
        result["transition"] = {
            "direction": "x64-to-x86",
            "module": bridge.name,
            "build": bridge.store_build,
            "layout": layout.derivation,
            "context_source": context.source,
            "context_va": f"0x{context.context_va:x}",
            "saved_eip": f"0x{context.eip:x}",
            "saved_esp": f"0x{context.esp:x}",
            "native_frame_count": len(frames) - len(x86_frames),
            "x86_frame_count": len(x86_frames),
        }
        if native_error:
            result["native_error"] = native_error
        if x86_result.get("error"):
            result["error"] = x86_result["error"]
        if x86_result.get("candidates"):
            result["candidates"] = x86_result["candidates"]
        if x86_result.get("metadata_errors"):
            result["metadata_errors"] = x86_result["metadata_errors"]

    def _unwind_x86_backtrace(self, depth: int) -> dict[str, Any]:
        """Unwind a WoW64 stack without requiring the native kernel view."""
        stop = self._require_stop_epoch()
        epoch = {"session_id": self.session_id, "stop_id": self.stop_id}
        eip = stop.rip & 0xFFFFFFFF
        esp = struct.unpack_from("<Q", stop.raw_regs, 7 * 8)[0] & 0xFFFFFFFF
        ebp = struct.unpack_from("<Q", stop.raw_regs, 6 * 8)[0] & 0xFFFFFFFF
        ebx = struct.unpack_from("<Q", stop.raw_regs, 1 * 8)[0] & 0xFFFFFFFF
        pages: dict[int, bytes] = {}

        def live_read(va: int, length: int) -> bytes:
            if va < 0 or length < 0 or va + length > (1 << 32):
                raise RuntimeError(
                    f"x86 live read outside uint32: 0x{va:x}+0x{length:x}"
                )
            output = bytearray()
            while length:
                page = va & ~0xFFF
                offset = va - page
                take = min(length, 0x1000 - offset)
                if page not in pages:
                    pages[page] = bytes.fromhex(
                        self.op_mem(page, 0x1000, **epoch)["bytes"]
                    )
                chunk = pages[page][offset:offset + take]
                if len(chunk) != take:
                    raise RuntimeError(f"short x86 live page at 0x{page:x}")
                output.extend(chunk)
                va += take
                length -= take
            return bytes(output)

        result = self._unwind_x86_context(
            eip, esp, ebp, ebx, depth, live_read,
        )
        if self.module_manifest is not None and len(result.get("frames") or []) < depth:
            self._stitch_wow64_x64(
                result, depth=depth, live_read=live_read,
            )
        return result

    def _stitch_wow64_x64(
        self, result: dict[str, Any], *, depth: int, live_read,
    ) -> None:
        """Append the exact suspended native chain at an arbitrary x86 stop."""
        del live_read  # x86 reader is deliberately uint32-bounded
        frames = result.get("frames") or []
        assert self.module_manifest is not None
        bridge_entries = [
            entry for entry in self.module_manifest.modules
            if entry.architecture == "x64"
            and _normalize_module_name(entry.name) == "wow64cpu"
        ]
        if len(bridge_entries) != 1:
            result["transition_error"] = (
                "attach manifest does not contain one exact x64 wow64cpu.dll"
            )
            return
        bridge = bridge_entries[0]
        try:
            from winbox.kdbg.decomp.identity import sha256_file
            from winbox.kdbg.wow64_transition import (
                Wow64TransitionError,
                derive_native_trap_layout,
                derive_transition_layout,
                recover_native_trap_context,
            )

            path = Path(bridge.pe_path).resolve(strict=True)
            if sha256_file(path).lower() != bridge.pe_sha256.lower():
                raise Wow64TransitionError("exact wow64cpu PE hash changed after attach")
            if not bridge.store_build:
                raise Wow64TransitionError("exact wow64cpu PDB was not enriched")
            record = self.store.load_build(bridge.store_name, bridge.store_build)
            if (
                str(record.get("pe_sha256") or "").lower()
                != bridge.pe_sha256.lower()
            ):
                raise Wow64TransitionError("wow64cpu PDB record is not bound to PE")
            transition_layout = derive_transition_layout(
                path, record.get("symbols") or {},
            )
            trap_layout = derive_native_trap_layout(self.store.struct)
            stop = self._require_stop_epoch()
            epoch = {"session_id": self.session_id, "stop_id": self.stop_id}

            def native_read(va: int, length: int) -> bytes:
                if (
                    va < 0 or length < 0 or length > 1 << 20
                    or va + length > (1 << 64)
                ):
                    raise Wow64TransitionError(
                        f"native context read out of bounds: 0x{va:x}+0x{length:x}"
                    )
                return bytes.fromhex(
                    self.op_mem(va, length, **epoch)["bytes"]
                )

            x64_ranges = [
                (entry.base, entry.base + entry.size)
                for entry in self.module_manifest.modules
                if entry.architecture == "x64"
            ]
            context = recover_native_trap_context(
                trap_layout, stop.raw_regs, native_read,
                expected_process=self.target.eprocess,
                is_x64_code=lambda address: any(
                    start <= address < end for start, end in x64_ranges
                ),
                is_bridge_code=lambda address: (
                    bridge.base <= address < bridge.base + bridge.size
                ),
            )
            remaining = depth - len(frames)
            # The persisted first frame is the just-returned syscall stub.
            # One unwind step reaches the still-suspended RunSimulatedCode
            # frame; retain only that frame and its callers.
            native_result = self._unwind_backtrace(
                remaining + 1, x64_context=context, allow_transition=False,
            )
            recovered = native_result.get("frames") or []
            if len(recovered) < 2:
                raise Wow64TransitionError(
                    native_result.get("error")
                    or "persisted bridge unwind returned fewer than two frames"
                )
            if any(
                _normalize_module_name(str(recovered[index].get("module", "")))
                != "wow64cpu"
                for index in (0, 1)
            ):
                raise Wow64TransitionError(
                    "persisted trap does not unwind into suspended wow64cpu code"
                )
            native_frames = recovered[1:remaining + 1]
            if not native_frames:
                raise Wow64TransitionError("no suspended native frames remain")
            first_rsp = int(str(native_frames[0].get("rsp", "0")), 0)
            if not context.stack_limit <= first_rsp < context.stack_base:
                raise Wow64TransitionError(
                    "recovered native caller lies outside TEB stack"
                )
        except Exception as exc:
            result["transition_error"] = f"{type(exc).__name__}: {exc}"
            return

        x86_error = result.pop("error", None)
        first_native_index = len(frames)
        for frame in native_frames:
            copied = dict(frame)
            copied["index"] = len(frames)
            if copied["index"] == first_native_index:
                copied["boundary"] = "wow64-x86-to-x64"
            frames.append(copied)
        result["method"] = "windows-wow64-mixed"
        result["architecture"] = "mixed-x86-x64"
        result["complete"] = bool(native_result.get("complete"))
        result["transition"] = {
            "direction": "x86-to-x64",
            "module": bridge.name,
            "build": bridge.store_build,
            "layout": transition_layout.derivation,
            "context_source": context.source,
            "kpcr": f"0x{context.kpcr:x}",
            "thread": f"0x{context.thread:x}",
            "trap_frame": f"0x{context.trap_frame:x}",
            "persisted_rip": f"0x{context.rip:x}",
            "persisted_rsp": f"0x{context.rsp:x}",
            "x86_frame_count": first_native_index,
            "x64_frame_count": len(native_frames),
            "discarded_historical_frames": 1,
        }
        if x86_error:
            result["x86_error"] = x86_error
        if native_result.get("error"):
            native_error = str(native_result["error"])
            result["error"] = (
                f"depth limit {depth} reached"
                if native_error.startswith("depth limit ") else native_error
            )

    def _unwind_x86_context(
        self, eip: int, esp: int, ebp: int, ebx: int, depth: int, live_read,
    ) -> dict[str, Any]:
        """Unwind one saved x86 context through exact manifest artifacts."""
        from winbox.kdbg.x86_unwind import X86HybridUnwinder, X86Module

        sources: list[tuple[str, Any, dict[str, Any]]] = []
        if self.module_manifest is not None:
            for entry in self.module_manifest.modules:
                if entry.architecture != "x86":
                    continue
                record: dict[str, Any] = {}
                if entry.store_build:
                    try:
                        candidate = self.store.load_build(
                            entry.store_name, entry.store_build,
                        )
                        if (
                            str(candidate.get("pe_sha256") or "").lower()
                            == entry.pe_sha256.lower()
                        ):
                            record = candidate
                    except Exception:
                        pass
                sources.append((entry.store_name, entry, record))
        else:
            try:
                store_names = self.store.list_modules()
            except Exception as exc:
                return {
                    "rsp": f"0x{esp:x}", "method": "windows-x86-hybrid",
                    "complete": False, "frames": [], "candidates": [],
                    "error": f"x86 symbol inventory failed: {exc}",
                }
            from types import SimpleNamespace
            for store_name in store_names:
                try:
                    record = self.store.load(store_name)
                except Exception:
                    continue
                _, architecture = _stored_module_identity(store_name, record)
                if architecture != "x86":
                    continue
                path_value = str(record.get("pe_path") or "")
                sources.append((store_name, SimpleNamespace(
                    name=_stored_module_identity(store_name, record)[0]
                    + Path(path_value).suffix.lower(),
                    base=int(record.get("base") or 0),
                    size=int(record.get("size_of_image") or 0),
                    pe_path=path_value,
                    pe_sha256=str(record.get("pe_sha256") or ""),
                ), record))

        modules: list[X86Module] = []
        relevant_errors: list[str] = []
        for store_name, entry, record in sources:
            relevant = False
            try:
                from winbox.kdbg.decomp.identity import (
                    IdentityError,
                    parse_live_pe,
                    parse_static_pe,
                    sha256_file,
                    validate_identity,
                )
                base = int(entry.base)
                size = int(entry.size)
                relevant = base <= eip < base + size
                if (
                    base <= 0 or size <= 0 or base > 0xFFFFFFFF
                    or base + size > (1 << 32)
                ):
                    raise RuntimeError("symbol store has invalid x86 base/size")
                path_value = entry.pe_path
                expected_sha = entry.pe_sha256
                if not path_value or not expected_sha:
                    raise RuntimeError("symbol store has no hash-bound PE")
                path = Path(path_value).resolve(strict=True)
                if sha256_file(path).lower() != str(expected_sha).lower():
                    raise RuntimeError("cached PE hash mismatch")
                static = parse_static_pe(path)
                try:
                    live = parse_live_pe(live_read, base)
                except IdentityError:
                    live = parse_live_pe(live_read, base, include_pdb=False)
                display_name = str(entry.name)
                confidence = validate_identity(
                    live, static, module_name=display_name,
                    live_module_size=size,
                )
                if static.machine != 0x014C:
                    raise RuntimeError(
                        f"cached PE machine 0x{static.machine:04x} is not x86"
                    )
                raw_frames = record.get("frame_data") or ()
                frame_data = tuple(raw_frames) if isinstance(raw_frames, list) else ()
                if not isinstance(raw_frames, (list, tuple)):
                    relevant_errors.append(
                        f"{store_name}: frame_data store field is not a list"
                    )
                names = set(record.get("function_symbols") or [])
                symbols = record.get("symbols") or {}
                starts: set[int] = set()
                for name in names:
                    try:
                        value = int(symbols[name])
                    except (KeyError, TypeError, ValueError):
                        continue
                    if 0 <= value < size:
                        starts.add(value)
                modules.append(X86Module(
                    name=display_name, base=base, size=size,
                    frame_data=frame_data,
                    function_starts=tuple(sorted(starts)),
                    metadata=(
                        f"verified-pdb:{confidence}:attach-manifest"
                        if record else f"verified-pe:{confidence}:attach-manifest"
                    ) if self.module_manifest is not None else (
                        f"verified-pdb:{confidence}"
                    ),
                ))
            except Exception as exc:
                if relevant:
                    relevant_errors.append(f"{store_name}: {exc}")

        unwinder = X86HybridUnwinder(
            modules, live_read, self._best_symbol_for_va,
        )
        result = unwinder.unwind(eip, esp, ebp, ebx, depth)
        if relevant_errors:
            result["metadata_errors"] = relevant_errors[:16]
            if not result["frames"]:
                result["error"] = "; ".join(relevant_errors[:4])
        return result

    def op_context(
        self,
        disasm_count: int = 8,
        stack_qwords: int = 16,
        bt_depth: int = 8,
        memory: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return bounded, epoch-consistent evidence for the current stop."""
        stop = self._require_stop_epoch()

        def bounded(name: str, value: Any, maximum: int) -> int:
            if isinstance(value, bool):
                raise ValueError(f"{name} must be an integer")
            try:
                parsed = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not 0 <= parsed <= maximum:
                raise ValueError(f"{name} must be between 0 and {maximum}")
            return parsed

        disasm_count = bounded("disasm_count", disasm_count, 32)
        stack_qwords = bounded("stack_qwords", stack_qwords, 32)
        bt_depth = bounded("bt_depth", bt_depth, 16)
        epoch = {"session_id": self.session_id, "stop_id": self.stop_id}
        response: dict[str, Any] = {
            "schema": "winbox.kdbg-context/1",
            "state": "halted",
            "stop_epoch": epoch,
            "target": {
                "pid": self.target.pid,
                "name": self.target.name,
                "dtb": f"0x{self.target.dtb:x}",
            },
            "stop": self._stop_summary(),
            "location": {
                "va": f"0x{stop.rip:x}",
                "symbol": self._best_symbol_for_va(stop.rip),
            },
            "registers": _decode_regs(stop.raw_regs),
        }

        assembly: list[dict[str, Any]] = []
        if disasm_count:
            try:
                import capstone
                raw = bytes.fromhex(self.op_mem(
                    stop.rip, min(15 * disasm_count, 480), **epoch
                )["bytes"])
                mode = (
                    capstone.CS_MODE_32 if self._is_x86_stop()
                    else capstone.CS_MODE_64
                )
                md = capstone.Cs(capstone.CS_ARCH_X86, mode)
                md.detail = True
                for instruction in md.disasm(raw, stop.rip):
                    item = {
                        "va": f"0x{instruction.address:x}",
                        "bytes": instruction.bytes.hex(),
                        "mnemonic": instruction.mnemonic,
                        "op_str": instruction.op_str,
                    }
                    if any(group in (
                        capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP
                    ) for group in instruction.groups):
                        for operand in instruction.operands:
                            if operand.type == capstone.x86.X86_OP_IMM:
                                item["target_va"] = f"0x{operand.imm:x}"
                                symbol = self._best_symbol_for_va(operand.imm)
                                if symbol:
                                    item["target_symbol"] = symbol
                                break
                    assembly.append(item)
                    if len(assembly) >= disasm_count:
                        break
            except Exception as exc:  # evidence remains useful if one read fails
                response["assembly_error"] = str(exc)
        response["assembly"] = assembly

        rsp_va = struct.unpack_from("<Q", stop.raw_regs, 7 * 8)[0]
        stack_width = 4 if self._is_x86_stop() else 8
        scan_qwords = stack_qwords
        stack_raw = b""
        if scan_qwords:
            try:
                stack_raw = bytes.fromhex(self.op_mem(
                    rsp_va, scan_qwords * stack_width, **epoch
                )["bytes"])
            except Exception as exc:
                response["stack_error"] = str(exc)
        stack_register = "esp" if stack_width == 4 else "rsp"
        stack_entries = [
            {
                "offset": f"{stack_register}+0x{offset:02x}",
                "va": f"0x{rsp_va + offset:x}",
                "value": f"0x{int.from_bytes(stack_raw[offset:offset + stack_width], 'little'):0{stack_width * 2}x}",
            }
            for offset in range(
                0, min(len(stack_raw), stack_qwords * stack_width), stack_width
            )
        ]
        response["stack"] = {
            "rsp": f"0x{rsp_va:x}",
            "sp": f"0x{rsp_va:x}",
            "stack_register": stack_register,
            "architecture": "x86" if stack_width == 4 else "x64",
            "word_size": stack_width,
            "entries": stack_entries,
        }
        response["stack"]["dwords" if stack_width == 4 else "qwords"] = stack_entries
        response["backtrace"] = (
            self._unwind_backtrace(bt_depth) if bt_depth else {
                "rsp": f"0x{rsp_va:x}",
                "method": (
                    "windows-x86-hybrid" if self._is_x86_stop()
                    else "windows-x64-pdata"
                ),
                "complete": False, "frames": [],
            }
        )

        bps = self.op_bp_list()["bps"]
        response["breakpoints"] = {
            "total": len(bps), "truncated": len(bps) > 32, "items": bps[:32]
        }

        requests = memory or []
        if not isinstance(requests, list) or len(requests) > 4:
            raise ValueError("memory must contain at most 4 read objects")
        reads = []
        total = 0
        for request in requests:
            if not isinstance(request, dict) or set(request) - {"va", "length"}:
                raise ValueError("each memory read must contain only va and length")
            if request.get("va") in (None, ""):
                raise ValueError("each memory read requires va")
            length = bounded("memory length", request.get("length", 64), 256)
            total += length
            if total > 1024:
                raise ValueError("combined memory reads may not exceed 1024 bytes")
            reads.append(self.op_mem(
                request.get("va"), length, **epoch
            ))
        if reads:
            response["memory"] = reads
        return response

    def _unwind_user_modules(self):
        """Use the immutable attach inventory for unwind when available."""
        if self.module_manifest is None:
            return self._live_modules("user")
        from types import SimpleNamespace
        return [
            SimpleNamespace(
                name=module.name,
                base=module.base,
                size=module.size,
                full_path=module.full_path,
                entry=0,
                architecture=module.architecture,
            )
            for module in self.module_manifest.loader_modules()
        ]

    def _live_modules(self, kind: str):
        """Return one fresh loader inventory while preserving RSP state."""
        from types import SimpleNamespace
        from winbox.kdbg.debugger.reader import use_local_rsp
        from winbox.kdbg.memory import WalkCache
        from winbox.kdbg.walk import ProcessRecord, list_modules, list_user_modules

        vcpu = self._pick_vcpu()
        stop = SimpleNamespace(thread=vcpu)
        target = ProcessRecord(
            pid=self.target.pid,
            name=self.target.name,
            eprocess=self.target.eprocess,
            directory_table_base=self.target.dtb,
            user_directory_table_base=self.target.user_dtb,
        )
        walk_completed = False
        try:
            with use_local_rsp(self.cfg.vm_name, self.rsp, stop):
                cache = WalkCache()
                if kind == "kernel":
                    modules = list_modules(
                        self.cfg.vm_name, self.store, cache=cache,
                    )
                else:
                    modules = list_user_modules(
                        self.cfg.vm_name, self.store, target, cache=cache,
                    )
                walk_completed = True
                return modules
        except Exception as exc:
            if walk_completed:
                self._cr3_corrupted = True
            raise RuntimeError(f"live module walk failed: {exc}") from exc
        finally:
            self._last_selected_vcpu = None

    @staticmethod
    def _module_payload(module, *, kind: str, va: int) -> dict[str, Any]:
        payload = {
            "name": module.name,
            "base": f"0x{module.base:x}",
            "size": module.size,
            "rva": f"0x{va - module.base:x}",
            "kind": kind,
            "full_path": getattr(module, "full_path", ""),
            "loader_entry": f"0x{module.entry:x}",
            "inventory": "fresh",
        }
        if kind == "user":
            payload["architecture"] = getattr(module, "architecture", "x64")
        return payload

    def op_module_at(
        self,
        va: int | str,
        session_id: str | None = None,
        stop_id: int | None = None,
    ) -> dict[str, Any]:
        """Resolve a live VA against a fresh loader-list snapshot.

        This operation exists for the static/dynamic decompilation bridge.
        It deliberately walks the live PEB/kernel list instead of trusting
        symbol-store bases: ASLR, unload/reload, and same-named modules make a
        stale cached base unsafe. The walk borrows this daemon's already
        halted RSP connection and restores the complete selected-vCPU register
        blob before returning.
        """
        self._require_stop_epoch(session_id, stop_id)
        if isinstance(va, str):
            try:
                va = int(va, 0)
            except ValueError as exc:
                raise ValueError(f"invalid virtual address: {va!r}") from exc
        if va < 0 or va >= (1 << 64):
            raise ValueError(f"virtual address outside uint64 range: {va}")

        kind = "kernel" if (va >> 47) == 0x1FFFF else "user"
        modules = self._live_modules(kind)

        matches = [m for m in modules if m.base <= va < m.base + m.size]
        if not matches:
            raise RuntimeError(
                f"0x{va:x} is not inside any live {kind} module "
                f"({len(modules)} loader entries checked)"
            )
        # Loader mappings should not overlap. Smallest is deterministic and
        # least permissive if corrupt guest metadata says that they do.
        module = min(matches, key=lambda item: item.size)
        return self._module_payload(module, kind=kind, va=va)

    def op_decomp_snapshot(
        self,
        va: int | str | None = None,
        module: str = "",
        rva: int | str | None = None,
    ) -> dict[str, Any]:
        """Atomically bind an address and live module to one stop epoch."""
        stop = self._require_stop_epoch()
        if bool(module) != (rva is not None and rva != ""):
            raise ValueError("module and rva must be supplied together")
        if module and va not in (None, ""):
            raise ValueError("va and module+rva are mutually exclusive")
        module_payload = None
        if module:
            module = module.strip()
            if not module:
                raise ValueError("module must not be blank")
            try:
                rva_value = int(rva, 0) if isinstance(rva, str) else int(rva)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid RVA: {rva!r}") from exc
            if rva_value < 0 or rva_value >= (1 << 32):
                raise ValueError(f"RVA outside supported PE range: {rva_value}")
            wanted = module.lower()
            wanted_arch = None
            if "@" in wanted:
                wanted, _, wanted_arch = wanted.rpartition("@")
                if wanted_arch not in {"x86", "x64"}:
                    raise ValueError("module architecture must be @x86 or @x64")
            wanted_stem = wanted.rsplit(".", 1)[0]
            selected_pair = None
            kernel_name = (
                wanted == "nt" or wanted.startswith("ntoskrnl")
                or wanted.startswith("ntkrnl")
            )
            for kind in (("kernel", "user") if kernel_name else ("user", "kernel")):
                matches = []
                for candidate in self._live_modules(kind):
                    if wanted_arch and getattr(candidate, "architecture", "x64") != wanted_arch:
                        continue
                    name = str(candidate.name).lower()
                    stem = name.rsplit(".", 1)[0]
                    if name == wanted or stem == wanted_stem:
                        matches.append(candidate)
                exact = [item for item in matches if str(item.name).lower() == wanted]
                if len(exact) == 1:
                    selected_pair = (kind, exact[0])
                    break
                if len(matches) == 1:
                    selected_pair = (kind, matches[0])
                    break
                if len(matches) > 1:
                    names = ", ".join(sorted(str(item.name) for item in matches))
                    raise RuntimeError(f"ambiguous live module {module!r}: {names}")
            if selected_pair is None:
                raise RuntimeError(f"live module not found: {module!r}")
            kind, selected_module = selected_pair
            if rva_value >= selected_module.size:
                raise ValueError(
                    f"RVA 0x{rva_value:x} outside {selected_module.name} "
                    f"(size 0x{selected_module.size:x})"
                )
            runtime_va = selected_module.base + rva_value
            module_payload = self._module_payload(
                selected_module, kind=kind, va=runtime_va
            )
        else:
            runtime_va = stop.rip if va in (None, "") else va
        if isinstance(runtime_va, str):
            try:
                runtime_va = int(runtime_va, 0)
            except ValueError as exc:
                raise ValueError(f"invalid virtual address: {runtime_va!r}") from exc
        if runtime_va < 0 or runtime_va >= (1 << 64):
            raise ValueError(f"virtual address outside uint64 range: {runtime_va}")
        if module_payload is None:
            module_payload = self.op_module_at(
                runtime_va, session_id=self.session_id, stop_id=self.stop_id
            )
        return {
            "session_id": self.session_id,
            "stop_id": self.stop_id,
            "state": self.run_state,
            "runtime_va": f"0x{runtime_va:x}",
            "rip": f"0x{stop.rip:x}",
            "target": {
                "pid": self.target.pid,
                "dtb": f"0x{self.target.dtb:x}",
                "name": self.target.name,
            },
            "module": module_payload,
        }

    def op_detach(self) -> dict[str, Any]:
        """Clean shutdown. Removes bps, detaches gdb (which resumes VM),
        signals the serve loop to exit. The connection that called this
        gets the reply; the daemon then exits."""
        self._shutdown_requested = True
        return {"shutting_down": True}

    # ── helpers ─────────────────────────────────────────────────────────

    def _resolve_target(self, target: str) -> int:
        """Turn ``module!sym`` or hex VA into a numeric VA."""
        if "!" in target:
            try:
                return self.store.resolve(target)
            except SymbolStoreError as e:
                raise RuntimeError(f"symbol: {e}") from e
        try:
            return int(target, 0)
        except ValueError as e:
            raise RuntimeError(f"not a hex VA or module!sym: {target!r}") from e

    def _read_rip(self) -> int:
        regs = self.rsp.read_registers()
        return struct.unpack_from("<Q", regs, 16 * 8)[0]

    def _capture_stop(self, sr) -> None:
        vcpu = self._stop_vcpu(sr)
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()
        self._capture_stop_with_regs(sr, regs, vcpu=vcpu)

    def _capture_stop_with_regs(self, sr, regs: bytes, *, vcpu: str | None = None) -> None:
        """Same as _capture_stop but reuses an already-fetched regs blob.

        Saves a g-packet round-trip when the caller (e.g. the predicate
        gate in op_cont) has just read regs to evaluate a condition.
        """
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
        """Resolve a stop to one concrete vCPU without SMP guessing.

        QEMU normally includes ``thread:`` in a T-stop.  A legacy/minimal
        S-stop does not; for an explicitly targeted single-step its requested
        vCPU is authoritative, otherwise query ``qC``.  Every returned id is
        syntax-checked before it can reach an ``Hg`` packet.
        """
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

    def _mem_qword_reader(
        self,
        fired_regs: bytes,
        bp: "Breakpoint | None" = None,
        *,
        vcpu: str | None = None,
    ):
        """Build a closure for typed scalars and bounded raw captures.

        Unmapped VA reads return 0 (predicate composes with dangling-pointer
        cases). Transport/session errors raise PredicateRuntimeError so the
        operator knows the condition failed for infrastructure reasons, not
        because the target value is actually 0. Read errors are counted on
        the bp's ``predicate_read_errors`` field for diagnostics.
        """
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
        bp: "Breakpoint | None" = None,
        vcpu: str | None = None,
    ):
        """Evaluate expressions with all successful reads under one CR3 swap.

        ``evaluate`` receives a qword-reader callback and must keep externally
        visible side effects until after it returns.  We first run it with a
        probe reader.  Register-only expressions and runtime-short-circuited
        memory branches therefore retain the zero-RSP-round-trip fast path.

        Once a read is actually needed, the *entire* evaluation is re-run
        inside one masquerade candidate.  This naturally batches independent
        actions and dependent ``poi(poi(...))`` chains alike.  If no single
        KPTI CR3 candidate maps every address, fall back to the established
        per-read candidate selection.  That preserves correctness for mixed
        user/kernel expressions and the documented unmapped-read-as-zero
        behavior; only this exceptional path pays the old round-trip cost.
        """
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
                # Let the outer candidate loop restart the complete, pure
                # evaluation under the other verified KPTI CR3 half.
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

        # No one CR3 mapped the complete expression.  Re-evaluate with the
        # proven per-read path: each dereference may select a different CR3,
        # and a read unmapped under every candidate becomes zero.
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
        """Item #30 Part B: passive check for hw bps that never fired.

        After a cont that ran for >5 seconds, any hw bp with hits==0 is
        suspicious — it may be silently non-functional (HVCI, QEMU bugs,
        etc.). Returns a dict with an ``unfired_hw_bps`` key listing them,
        or an empty dict if there's nothing to report.
        """
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
            # primary_cr3 is whichever CR3 was loaded at thread creation
            # (KPROCESS.DirectoryTableBase). second_cr3 is the other half
            # of the KVA Shadow pair. Don't try to label which is "user"
            # vs "kernel" — semantics have drifted across builds.
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
        """Evaluate actions as one batch and append their trace entry.

        Kept as a standalone helper for direct callers/tests.  The cont hot
        path evaluates predicate + actions together via
        ``_evaluate_breakpoint_expressions`` so both share one masquerade.
        """
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

    # ── serve loop ──────────────────────────────────────────────────────

    def _rsp_fd(self) -> int | None:
        """fileno of the gdbstub socket, or None if unavailable.

        Returns None for RspClient stand-ins that hold no socket (unit
        tests), which is the signal to fall back to a plain blocking wait.
        """
        sock = getattr(self.rsp, "_sock", None)
        if sock is None:
            return None
        try:
            fd = sock.fileno()
        except (OSError, AttributeError):
            return None
        return fd if fd >= 0 else None

    def _wait_for_stop_serving(self, timeout: float):
        """``rsp.wait_for_stop`` that keeps answering daemon clients.

        WHY this exists: ``serve`` accepts one connection, runs the op to
        completion, and only then loops back to ``select``/``accept``. So
        for the whole of a ``cont`` — up to the caller's full timeout —
        nothing accepts. A concurrently-launched ``winbox kdbg interrupt``
        never gets read off the backlog, hits its own 60s socket timeout
        and tells the operator the daemon "went away" on a session that is
        perfectly healthy. The ``is_lightweight`` bypass in ``_serve_one``
        was written for a concurrency that did not exist at the transport
        layer; this is what supplies it.

        We deliberately do NOT slice the RSP read into short timeouts:
        ``_read_packet`` consumes the frame byte by byte and drops what it
        has collected when a read times out, so a stop reply straddling a
        slice boundary would desync the stream. Instead we select on both
        fds and only enter ``wait_for_stop`` once the gdbstub actually has
        bytes for us; the rest of the budget is spent serving clients.
        """
        fd = self._rsp_fd()
        listen = self._listen_sock
        if fd is None or listen is None:
            return self.rsp.wait_for_stop(timeout=timeout)

        deadline = time.monotonic() + timeout
        # Bytes already buffered by a previous read mean select would never
        # fire for them — check before ever blocking.
        while not getattr(self.rsp, "_inbuf", None):
            left = deadline - time.monotonic()
            if left <= 0:
                # Same error shape a bounded rsp read raises, so op_cont's
                # existing "timed out" handling applies unchanged.
                raise RspError("read timed out")
            try:
                ready, _, _ = select.select([fd, listen], [], [], min(left, 0.5))
            except (OSError, InterruptedError):
                # A signal landed mid-select (e.g. SIGUSR1) — re-check.
                continue
            if fd in ready:
                break
            if listen in ready:
                self._pump_client()
        return self.rsp.wait_for_stop(
            timeout=max(0.5, deadline - time.monotonic())
        )

    def _pump_client(self) -> None:
        """Accept and service one client from inside a long-running op."""
        listen = self._listen_sock
        if listen is None:
            return
        try:
            conn, _ = listen.accept()
        except OSError:
            return
        # Force the busy flag: op_cont may have been entered directly (not
        # through _serve_one), and a heavy op running reentrantly on this
        # stack would interleave RSP packets with the cont we're inside of.
        was_busy = self._busy
        self._busy = True
        try:
            # Short read budget — this is on the debugger's hot path, so a
            # client that connects and then says nothing must not stall the
            # cont for the serve loop's full 60s.
            self._serve_one(conn, read_timeout=5.0)
        finally:
            self._busy = was_busy
            with suppress(OSError):
                conn.close()

    def serve(self, listen_sock: socket.socket) -> None:
        """Single-threaded select loop. Returns when detach is requested
        or a signal asks for shutdown."""
        self._listen_sock = listen_sock
        self._serving = True
        self._shutdown_requested = False
        listen_sock.setblocking(False)

        while self._serving and not self._shutdown_requested:
            try:
                ready, _, _ = select.select([listen_sock], [], [], 0.5)
            except (OSError, InterruptedError):
                # Signal interrupted select — just loop and re-check flags.
                continue
            if not ready:
                continue
            try:
                conn, _ = listen_sock.accept()
            except OSError:
                continue
            try:
                self._serve_one(conn)
            finally:
                with suppress(OSError):
                    conn.close()

    def _serve_one(self, conn: socket.socket, *, read_timeout: float = 60.0) -> None:
        conn.settimeout(read_timeout)
        try:
            line = read_line(conn)
        except (ProtocolError, OSError) as e:
            # OSError covers the socket timeout: a client that connects and
            # sends nothing used to let socket.timeout escape all the way
            # out of serve() and kill the daemon.
            with suppress(OSError):
                conn.sendall(encode(reply_err(f"protocol: {e}")))
            return
        try:
            req = decode(line)
        except ProtocolError as e:
            with suppress(OSError):
                conn.sendall(encode(reply_err(str(e))))
            return

        op = req.get("op")
        args = req.get("args") or {}
        if not isinstance(op, str) or not isinstance(args, dict):
            with suppress(OSError):
                conn.sendall(encode(reply_err("malformed request")))
            return

        # Lightweight ops (status/interrupt) bypass the busy lock so they
        # can break out of a stuck cont — but cont can't run concurrent
        # with itself, so the guard still applies elsewhere.
        is_lightweight = op in ("status", "interrupt")
        if self._busy and not is_lightweight:
            with suppress(OSError):
                conn.sendall(encode(self.BUSY_REPLY))
            return

        if not is_lightweight:
            self._busy = True
        try:
            reply = self.handle_op(op, args)
        finally:
            if not is_lightweight:
                self._busy = False

        with suppress(OSError):
            conn.sendall(encode(reply))

    def shutdown(self) -> None:
        """Best-effort cleanup. Removes bps, resumes VM, detaches gdb,
        closes sock.

        We DO NOT use ``rsp.close()`` here — its interrupt+wait+D dance
        was designed for the case where a client may be detaching from
        a running VM, but in our daemon-shutdown context the VM is
        usually halted (caller just did cont and got a stop). In that
        state interrupt+wait double-halts QEMU's run-state machine and
        leaves the VM in ``RUN_STATE_PAUSED`` after D — virsh shows
        plain ``paused`` (not ``paused (debug)``) and ``virsh resume``
        is needed to wake it. Direct cont→D bypasses that path:

            cont        — sets QEMU's run state to RUNNING
            D detach    — gdb_continue() inside QEMU re-runs vm_start()
                          and clears the gdbstub's halt registry

        After D, QEMU sends OK (which we read or skip) and the VM
        keeps running until something else stops it.
        """
        # If a CR3 dance is currently in flight on another op, give it
        # a brief window to unwind before we touch the gdbstub. The
        # masquerade context manager restores CR3 in its finally clause,
        # so waiting on _busy avoids races where shutdown() yanks the
        # socket mid-restore (which would mark the session corrupted
        # spuriously and leave bps in QEMU we couldn't clear).
        deadline = time.monotonic() + 2.0
        while self._busy and time.monotonic() < deadline:
            time.sleep(0.02)

        # Remove bps first so the gdbstub's bp registry is clean. Pass
        # hardware=bp.hw so hardware bps installed via Z1 actually get
        # removed via z1 — sending z0 for an hw bp is a no-op in QEMU
        # and leaks DR0..3 across the detach.
        if not self._cr3_corrupted:
            for bp in list(self.bps.values()):
                # User-mode soft bps must be cleared under the CR3
                # masquerade (see _remove_bp_via_stub) or their 0xCC is
                # left in target's page. suppress() still swallows a plain
                # removal failure, but a masquerade restore failure sets
                # _cr3_corrupted, which correctly gates off the cont below.
                with suppress(Exception):
                    self._remove_bp_via_stub(bp)
        self.bps.clear()

        # Send cont to resume the VM, give QEMU time to process it,
        # then just close the socket. QEMU's CHR_EVENT_CLOSED handler
        # removes any leftover breakpoints (we already cleared ours
        # above) but does NOT halt the VM — it keeps running in
        # whatever state it was in at disconnect, which after our
        # cont() is RUN_STATE_RUNNING. No D-packet needed; D's
        # gdb_continue() was the source of the "paused after detach"
        # bug because it raced with our cont's vm_start in QEMU's
        # run-state machine.
        #
        # If _cr3_corrupted is set, the firing vCPU still holds a
        # masqueraded target CR3 in its register file; resuming with
        # vCont;c would run kernel code under the wrong page tables
        # and instant-BSOD the guest. Skip the cont entirely and just
        # close the socket — QEMU's CHR_EVENT_CLOSED halts the stub
        # without resuming, leaving the VM paused so the operator
        # can recover the CR3 manually (or restore from snapshot).
        try:
            if not self._cr3_corrupted:
                with suppress(Exception):
                    self.rsp.cont()
                # Hold long enough that vCont;c is fully processed by
                # QEMU before we yank the socket. 100ms is more than
                # enough — vCont round-trip is sub-ms.
                time.sleep(0.1)
            else:
                print(
                    "[kdbg-daemon] CR3 corrupted; skipping cont on shutdown — "
                    "VM will remain paused. Recover CR3 via HMP or restore snapshot.",
                    file=sys.stderr, flush=True,
                )
        finally:
            with suppress(OSError):
                self.rsp._sock.close()

        if self._listen_sock is not None:
            with suppress(OSError):
                self._listen_sock.close()


# ── helpers (module-private) ────────────────────────────────────────────


# Names map to the same offsets as in test_kdbg_install — single source
# of truth lives in install._CR3_OFFSET_IN_G already. We mirror the GPR
# names here for decode formatting only.
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

    # RIP must be canonical x86-64 (bits 48..63 = bit 47 sign-extended)
    high = rip >> 47
    if high not in (0, 0x1FFFF):
        raise DaemonError(
            f"RIP 0x{rip:x} from g-packet offset 128 is not canonical — "
            "register layout may be wrong for this QEMU build"
        )
    # CS must be a plausible x86-64 segment selector (low 2 bits = RPL)
    if cs not in (0x10, 0x33, 0x08, 0x23, 0x2b, 0x1b):
        raise DaemonError(
            f"CS 0x{cs:x} from g-packet offset 140 is not a recognized "
            "x86-64 selector — register layout may be wrong"
        )
    # CR3 non-zero with a valid physical frame
    if cr3 == 0 or cr3 >= (1 << 52):
        raise DaemonError(
            f"CR3 0x{cr3:x} from g-packet offset {_CR3_OFFSET_IN_G} is "
            "implausible — register layout may be wrong"
        )


def _decode_regs(blob: bytes) -> dict[str, str]:
    """Format a g-packet blob as a flat string-keyed dict.

    All values are hex strings (clients render at will). We expose the
    common-case registers; FPU/SSE state lives further in the blob and
    can be added if a use case demands it.
    """
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
    """Heuristic: kernel-half OR low user-mode (0x7ff..) but not stack/heap.

    We flag things that *might* be code addresses for backtrace display.
    Wrong guesses just get printed without symbol resolution; right
    guesses get a symbol annotation.
    """
    if va == 0:
        return False
    high = va >> 47
    # Canonical-high (kernel) addresses — definitely valid
    if high == 0x1FFFF:
        return True
    # Canonical-low user space — image bases on x64 typically 0x7ff... or
    # 0x180... etc. Be permissive: anything under 0x800_0000_0000 with
    # high half zero counts as "could be code".
    if high == 0 and va > 0x10000:
        return True
    return False


# ── Fork / daemonize ────────────────────────────────────────────────────


def _detach_to_log(log_file: Path) -> None:
    """Standard double-fork-style detach but we keep stderr/stdout
    redirected to a log file rather than /dev/null so daemon errors are
    visible during development."""
    os.setsid()
    f = open(log_file, "ab", buffering=0)
    os.dup2(f.fileno(), 1)
    os.dup2(f.fileno(), 2)
    # Close stdin
    try:
        with open(os.devnull, "rb") as dn:
            os.dup2(dn.fileno(), 0)
    except OSError:
        pass


def _acquire_lock_or_die(lock_file: Path) -> int:
    """Try LOCK_EX_NB; return fd. Raise DaemonError on failure."""
    fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise DaemonError("another kdbg session holds the lock")
    # Write our pid for diagnostic visibility (lock fd itself is the
    # source of truth, but reading the file is convenient).
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    os.fsync(fd)
    return fd


def _write_session_file(path: Path, info: dict[str, Any]) -> None:
    path.write_text(json.dumps(info, indent=2), encoding="utf-8")


def _bind_unix_socket(sock_file: Path) -> socket.socket:
    """Create a fresh listen socket. Removes any stale .sock left from
    a crashed previous daemon (we'd already have proven via the lock
    that no other live daemon exists)."""
    if sock_file.exists():
        sock_file.unlink()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock_file))
    sock_file.chmod(0o600)
    s.listen(8)
    return s


def _read_target_bytes(rsp: "RspClient", target_dtb: int, va: int, length: int) -> bytes:
    """One-shot CR3-masquerade read. Used by attach-time stale-base
    detection — borrows the same primitive op_mem uses but doesn't
    need a DaemonSession yet.

    NOTE on vCPU selection: this is called BEFORE any DaemonSession
    exists (and therefore before ``self.stop`` could record the firing
    vCPU). We fall back to ``threads[0]`` because there's nothing
    better available pre-stop. Callers post-stop should go through
    ``DaemonSession.op_mem`` / ``_pick_vcpu`` instead, which prefers
    the recorded firing vCPU.

    Restore failures here can't poison a session that doesn't exist,
    but they DO leave the firing vCPU with a masqueraded CR3 — which
    will instantly BSOD the guest on resume. Surface as DaemonError
    so the parent fails the attach and the operator can recover.
    """
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
    """Strip common PE suffixes for matching across naming conventions.

    SymbolStore short names: ``notepad``, ``ntdll`` (filename stems).
    PEB.Ldr BaseDllName values: ``notepad.exe``, ``ntdll.dll``.
    Match case-insensitively after stripping the extension.
    """
    n = name.lower().rsplit(".", 1)[0]
    return n


def _stored_module_identity(name: str, data: dict) -> tuple[str, str]:
    """Return a loader basename and architecture for one store entry.

    Older records predate the explicit architecture field. x86 user modules
    have always used the ``_x86`` suffix, so that convention is a safe
    migration fallback and prevents native/WoW64 basename collisions.
    """
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
    """Explain a failed hardware breakpoint without inventing a cause.

    The old message asserted the DR0..3 budget was exhausted whatever
    happened. A stalled read is the commoner failure and says nothing about
    slots, so pointing at the budget sent people looking in the wrong place.
    """
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
    """Explain a failed software breakpoint.

    A software breakpoint writes 0xCC into the code page. Windows 11 enables
    HVCI by default, which is precisely a guard against writing to kernel
    code — so on a client SKU this path fails for a structural reason, and
    reporting only "read timed out" left no way to know that.
    """
    parts = [f"soft bp install failed: {err}."]
    if not is_user and _looks_like_timeout(err):
        parts.append(
            "A software breakpoint patches 0xCC into the kernel code page, "
            "which HVCI exists to prevent — and HVCI is on by default on "
            "Windows 11. If this guest is a client SKU, hardware breakpoints "
            "(mode='hw') are the only ones that will install."
        )
    return " ".join(parts)


def _validate_module_bases(
    cfg: Config,
    rsp: "RspClient",
    target,
    store: SymbolStore,
) -> None:
    """Verify cached module bases match what's actually loaded in target.

    The check has THREE failure modes to distinguish:

    1. Module is loaded in target but its base differs from our cached
       value → STALE (ASLR moved it across a VM reboot, or symbols
       loaded against a different process). Forces a clear error
       naming the affected modules.

    2. Module is in our store but NOT loaded in this target → SKIP.
       The store is global across the whole VM; entries from a
       different process (e.g. notepad symbols cached when we worked
       with notepad, now attaching to cyserver) are perfectly fine,
       just irrelevant to this target. Validating them against this
       target's CR3 would falsely report stale.

    3. Special-case ``nt`` (the kernel): not in PEB.Ldr — re-derive
       its live base from the IDT (the same primitive ``load_nt``
       uses) and compare against the cached value. Mismatch → stale.
       Failure to derive (transient HMP issue, missing PDB symbol) is
       logged and skipped, not fatal.

    Strategy:
      - For ``nt``: re-derive live base via ``resolve_nt_base``; compare.
      - Walk target's PEB.Ldr once → {(normalized_name, architecture): base}.
      - For each cached user-mode module: look it up in the target's
        loaded set. Found + mismatch → stale. Not found → skip silently.

    Raises ``DaemonError`` with a remediation message listing each
    stale module — for user-mode modules names match the
    ``kdbg_user_symbols_load`` arg; for ``nt`` the message points at
    ``winbox kdbg base`` + ``kdbg symbols load -m nt``.
    """
    try:
        modules = store.list_modules()
    except Exception:
        return  # No store, nothing to validate

    # ── Step 1: validate nt separately (kernel — no PEB.Ldr entry) ──
    if "nt" in modules:
        try:
            nt_data = store.load("nt")
        except Exception:
            nt_data = None
        cached_nt_base = (nt_data or {}).get("base")
        nt_syms = (nt_data or {}).get("symbols") or {}
        if cached_nt_base and nt_syms:
            from winbox.kdbg.hmp import HmpError
            from winbox.kdbg.symbols import SymbolLoadError, resolve_nt_base
            try:
                live_nt_base = resolve_nt_base(cfg, nt_syms)
            except (HmpError, SymbolLoadError, OSError) as e:
                # Can't derive live nt base right now — log + skip
                # rather than fail. A concrete bp install against a
                # stale nt base will surface a clearer error later.
                print(
                    f"warning: could not validate nt base "
                    f"({type(e).__name__}: {e}); skipping nt staleness check",
                    file=sys.stderr,
                )
            else:
                if live_nt_base != cached_nt_base:
                    # ASLR moves the kernel every boot, and the symbol store
                    # outlives the boot that produced it — so this fires after
                    # any restart. Only the *base* moved; every RVA in the
                    # store is still correct, so re-pointing it is the whole
                    # repair. Telling the user to run two commands that do
                    # exactly this was busywork standing between them and a
                    # working debugger.
                    store.set_base("nt", live_nt_base)
                    print(
                        f"note: nt base moved 0x{cached_nt_base:x} -> "
                        f"0x{live_nt_base:x} (ASLR, typically a VM reboot); "
                        f"refreshed automatically",
                        file=sys.stderr,
                    )

    # ── Step 2: collect user-mode candidates with cached bases ──
    candidates: list[tuple[str, int, tuple[str, str]]] = []
    for mod_name in modules:
        if mod_name == "nt":
            continue
        try:
            data = store.load(mod_name)
        except Exception:
            continue
        base = data.get("base")
        if not base:
            continue
        candidates.append(
            (mod_name, base, _stored_module_identity(mod_name, data))
        )

    if not candidates:
        return  # Nothing user-mode to check; skip the PEB.Ldr walk.

    # Walk target's PEB.Ldr to get the actual loaded modules.
    # ensure_types_loaded for _PEB / _PEB_LDR_DATA may be needed if
    # the store predates their inclusion — handle gracefully.
    from winbox.kdbg import ensure_types_loaded
    from winbox.kdbg.hmp import HmpError
    from winbox.kdbg.walk import list_user_modules
    try:
        ensure_types_loaded(cfg, store, ["_PEB", "_PEB_LDR_DATA"], module="nt")
        loaded = list_user_modules(cfg.vm_name, store, target)
    except (HmpError, OSError, RuntimeError, LookupError, SymbolStoreError) as e:
        # Expected failure modes:
        #   HmpError       - transient HMP / virsh failure
        #   OSError        - socket/IO during a memory read
        #   RuntimeError   - generic walker failures (page fault, bad PEB)
        #   LookupError    - store missing nt or required type entries
        #   SymbolStoreError - store on disk but malformed
        # Surface a warning and skip user-mode validation rather than
        # block the attach. Anything else (TypeError, ValueError on a
        # real bug, etc.) falls through unchanged so the daemon dies
        # loudly instead of silently skipping checks.
        print(
            f"warning: PEB.Ldr walk failed: {type(e).__name__}: {e}; "
            "cannot validate user-mode module bases for stale state",
            file=sys.stderr,
        )
        return

    # Build normalized lookup of currently loaded modules in target.
    target_loaded: dict[tuple[str, str], int] = {
        (
            _normalize_module_name(m.name),
            str(getattr(m, "architecture", "x64")).lower(),
        ): m.base
        for m in loaded
    }

    stale: list[tuple[str, int, int]] = []  # (cached_name, cached_base, current_base)
    for mod_name, cached_base, identity in candidates:
        actual_base = target_loaded.get(identity)
        if actual_base is None:
            # Not loaded in this target — store entry is from a
            # different process. Skip without complaint.
            continue
        if actual_base != cached_base:
            stale.append((mod_name, cached_base, actual_base))

    if stale:
        # Same story as the kernel above: ASLR relocated the images, but the
        # symbols themselves are still valid — only the base each RVA is added
        # to has changed, and the live value is right here in `target_loaded`.
        # The documented remedy (kdbg_user_symbols_load per module) re-copied
        # the PE and re-parsed its PDB purely to arrive at this same number.
        repaired: list[str] = []
        failed: list[str] = []
        for name, cached, actual in stale:
            try:
                store.set_base(name, actual)
            except Exception as e:  # store unwritable, malformed, ...
                failed.append(f"{name} ({type(e).__name__}: {e})")
            else:
                repaired.append(f"{name} 0x{cached:x} -> 0x{actual:x}")

        if repaired:
            print(
                f"note: refreshed {len(repaired)} stale module base(s) for "
                f"{target.name} after ASLR: {', '.join(repaired)}",
                file=sys.stderr,
            )
        if failed:
            raise DaemonError(
                f"stale module bases for {target.name} could not be "
                f"refreshed: {', '.join(failed)}. Re-run "
                f"kdbg_user_symbols_load for each before retrying."
            )


def fork_daemon(
    cfg: Config,
    target_pid: int,
    *,
    gdbstub_port: int = 1234,
    module_manifest: UserModuleManifest | None = None,
) -> int:
    """Fork off a session daemon. Parent returns the daemon pid; child
    never returns from this function (it enters serve_forever).

    The child connects the gdbstub first (halting the VM for a stable
    CR3), then walks the process list to find ``target_pid``. Walking
    after the halt avoids KPTI CR3 races that truncate the list on a
    running VM.

    The parent waits on a status pipe for the child to either say "OK"
    (everything wired) or "ERR: ..." (and exits with that error).
    """
    if module_manifest is not None and module_manifest.pid != target_pid:
        raise DaemonError(
            f"module manifest pid {module_manifest.pid} does not match "
            f"target pid {target_pid}"
        )

    # Fail closed before attaching QEMU's gdbstub. Repeated RSP stop/resume is
    # known to corrupt CET shadow-stack state on affected QEMU/KVM builds.
    from winbox.kdbg.cet import CetSafetyError, require_safe
    try:
        require_safe(cfg)
    except CetSafetyError as exc:
        raise DaemonError(str(exc)) from exc

    pipe_r, pipe_w = os.pipe()
    pid = os.fork()
    if pid > 0:
        # Parent
        os.close(pipe_w)
        try:
            line = b""
            while True:
                chunk = os.read(pipe_r, 4096)
                if not chunk:
                    break
                line += chunk
                if b"\n" in line:
                    break
        finally:
            os.close(pipe_r)
        line = line.split(b"\n", 1)[0]
        if line == b"OK":
            return pid
        text = line.decode("utf-8", errors="replace")
        if text.startswith("ERR:"):
            raise DaemonError(text[4:].strip())
        raise DaemonError(f"unexpected daemon status: {text!r}")

    # Child — won't return
    os.close(pipe_r)
    # Track lifecycle so the error paths can do the right thing without
    # double-closing the pipe (writes after close = EBADF, parent then
    # sees an empty pipe instead of our error message) and so we can
    # resume the VM if attach failed after the gdbstub halted it.
    rsp: RspClient | None = None
    pipe_signaled = False
    try:
        _detach_to_log(log_path(cfg))
        lock_fd = _acquire_lock_or_die(lock_path(cfg))

        # Item #28: Bounded retry on "empty stop reply" — the gdbstub
        # occasionally returns an empty body to the '?' query after a
        # fresh start. Instead of forcing the operator to manually cycle
        # kdbg_stop + kdbg_start, restart the stub via HMP and reconnect.
        _MAX_ATTACH_ATTEMPTS = 3
        for _attempt in range(1, _MAX_ATTACH_ATTEMPTS + 1):
            rsp = RspClient.connect("127.0.0.1", gdbstub_port, timeout=5.0)
            try:
                rsp.handshake()
                initial_sr = rsp.query_halt_reason()
                break  # success
            except RspError as _rsp_err:
                if "empty stop reply" not in str(_rsp_err):
                    raise  # not the retryable failure — propagate
                # Close raw socket (no D-packet dance)
                with suppress(OSError):
                    rsp._sock.close()
                rsp = None
                if _attempt >= _MAX_ATTACH_ATTEMPTS:
                    raise DaemonError(
                        f"gdbstub returned empty stop reply on "
                        f"{_MAX_ATTACH_ATTEMPTS} consecutive attempts. "
                        f"Recovery: kdbg_stop, kdbg_start, then retry."
                    ) from _rsp_err
                # Restart the gdbstub via HMP
                from winbox.kdbg.hmp import hmp
                with suppress(Exception):
                    hmp(cfg.vm_name, "gdbserver none")
                time.sleep(0.5)
                hmp(
                    cfg.vm_name,
                    f"gdbserver tcp:127.0.0.1:{gdbstub_port}",
                )
                time.sleep(0.3)  # let stub settle

        # VM is now halted. Route every bootstrap register/memory operation
        # through this already-owned RSP connection; opening the background
        # reader here would contend for QEMU's single gdb client.
        store = SymbolStore(cfg.symbols_dir)
        from winbox.kdbg.debugger.reader import use_local_rsp
        from winbox.kdbg.symbols import ensure_nt_base_current
        from winbox.kdbg.walk import find_process
        with use_local_rsp(cfg.vm_name, rsp, initial_sr):
            ensure_nt_base_current(cfg, store)
            target_rec = find_process(cfg.vm_name, store, pid=target_pid)
        if target_rec is None:
            # Resume VM and close socket using the same safe pattern as
            # DaemonSession.shutdown(): raw socket close, no D-packet.
            # rsp.close() does interrupt+wait+D which halts-resumes-halts
            # the VM and corrupts the virtio-serial GA channel. (Item #29)
            rsp.cont()
            time.sleep(0.1)
            rsp._sock.close()
            # Check GA health — warn if the channel dropped.
            ga_warning = ""
            try:
                from winbox.vm.lifecycle import agent_channel_connected
                if not agent_channel_connected(cfg.vm_name):
                    ga_warning = (
                        " (warning: guest-agent channel is down; "
                        "it may need a few seconds to reconnect)"
                    )
            except Exception:
                pass
            msg = f"ERR: pid {target_pid} not found{ga_warning}\n"
            os.write(pipe_w, msg.encode())
            os.close(pipe_w)
            pipe_signaled = True
            os._exit(1)
        target = TargetInfo(
            pid=target_rec.pid,
            dtb=target_rec.directory_table_base,
            name=target_rec.name,
            user_dtb=target_rec.user_directory_table_base,
            eprocess=target_rec.eprocess,
        )

        with use_local_rsp(cfg.vm_name, rsp, initial_sr):
            _validate_module_bases(cfg, rsp, target, store)

        listen_sock = _bind_unix_socket(sock_path(cfg))
        _write_session_file(session_path(cfg), {
            "target_pid": target.pid,
            "target_dtb": f"0x{target.dtb:x}",
            "target_name": target.name,
            "daemon_pid": os.getpid(),
            "gdbstub_port": gdbstub_port,
            "attach_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "auto_stage": (
                module_manifest.summary() if module_manifest is not None else None
            ),
        })
        session = DaemonSession(
            cfg=cfg, rsp=rsp, target=target, store=store,
            module_manifest=module_manifest,
        )
        session._capture_stop(initial_sr)
        _validate_register_layout(session.stop.raw_regs)
        _install_signal_handlers(session)

        os.write(pipe_w, b"OK\n")
        os.close(pipe_w)
        pipe_signaled = True

        sys.stderr.write(f"[kdbg-daemon pid={os.getpid()}] attached to "
                         f"{target.name}({target.pid}) dtb=0x{target.dtb:x}\n")
        sys.stderr.flush()

        try:
            session.serve(listen_sock)
        finally:
            session.shutdown()
            with suppress(OSError):
                sock_path(cfg).unlink()
            with suppress(OSError):
                session_path(cfg).unlink()
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
            with suppress(OSError):
                lock_path(cfg).unlink()
        os._exit(0)
    except DaemonError as e:
        # Resume the VM ONLY if we failed during startup — i.e., before
        # the parent was signaled OK. Past that point the daemon was
        # driving the stub through normal cont/halt cycles, so an
        # unconditional ``rsp.cont()`` here could double-resume against
        # an unexpected state. ``pipe_signaled`` is the cleanest "we
        # got past startup" gate (set immediately after the parent ack).
        if rsp is not None and not pipe_signaled:
            with suppress(Exception):
                rsp.cont()
        if not pipe_signaled:
            with suppress(OSError):
                os.write(pipe_w, f"ERR: {e}\n".encode())
                os.close(pipe_w)
        os._exit(1)
    except Exception as e:  # noqa: BLE001 — surface anything that broke setup
        if rsp is not None and not pipe_signaled:
            with suppress(Exception):
                rsp.cont()
        if not pipe_signaled:
            with suppress(OSError):
                os.write(pipe_w, f"ERR: {type(e).__name__}: {e}\n".encode())
                os.close(pipe_w)
        os._exit(1)


def _install_signal_handlers(session: DaemonSession) -> None:
    def on_term(signum, frame):  # noqa: ARG001
        session._serving = False
        session._shutdown_requested = True

    def on_usr1(signum, frame):  # noqa: ARG001
        # Hint for cont loop to break out next iteration.
        session._interrupt_pending = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    signal.signal(signal.SIGUSR1, on_usr1)
