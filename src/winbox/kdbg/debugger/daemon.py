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


# ── Filesystem layout ───────────────────────────────────────────────────


def _runtime_dir(cfg: Config) -> Path:
    """Where lock/sock/session/log live. Reuses cfg's root for portability."""
    p = cfg.root_dir if hasattr(cfg, "root_dir") else (Path.home() / ".winbox")
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
    condition: str | None = None
    _predicate: Any = field(default=None, repr=False)
    predicate_hits: int = 0
    predicate_skips: int = 0
    predicate_errors: int = 0


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
    ) -> None:
        self.cfg = cfg
        self.rsp = rsp
        self.target = target
        self.store = store

        self.bps: dict[int, Breakpoint] = {}
        # va -> bp_id index for O(1) lookup on the cont/predicate hot
        # path. Populated/cleaned in op_bp_add / op_bp_remove. If two
        # bps share a VA (shouldn't happen in normal use) only the
        # latest is indexed; the others still appear in self.bps.
        self._bp_by_va: dict[int, int] = {}
        self._next_bp_id = 0
        self.stop: StopState | None = None
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
        return {
            "target": {
                "pid": self.target.pid,
                "dtb": f"0x{self.target.dtb:x}",
                "name": self.target.name,
            },
            "bps": len(self.bps),
            "halted": self.stop is not None,
            "uptime_s": time.monotonic() - self.attach_time,
            "daemon_pid": os.getpid(),
        }

    def op_bp_add(
        self,
        target: str,
        mode: str = "hw",
        condition: str | None = None,
    ) -> dict[str, Any]:
        """Install a bp at sym/VA.

        ``mode`` selects the bp mechanism:

        * ``"hw"`` (default) — hardware bp via gdbstub ``Z1`` packet.
          Sets a CPU debug register (DR0..3). Invisible to PatchGuard
          (no code modification) and invisible to in-guest GetThread\
          Context (KVM virtualizes DR access). For user-mode VAs no
          CR3 masquerade is needed — Z1 doesn't translate the VA, it
          just configures a register match. Limit: 4 active per vCPU.
        * ``"soft"`` — software bp via gdbstub ``Z0`` (0xCC patch).
          Visible to code self-hashing and PatchGuard. Unlimited count.
          For user-mode VAs goes through ``install_user_breakpoint``
          (CR3 masquerade dance).
        * ``"auto"`` — try hw first; on slot exhaustion fall back to
          soft. Surfaces neither the hw success nor the fallback in
          a special way; the resulting bp's ``hw`` field tells which
          you got.

        ``condition`` is an optional predicate evaluated server-side on
        each in-target fire. False predicate -> silent-cont (no halt
        surfaced to client). True predicate -> halt as today. Parse
        errors raise immediately, before any RSP packet is sent, so a
        bad predicate never installs a bp. See ``predicate.py`` for the
        grammar (regs, ``[reg+offset]`` qword reads, ``== != < <= > >=``,
        ``&``, ``&&``, ``||``).
        """
        # Treat empty string the same as None — convenient for callers
        # that always pass the arg through.
        if isinstance(condition, str) and not condition.strip():
            condition = None

        # Parse predicate FIRST. We don't want a bp installed in the
        # gdbstub if the predicate is malformed.
        predicate_ast = None
        if condition is not None:
            try:
                predicate_ast = parse_predicate(condition)
            except PredicateSyntaxError as e:
                raise RuntimeError(f"bad condition: {e}") from e

        va = self._resolve_target(target)
        is_user = (va >> 47) != 0x1FFFF  # canonical-high == kernel half

        if mode not in ("hw", "soft", "auto"):
            raise ValueError(f"mode must be 'hw', 'soft', or 'auto'; got {mode!r}")

        # Track how the bp got installed for the registry + reply.
        installed_hw = False
        elapsed_ms = 0.0

        hw_error: Exception | None = None
        if mode in ("hw", "auto"):
            # Try hw first: DR-register breakpoints are PatchGuard-safe and
            # invisible to in-guest anti-debug, so they are always preferred.
            t0 = time.monotonic()
            try:
                self.rsp.insert_breakpoint(va, kind=1, hardware=True)
                installed_hw = True
                elapsed_ms = (time.monotonic() - t0) * 1000.0
            except RspError as e:
                hw_error = e
                if mode == "hw":
                    raise RuntimeError(_hw_bp_failure(e)) from e
                # mode == "auto" — fall through to soft path

        if not installed_hw:
            # Software path. Kernel VAs get plain Z0 (kernel pages are
            # in every CR3); user VAs need the CR3-masquerade dance.
            t0 = time.monotonic()
            try:
                if is_user:
                    report = install_user_breakpoint(
                        self.rsp, self.cfg.vm_name, self.store,
                        cr3_candidates=self.target.masquerade_candidates,
                        user_va=va,
                    )
                    elapsed_ms = report.elapsed * 1000.0
                    # install_user_breakpoint issues its own Hg (threads[0])
                    # via code we don't own — invalidate the cache so the
                    # next op_cont re-selects rather than trusting a stale
                    # _last_selected_vcpu.
                    self._last_selected_vcpu = None
                else:
                    self.rsp.insert_breakpoint(va, kind=1)
                    elapsed_ms = (time.monotonic() - t0) * 1000.0
            except (RspError, InstallError) as e:
                raise RuntimeError(
                    _soft_bp_failure(e, is_user=is_user, hw_error=hw_error)
                ) from e

        bp_id = self._next_bp_id
        self._next_bp_id += 1
        # For user-mode soft bps, record the CR3 that
        # install_user_breakpoint actually used so removal can target it
        # directly instead of re-iterating all candidates (bug #21).
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
        )
        self.bps[bp_id] = bp
        self._bp_by_va[va] = bp_id
        return {
            "id": bp_id,
            "va": f"0x{va:x}",
            "user_mode": is_user,
            "hw": installed_hw,
            "condition": condition,
            "elapsed_ms": round(elapsed_ms, 2),
        }

    def op_bp_list(self) -> dict[str, Any]:
        from winbox.kdbg.demangle import pretty_symbol
        return {
            "bps": [
                {
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
                    "age_s": round(time.monotonic() - b.installed_at, 2),
                }
                for b in self.bps.values()
            ]
        }

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
        if bp.user_mode and not bp.hw:
            vcpu = self._pick_vcpu()
            self._select_thread(vcpu)
            regs = self.rsp.read_registers()
            if bp.installed_cr3:
                # Use the exact CR3 that install_user_breakpoint placed
                # the 0xCC under — avoids re-iterating all candidates
                # and eliminates E22 on removal (bug #21).
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
        deadline = time.monotonic() + max(0.5, float(timeout))
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
                return {"reason": "interrupt", **self._stop_summary()}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"reason": "timeout"}

            self.rsp.cont()
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
                        pass
                    return {"reason": "timeout", **self._stop_summary()}
                raise RuntimeError(f"cont/wait failed: {e}") from e

            if self._interrupt_pending:
                # An interrupt was served mid-wait and its \x03 is what
                # halted us (QEMU reports SIGINT, not SIGTRAP). Consume the
                # flag here so it can't leak into the next cont, and label
                # the stop for what the operator asked for.
                self._interrupt_pending = False
                self._capture_stop(sr)
                return {"reason": "interrupt", **self._stop_summary()}

            if sr.signal != 5:
                # Not a bp — surface anyway, caller decides.
                self._capture_stop(sr)
                return {"reason": "signal", **self._stop_summary()}

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
            firing_vcpu = sr.thread or "01"
            if self._last_selected_vcpu != firing_vcpu:
                self._select_thread(firing_vcpu)
            regs = self.rsp.read_registers()
            cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
            rip = struct.unpack_from("<Q", regs, 128)[0]

            if cr3 not in accepted_cr3s:
                # silent-continue — bump bp hit counter best-effort
                self._bump_bp_hits(rip, in_target=False)
                continue

            # Predicate gate. Reuse the regs blob we already read so
            # the per-fire cost stays at one g-packet plus any mem
            # derefs the predicate explicitly triggers.
            bp = self.bps.get(self._bp_by_va.get(rip, -1))

            if bp is not None and bp._predicate is not None:
                try:
                    truthy = bool(bp._predicate.eval(
                        regs, self._mem_qword_reader(regs)
                    ))
                except PredicateRuntimeError as e:
                    bp.predicate_errors += 1
                    bp.hits += 1
                    self._capture_stop_with_regs(sr, regs)
                    return {
                        "reason": "predicate_error",
                        "error": str(e),
                        **self._stop_summary(),
                    }
                if not truthy:
                    bp.predicate_skips += 1
                    bp.hits += 1
                    continue
                bp.predicate_hits += 1

            self._capture_stop_with_regs(sr, regs)
            if bp is not None:
                bp.hits += 1
            else:
                self._bump_bp_hits(rip, in_target=True)
            return {"reason": "bp", **self._stop_summary()}

    def op_step(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        vcpu = self.stop.vcpu
        self.rsp.step(vcpu)
        try:
            sr = self.rsp.wait_for_stop(timeout=5.0)
        except RspError as e:
            if "timed out" not in str(e).lower():
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
                recovered = True
            except RspError:
                # Recovery interrupt+wait also failed → genuine hang.
                # ``self.stop`` is whatever the pre-step state was; we
                # don't claim it's current.
                pass
            if recovered:
                raise RuntimeError(
                    "step did not complete within 5s; stub recovered to halted state"
                ) from e
            raise RuntimeError(
                "step did not complete within 5s and recovery halt failed; "
                "stub state is indeterminate, daemon may need restart"
            ) from e
        self._select_thread(sr.thread or vcpu)
        self._capture_stop(sr)
        return {"reason": "step", **self._stop_summary()}

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
            # Re-read live — useful between ops.
            blob = self.rsp.read_registers()
            return _decode_regs(blob)
        return _decode_regs(self.stop.raw_regs)

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

    def op_mem(self, va: int | str, length: int = 64) -> dict[str, Any]:
        """Read `length` bytes at `va` in target's CR3. Uses the same
        CR3-masquerade trick as bp install: temporarily writes target
        DTB into the firing vCPU's CR3 register, reads via gdb `m`,
        restores. Way faster than HMP page walks (~1ms vs ~40ms)."""
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

        # gdb ``M addr,len:hex`` writes payload bytes at addr.
        self._cr3_masqueraded_call(
            vcpu, regs, lambda: self.rsp.write_memory(va, payload)
        )

        return {"va": f"0x{va:x}", "length": len(payload)}

    def op_stack(self, n: int = 16) -> dict[str, Any]:
        """N qwords starting at RSP, with RSP-relative offset labels."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        n = max(1, min(int(n), 256))
        rsp_va = struct.unpack_from("<Q", self.stop.raw_regs, 7 * 8)[0]
        result = self.op_mem(rsp_va, n * 8)
        raw = bytes.fromhex(result["bytes"])
        return {
            "rsp": f"0x{rsp_va:x}",
            "qwords": [
                {
                    "offset": f"rsp+0x{i:02x}",
                    "va": f"0x{rsp_va + i:x}",
                    "value": "0x{:016x}".format(
                        int.from_bytes(raw[i:i+8], "little")
                    ),
                }
                for i in range(0, n * 8, 8)
            ],
        }

    def op_bt(self, depth: int = 8) -> dict[str, Any]:
        """Crude backtrace: walk RSP qwords, treat anything that looks
        like a kernel/user code VA as a return address, symbolicate via
        the loaded stores. Best-effort — frame-pointer-omitted code
        won't unwind nicely; that needs proper CFI which is out of scope."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        depth = max(1, min(int(depth), 64))
        rsp_va = struct.unpack_from("<Q", self.stop.raw_regs, 7 * 8)[0]
        # Dump enough stack to find candidates
        scan_qwords = min(depth * 8, 256)
        mem = self.op_mem(rsp_va, scan_qwords * 8)
        raw = bytes.fromhex(mem["bytes"])

        frames = []
        for i in range(0, len(raw), 8):
            qw = int.from_bytes(raw[i:i + 8], "little")
            if not _looks_like_code_va(qw):
                continue
            sym = self._best_symbol_for_va(qw)
            frames.append({
                "addr": f"0x{qw:x}",
                "sym": sym,
                "stack_off": f"+0x{i:x}",
            })
            if len(frames) >= depth:
                break
        return {"rsp": f"0x{rsp_va:x}", "frames": frames}

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
        vcpu = sr.thread or "01"
        self._select_thread(vcpu)
        regs = self.rsp.read_registers()
        self._capture_stop_with_regs(sr, regs, vcpu=vcpu)

    def _capture_stop_with_regs(self, sr, regs: bytes, *, vcpu: str | None = None) -> None:
        """Same as _capture_stop but reuses an already-fetched regs blob.

        Saves a g-packet round-trip when the caller (e.g. the predicate
        gate in op_cont) has just read regs to evaluate a condition.
        """
        if vcpu is None:
            vcpu = sr.thread or "01"
            self._select_thread(vcpu)
        self.stop = StopState(
            vcpu=vcpu,
            rip=struct.unpack_from("<Q", regs, 16 * 8)[0],
            cr3=struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0],
            signal=sr.signal,
            raw_regs=regs,
        )

    def _mem_qword_reader(self, fired_regs: bytes):
        """Build a closure that reads a qword from target's address space.

        Uses ``_cr3_masqueraded_call`` (same dance as op_mem / op_write_mem),
        so on a build with a verified ``user_dtb`` a read that's unmapped
        under the primary CR3 gets retried against the other half before
        giving up. Per-call cost is 3 RSP packets per candidate tried
        (G-swap, m, G-restore). The firing vCPU must still be selected
        when the closure runs — caller's responsibility to invoke before
        yielding control.

        Failure modes:
          * Read rejected under every candidate CR3 (unmapped VA, gdbstub
            error) → return 0. The documented predicate semantic is that
            unmapped derefs read as zero so a check like
            ``[rcx+0x10] != 0`` composes with dangling-pointer cases
            without the operator pre-validating the deref. The cost: a
            real transport hiccup looks the same as an unmapped read
            inside the predicate. Acceptable because the surrounding
            session would also be visibly broken (next op fails for
            other reasons).
          * G-swap rejected → ``PredicateRuntimeError`` (op_cont converts
            to ``reason="predicate_error"`` and stays halted; this is a
            session-level failure, not a data-level miss).
          * G-restore failed → ``CR3RestoreError`` propagates up (the
            session is poisoned at this point; cont will tear down).
          * Short read with no error → ``PredicateRuntimeError`` — the
            chunked-read path post-1.3.0 should never produce this; if
            it does, surface loudly rather than silently returning 0.
        """
        rsp = self.rsp
        session = self
        # Snapshot vcpu hint at construction time; if the daemon hasn't
        # captured a stop yet we trust the firing vCPU is still selected.
        vcpu_hint = self.stop.vcpu if self.stop is not None else "01"

        def _read(addr: int) -> int:
            try:
                data = session._cr3_masqueraded_call(
                    vcpu_hint, fired_regs, lambda: rsp.read_memory(addr, 8)
                )
            except RspError:
                # Unmapped (or rejected) under every candidate CR3 —
                # predicate sees 0.
                return 0
            except CR3RestoreError:
                # Don't dress this up as a predicate failure — the
                # session is dead and the operator needs to know.
                raise
            except RuntimeError as e:
                # G-swap rejected (in-context, before yield). Convert
                # to a predicate-level failure so op_cont reports it
                # cleanly without poisoning the session.
                if "G-packet" in str(e):
                    raise PredicateRuntimeError(str(e)) from e
                raise
            if len(data) != 8:
                raise PredicateRuntimeError(
                    f"short mem read at 0x{addr:x}: got {len(data)} bytes"
                )
            return int.from_bytes(data, "little")

        return _read

    def _stop_summary(self) -> dict[str, Any]:
        if self.stop is None:
            return {}
        bp_hit = next((b for b in self.bps.values() if b.va == self.stop.rip), None)
        return {
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
        }

    def _bump_bp_hits(self, va: int, *, in_target: bool) -> None:
        if not in_target:
            return
        for b in self.bps.values():
            if b.va == va:
                b.hits += 1
                return

    # Fallback span when a module has no recorded SizeOfImage (legacy
    # store entries from before that field was tracked). 16 MiB is
    # bigger than any single Windows image in practice, but small
    # enough that it won't match VAs in unrelated modules.
    _LEGACY_SIZE_FALLBACK = 16 * 1024 * 1024

    def _best_symbol_for_va(self, va: int) -> str | None:
        """Find the symbol whose owning module actually contains ``va``.

        Old behaviour was "closest <= symbol from any module" — which
        produced nonsense like ``ntdll!__guard...+0x3a6e9a376`` for
        VAs in user32 (just the closest known symbol overall, regardless
        of which module the VA was in).

        Fix: only consider modules whose ``[base, base+size)`` range
        contains ``va``. If no module covers it, return None rather
        than report a wrong-module guess. If a module has no recorded
        size (legacy store entry), use ``_LEGACY_SIZE_FALLBACK`` as a
        coarse upper bound.

        Symbol display goes through ``demangle.pretty_symbol`` so
        mangled C++ names render as readable signatures.
        """
        from winbox.kdbg.demangle import pretty_symbol
        try:
            modules = self.store.list_modules()
        except Exception:
            return None
        best: tuple[str, str, int] | None = None
        for module in modules:
            try:
                data = self.store.load(module)
            except Exception:
                continue
            base = data.get("base") or 0
            if not base:
                continue
            size = data.get("size_of_image") or self._LEGACY_SIZE_FALLBACK
            # Filter: this module actually contains the VA?
            if not (base <= va < base + size):
                continue
            symbols = data.get("symbols", {})
            local_best: tuple[str, int] | None = None
            for name, rva in symbols.items():
                target = base + rva
                if target <= va and (local_best is None or target > local_best[1]):
                    local_best = (name, target)
            if local_best is None:
                continue
            # Among modules that contain the VA, pick the one with the
            # closest symbol. (In practice the VA is in exactly one
            # module's range; this only matters for overlapping ranges
            # which shouldn't happen but cheap to handle.)
            if best is None or local_best[1] > best[2]:
                best = (module, local_best[0], local_best[1])
        if best is None:
            return None
        module, name, addr = best
        return f"{pretty_symbol(f'{module}!{name}')}+0x{va - addr:x}"

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
            f"and try mode='auto' to fall back to a software breakpoint."
        )
    return (
        f"hw bp install failed: {err}. The 4-slot DR0..3 budget is the usual "
        f"cause; check `kdbg bps`. mode='soft' uses a software breakpoint "
        f"instead — unlimited, but PatchGuard-visible and hash-detectable."
    )


def _soft_bp_failure(
    err: Exception, *, is_user: bool, hw_error: Exception | None
) -> str:
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
    if hw_error is not None:
        parts.append(f"The hardware path was tried first and also failed: {hw_error}")
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
      - Walk target's PEB.Ldr once → {normalized_name: base}.
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
    candidates: list[tuple[str, int]] = []
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
        candidates.append((mod_name, base))

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
    target_loaded: dict[str, int] = {
        _normalize_module_name(m.name): m.base for m in loaded
    }

    stale: list[tuple[str, int, int]] = []  # (cached_name, cached_base, current_base)
    for mod_name, cached_base in candidates:
        norm = _normalize_module_name(mod_name)
        actual_base = target_loaded.get(norm)
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

        rsp = RspClient.connect("127.0.0.1", gdbstub_port, timeout=5.0)
        rsp.handshake()
        initial_sr = rsp.query_halt_reason()

        # VM is now halted — CR3 is stable, safe to walk kernel structures.
        store = SymbolStore(cfg.symbols_dir)
        from winbox.kdbg.symbols import ensure_nt_base_current
        ensure_nt_base_current(cfg, store)
        from winbox.kdbg.walk import list_processes
        procs = list_processes(cfg.vm_name, store)
        target_rec = next((p for p in procs if p.pid == target_pid), None)
        if target_rec is None:
            os.write(pipe_w, f"ERR: pid {target_pid} not found\n".encode())
            os.close(pipe_w)
            pipe_signaled = True
            rsp.cont()
            rsp.close()
            os._exit(1)
        target = TargetInfo(
            pid=target_rec.pid,
            dtb=target_rec.directory_table_base,
            name=target_rec.name,
            user_dtb=target_rec.user_directory_table_base,
            eprocess=target_rec.eprocess,
        )

        _validate_module_bases(cfg, rsp, target, store)

        listen_sock = _bind_unix_socket(sock_path(cfg))
        _write_session_file(session_path(cfg), {
            "target_pid": target.pid,
            "target_dtb": f"0x{target.dtb:x}",
            "target_name": target.name,
            "daemon_pid": os.getpid(),
            "gdbstub_port": gdbstub_port,
            "attach_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        session = DaemonSession(cfg=cfg, rsp=rsp, target=target, store=store)
        session._capture_stop(initial_sr)
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
