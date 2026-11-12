"""Shared types, errors, path helpers, and constants for the daemon package."""

from __future__ import annotations

import os
import re
import secrets
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from winbox.config import Config


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
_DAEMON_STARTUP_TIMEOUT = 60.0
_STARTUP_STATUS_MAX_BYTES = 64 * 1024
_MODULE_OFFSET_TARGET = re.compile(
    r"^(?P<module>[A-Za-z0-9_.-]+)\+(?P<offset>0x[0-9a-fA-F]+)$"
)


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
    create_time: int = 0  # captured EPROCESS.CreateTime identity evidence

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


# ── Errors ──────────────────────────────────────────────────────────────


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

    def __init__(self, error: "RspError") -> None:
        self.error = error
