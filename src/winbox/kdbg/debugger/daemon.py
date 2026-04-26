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

Single-threaded serve loop: one op at a time. While a long-running op
(``cont``) is in flight, other connections get an immediate
``BUSY`` reply — except SIGUSR1 (sent by ``winbox kdbg interrupt``)
which interrupts the in-flight gdb wait and lets ``cont`` return.
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
from contextlib import suppress
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
from winbox.kdbg.walk import list_processes


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
    hits: int = 0


@dataclass
class StopState:
    """Latest debugger halt info (returned by ops that need it)."""

    vcpu: str             # gdb thread id, e.g. "01"
    rip: int
    cr3: int
    signal: int
    raw_regs: bytes       # full g-packet blob — kept so re-reads are cheap


@dataclass
class TargetInfo:
    pid: int
    dtb: int
    name: str


# ── Daemon process ──────────────────────────────────────────────────────


class DaemonError(RuntimeError):
    pass


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
        self._next_bp_id = 0
        self.stop: StopState | None = None
        self.attach_time = time.monotonic()

        # Set when an op accesses gdb so other ops can detect "in flight".
        self._busy = False

        # Set by signal handler when SIGUSR1 arrives — a hint to the cont
        # loop to break out.
        self._interrupt_pending = False

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
        try:
            result = method(**args)
        except TypeError as e:
            return reply_err(f"bad args for {op!r}: {e}")
        except Exception as e:  # noqa: BLE001 — surface any op-level failure
            return reply_err(f"{type(e).__name__}: {e}")
        if isinstance(result, dict):
            return reply_ok(result)
        return reply_ok({"value": result})

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

    def op_bp_add(self, target: str, mode: str = "hw") -> dict[str, Any]:
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
        """
        va = self._resolve_target(target)
        is_user = (va >> 47) != 0x1FFFF  # canonical-high == kernel half

        if mode not in ("hw", "soft", "auto"):
            raise ValueError(f"mode must be 'hw', 'soft', or 'auto'; got {mode!r}")

        # Track how the bp got installed for the registry + reply.
        installed_hw = False
        elapsed_ms = 0.0

        if mode in ("hw", "auto"):
            # Try hw first.
            t0 = time.monotonic()
            try:
                self.rsp.insert_breakpoint(va, kind=1, hardware=True)
                installed_hw = True
                elapsed_ms = (time.monotonic() - t0) * 1000.0
            except RspError as e:
                if mode == "hw":
                    raise RuntimeError(
                        f"hw bp install failed: {e}. The 4-slot DR0..3 budget "
                        f"may be exhausted; set mode='soft' to use a software "
                        f"breakpoint instead (unlimited but PG-visible / hash-"
                        f"detectable)."
                    ) from e
                # mode == "auto" — fall through to soft path

        if not installed_hw:
            # Software path. Kernel VAs get plain Z0 (kernel pages are
            # in every CR3); user VAs need the CR3-masquerade dance.
            t0 = time.monotonic()
            if is_user:
                report = install_user_breakpoint(
                    self.rsp, self.cfg.vm_name, self.store,
                    target_dtb=self.target.dtb,
                    user_va=va,
                )
                elapsed_ms = report.elapsed * 1000.0
            else:
                self.rsp.insert_breakpoint(va, kind=1)
                elapsed_ms = (time.monotonic() - t0) * 1000.0

        bp_id = self._next_bp_id
        self._next_bp_id += 1
        bp = Breakpoint(
            bp_id=bp_id,
            va=va,
            target=target,
            user_mode=is_user,
            hw=installed_hw,
            installed_at=time.monotonic(),
        )
        self.bps[bp_id] = bp
        return {
            "id": bp_id,
            "va": f"0x{va:x}",
            "user_mode": is_user,
            "hw": installed_hw,
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
                    "age_s": round(time.monotonic() - b.installed_at, 2),
                }
                for b in self.bps.values()
            ]
        }

    def op_bp_remove(self, id: int) -> dict[str, Any]:  # noqa: A002 — wire name
        bp = self.bps.get(id)
        if bp is None:
            raise ValueError(f"no bp with id {id}")
        try:
            # Route to the right packet (z0 vs z1) based on how it
            # was installed. Mismatching is a no-op or error in QEMU.
            self.rsp.remove_breakpoint(bp.va, kind=1, hardware=bp.hw)
        except RspError as e:
            # Surface but still drop from registry — the alternative is a
            # stale entry the user can't get rid of.
            del self.bps[id]
            packet = "z1" if bp.hw else "z0"
            raise RuntimeError(f"{packet} failed: {e}; bp untracked") from e
        del self.bps[id]
        return {"removed": id, "va": f"0x{bp.va:x}", "hw": bp.hw}

    def op_cont(self, timeout: float = 30.0) -> dict[str, Any]:
        """Resume; block until next stop *in target's CR3*. Silent-cont
        all other firings (typical when a bp hit is in shared code)."""
        target_dtb = self.target.dtb
        deadline = time.monotonic() + max(0.5, float(timeout))
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
                sr = self.rsp.wait_for_stop(timeout=remaining)
            except RspError as e:
                if "timed out" in str(e).lower():
                    # Wall-clock budget exhausted in wait_for_stop —
                    # interrupt the running VM so we end in a halted
                    # state and return cleanly.
                    try:
                        self.rsp.interrupt()
                        self.rsp.wait_for_stop(timeout=2.0)
                    except RspError:
                        pass
                    return {"reason": "timeout"}
                raise RuntimeError(f"cont/wait failed: {e}") from e

            if sr.signal != 5:
                # Not a bp — surface anyway, caller decides.
                self._capture_stop(sr)
                return {"reason": "signal", **self._stop_summary()}

            self.rsp.select_thread(sr.thread or "01")
            cr3 = self.rsp.read_cr3()
            if cr3 != target_dtb:
                # silent-continue — bump bp hit counter best-effort
                self._bump_bp_hits(self._read_rip(), in_target=False)
                continue

            self._capture_stop(sr)
            self._bump_bp_hits(self.stop.rip if self.stop else 0, in_target=True)
            return {"reason": "bp", **self._stop_summary()}

    def op_step(self) -> dict[str, Any]:
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        vcpu = self.stop.vcpu
        self.rsp.step(vcpu)
        sr = self.rsp.wait_for_stop(timeout=5.0)
        self.rsp.select_thread(sr.thread or vcpu)
        self._capture_stop(sr)
        return {"reason": "step", **self._stop_summary()}

    def op_interrupt(self) -> dict[str, Any]:
        """Mark interrupt-pending; if a cont is in flight (different
        connection), the loop will pick it up and break out."""
        self._interrupt_pending = True
        return {"queued": True}

    def op_regs(self) -> dict[str, Any]:
        if self.stop is None:
            # Re-read live — useful between ops.
            blob = self.rsp.read_registers()
            return _decode_regs(blob)
        return _decode_regs(self.stop.raw_regs)

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

        # Pick a vCPU and snapshot its CR3.
        threads = self.rsp.list_threads()
        if not threads:
            raise RuntimeError("no vCPUs returned by gdbstub")
        vcpu = threads[0]
        self.rsp.select_thread(vcpu)
        regs = self.rsp.read_registers()
        original_cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]

        try:
            mod = bytearray(regs)
            struct.pack_into("<Q", mod, _CR3_OFFSET_IN_G, self.target.dtb)
            resp = self.rsp._exchange(b"G" + bytes(mod).hex().encode("ascii"))
            if resp != b"OK":
                raise RuntimeError(f"G-packet (mem) rejected: {resp!r}")
            data = self.rsp.read_memory(va, length)
        finally:
            restore = bytearray(regs)
            struct.pack_into("<Q", restore, _CR3_OFFSET_IN_G, original_cr3)
            with suppress(Exception):
                self.rsp._exchange(b"G" + bytes(restore).hex().encode("ascii"))

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

        threads = self.rsp.list_threads()
        if not threads:
            raise RuntimeError("no vCPUs returned by gdbstub")
        vcpu = threads[0]
        self.rsp.select_thread(vcpu)
        regs = self.rsp.read_registers()
        original_cr3 = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]

        try:
            mod = bytearray(regs)
            struct.pack_into("<Q", mod, _CR3_OFFSET_IN_G, self.target.dtb)
            resp = self.rsp._exchange(b"G" + bytes(mod).hex().encode("ascii"))
            if resp != b"OK":
                raise RuntimeError(f"G-packet (write_mem) rejected: {resp!r}")
            # gdb ``M addr,len:hex`` writes payload bytes at addr.
            self.rsp.write_memory(va, payload)
        finally:
            restore = bytearray(regs)
            struct.pack_into("<Q", restore, _CR3_OFFSET_IN_G, original_cr3)
            with suppress(Exception):
                self.rsp._exchange(b"G" + bytes(restore).hex().encode("ascii"))

        return {"va": f"0x{va:x}", "length": len(payload)}

    def op_stack(self, n: int = 16) -> dict[str, Any]:
        """N qwords starting at RSP."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        n = max(1, min(int(n), 256))
        rsp_va = struct.unpack_from("<Q", self.stop.raw_regs, 7 * 8)[0]
        # Stack lives in target's address space — use the same masquerade-read.
        result = self.op_mem(rsp_va, n * 8)
        return {
            "rsp": f"0x{rsp_va:x}",
            "qwords": [
                "0x{:016x}".format(
                    int.from_bytes(bytes.fromhex(result["bytes"])[i:i+8], "little")
                )
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
        self.rsp.select_thread(vcpu)
        regs = self.rsp.read_registers()
        self.stop = StopState(
            vcpu=vcpu,
            rip=struct.unpack_from("<Q", regs, 16 * 8)[0],
            cr3=struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0],
            signal=sr.signal,
            raw_regs=regs,
        )

    def _stop_summary(self) -> dict[str, Any]:
        if self.stop is None:
            return {}
        bp_hit = next((b for b in self.bps.values() if b.va == self.stop.rip), None)
        return {
            "vcpu": self.stop.vcpu,
            "rip": f"0x{self.stop.rip:x}",
            "cr3": f"0x{self.stop.cr3:x}",
            "in_target": self.stop.cr3 == self.target.dtb,
            "bp_id": bp_hit.bp_id if bp_hit else None,
            "bp_target": bp_hit.target if bp_hit else None,
        }

    def _bump_bp_hits(self, va: int, *, in_target: bool) -> None:
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

    def _serve_one(self, conn: socket.socket) -> None:
        conn.settimeout(60.0)
        try:
            line = read_line(conn)
        except ProtocolError as e:
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
        # Remove bps first so the gdbstub's bp registry is clean.
        for bp in list(self.bps.values()):
            with suppress(Exception):
                self.rsp.remove_breakpoint(bp.va, kind=1)
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
        try:
            with suppress(Exception):
                self.rsp.cont()
            # Hold long enough that vCont;c is fully processed by
            # QEMU before we yank the socket. 100ms is more than
            # enough — vCont round-trip is sub-ms.
            import time as _time
            _time.sleep(0.1)
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
    need a DaemonSession yet."""
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
        with suppress(Exception):
            rsp._exchange(b"G" + bytes(restore).hex().encode("ascii"))


def _normalize_module_name(name: str) -> str:
    """Strip common PE suffixes for matching across naming conventions.

    SymbolStore short names: ``notepad``, ``ntdll`` (filename stems).
    PEB.Ldr BaseDllName values: ``notepad.exe``, ``ntdll.dll``.
    Match case-insensitively after stripping the extension.
    """
    n = name.lower().rsplit(".", 1)[0]
    return n


def _validate_module_bases(
    cfg: Config,
    rsp: "RspClient",
    target,
    store: SymbolStore,
) -> None:
    """Verify cached module bases match what's actually loaded in target.

    The check has TWO failure modes to distinguish:

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

    Strategy:
      - Walk target's PEB.Ldr once → {normalized_name: base}
      - For each cached store module: look it up in the target's
        loaded set. If found and bases mismatch → stale. If not
        found → skip silently.
      - Skip ``nt`` (kernel module, handled by kdbg_base_refresh).

    Raises ``DaemonError`` with remediation message listing each
    stale module — names match the ``kdbg_user_symbols_load`` arg
    the user should pass to fix it.
    """
    try:
        modules = store.list_modules()
    except Exception:
        return  # No store, nothing to validate

    # Filter to modules with cached bases that aren't the kernel.
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
        return  # Nothing to check; skip the PEB.Ldr walk entirely.

    # Walk target's PEB.Ldr to get the actual loaded modules.
    # ensure_types_loaded for _PEB / _PEB_LDR_DATA may be needed if
    # the store predates their inclusion — handle gracefully.
    from winbox.kdbg import ensure_types_loaded
    from winbox.kdbg.walk import list_user_modules
    try:
        ensure_types_loaded(cfg, store, ["_PEB", "_PEB_LDR_DATA"], module="nt")
        loaded = list_user_modules(cfg.vm_name, store, target)
    except Exception as e:
        # Couldn't walk PEB.Ldr — skip validation rather than block
        # the attach. The user will get a clearer error later if a
        # specific bp install actually fails on a stale base.
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
        details = ", ".join(
            f"{name} (cached 0x{cached:x}, actual 0x{actual:x})"
            for name, cached, actual in stale
        )
        raise DaemonError(
            f"stale module bases for {target.name}: {details}. "
            f"ASLR moved them since symbols were loaded. "
            f"Re-run kdbg_user_symbols_load for each stale module before retrying."
        )


def fork_daemon(
    cfg: Config,
    target_pid: int,
    *,
    gdbstub_port: int = 1234,
) -> int:
    """Fork off a session daemon. Parent returns the daemon pid; child
    never returns from this function (it enters serve_forever).

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
    try:
        _detach_to_log(log_path(cfg))
        lock_fd = _acquire_lock_or_die(lock_path(cfg))

        # Resolve target now that we're inside the daemon (parent doesn't
        # need to talk to gdb).
        store = SymbolStore(cfg.symbols_dir)
        procs = list_processes(cfg.vm_name, store)
        target = next((p for p in procs if p.pid == target_pid), None)
        if target is None:
            os.write(pipe_w, f"ERR: pid {target_pid} not found\n".encode())
            os._exit(1)

        rsp = RspClient.connect("127.0.0.1", gdbstub_port, timeout=5.0)
        rsp.handshake()
        rsp.query_halt_reason()

        # Stale-base check. If the VM rebooted since the symbol store
        # was last updated, ASLR moved every module's base. The cached
        # ``base`` field in store entries points nowhere in current
        # process — Z0 user_va install fails later with cryptic E22.
        # Catch it now and tell the user exactly what to do.
        # Only validates store entries that are ACTUALLY loaded in the
        # target — irrelevant entries (e.g. notepad symbols cached
        # while now attaching to cyserver) are skipped without complaint.
        _validate_module_bases(cfg, rsp, target, store)

        listen_sock = _bind_unix_socket(sock_path(cfg))
        info = TargetInfo(pid=target.pid, dtb=target.directory_table_base, name=target.name)
        _write_session_file(session_path(cfg), {
            "target_pid": info.pid,
            "target_dtb": f"0x{info.dtb:x}",
            "target_name": info.name,
            "daemon_pid": os.getpid(),
            "gdbstub_port": gdbstub_port,
            "attach_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        session = DaemonSession(cfg=cfg, rsp=rsp, target=info, store=store)
        _install_signal_handlers(session)

        os.write(pipe_w, b"OK\n")
        os.close(pipe_w)

        sys.stderr.write(f"[kdbg-daemon pid={os.getpid()}] attached to "
                         f"{info.name}({info.pid}) dtb=0x{info.dtb:x}\n")
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
        os.write(pipe_w, f"ERR: {e}\n".encode())
        os.close(pipe_w)
        os._exit(1)
    except Exception as e:  # noqa: BLE001 — surface anything that broke setup
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
