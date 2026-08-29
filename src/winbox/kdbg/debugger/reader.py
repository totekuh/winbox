"""Persistent, process-safe RSP transport for debugger memory operations.

QEMU exposes one gdbstub client at a time.  Keeping that client inside each
CLI or MCP process would make the first long-lived process monopolise the
stub, while reconnecting for every individual memory read would be slow and
would repeatedly perturb QEMU's debug state.  This module therefore owns the
RSP connection in a tiny broker process and exposes coherent read snapshots
over a private Unix socket.

The ownership boundary is deliberate:

* QMP/HMP is used only to bootstrap the gdbserver.
* RSP owns halt/resume, register reads/writes, CR3 masquerade, and memory.
* One Unix client connection represents one complete snapshot transaction.
* The original register block is restored before the guest is resumed.

Repeated RSP stop/resume is only enabled after the guest reports Windows CET
``UserShadowStack=OFF``.  On affected QEMU/KVM versions, stop/resume itself can
lose the guest's shadow-stack pointer and bugcheck Windows; this module fails
closed before opening GDB unless the explicit preparation has taken effect.

The broker keeps the guest running between transactions.  If CR3 restoration
fails it fails closed: the guest is left halted and the poisoned broker exits.
"""

from __future__ import annotations

import atexit
import fcntl
import json
import os
import signal
import socket
import struct
import time
from contextlib import ExitStack, contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from winbox.config import Config
from winbox.kdbg.admission import (
    OperationBusyError,
    OperationLease,
    active_admission,
    admit_operation,
)
from winbox.kdbg.debugger.install import _CR3_OFFSET_IN_G
from winbox.kdbg.debugger.protocol import ProtocolError, decode, encode, read_line
from winbox.kdbg.debugger.rsp import RspClient, RspError, StopReply
from winbox.kdbg.hmp import HmpError, gdbstub_has_client, hmp, probe_port


class ReaderError(HmpError):
    """A persistent debugger-reader transport or safety failure."""


_MAX_READ = 1 << 20
_DEFAULT_PORT = 1234
_READER_STARTUP_TIMEOUT = 30.0
_STARTUP_STATUS_MAX_BYTES = 64 * 1024
_DEFAULT_SNAPSHOT_DURATION_MS = 15_000
_DEFAULT_SNAPSHOT_MAX_READS = 16_384
_DEFAULT_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024
_SNAPSHOT_CACHE_MAX_BYTES = 2 * 1024 * 1024
_active_snapshot: ContextVar["DebugSnapshot | None"] = ContextVar(
    "winbox_kdbg_snapshot", default=None,
)


@dataclass(frozen=True)
class SnapshotBudget:
    """Hard upper bounds for one coherent stopped-guest transaction.

    The reader broker enforces these limits, so an abandoned or unusually
    expensive client cannot hold Windows at an RSP stop indefinitely.  The
    duration bound is also the socket-idle deadline in the broker: a client
    doing CPU work after its final read cannot strand the guest merely by
    forgetting to close its snapshot.
    """

    max_duration_ms: int = _DEFAULT_SNAPSHOT_DURATION_MS
    max_reads: int = _DEFAULT_SNAPSHOT_MAX_READS
    max_bytes: int = _DEFAULT_SNAPSHOT_MAX_BYTES

    def __post_init__(self) -> None:
        if not 100 <= self.max_duration_ms <= 60_000:
            raise ValueError("snapshot max_duration_ms must be between 100 and 60000")
        if not 1 <= self.max_reads <= 65_536:
            raise ValueError("snapshot max_reads must be between 1 and 65536")
        if not 1 <= self.max_bytes <= 64 * 1024 * 1024:
            raise ValueError("snapshot max_bytes must be between 1 and 67108864")

    def public(self) -> dict[str, int]:
        return {
            "max_duration_ms": self.max_duration_ms,
            "max_reads": self.max_reads,
            "max_bytes": self.max_bytes,
        }

    @classmethod
    def from_wire(cls, raw: object) -> "SnapshotBudget":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ReaderError("snapshot budget must be an object")
        try:
            values = {
                key: int(raw[key])
                for key in ("max_duration_ms", "max_reads", "max_bytes")
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("snapshot budget has invalid fields") from exc
        if any(isinstance(raw[key], bool) for key in values):
            raise ReaderError("snapshot budget fields must be integers")
        try:
            return cls(**values)
        except ValueError as exc:
            raise ReaderError(str(exc)) from exc


class SnapshotBudgetError(ReaderError):
    """A stopped snapshot reached its explicit cooperative safety bound."""

    code = "snapshot_budget_exceeded"
    retryable = True

    def __init__(
        self,
        reason: str,
        *,
        budget: SnapshotBudget,
        read_count: int,
        bytes_read: int,
        elapsed_ms: float,
    ) -> None:
        self.details = {
            "reason": reason,
            "budget": budget.public(),
            "read_count": read_count,
            "bytes_read": bytes_read,
            "elapsed_ms": round(max(0.0, elapsed_ms), 3),
        }
        super().__init__(
            f"snapshot budget exceeded ({reason}); guest was resumed after "
            f"{read_count} reads / {bytes_read} bytes"
        )


def _runtime_dir(cfg: Config) -> Path:
    path = Path(cfg.winbox_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def lock_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.lock"


def sock_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.sock"


def session_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.session.json"


def log_path(cfg: Config) -> Path:
    return _runtime_dir(cfg) / "kdbg-reader.log"


def _reply_ok(result: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result or {}}


def _reply_err(exc: BaseException | str) -> dict[str, Any]:
    """Serialize typed broker failures without breaking legacy string peers."""
    if isinstance(exc, BaseException):
        error: dict[str, Any] = {"message": str(exc)}
        code = getattr(exc, "code", None)
        if isinstance(code, str) and code:
            error["code"] = code[:64]
        retryable = getattr(exc, "retryable", None)
        if isinstance(retryable, bool):
            error["retryable"] = retryable
        details = getattr(exc, "details", None)
        if isinstance(details, dict):
            error["details"] = details
        return {"ok": False, "error": error}
    return {"ok": False, "error": str(exc)}


def _bounded_counter(value: object, fallback: int) -> int:
    """Accept broker-owned non-negative counters without trusting wire junk."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return fallback
    return value


def _request(sock: socket.socket, op: str, **args: Any) -> dict[str, Any]:
    try:
        sock.sendall(encode({"op": op, "args": args}))
    except OSError as write_exc:
        # The broker may have hit its idle duration while this client was
        # computing. It queues a typed budget error before resuming/closing;
        # consume that final frame instead of laundering it into Broken pipe.
        try:
            reply = decode(read_line(sock, max_bytes=(_MAX_READ * 2) + 65536))
        except (OSError, ProtocolError) as exc:
            raise ReaderError(f"RSP reader broker communication failed: {exc}") from write_exc
    else:
        try:
            reply = decode(read_line(sock, max_bytes=(_MAX_READ * 2) + 65536))
        except (OSError, ProtocolError) as exc:
            raise ReaderError(f"RSP reader broker communication failed: {exc}") from exc
    if not reply.get("ok"):
        raw_error = reply.get("error")
        if isinstance(raw_error, dict):
            error = ReaderError(str(raw_error.get("message") or "RSP reader broker failed"))
            code = raw_error.get("code")
            if isinstance(code, str):
                error.code = code
            if isinstance(raw_error.get("retryable"), bool):
                error.retryable = raw_error["retryable"]
            if isinstance(raw_error.get("details"), dict):
                error.details = raw_error["details"]
            raise error
        raise ReaderError(raw_error or "RSP reader broker failed")
    result = reply.get("result")
    if not isinstance(result, dict):
        raise ReaderError("RSP reader broker returned a malformed result")
    return result


class DebugSnapshot:
    """Interface consumed by ``memory.py`` and ``walk.py``."""

    vm_name: str
    current_cr3: int
    cr3_candidates: tuple[int, ...]
    kernel_gs_bases: tuple[int, ...]
    # One tuple per halted QEMU vCPU: (numeric vCPU id, candidate KPCR bases).
    # ``kernel_gs_bases`` remains the flattened compatibility view used by
    # nt-base discovery; callers that need scheduler attribution must retain
    # this per-vCPU relationship.
    vcpu_kernel_gs_bases: tuple[tuple[int, tuple[int, ...]], ...]

    def read_virtual(self, cr3: int, addr: int, length: int) -> bytes:
        raise NotImplementedError

    def read_physical(self, addr: int, length: int) -> bytes:
        raise NotImplementedError

    def phase_started(self, name: str) -> None:
        """Record an operator-visible phase; adapters may implement this."""

    def phase_finished(self, name: str, elapsed_ms: float) -> None:
        """Record one completed phase; adapters may implement this."""

    def operation_metadata(self) -> dict[str, Any]:
        """Additive timing/ownership evidence for a coherent RSP stop."""
        return {
            "snapshot_id": None,
            "reader_owner": "embedded_snapshot",
            "admission": "embedded",
            "queue_delay_ms": 0.0,
            "stop_duration_ms": None,
            "read_count": None,
            "bytes_read": None,
            "logical_read_count": None,
            "logical_bytes_read": None,
            "cache_hits": None,
            "budget": None,
            "budget_exhausted": False,
            "phases_ms": {},
        }


def snapshot_metadata(snapshot: DebugSnapshot | None) -> dict[str, Any]:
    """Return safe timing evidence even for legacy/mock snapshot contexts."""
    if snapshot is None:
        return {
            "snapshot_id": None,
            "reader_owner": "unknown",
            "admission": "unknown",
            "queue_delay_ms": None,
            "stop_duration_ms": None,
            "read_count": None,
            "bytes_read": None,
            "budget": None,
            "budget_exhausted": False,
        }
    try:
        value = snapshot.operation_metadata()
    except (AttributeError, TypeError, ValueError):
        value = None
    return value if isinstance(value, dict) else {
        "snapshot_id": None,
        "reader_owner": "unknown",
        "admission": "unknown",
        "queue_delay_ms": None,
        "stop_duration_ms": None,
        "read_count": None,
        "bytes_read": None,
        "logical_read_count": None,
        "logical_bytes_read": None,
        "cache_hits": None,
        "budget": None,
        "budget_exhausted": False,
        "phases_ms": {},
    }


class _RemoteSnapshot(DebugSnapshot):
    def __init__(
        self, cfg: Config, sock: socket.socket, begin: dict[str, Any],
        admission: ExitStack, lease: OperationLease, budget: SnapshotBudget,
    ):
        self.cfg = cfg
        self.vm_name = cfg.vm_name
        self._sock = sock
        self._closed = False
        self._admission = admission
        self._lease = lease
        self._budget = budget
        self._read_count = 0
        self._bytes_read = 0
        self._logical_read_count = 0
        self._logical_bytes_read = 0
        self._cache_hits = 0
        self._phases_ms: dict[str, float] = {}
        self._budget_error: dict[str, Any] | None = None
        self.current_cr3 = int(begin["current_cr3"], 0)
        self.cr3_candidates = tuple(int(value, 0) for value in begin["cr3s"])
        self.kernel_gs_bases = tuple(
            int(value, 0) for value in begin.get("kernel_gs_bases", [])
        )
        vcpu_bases: list[tuple[int, tuple[int, ...]]] = []
        for item in begin.get("vcpu_kernel_gs_bases", []):
            if not isinstance(item, dict):
                continue
            try:
                vcpu = int(item["vcpu"])
                bases = tuple(int(value, 0) for value in item.get("bases", []))
            except (KeyError, TypeError, ValueError):
                continue
            if vcpu >= 0 and bases:
                vcpu_bases.append((vcpu, bases))
        self.vcpu_kernel_gs_bases = tuple(vcpu_bases)

    @classmethod
    def connect(
        cls,
        cfg: Config,
        *,
        timeout: float = 15.0,
        budget: SnapshotBudget | None = None,
    ) -> "_RemoteSnapshot":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        admission = ExitStack()
        selected_budget = budget or SnapshotBudget()
        try:
            lease = admission.enter_context(admit_operation(
                _runtime_dir(cfg), "kdbg-snapshot", operation="snapshot",
                owner="persistent_reader", details={
                    "vm_name": cfg.vm_name,
                    # Doctor exposes the live admission record. Include the
                    # hard stop contract there too, so an active reader is
                    # observable without having to wait for its result.
                    "budget": selected_budget.public(),
                },
            ))
            sock.settimeout(timeout)
            sock.connect(str(sock_path(cfg)))
            begin = _request(
                sock, "begin", snapshot_id=lease.token,
                budget=selected_budget.public(),
            )
            return cls(cfg, sock, begin, admission, lease, selected_budget)
        except OperationBusyError as exc:
            sock.close()
            admission.close()
            error = ReaderError(str(exc))
            error.code = exc.code
            error.retryable = exc.retryable
            error.details = exc.details
            raise error from exc
        except BaseException:
            sock.close()
            admission.close()
            raise

    def read_virtual(self, cr3: int, addr: int, length: int) -> bytes:
        if length <= 0:
            return b""
        if length > _MAX_READ:
            raise ReaderError(f"single debugger read capped at {_MAX_READ} bytes")
        try:
            result = _request(
                self._sock, "read", cr3=f"0x{cr3:x}", addr=f"0x{addr:x}", length=length,
            )
        except ReaderError as exc:
            self._record_budget_error(exc)
            raise
        try:
            data = bytes.fromhex(result["bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("RSP reader returned invalid memory bytes") from exc
        self._account_read(data, result)
        return data

    def read_physical(self, addr: int, length: int) -> bytes:
        if length <= 0:
            return b""
        if length > _MAX_READ:
            raise ReaderError(f"single debugger read capped at {_MAX_READ} bytes")
        try:
            result = _request(
                self._sock, "read_phys", addr=f"0x{addr:x}", length=length,
            )
        except ReaderError as exc:
            self._record_budget_error(exc)
            raise
        try:
            data = bytes.fromhex(result["bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderError("RSP reader returned invalid physical bytes") from exc
        self._account_read(data, result)
        return data

    def _account_read(self, data: bytes, result: dict[str, Any]) -> None:
        self._logical_read_count += 1
        self._logical_bytes_read += len(data)
        # The broker owns the actual RSP connection and cache, so only it can
        # distinguish a client request from a physical transport fill.  Do not
        # turn a cache hit into a fictitious wire read in operator accounting.
        self._read_count = _bounded_counter(
            result.get("transport_read_count"), self._read_count,
        )
        self._bytes_read = _bounded_counter(
            result.get("transport_bytes_read"), self._bytes_read,
        )
        cache_hits = result.get("cache_hits")
        self._cache_hits = _bounded_counter(cache_hits, self._cache_hits)

    def _record_budget_error(self, exc: ReaderError) -> None:
        if getattr(exc, "code", None) != SnapshotBudgetError.code:
            return
        details = getattr(exc, "details", None)
        if isinstance(details, dict):
            self._budget_error = dict(details)
            self._read_count = int(details.get("read_count", self._read_count))
            self._bytes_read = int(details.get("bytes_read", self._bytes_read))

    def phase_started(self, name: str) -> None:
        return None

    def phase_finished(self, name: str, elapsed_ms: float) -> None:
        safe = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in name)[:64]
        if not safe or elapsed_ms < 0:
            return
        self._phases_ms[safe] = round(self._phases_ms.get(safe, 0.0) + elapsed_ms, 3)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            result = _request(self._sock, "end")
            self._read_count = _bounded_counter(
                result.get("transport_read_count"), self._read_count,
            )
            self._bytes_read = _bounded_counter(
                result.get("transport_bytes_read"), self._bytes_read,
            )
            self._cache_hits = _bounded_counter(
                result.get("cache_hits"), self._cache_hits,
            )
        finally:
            try:
                self._sock.close()
            finally:
                self._admission.close()

    def operation_metadata(self) -> dict[str, Any]:
        timing = self._lease.metadata()
        return {
            "snapshot_id": timing["id"],
            "reader_owner": "persistent_reader",
            "admission": timing["admission"],
            "queue_delay_ms": timing["queue_delay_ms"],
            "stop_duration_ms": timing["elapsed_ms"],
            "read_count": self._read_count,
            "bytes_read": self._bytes_read,
            "logical_read_count": self._logical_read_count,
            "logical_bytes_read": self._logical_bytes_read,
            "cache_hits": self._cache_hits,
            "budget": self._budget.public(),
            "budget_exhausted": self._budget_error is not None,
            "budget_error": self._budget_error,
            "phases_ms": dict(self._phases_ms),
        }


class _LocalRspSnapshot(DebugSnapshot):
    """Snapshot adapter for code already owning a halted RSP connection."""

    def __init__(self, vm_name: str, rsp: RspClient, stop: StopReply):
        self.vm_name = vm_name
        self.rsp = rsp
        threads = rsp.list_threads()
        if not threads:
            raise ReaderError("gdbstub returned no vCPUs")
        self._vcpu = stop.thread or rsp.current_thread()
        if self._vcpu not in threads:
            # Accept equivalent zero-padded spellings (QEMU versions differ
            # between "1" and "01"), but never silently select another CPU.
            try:
                wanted = int(self._vcpu, 16)
                self._vcpu = next(t for t in threads if int(t, 16) == wanted)
            except (ValueError, StopIteration) as exc:
                raise ReaderError(
                    f"stop vCPU {self._vcpu!r} is absent from gdbstub thread list"
                ) from exc
        cr3s: list[int] = []
        kernel_gs_bases: list[int] = []
        vcpu_kernel_gs_bases: list[tuple[int, tuple[int, ...]]] = []
        regs_by_thread: dict[str, bytes] = {}
        for thread in threads:
            rsp.select_thread(thread)
            regs = rsp.read_registers()
            regs_by_thread[thread] = regs
            value = struct.unpack_from("<Q", regs, _CR3_OFFSET_IN_G)[0]
            if value not in cr3s:
                cr3s.append(value)
            # QEMU's x86-64 XML places gs_base and k_gs_base at offsets
            # 172/180. Depending on whether this vCPU stopped in user or
            # kernel mode, either side of SWAPGS can contain KPCR. Keep only
            # canonical-high candidates and validate IdtBase later.
            vcpu_bases: list[int] = []
            for offset in (172, 180):
                base = struct.unpack_from("<Q", regs, offset)[0]
                if base >> 47 == 0x1FFFF:
                    if base not in vcpu_bases:
                        vcpu_bases.append(base)
                    if base not in kernel_gs_bases:
                        kernel_gs_bases.append(base)
            try:
                vcpu = int(thread, 16)
            except ValueError as exc:
                raise ReaderError(f"gdbstub returned invalid vCPU id {thread!r}") from exc
            if vcpu_bases:
                vcpu_kernel_gs_bases.append((vcpu, tuple(vcpu_bases)))
        rsp.select_thread(self._vcpu)
        self._original_regs = regs_by_thread.get(self._vcpu) or rsp.read_registers()
        self.current_cr3 = struct.unpack_from(
            "<Q", self._original_regs, _CR3_OFFSET_IN_G,
        )[0]
        self.cr3_candidates = tuple(cr3s)
        self.kernel_gs_bases = tuple(kernel_gs_bases)
        self.vcpu_kernel_gs_bases = tuple(vcpu_kernel_gs_bases)
        self._active_cr3 = self.current_cr3
        self._physical = False
        self._poisoned = False
        self._registers_dirty = False
        self._virtual_cache: dict[tuple[int, int, int], bytes] = {}
        self._virtual_cache_bytes = 0
        self._transport_read_count = 0
        self._transport_bytes_read = 0
        self._logical_read_count = 0
        self._logical_bytes_read = 0
        self._cache_hits = 0
        self._phases_ms: dict[str, float] = {}

    def _set_cr3(self, cr3: int) -> None:
        if self._physical:
            self._set_physical(False)
        if cr3 == self._active_cr3:
            return
        regs = bytearray(self._original_regs)
        struct.pack_into("<Q", regs, _CR3_OFFSET_IN_G, cr3)
        reply = self.rsp.write_registers(bytes(regs))
        if reply != b"OK":
            raise ReaderError(f"gdbstub rejected CR3 0x{cr3:x}: {reply!r}")
        self._active_cr3 = cr3
        self._registers_dirty = True

    def _set_physical(self, enabled: bool) -> None:
        if self._physical == enabled:
            return
        self.rsp.set_physical_memory_mode(enabled)
        self._physical = enabled

    def virtual_cache_hit(self, cr3: int, addr: int, length: int) -> bool:
        """Whether the exact requested range can avoid another RSP read.

        The broker checks this before budget admission.  A cached repeat has
        no wire cost, while a new fill must remain within the transport caps.
        """
        return (cr3, addr, length) in self._virtual_cache

    def transport_counters(self) -> dict[str, int]:
        return {
            "transport_read_count": self._transport_read_count,
            "transport_bytes_read": self._transport_bytes_read,
            "logical_read_count": self._logical_read_count,
            "logical_bytes_read": self._logical_bytes_read,
            "cache_hits": self._cache_hits,
        }

    def read_virtual(self, cr3: int, addr: int, length: int) -> bytes:
        self._logical_read_count += 1
        self._logical_bytes_read += max(0, length)
        key = (cr3, addr, length)
        cached = self._virtual_cache.get(key)
        if cached is not None:
            self._cache_hits += 1
            return cached
        self._set_cr3(cr3)
        data = self.rsp.read_memory(addr, length)
        self._transport_read_count += 1
        self._transport_bytes_read += len(data)
        # Exact-range caching is intentionally conservative.  It cannot change
        # read semantics, only collapse duplicate reads within one halted stop.
        if 0 < len(data) <= 4096 and self._virtual_cache_bytes + len(data) <= _SNAPSHOT_CACHE_MAX_BYTES:
            self._virtual_cache[key] = data
            self._virtual_cache_bytes += len(data)
        return data

    def read_physical(self, addr: int, length: int) -> bytes:
        self._set_physical(True)
        try:
            data = self.rsp.read_memory(addr, length)
            self._transport_read_count += 1
            self._transport_bytes_read += len(data)
            self._logical_read_count += 1
            self._logical_bytes_read += max(0, length)
            return data
        finally:
            self._set_physical(False)

    def phase_started(self, name: str) -> None:
        # Kept for the protocol symmetry; accumulation occurs on finish.
        return None

    def phase_finished(self, name: str, elapsed_ms: float) -> None:
        safe = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in name)[:64]
        if not safe or elapsed_ms < 0:
            return
        self._phases_ms[safe] = round(self._phases_ms.get(safe, 0.0) + elapsed_ms, 3)

    def operation_metadata(self) -> dict[str, Any]:
        return {
            "snapshot_id": None,
            "reader_owner": "interactive_daemon",
            "admission": "embedded",
            "queue_delay_ms": 0.0,
            "stop_duration_ms": None,
            "read_count": self._transport_read_count,
            "bytes_read": self._transport_bytes_read,
            "logical_read_count": self._logical_read_count,
            "logical_bytes_read": self._logical_bytes_read,
            "cache_hits": self._cache_hits,
            "budget": None,
            "budget_exhausted": False,
            "phases_ms": dict(self._phases_ms),
        }

    def restore(self) -> None:
        try:
            if self._physical:
                self._set_physical(False)
            # QEMU's x86-64 G handler can lose hidden CS compatibility-mode
            # state even when handed the exact blob returned by g. A
            # read-only snapshot in the already-active CR3 has nothing to
            # restore, so never issue that dangerous redundant G packet.
            if self._registers_dirty:
                reply = self.rsp.write_registers(self._original_regs)
                if reply != b"OK":
                    raise ReaderError(
                        f"gdbstub rejected register restore: {reply!r}"
                    )
            self._active_cr3 = self.current_cr3
            self._registers_dirty = False
        except BaseException:
            self._poisoned = True
            raise


def current_snapshot(vm_name: str | None = None) -> DebugSnapshot | None:
    snapshot = _active_snapshot.get()
    if snapshot is not None and vm_name is not None and snapshot.vm_name != vm_name:
        return None
    return snapshot


@contextmanager
def snapshot_phase(name: str) -> Iterator[None]:
    """Attribute caller work to a named phase of the active stop.

    The phase is advisory accounting only; it never starts a snapshot and is
    intentionally harmless in unit fixtures or code outside a debug stop.
    """
    snapshot = current_snapshot()
    started = time.monotonic()
    if snapshot is not None:
        snapshot.phase_started(name)
    try:
        yield
    finally:
        if snapshot is not None:
            snapshot.phase_finished(name, (time.monotonic() - started) * 1000)


@contextmanager
def use_local_rsp(
    vm_name: str, rsp: RspClient, stop: StopReply,
) -> Iterator[DebugSnapshot]:
    """Expose an already halted RSP connection to walkers in this process."""
    existing = current_snapshot(vm_name)
    if existing is not None:
        yield existing
        return
    snapshot = _LocalRspSnapshot(vm_name, rsp, stop)
    token = _active_snapshot.set(snapshot)
    try:
        yield snapshot
    finally:
        try:
            snapshot.restore()
        finally:
            _active_snapshot.reset(token)


class _ReaderBroker:
    def __init__(self, cfg: Config, rsp: RspClient, port: int):
        self.cfg = cfg
        self.rsp = rsp
        self.port = port
        self.shutdown_requested = False
        self.poisoned = False

    def _halt_snapshot(self) -> tuple[StopReply, _LocalRspSnapshot]:
        self.rsp.interrupt()
        stop = self.rsp.wait_for_stop(timeout=10.0)
        return stop, _LocalRspSnapshot(self.cfg.vm_name, self.rsp, stop)

    def serve(self, listener: socket.socket) -> None:
        listener.settimeout(0.5)
        while not self.shutdown_requested and not self.poisoned:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    conn.settimeout(30.0)
                    # A standalone shutdown request does not halt the guest.
                    first = decode(read_line(conn))
                    if first.get("op") == "shutdown":
                        self.shutdown_requested = True
                        conn.sendall(encode(_reply_ok()))
                        continue
                    if first.get("op") != "begin":
                        conn.sendall(encode(_reply_err("expected begin or shutdown")))
                        continue
                    self._serve_snapshot_after_begin(conn, first)
                except (OSError, ProtocolError):
                    continue

    def _serve_snapshot_after_begin(self, conn: socket.socket, begin: dict[str, Any]) -> None:
        snapshot: _LocalRspSnapshot | None = None
        try:
            budget = SnapshotBudget.from_wire((begin.get("args") or {}).get("budget"))
            try:
                stop, snapshot = self._halt_snapshot()
            except BaseException as exc:
                # A rebooted/dead gdbstub is not recoverable inside this RSP
                # connection. Tell the caller immediately, then exit so the
                # next call can spawn a fresh broker against the new stub.
                with suppress(OSError):
                    conn.sendall(encode(_reply_err(
                        f"{type(exc).__name__}: {exc}"
                    )))
                self.shutdown_requested = True
                return
            started = time.monotonic()

            def budget_error(reason: str) -> SnapshotBudgetError:
                counters = snapshot.transport_counters()
                return SnapshotBudgetError(
                    reason, budget=budget,
                    read_count=counters["transport_read_count"],
                    bytes_read=counters["transport_bytes_read"],
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )

            def check_transport_fill(length: int) -> None:
                elapsed_ms = (time.monotonic() - started) * 1000
                counters = snapshot.transport_counters()
                if elapsed_ms >= budget.max_duration_ms:
                    raise budget_error("duration")
                if counters["transport_read_count"] >= budget.max_reads:
                    raise budget_error("read_count")
                if counters["transport_bytes_read"] + length > budget.max_bytes:
                    raise budget_error("bytes")

            conn.sendall(encode(_reply_ok({
                "stop": stop.raw,
                "current_cr3": f"0x{snapshot.current_cr3:x}",
                "cr3s": [f"0x{value:x}" for value in snapshot.cr3_candidates],
                "kernel_gs_bases": [
                    f"0x{value:x}" for value in snapshot.kernel_gs_bases
                ],
                "vcpu_kernel_gs_bases": [
                    {
                        "vcpu": vcpu,
                        "bases": [f"0x{value:x}" for value in bases],
                    }
                    for vcpu, bases in snapshot.vcpu_kernel_gs_bases
                ],
            })))
            while True:
                remaining = (budget.max_duration_ms / 1000) - (time.monotonic() - started)
                if remaining <= 0:
                    conn.sendall(encode(_reply_err(budget_error("duration"))))
                    return
                conn.settimeout(min(30.0, max(0.001, remaining)))
                try:
                    request = decode(read_line(conn))
                except TimeoutError:
                    # A client may be doing CPU work between reads. Queue a
                    # typed reply before cleanup; its next receive observes
                    # the cause instead of a mysterious closed socket.
                    with suppress(OSError):
                        conn.sendall(encode(_reply_err(budget_error("duration"))))
                    return
                op = request.get("op")
                args = request.get("args") or {}
                try:
                    if op == "read":
                        length = int(args["length"])
                        if not 0 <= length <= _MAX_READ:
                            raise ReaderError(f"invalid read length {length}")
                        cr3 = int(args["cr3"], 0)
                        address = int(args["addr"], 0)
                        if not snapshot.virtual_cache_hit(cr3, address, length):
                            check_transport_fill(length)
                        data = snapshot.read_virtual(
                            cr3, address, length,
                        )
                        conn.sendall(encode(_reply_ok({
                            "bytes": data.hex(), **snapshot.transport_counters(),
                        })))
                    elif op == "read_phys":
                        length = int(args["length"])
                        if not 0 <= length <= _MAX_READ:
                            raise ReaderError(f"invalid read length {length}")
                        check_transport_fill(length)
                        data = snapshot.read_physical(int(args["addr"], 0), length)
                        conn.sendall(encode(_reply_ok({
                            "bytes": data.hex(), **snapshot.transport_counters(),
                        })))
                    elif op == "end":
                        counters = snapshot.transport_counters()
                        snapshot.restore()
                        snapshot = None
                        try:
                            self.rsp.cont()
                        except BaseException:
                            # Registers are back, but QEMU did not confirm
                            # execution resumed. Do not accept another client
                            # against an indeterminate/halted guest.
                            self.poisoned = True
                            raise
                        conn.sendall(encode(_reply_ok({
                            **counters,
                            "budget": budget.public(),
                        })))
                        return
                    else:
                        conn.sendall(encode(_reply_err(f"unknown reader op {op!r}")))
                except BaseException as exc:
                    with suppress(OSError):
                        conn.sendall(encode(_reply_err(exc)))
                    if snapshot is not None and snapshot._poisoned:
                        self.poisoned = True
                        return
        finally:
            if snapshot is not None:
                try:
                    snapshot.restore()
                except BaseException:
                    self.poisoned = True
                if not self.poisoned:
                    try:
                        self.rsp.cont()
                    except BaseException:
                        self.poisoned = True


def _reader_alive(cfg: Config) -> bool:
    path = lock_path(cfg)
    if not path.exists():
        return False
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def reader_info(cfg: Config) -> dict[str, Any] | None:
    """Return verified live-broker metadata, or ``None`` when idle.

    The lock is authoritative; a leftover session JSON file by itself never
    counts as a live reader after a crash or reboot.
    """
    if not _reader_alive(cfg):
        return None
    admission = active_admission(_runtime_dir(cfg), "kdbg-snapshot")
    try:
        info = json.loads(session_path(cfg).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result = {"active": True}
        if admission is not None:
            result["snapshot"] = admission
        return result
    if not isinstance(info, dict):
        result = {"active": True}
        if admission is not None:
            result["snapshot"] = admission
        return result
    result = {"active": True, **info}
    if admission is not None:
        result["snapshot"] = admission
    return result


def _acquire_lock(cfg: Config) -> int:
    fd = os.open(lock_path(cfg), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise ReaderError("another RSP reader owns the gdbstub") from exc
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())
    return fd


def _detach_to_log(cfg: Config) -> None:
    os.setsid()
    stream = open(log_path(cfg), "ab", buffering=0)
    os.dup2(stream.fileno(), 1)
    os.dup2(stream.fileno(), 2)
    with open(os.devnull, "rb") as devnull:
        os.dup2(devnull.fileno(), 0)


def _bind_listener(cfg: Config) -> socket.socket:
    path = sock_path(cfg)
    with suppress(OSError):
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)
    listener.listen(16)
    return listener


def _open_rsp(cfg: Config, port: int) -> RspClient:
    if gdbstub_has_client(port):
        raise ReaderError(
            "gdbstub already has a client; detach the interactive debugger first"
        )
    if not probe_port("127.0.0.1", port):
        rc, out, err = hmp(
            cfg.vm_name, f"gdbserver tcp:127.0.0.1:{port}", mode="tuple",
        )
        if rc:
            raise ReaderError(err or out or "failed to start gdbserver")
    rsp = RspClient.connect("127.0.0.1", port, timeout=5.0)
    try:
        rsp.handshake()
        rsp.query_halt_reason()
        return rsp
    except BaseException:
        # A startup cancellation or handshake failure may arrive after QEMU
        # accepted the connection and halted. Best-effort resume before raw
        # close; no CR3 masquerade has happened on this startup path.
        with suppress(Exception):
            rsp.cont()
        with suppress(OSError):
            rsp._sock.close()
        raise


def _fork_reader(cfg: Config, port: int) -> int:
    from winbox.kdbg.debugger.child_lifecycle import (
        ChildStartupError,
        supervise_startup,
    )

    pipe_r, pipe_w = os.pipe()
    pid = os.fork()
    if pid:
        os.close(pipe_w)
        try:
            line = supervise_startup(
                pid,
                pipe_r,
                timeout=_READER_STARTUP_TIMEOUT,
                max_bytes=_STARTUP_STATUS_MAX_BYTES,
                label="RSP reader",
            )
        except ChildStartupError as exc:
            raise ReaderError(str(exc)) from exc
        status = line.decode(errors="replace")
        if status == "OK":
            return pid
        raise ReaderError(status.removeprefix("ERR: ") or "reader broker failed")

    os.close(pipe_r)
    class _StartupCancelled(Exception):
        pass

    def _cancel_startup(_signum, _frame):
        raise _StartupCancelled("reader startup cancelled by parent")

    signal.signal(signal.SIGTERM, _cancel_startup)
    signal.signal(signal.SIGINT, _cancel_startup)
    rsp: RspClient | None = None
    listener: socket.socket | None = None
    lock_fd: int | None = None
    exit_code = 0
    guest_running = False
    try:
        _detach_to_log(cfg)
        lock_fd = _acquire_lock(cfg)
        rsp = _open_rsp(cfg, port)
        # A fresh gdb connection halts the guest.  The broker keeps it running
        # between transactions and uses RSP Ctrl-C for each coherent snapshot.
        rsp.cont()
        guest_running = True
        listener = _bind_listener(cfg)
        reader_session_path = session_path(cfg)
        reader_session_path.write_text(json.dumps({
            "pid": os.getpid(), "port": port, "vm_name": cfg.vm_name,
            "cet_safe": True,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }), encoding="utf-8")
        os.chmod(reader_session_path, 0o600)

        broker = _ReaderBroker(cfg, rsp, port)
        def _signal(_signum, _frame):
            broker.shutdown_requested = True

        signal.signal(signal.SIGTERM, _signal)
        signal.signal(signal.SIGINT, _signal)
        os.write(pipe_w, b"OK\n")
        os.close(pipe_w)
        pipe_w = -1

        broker.serve(listener)
        if broker.poisoned:
            exit_code = 2
    except BaseException as exc:
        if pipe_w >= 0:
            with suppress(OSError):
                os.write(pipe_w, f"ERR: {type(exc).__name__}: {exc}\n".encode())
        exit_code = 1
    finally:
        if listener is not None:
            with suppress(OSError):
                listener.close()
        if rsp is not None:
            if pipe_w >= 0 and not guest_running:
                with suppress(Exception):
                    rsp.cont()
            # Broker only leaves this path while the guest is running unless it
            # is poisoned.  Raw close avoids RspClient.close's extra halt dance.
            with suppress(OSError):
                rsp._sock.close()
        with suppress(OSError):
            sock_path(cfg).unlink()
        with suppress(OSError):
            session_path(cfg).unlink()
        if lock_fd is not None:
            with suppress(OSError):
                os.close(lock_fd)
    os._exit(exit_code)


def ensure_reader(cfg: Config, *, port: int = _DEFAULT_PORT) -> None:
    if _reader_alive(cfg):
        # Readers created before the CET gate existed have no proof that they
        # were started in a safe boot. Replace those instead of inheriting an
        # unverified live GDB connection after an in-place upgrade.
        try:
            info = json.loads(session_path(cfg).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            info = {}
        if info.get("cet_safe") is True:
            return
        stop_reader(cfg)
    # The interactive daemon owns the same one-client gdbstub.  Never disturb
    # it by probing with a second TCP connection.
    from winbox.kdbg.debugger.client import DaemonClient
    if DaemonClient(cfg).session_alive():
        raise ReaderError(
            "interactive kdbg session owns the gdbstub; detach it before a standalone walk"
        )
    # Query the guest before opening GDB. On affected QEMU/KVM versions even
    # read-only repeated stop/resume cycles can zero CET's PL3 SSP and bugcheck
    # Windows; explicit OFF is the only live configuration proven safe.
    from winbox.kdbg.cet import CetSafetyError, require_safe
    try:
        require_safe(cfg)
    except CetSafetyError as exc:
        raise ReaderError(str(exc)) from exc
    try:
        _fork_reader(cfg, port)
    except ReaderError:
        # A concurrent caller may have won the fork/lock race.
        if not _reader_alive(cfg):
            raise
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if sock_path(cfg).exists():
            return
        time.sleep(0.01)
    raise ReaderError("RSP reader started but its Unix socket did not appear")


def stop_reader(cfg: Config, *, timeout: float = 5.0) -> bool:
    """Stop the persistent reader if present. Returns whether one existed."""
    if not _reader_alive(cfg):
        return False
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(str(sock_path(cfg)))
        _request(sock, "shutdown")
    except (OSError, ReaderError):
        # Fall back to the diagnostic pid file. SIGTERM is still recoverable:
        # the process's finally closes its RSP socket without stopping QEMU.
        try:
            info = json.loads(session_path(cfg).read_text(encoding="utf-8"))
            os.kill(int(info["pid"]), signal.SIGTERM)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
    finally:
        sock.close()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and _reader_alive(cfg):
        time.sleep(0.02)
    return True


@contextmanager
def debug_snapshot(
    cfg: Config,
    *,
    port: int = _DEFAULT_PORT,
    budget: SnapshotBudget | None = None,
    operation: str = "snapshot",
) -> Iterator[DebugSnapshot]:
    """Yield one budgeted coherent RSP stop.

    Callers normally use the conservative default.  The optional budget is
    deliberately an internal typed object rather than loosely parsed tool
    arguments, keeping every public snapshot path bounded even when a caller
    does not expose tuning knobs.
    """
    existing = current_snapshot(cfg.vm_name)
    if existing is not None:
        yield existing
        return
    snapshot: _RemoteSnapshot | None = None
    for attempt in range(2):
        ensure_reader(cfg, port=port)
        try:
            snapshot = (
                _RemoteSnapshot.connect(cfg)
                if budget is None else _RemoteSnapshot.connect(cfg, budget=budget)
            )
            break
        except (OSError, ReaderError) as exc:
            if getattr(exc, "code", None) == "busy":
                raise
            if attempt:
                raise
            # A reboot can leave the old broker/socket observable just long
            # enough for the first transaction to fail. Retire it and retry
            # once; ensure_reader will re-check CET before opening fresh RSP.
            stop_reader(cfg)
    assert snapshot is not None
    token = _active_snapshot.set(snapshot)
    outcome = "ok"
    error_code: str | None = None
    try:
        yield snapshot
    except BaseException as exc:
        outcome = "error"
        raw_code = getattr(exc, "code", None)
        error_code = raw_code if isinstance(raw_code, str) else None
        raise
    finally:
        try:
            snapshot.close()
        finally:
            # The telemetry writer is intentionally best effort and records
            # only transport metadata; it cannot leak a read payload or mask
            # a primary snapshot failure.
            try:
                from winbox.kdbg.telemetry import record_snapshot_operation
                record_snapshot_operation(
                    cfg, operation=operation, outcome=outcome,
                    snapshot_metadata=snapshot.operation_metadata(), error_code=error_code,
                )
            except Exception:
                pass
            _active_snapshot.reset(token)


@contextmanager
def debug_snapshot_for_vm(vm_name: str) -> Iterator[DebugSnapshot]:
    cfg = Config.load()
    if cfg.vm_name != vm_name:
        cfg.vm_name = vm_name
    with debug_snapshot(cfg) as snapshot:
        yield snapshot


def snapshot_operation(func):
    """Wrap a public walker/memory operation in one coherent RSP snapshot."""
    def wrapped(vm_name: str, *args, **kwargs):
        with debug_snapshot_for_vm(vm_name):
            return func(vm_name, *args, **kwargs)
    wrapped.__name__ = func.__name__
    wrapped.__doc__ = func.__doc__
    wrapped.__module__ = func.__module__
    return wrapped


atexit.register(lambda: None)  # Broker lifetime is intentionally cross-process.
