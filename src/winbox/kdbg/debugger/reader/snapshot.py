"""Abstract DebugSnapshot interface and remote (IPC) snapshot client."""

from __future__ import annotations

import socket
from contextlib import ExitStack
from typing import Any

from winbox.config import Config
from winbox.kdbg.admission import OperationBusyError, admit_operation
from winbox.kdbg.debugger.reader.types import (
    ReaderError,
    SnapshotBudget,
    SnapshotBudgetError,
    _MAX_READ,
    _bounded_counter,
    _request,
    _runtime_dir,
    sock_path,
)
from winbox.kdbg.admission import OperationLease


class DebugSnapshot:
    """Interface consumed by ``memory.py`` and ``walk.py``."""

    vm_name: str
    current_cr3: int
    cr3_candidates: tuple[int, ...]
    kernel_gs_bases: tuple[int, ...]
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
