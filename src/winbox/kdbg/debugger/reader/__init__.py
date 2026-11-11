"""Persistent, process-safe RSP transport for debugger memory operations.

Re-export facade — all symbols remain importable from
``winbox.kdbg.debugger.reader``.
"""

from winbox.kdbg.debugger.reader.types import (  # noqa: F401
    ReaderError,
    SnapshotBudget,
    SnapshotBudgetError,
    _MAX_READ,
    _DEFAULT_PORT,
    _READER_STARTUP_TIMEOUT,
    _STARTUP_STATUS_MAX_BYTES,
    _SNAPSHOT_CACHE_MAX_BYTES,
    _active_snapshot,
    _bounded_counter,
    _reply_err,
    _reply_ok,
    _request,
    _runtime_dir,
    lock_path,
    log_path,
    session_path,
    sock_path,
)
from winbox.kdbg.debugger.reader.snapshot import (  # noqa: F401
    DebugSnapshot,
    _RemoteSnapshot,
    snapshot_metadata,
)
from winbox.kdbg.debugger.reader.local import (  # noqa: F401
    _LocalRspSnapshot,
    current_snapshot,
    snapshot_phase,
    use_local_rsp,
)
from winbox.kdbg.debugger.reader.broker import (  # noqa: F401
    _ReaderBroker,
    _reader_alive,
    reader_info,
)
from winbox.kdbg.debugger.reader.lifecycle import (  # noqa: F401
    _acquire_lock,
    _bind_listener,
    _detach_to_log,
    _fork_reader,
    _open_rsp,
    debug_snapshot,
    debug_snapshot_for_vm,
    ensure_reader,
    snapshot_operation,
    stop_reader,
)
