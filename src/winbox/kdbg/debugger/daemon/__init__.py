"""kdbg session daemon — holds a live gdb connection and serves ops.

The implementation is split across submodules by concern; this file
re-exports every public and test-used symbol so that existing import
paths (``from winbox.kdbg.debugger.daemon import X``) continue to work.
"""

from winbox.kdbg.debugger.daemon._types import (  # noqa: F401
    Breakpoint,
    CR3RestoreError,
    DaemonError,
    MAX_BREAKPOINT_ACTIONS,
    MAX_CAPTURE_BYTES_PER_HIT,
    MAX_CAPTURE_BYTES_PER_TRACE,
    StopState,
    TargetInfo,
    _CandidateReadFailed,
    _DAEMON_STARTUP_TIMEOUT,
    _MemoryReadNeeded,
    _MODULE_OFFSET_TARGET,
    _STARTUP_STATUS_MAX_BYTES,
    lock_path,
    log_path,
    masquerade_cr3_candidates,
    session_path,
    sock_path,
)
from winbox.kdbg.debugger.daemon._session import DaemonSession  # noqa: F401
from winbox.kdbg.debugger.daemon._helpers import (  # noqa: F401
    _GPR_NAMES,
    _decode_regs,
    _hw_bp_failure,
    _looks_like_code_va,
    _looks_like_timeout,
    _normalize_module_name,
    _read_target_bytes,
    _soft_bp_failure,
    _stored_module_identity,
    _validate_register_layout,
)
from winbox.kdbg.debugger.daemon._validation import (  # noqa: F401
    _apply_breakpoint_intents,
    _validate_module_bases,
    _validated_breakpoint_intents,
)
from winbox.kdbg.debugger.daemon._fork import (  # noqa: F401
    _acquire_lock_or_die,
    _bind_unix_socket,
    _detach_to_log,
    _install_signal_handlers,
    _write_session_file,
    fork_daemon,
)
