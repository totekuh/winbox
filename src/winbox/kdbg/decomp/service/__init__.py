"""Composition layer joining a live kdbg stop to focused Ghidra output.

Re-export facade — all public and test-used symbols.
"""

from winbox.kdbg.decomp.service.resolve import (  # noqa: F401
    ASSEMBLY_MODES,
    DETAIL_LEVELS,
    MAX_CONTEXT_LINES,
    MAX_LINE_BATCH,
    MAX_LIVE_READ,
    _annotate_flow_symbols,
    _assembly_mode,
    _binary_candidates,
    _bounded_int,
    _decode_cursor,
    _detail_level,
    _encode_cursor,
    _hex_int,
    _line_range,
    _nearest_symbol_hint,
    _resolve_binary,
    _resolve_verified_binary,
    _snapshot_binary,
)
from winbox.kdbg.decomp.service.format import (  # noqa: F401
    _format_instruction,
    _format_result,
    _mapping_reason,
    _mapping_relation,
)
from winbox.kdbg.decomp.service.prepare import (  # noqa: F401
    MAX_PREPARE_MODULES,
    PREPARE_JOB_HEARTBEAT_STALE,
    PREPARE_JOB_LEGACY_SCHEMA,
    PREPARE_JOB_MAX_AGE,
    PREPARE_JOB_MAX_BYTES,
    PREPARE_JOB_MAX_RETAINED,
    PREPARE_JOB_SCHEMA,
    PREPARE_JOB_START_GRACE,
    _PREPARE_TOKEN,
    _load_prepare_job,
    _lost_prepare_job,
    _prepare_job_dir,
    _prepare_job_path,
    _prepare_modules,
    _process_identity,
    _process_start_ticks,
    _write_prepare_job,
    prepare_decomp,
)
from winbox.kdbg.decomp.service.prepare_bg import (  # noqa: F401
    _reconcile_prepare_job,
    _retain_prepare_jobs,
    cancel_prepare_job,
    prepare_status,
    start_prepare_background,
)
from winbox.kdbg.decomp.service.lifecycle import (  # noqa: F401
    _wrapped_decomp_error,
    cancel_decomp,
    install_service,
    start_service,
    stop_service,
    worker_status,
)
from winbox.kdbg.decomp.service.query import query_decomp  # noqa: F401
