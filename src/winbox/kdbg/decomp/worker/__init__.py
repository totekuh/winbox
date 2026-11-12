"""Persistent, serialized PyGhidra worker — re-export facade.

The implementation lives in the submodules.  This file re-exports every
public and test-used symbol so that existing import paths
(``from winbox.kdbg.decomp.worker import X``) continue to work.
"""

from winbox.kdbg.decomp.worker._common import (  # noqa: F401
    ANALYSIS_PROFILE,
    DEFAULT_MAX_OPEN_PROGRAMS,
    ENRICHMENT_REVISION,
    ERROR_SCHEMA,
    HEARTBEAT_INTERVAL,
    MAX_CODE,
    MAX_CONTEXT_LINES,
    MAX_ENRICHMENT_BYTES,
    MAX_ENRICHMENT_EVENTS,
    MAX_ENRICHMENT_RECORDS,
    MAX_LINE_BATCH,
    MAX_MAPPED_INSTRUCTION_ASSOCIATIONS,
    MAX_REQUEST,
    REQUEST_READ_TIMEOUT,
    WORKER_API,
    WorkerError,
    _count_projects,
    _error_info,
    _looks_like_project_corruption,
    _project_name,
    _safe_binary_name,
    _sha256,
    _verified_function_name,
)
from winbox.kdbg.decomp.worker._mapping import (  # noqa: F401
    _attach_mapped_assembly,
    _bounded_code_payload,
    _instruction_payload,
    _map_source,
    _nearby_instructions,
    _requested_lines,
    _walk_tokens,
)
from winbox.kdbg.decomp.worker._recovery import (  # noqa: F401
    _recover_function,
)
from winbox.kdbg.decomp.worker._worker import (  # noqa: F401
    OpenProgram,
    Worker,
)
from winbox.kdbg.decomp.worker._server import (  # noqa: F401
    _read_request,
    _write_session,
    main,
)
