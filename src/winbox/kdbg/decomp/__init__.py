"""Static/dynamic decompilation bridge for :mod:`winbox.kdbg`.

The debugger daemon remains the authority for live process state.  This
package maps that state to an exact cached PE by module-relative RVA and asks
an isolated, persistent PyGhidra worker for focused pseudocode.
"""

from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.service import (
    install_service,
    query_decomp,
    start_service,
    stop_service,
    worker_status,
)

__all__ = [
    "DecompClient", "DecompError", "install_service", "query_decomp",
    "start_service", "stop_service", "worker_status",
]
