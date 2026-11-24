"""MCP control plane for the winbox Windows vulnerability-research platform."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "winbox",
    instructions=(
        "Isolated Windows vulnerability-research platform for AI agents. "
        "Manage a QEMU/KVM Windows lab; execute and instrument targets; "
        "debug from the hypervisor with PDB symbols, breakpoints, and memory "
        "access; combine live stops with exact-binary static decompilation; "
        "exercise drivers and IPC; control defenses and networking; "
        "and collect bounded evidence."
    ),
)


def run_server() -> None:
    """Start the MCP server on stdio transport."""
    mcp.run(transport="stdio")


# Import submodules to trigger @mcp.tool() registration, then
# re-export all tool functions and test-used helpers so that
# ``from winbox.mcp import X`` and ``import winbox.mcp as m; m.X``
# still work after the single-file → subpackage conversion.
from winbox.mcp import _common  # noqa: E402, F401
from winbox.mcp._common import *  # noqa: E402, F401, F403
from winbox.mcp._common import (  # noqa: E402, F401 — underscore names excluded by *
    _ensure_vm_ready, _exec_python, _format_exec_result, _get_state,
    _research_ok, _research_error, _bg_label, _launch_bg_job, _execution_json,
)
from winbox.mcp import _vm  # noqa: E402, F401
from winbox.mcp._vm import *  # noqa: E402, F401, F403
from winbox.mcp import _exec  # noqa: E402, F401
from winbox.mcp._exec import *  # noqa: E402, F401, F403
from winbox.mcp import _registry  # noqa: E402, F401
from winbox.mcp._registry import *  # noqa: E402, F401, F403
from winbox.mcp import _guest  # noqa: E402, F401
from winbox.mcp._guest import *  # noqa: E402, F401, F403
from winbox.mcp import _transfer  # noqa: E402, F401
from winbox.mcp._transfer import *  # noqa: E402, F401, F403
from winbox.mcp import _defenses  # noqa: E402, F401
from winbox.mcp._defenses import *  # noqa: E402, F401, F403
from winbox.mcp import _network  # noqa: E402, F401
from winbox.mcp._network import *  # noqa: E402, F401, F403
from winbox.mcp import _shares  # noqa: E402, F401
from winbox.mcp._shares import *  # noqa: E402, F401, F403
from winbox.mcp import _shares_io  # noqa: E402, F401
from winbox.mcp._shares_io import *  # noqa: E402, F401, F403
from winbox.mcp import _ad  # noqa: E402, F401
from winbox.mcp._ad import *  # noqa: E402, F401, F403
from winbox.mcp import _ad_objects  # noqa: E402, F401
from winbox.mcp._ad_objects import *  # noqa: E402, F401, F403
from winbox.mcp import _ad_gpo  # noqa: E402, F401
from winbox.mcp._ad_gpo import *  # noqa: E402, F401, F403
from winbox.mcp import _ad_dfs  # noqa: E402, F401
from winbox.mcp._ad_dfs import *  # noqa: E402, F401, F403
from winbox.mcp import _pipes  # noqa: E402, F401
from winbox.mcp._pipes import *  # noqa: E402, F401, F403
from winbox.mcp._pipes import _next_seq, _is_broker_alive, _session_dir  # noqa: E402, F401
from winbox.mcp import _broker  # noqa: E402, F401
from winbox.mcp._broker import *  # noqa: E402, F401, F403
from winbox.mcp._broker import _BROKER_SCRIPT  # noqa: E402, F401
from winbox.mcp import _kdbg_infra  # noqa: E402, F401
from winbox.mcp._kdbg_infra import *  # noqa: E402, F401, F403
from winbox.mcp._kdbg_infra import _kdbg_probe, _kdbg_hmp, _kdbg_get_store  # noqa: E402, F401
from winbox.mcp import _kdbg_walk  # noqa: E402, F401
from winbox.mcp._kdbg_walk import *  # noqa: E402, F401, F403
from winbox.mcp import _kdbg_threads  # noqa: E402, F401
from winbox.mcp._kdbg_threads import *  # noqa: E402, F401, F403
from winbox.mcp import _kdbg_triage  # noqa: E402, F401
from winbox.mcp._kdbg_triage import *  # noqa: E402, F401, F403
from winbox.mcp import _kdbg_user  # noqa: E402, F401
from winbox.mcp._kdbg_user import *  # noqa: E402, F401, F403
from winbox.mcp import _kdbg_session  # noqa: E402, F401
from winbox.mcp._kdbg_session import *  # noqa: E402, F401, F403
from winbox.mcp._kdbg_session import _kdbg_client, _kdbg_cfg_only, _fork_daemon  # noqa: E402, F401
from winbox.mcp import _kdbg_run  # noqa: E402, F401
from winbox.mcp._kdbg_run import *  # noqa: E402, F401, F403
from winbox.mcp import _kdbg_inspect  # noqa: E402, F401
from winbox.mcp._kdbg_inspect import *  # noqa: E402, F401, F403
from winbox.mcp import _kdbg_recovery  # noqa: E402, F401
from winbox.mcp._kdbg_recovery import *  # noqa: E402, F401, F403
