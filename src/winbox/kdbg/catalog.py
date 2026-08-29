"""Single-source public MCP catalog identity.

The CLI readiness report and the MCP server must advertise the same revision
and expected tool inventory.  Keeping these values here makes a stale reload
or a missed catalog bump visible instead of silently divergent.
"""

from __future__ import annotations


MCP_CATALOG_REVISION = "2026-08-29.capture-vad-object-evidence.1"
MCP_TOOL_COUNT = 92


def catalog_identity() -> dict[str, int | str]:
    """Return the compact, stable catalog identity used by readiness views."""
    return {
        "catalog_revision": MCP_CATALOG_REVISION,
        "tool_count": MCP_TOOL_COUNT,
    }
