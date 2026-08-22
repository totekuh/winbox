"""MCP server command — starts the winbox MCP server."""

from __future__ import annotations

import click


@click.command("mcp")
def mcp_cmd() -> None:
    """Start the winbox MCP server (stdio transport).

    Exposes the full research control plane to AI agents: VM lifecycle,
    execution, hypervisor debugging, memory/symbol inspection, drivers,
    IPC, defenses, networking, containment, and evidence collection.
    """
    try:
        from winbox.mcp import run_server
    except ImportError:
        click.echo(
            "MCP dependencies not installed. Install with: pip install winbox[mcp]",
            err=True,
        )
        raise SystemExit(1)

    run_server()


REGISTER = ("Integrations", [mcp_cmd])
