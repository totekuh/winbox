"""MCP server command — starts the winbox MCP server."""

from __future__ import annotations

import click


@click.command("mcp")
def mcp_cmd() -> None:
    """Start the winbox MCP server (stdio transport).

    Exposes vulnerability research primitives: python, ioctl, reg_query,
    reg_set, ps — all executing inside the Windows VM.
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
