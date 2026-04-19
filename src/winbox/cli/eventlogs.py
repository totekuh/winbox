"""Query Windows event logs from inside the VM via Get-WinEvent."""

from __future__ import annotations

import json

import click
from rich.console import Console

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.eventlogs import (
    LEVEL_CHOICES,
    EventQuery,
    build_powershell,
    format_compact_table,
    parse_events,
    parse_since,
)
from winbox.vm import GuestAgent, VM


@click.command("eventlogs")
@click.option(
    "--log",
    "logs",
    multiple=True,
    default=("Security",),
    show_default=True,
    help="Event log channel (repeatable). E.g. Security, System, "
    "'Microsoft-Windows-Sysmon/Operational'.",
)
@click.option(
    "--since",
    default="1h",
    show_default=True,
    help="Time range: Nh/Nm/Nd/Nw or ISO 8601 timestamp.",
)
@click.option(
    "--id",
    "ids",
    multiple=True,
    type=int,
    help="Event ID (repeatable, OR'd).",
)
@click.option(
    "--provider",
    default=None,
    help="Provider name filter (e.g. Microsoft-Windows-Windows Defender).",
)
@click.option(
    "--level",
    type=click.Choice(LEVEL_CHOICES, case_sensitive=False),
    default=None,
    help="Severity level filter.",
)
@click.option(
    "--max",
    "max_events",
    default=100,
    show_default=True,
    help="Cap on returned events. Big channels can return MB; keep reasonable.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit raw event JSON array instead of the compact table.",
)
@click.option(
    "--timeout",
    default=60,
    show_default=True,
    help="Get-WinEvent timeout in seconds.",
)
@click.pass_context
def eventlogs(
    ctx: click.Context,
    logs: tuple[str, ...],
    since: str,
    ids: tuple[int, ...],
    provider: str | None,
    level: str | None,
    max_events: int,
    as_json: bool,
    timeout: int,
) -> None:
    """Query Windows event logs and print as a table.

    Examples:

      winbox eventlogs --since 5m --max 20
      winbox eventlogs --log "Microsoft-Windows-Sysmon/Operational" --since 1h
      winbox eventlogs --log Security --id 4624 --id 4625 --since 1d
      winbox eventlogs --level Error --since 1d --json | jq '.[0]'
    """
    cfg: Config = ctx.obj["cfg"]

    try:
        since_dt = parse_since(since)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--since")

    if level is not None:
        for canonical in LEVEL_CHOICES:
            if canonical.lower() == level.lower():
                level = canonical
                break

    query = EventQuery(
        logs=list(logs),
        since=since_dt,
        ids=list(ids),
        provider=provider,
        level=level,
        max_events=max_events,
    )
    script = build_powershell(query)

    vm = VM(cfg)
    ga = GuestAgent(cfg)
    ensure_running(vm, ga, cfg)

    console.print(
        f"[blue][*][/] Querying {','.join(query.logs)} since {since_dt:%Y-%m-%d %H:%M:%S} (max {max_events})..."
    )
    result = ga.exec_powershell(script, timeout=timeout)

    if result.exitcode != 0:
        console.print("[red][-][/] Get-WinEvent failed:")
        if result.stderr:
            console.print(result.stderr.strip(), markup=False, highlight=False, style="red")
        if result.stdout:
            console.print(result.stdout.strip(), markup=False, highlight=False)
        raise SystemExit(result.exitcode or 1)

    try:
        events = parse_events(result.stdout)
    except (ValueError, json.JSONDecodeError) as e:
        console.print(f"[red][-][/] Could not parse Get-WinEvent JSON: {e}")
        if result.stdout:
            console.print(result.stdout.strip(), markup=False, highlight=False)
        raise SystemExit(1)

    if as_json:
        console.print(
            json.dumps(events, indent=2, default=str), markup=False, highlight=False
        )
        return

    if not events:
        console.print("[yellow][!][/] No matching events.")
        return

    # Force a wide rendering width (terminal often 80) so column auto-sizing
    # has room. Message is already pre-truncated to a sane single-line width
    # so Rich does not have to balance a 2KB cell against 4 small ones.
    wide = Console(width=max(console.size.width, 160), highlight=False)
    wide.print(format_compact_table(events))
    console.print(f"[green][+][/] {len(events)} event(s)")
