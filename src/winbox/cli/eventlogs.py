"""Query / clear Windows event logs from inside the VM."""

from __future__ import annotations

import json

import click
from rich.console import Console

from winbox.cli import ensure_running
from winbox.config import Config
from winbox.eventlogs import (
    LEVEL_CHOICES,
    EventQuery,
    build_clear_powershell,
    build_powershell,
    format_csv,
    parse_clear_result,
    parse_events,
    parse_since,
)
from winbox.vm import GuestAgent, VM


_stderr = Console(stderr=True, highlight=False)


def _err(msg: str) -> None:
    _stderr.print(msg)


def _query_options(fn):
    """Shared options between the eventlogs group default and the explicit query subcommand."""
    fn = click.option(
        "--timeout", default=60, show_default=True,
        help="Get-WinEvent timeout in seconds.",
    )(fn)
    fn = click.option(
        "--json", "as_json", is_flag=True,
        help="Emit raw event JSON array (default is CSV).",
    )(fn)
    fn = click.option(
        "--max", "max_events", default=100, show_default=True,
        help="Cap on returned events. Big channels can return MB; keep reasonable.",
    )(fn)
    fn = click.option(
        "--level",
        type=click.Choice(LEVEL_CHOICES, case_sensitive=False),
        default=None, help="Severity level filter.",
    )(fn)
    fn = click.option(
        "--provider", default=None,
        help="Provider name filter (e.g. Microsoft-Windows-Windows Defender).",
    )(fn)
    fn = click.option(
        "--id", "ids", multiple=True, type=int,
        help="Event ID (repeatable, OR'd).",
    )(fn)
    fn = click.option(
        "--since", default="1h", show_default=True,
        help="Time range: Nh/Nm/Nd/Nw or ISO 8601 timestamp.",
    )(fn)
    fn = click.option(
        "--log", "logs", multiple=True, default=("Security",), show_default=True,
        help="Event log channel (repeatable). E.g. Security, System, "
        "'Microsoft-Windows-Sysmon/Operational'.",
    )(fn)
    return fn


def _do_query(
    cfg: Config,
    logs: tuple[str, ...],
    since: str,
    ids: tuple[int, ...],
    provider: str | None,
    level: str | None,
    max_events: int,
    as_json: bool,
    timeout: int,
) -> None:
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

    _err(
        f"[blue][*][/] Querying {','.join(query.logs)} since "
        f"{since_dt:%Y-%m-%d %H:%M:%S} (max {max_events})..."
    )
    result = ga.exec_powershell(script, timeout=timeout)

    if result.exitcode != 0:
        _err("[red][-][/] Get-WinEvent failed:")
        if result.stderr:
            _err(result.stderr.strip())
        if result.stdout:
            _err(result.stdout.strip())
        raise SystemExit(result.exitcode or 1)

    try:
        events = parse_events(result.stdout)
    except (ValueError, json.JSONDecodeError) as e:
        _err(f"[red][-][/] Could not parse Get-WinEvent JSON: {e}")
        if result.stdout:
            _err(result.stdout.strip())
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(events, indent=2, default=str))
    else:
        click.echo(format_csv(events), nl=False)

    _err(f"[green][+][/] {len(events)} event(s)")


@click.group("eventlogs", invoke_without_command=True)
@_query_options
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
    """Query / clear Windows event logs.

    With no subcommand: queries the Security log (CSV by default).
    Use 'clear' to wipe channels. Run 'winbox eventlogs --help' for
    query flags and 'winbox eventlogs clear --help' for clear flags.

    Examples:

      winbox eventlogs --since 5m --max 20
      winbox eventlogs --log "Microsoft-Windows-Sysmon/Operational"
      winbox eventlogs --level Error --since 1d --json | jq '.[0]'
      winbox eventlogs clear --log Security
      winbox eventlogs clear --all -y
    """
    if ctx.invoked_subcommand is not None:
        return
    cfg: Config = ctx.obj["cfg"]
    _do_query(cfg, logs, since, ids, provider, level, max_events, as_json, timeout)


@eventlogs.command("clear")
@click.option(
    "--log", "logs", multiple=True,
    help="Channel name to clear (repeatable).",
)
@click.option(
    "--all", "all_logs", is_flag=True,
    help="Clear ALL channels (skips read-only / system-protected with no error).",
)
@click.option(
    "-y", "--yes", is_flag=True,
    help="Skip confirmation prompt.",
)
@click.option(
    "--timeout", default=180, show_default=True,
    help="Clear timeout in seconds (raise for --all on busy systems).",
)
@click.pass_context
def clear(
    ctx: click.Context,
    logs: tuple[str, ...],
    all_logs: bool,
    yes: bool,
    timeout: int,
) -> None:
    """Clear one or more event channels via wevtutil cl.

    Examples:

      winbox eventlogs clear --log Security
      winbox eventlogs clear --log Security --log System
      winbox eventlogs clear --all -y
    """
    cfg: Config = ctx.obj["cfg"]

    if all_logs and logs:
        raise click.UsageError("--log and --all are mutually exclusive")
    if not all_logs and not logs:
        raise click.UsageError("specify --log NAME (repeatable) or --all")

    target = "ALL channels" if all_logs else f"{len(logs)} channel(s): {', '.join(logs)}"

    if not yes:
        click.confirm(f"Clear {target}? This cannot be undone.", abort=True)

    try:
        script = build_clear_powershell(list(logs) if logs else None, all_logs=all_logs)
    except ValueError as e:
        raise click.UsageError(str(e))

    vm = VM(cfg)
    ga = GuestAgent(cfg)
    ensure_running(vm, ga, cfg)

    _err(f"[blue][*][/] Clearing {target}...")
    result = ga.exec_powershell(script, timeout=timeout)

    if result.exitcode != 0:
        _err("[red][-][/] Clear failed:")
        if result.stderr:
            _err(result.stderr.strip())
        if result.stdout:
            _err(result.stdout.strip())
        raise SystemExit(result.exitcode or 1)

    try:
        info = parse_clear_result(result.stdout)
    except (ValueError, json.JSONDecodeError) as e:
        _err(f"[red][-][/] Could not parse clear result: {e}")
        if result.stdout:
            _err(result.stdout.strip())
        raise SystemExit(1)

    cleared = info["cleared"]
    failed = info["failed"]
    total = info["total"]

    if failed:
        if all_logs:
            _err(
                f"[yellow][!][/] Cleared {cleared}/{total} (failed {failed}; "
                "read-only / system-protected channels expected)"
            )
        else:
            _err(f"[yellow][!][/] Cleared {cleared}/{total}, failed {failed}:")
            for err in info["errors"]:
                _err(f"  {err}")
            raise SystemExit(1)
    else:
        _err(f"[green][+][/] Cleared {cleared} channel(s)")
