"""Execution control — bp-trace, cont, step, interrupt, regs, search."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg
from winbox.cli.kdbg.debugger import _client, _print_stop
from winbox.config import Config
from winbox.kdbg.debugger import ClientError
from winbox.kdbg.debugger.trace import MAX_SUMMARY_TOP, MAX_TRACE_RESULTS


@kdbg.command("bp-trace")
@click.argument("bp_id", type=int)
@click.option(
    "--tail", type=click.IntRange(1, MAX_TRACE_RESULTS),
    default=20, show_default=True,
)
@click.option("--from-hit", type=click.IntRange(min=0), default=None)
@click.option(
    "--limit", type=click.IntRange(1, MAX_TRACE_RESULTS),
    default=20, show_default=True,
)
@click.option("--expression", default=None, help="Filter/project one exact action.")
@click.option("--value", default=None, help="Filter an exact numeric or string value.")
@click.option("--errors-only", is_flag=True, help="Return only action errors.")
@click.option("--summary", is_flag=True, help="Include bounded value distributions.")
@click.option(
    "--top", type=click.IntRange(1, MAX_SUMMARY_TOP),
    default=10, show_default=True,
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_bp_trace(
    ctx: click.Context,
    bp_id: int,
    tail: int,
    from_hit: int | None,
    limit: int,
    expression: str | None,
    value: str | None,
    errors_only: bool,
    summary: bool,
    top: int,
    as_json: bool,
) -> None:
    """Query bounded action-trace records for BP_ID."""
    cfg: Config = ctx.obj["cfg"]
    kwargs = {
        "id": bp_id,
        "tail": tail,
        "limit": limit,
        "errors_only": errors_only,
        "summary": summary,
        "top": top,
    }
    if from_hit is not None:
        kwargs["from_hit"] = from_hit
    if expression is not None:
        kwargs["expression"] = expression
    if value is not None:
        kwargs["value"] = value
    try:
        result = _client(cfg).call("bp_trace", **kwargs)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    if as_json:
        import json as _json
        click.echo(_json.dumps(result, indent=2))
        return

    entries = result.get("entries", [])
    if not entries:
        console.print("[dim](no matching trace entries)[/]")
    for entry in entries:
        values = entry.get("values") or {}
        rendered = "  ".join(f"{key}={val}" for key, val in values.items())
        console.print(
            f"  #{entry.get('hit', '?'):<6} {entry.get('rip', '?'):18s} {rendered}"
        )
    suffix = " truncated" if result.get("truncated") else ""
    cursor = (
        f" next_hit={result['next_hit']}" if result.get("next_hit") is not None else ""
    )
    console.print(
        f"[dim]returned={result.get('returned', len(entries))} "
        f"total={result.get('total', '?')}{cursor}{suffix}[/]"
    )
    if result.get("summary") is not None:
        import json as _json
        console.print("[dim]summary[/]")
        click.echo(_json.dumps(result["summary"], indent=2))


@kdbg.command("cont")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="Wall-clock cap before returning 'timeout'.")
@click.pass_context
def kdbg_cont(ctx: click.Context, timeout: float) -> None:
    """Resume the VM. Blocks until next bp hit in target's CR3."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call(
            "cont",
            sock_timeout=float(timeout) + 10.0,
            timeout=float(timeout),
        )
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    _print_stop(result.get("reason", "?"), result)


@kdbg.command("cont-start")
@click.option(
    "--timeout", default=300.0, show_default=True, type=float,
    help="Wall-clock budget for the detached continue operation.",
)
@click.pass_context
def kdbg_cont_start(ctx: click.Context, timeout: float) -> None:
    """Start a durable continue operation and return immediately as JSON."""
    import json as _json
    from winbox.kdbg.debugger.continue_job import ContinueJobError, start_continue

    try:
        result = start_continue(ctx.obj["cfg"], timeout=timeout)
    except ContinueJobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("cont-poll")
@click.argument("token", required=False, default="")
@click.pass_context
def kdbg_cont_poll(ctx: click.Context, token: str) -> None:
    """Poll the current durable continue operation as JSON."""
    import json as _json
    from winbox.kdbg.debugger.continue_job import ContinueJobError, poll_continue

    try:
        result = poll_continue(ctx.obj["cfg"], token=token)
    except ContinueJobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("cont-cancel")
@click.argument("token", required=False, default="")
@click.pass_context
def kdbg_cont_cancel(ctx: click.Context, token: str) -> None:
    """Interrupt and cancel the current durable continue operation."""
    import json as _json
    from winbox.kdbg.debugger.continue_job import ContinueJobError, cancel_continue

    try:
        result = cancel_continue(ctx.obj["cfg"], token=token)
    except ContinueJobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("step")
@click.option("--over", is_flag=True, default=False,
              help="Step OVER call/syscall — temp hw bp at next instruction.")
@click.option("--out", is_flag=True, default=False,
              help="Step OUT of current function — temp hw bp at [rsp] return address.")
@click.pass_context
def kdbg_step(ctx: click.Context, over: bool, out: bool) -> None:
    """Single-step the firing vCPU."""
    if over and out:
        console.print("[red][-][/] --over and --out are mutually exclusive")
        raise SystemExit(1)
    cfg: Config = ctx.obj["cfg"]
    op = "step_out" if out else ("step_over" if over else "step")
    try:
        result = _client(cfg).call(op)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    _print_stop(result.get("reason", op), result)


@kdbg.command("interrupt")
@click.pass_context
def kdbg_interrupt(ctx: click.Context) -> None:
    """Async halt the running target (use during a stuck cont)."""
    cfg: Config = ctx.obj["cfg"]
    try:
        _client(cfg).call("interrupt")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    console.print("[dim]interrupt queued[/]")


@kdbg.command("regs")
@click.pass_context
def kdbg_regs(ctx: click.Context) -> None:
    """Dump current register state."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("regs")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    order = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
             "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
             "eflags", "cs", "cr0", "cr2", "cr3", "cr4"]
    for k in order:
        if k in result:
            console.print(f"  {k.upper():6s}= {result[k]}")


@kdbg.command("search")
@click.argument("module")
@click.argument("query")
@click.option("--limit", type=click.IntRange(1, 64), default=32, show_default=True)
@click.option(
    "--sha256", "sha256", default="", metavar="DIGEST",
    help="Exact decomp-cache SHA-256 selector; disambiguates same-named cached binaries.",
)
@click.pass_context
def kdbg_search(
    ctx: click.Context, module: str, query: str, limit: int, sha256: str,
) -> None:
    """Find static string, export, and RTTI leads in one exact cached PE.

    This is offline: it never opens the RSP debugger connection or changes the
    VM stop state. ``MODULE`` first resolves through the local symbol cache,
    then through named exact artifacts in the persistent decomp cache. Use
    ``--sha256`` to select one exact cached build after an ambiguity error.
    """
    import json as _json
    from winbox.kdbg.static_search import StaticSearchError, search_cached_module

    try:
        result = search_cached_module(
            ctx.obj["cfg"], module=module, query=query, limit=limit, sha256=sha256,
        )
    except StaticSearchError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))
