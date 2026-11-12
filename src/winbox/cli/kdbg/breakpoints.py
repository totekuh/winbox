"""Breakpoint management — bp, bps, rm, and durable bp-intent commands."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg
from winbox.cli.kdbg.debugger import _client
from winbox.config import Config
from winbox.kdbg.debugger import ClientError
from winbox.kdbg.debugger.protocol import WATCHPOINT_SIZES, WATCHPOINT_TYPES


@kdbg.command("bp-intent-add")
@click.argument("target")
@click.option("--mode", type=click.Choice(("hw", "soft")), default="hw", show_default=True)
@click.option("--condition", default=None, help="Breakpoint predicate expression.")
@click.option("--watch", "wp_type", type=click.Choice(("write", "read", "access")))
@click.option("--size", "wp_size", type=click.Choice((1, 2, 4, 8)), default=1, show_default=True)
@click.option("--action", "actions", multiple=True, help="Persist an action expression; repeatable.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_bp_intent_add(
    ctx: click.Context,
    target: str,
    mode: str,
    condition: str | None,
    wp_type: str | None,
    wp_size: int,
    actions: tuple[str, ...],
    as_json: bool,
) -> None:
    """Save a detached module+offset breakpoint intent without touching the VM."""
    import json as _json
    from winbox.kdbg.breakpoint_intent import (
        BreakpointIntentError,
        BreakpointIntentStore,
    )

    try:
        record = BreakpointIntentStore(ctx.obj["cfg"]).add(
            target, mode=mode, condition=condition, wp_type=wp_type,
            wp_size=wp_size, actions=actions,
        )
    except BreakpointIntentError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(record, indent=2))
    else:
        console.print(f"[green][+][/] saved breakpoint intent {record['id']}: {record['target']}")
        console.print("    [dim]use kdbg attach PID --apply-intents to install it[/]")


@kdbg.command("bp-intents")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_bp_intents(ctx: click.Context, as_json: bool) -> None:
    """List durable breakpoint intents; this never touches the VM."""
    import json as _json
    from winbox.kdbg.breakpoint_intent import (
        BreakpointIntentError,
        BreakpointIntentStore,
    )

    try:
        result = BreakpointIntentStore(ctx.obj["cfg"]).inventory()
    except BreakpointIntentError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return
    if not result["intents"]:
        console.print("[dim]No saved breakpoint intents.[/]")
        return
    for intent in result["intents"]:
        kind = f"watch:{intent['wp_type']}" if intent["wp_type"] else intent["mode"]
        console.print(f"  {intent['id']:3d}  {kind:12s}  {intent['target']}")


@kdbg.command("bp-intent-rm")
@click.argument("intent_id", type=click.IntRange(min=0))
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_bp_intent_rm(ctx: click.Context, intent_id: int, as_json: bool) -> None:
    """Remove one durable breakpoint intent without touching the VM."""
    import json as _json
    from winbox.kdbg.breakpoint_intent import (
        BreakpointIntentError,
        BreakpointIntentStore,
    )

    try:
        result = BreakpointIntentStore(ctx.obj["cfg"]).remove(intent_id)
    except BreakpointIntentError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(result, indent=2))
    else:
        console.print(f"[green][+][/] removed breakpoint intent {intent_id}")


@kdbg.command("bp")
@click.argument("target", metavar="VA_OR_SYMBOL")
@click.option(
    "--mode", type=click.Choice(["hw", "soft"], case_sensitive=False),
    default="hw", show_default=True,
    help=(
        "Breakpoint mechanism. 'hw' uses CPU debug registers (Z1) — "
        "PG-safe and anti-debug-invisible, limit 4 per vCPU. "
        "'soft' uses 0xCC patches (Z0) — unlimited but PG/hash visible."
    ),
)
@click.option(
    "--condition", "condition", default=None,
    help=(
        "Optional predicate evaluated server-side on every in-target "
        "fire. False -> silent-cont (no halt surfaced). True -> halt. "
        "Grammar: regs (rax..r15, rip, eflags), [reg+0xN] qword reads, "
        "== != < <= > >=, & (bitwise), && || (short-circuit), parens. "
        "Examples: 'rcx == 0xdeadbeef', '[rsp+0x18] == 0x226048', "
        "'(rax & 0x80000000) != 0'."
    ),
)
@click.option(
    "--watch", "wp_type",
    type=click.Choice(WATCHPOINT_TYPES, case_sensitive=False),
    default=None,
    help="Install a hardware watchpoint (Z2/Z3/Z4) instead of an execution bp.",
)
@click.option(
    "--size", "wp_size", type=click.Choice(WATCHPOINT_SIZES),
    default=1, show_default=True,
    help="Watched byte width; meaningful only with --watch.",
)
@click.option(
    "--action", "actions", multiple=True,
    help="Expression/capture to log on every hit; repeat up to 16 times.",
)
@click.pass_context
def kdbg_bp(
    ctx: click.Context,
    target: str,
    mode: str,
    condition: str | None,
    wp_type: str | None,
    wp_size: int,
    actions: tuple[str, ...],
) -> None:
    """Install a bp at TARGET (hex VA, ``module!symbol``, or ``module+0xoffset``).

    Default mode is hardware (Z1) — invisible to PatchGuard and
    anti-debug GetThreadContext checks because KVM virtualizes DR
    access. Use ``--mode soft`` for the legacy 0xCC behaviour
    (needed when >4 simultaneous bps required).

    ``module+0xoffset`` is case-insensitive and resolves only against the
    exact staged modules frozen at attach (for example ``mpengine+0xb52c40``).

    ``--watch`` selects a hardware data watchpoint. Repeat ``--action``
    to log expressions/captures and auto-continue instead of halting.
    With ``--condition`` only matching hits are surfaced or logged.
    """
    cfg: Config = ctx.obj["cfg"]
    if condition is not None and not condition.strip():
        condition = None
    try:
        kwargs = {
            "target": target,
            "mode": mode,
            "condition": condition,
        }
        if wp_type is not None:
            kwargs.update({"wp_type": wp_type, "wp_size": wp_size})
        if actions:
            kwargs["actions"] = list(actions)
        result = _client(cfg).call("bp_add", **kwargs)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    user_kernel = "user" if result["user_mode"] else "kernel"
    if result.get("wp_type"):
        bp_kind = f"watch-{result['wp_type']}/{result['wp_size']}"
    else:
        bp_kind = "hw" if result["hw"] else "soft"
    cond_suffix = ""
    if result.get("condition"):
        cond_suffix = f"  cond={result['condition']!r}"
    action_suffix = ""
    if result.get("actions"):
        action_suffix = f"  actions={len(result['actions'])}"
    console.print(
        f"[green][+][/] bp #{result['id']} at {result['va']} "
        f"({user_kernel}-mode, {bp_kind}, {result['elapsed_ms']:.1f}ms)"
        f"{cond_suffix}{action_suffix}"
    )


@kdbg.command("bps")
@click.pass_context
def kdbg_bps(ctx: click.Context) -> None:
    """List installed breakpoints."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("bp_list")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    bps = result.get("bps", [])
    if not bps:
        console.print("[dim](no bps)[/]")
        return
    console.print("[dim]  id  VA                 kind  hits  age      target[/]")
    for b in bps:
        if b.get("wp_type"):
            kind = f"{b['wp_type']}/{b.get('wp_size', '?')}"
        else:
            kind = "hw" if b.get("hw") else "soft"
        console.print(
            f"  {b['id']:2d}  {b['va']:18s} {kind:4s}  {b['hits']:5d}  "
            f"{b['age_s']:6.1f}s  {b.get('target_pretty') or b['target']}"
        )


@kdbg.command("rm")
@click.argument("bp_id", type=int)
@click.pass_context
def kdbg_rm(ctx: click.Context, bp_id: int) -> None:
    """Remove bp by id."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("bp_remove", id=bp_id)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    console.print(f"[green][+][/] removed bp #{result['removed']} ({result['va']})")
