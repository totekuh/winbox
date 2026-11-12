"""Decompilation and Ghidra service management commands."""

from __future__ import annotations

from pathlib import Path

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg
from winbox.config import Config


@kdbg.command("decomp")
@click.argument("address", required=False, default="")
@click.option("--symbol", default="", help="Loaded module!symbol to decompile.")
@click.option("--module", default="", help="Live module name (requires --rva).")
@click.option("--rva", default="", help="Module-relative address (requires --module).")
@click.option("--cursor", default="", help="Continuation cursor from a prior page.")
@click.option("--before", type=click.IntRange(0, 20), default=3, show_default=True)
@click.option("--after", type=click.IntRange(0, 20), default=5, show_default=True)
@click.option("--full", is_flag=True, help="Include the complete containing function.")
@click.option(
    "--binary", type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None, help="Exact host-side PE; otherwise use the symbols cache.",
)
@click.option("--timeout", type=click.IntRange(5, 300), default=60, show_default=True)
@click.option(
    "--analysis-timeout", type=click.IntRange(5, 1800), default=900,
    show_default=True, help="Cold import/auto-analysis budget.",
)
@click.option(
    "--detail",
    type=click.Choice(["compact", "standard", "diagnostic"]),
    default="compact",
    show_default=True,
    help="Response evidence level.",
)
@click.option(
    "--lines",
    default="",
    metavar="N[-M]",
    help="Absolute pseudocode line or range; overrides before/after context.",
)
@click.option(
    "--assembly",
    type=click.Choice(["nearby", "mapped"]),
    default="nearby",
    show_default=True,
    help="Attach assembly to each selected mapped pseudocode line.",
)
@click.option("--instruction-bytes", is_flag=True, help="Include raw instruction bytes.")
@click.option("--runtime-vas", is_flag=True, help="Include repeated static/runtime VAs.")
@click.option("--callers", is_flag=True, help="Include static direct callers from the exact cached PE.")
@click.option("--callees", is_flag=True, help="Include static direct callees from the exact cached PE.")
@click.option(
    "--allow-cold", is_flag=True,
    help="Permit cold Ghidra analysis while the debugger target remains halted.",
)
@click.pass_context
def kdbg_decomp(
    ctx: click.Context,
    address: str,
    symbol: str,
    module: str,
    rva: str,
    cursor: str,
    before: int,
    after: int,
    full: bool,
    binary: Path | None,
    timeout: int,
    analysis_timeout: int,
    detail: str,
    lines: str,
    assembly: str,
    instruction_bytes: bool,
    runtime_vas: bool,
    callers: bool,
    callees: bool,
    allow_cold: bool,
) -> None:
    """Show Ghidra pseudocode at ADDRESS, or at the current RIP.

    Resolves the live loaded module, converts the runtime VA to an RVA,
    verifies the cached PE against live CodeView/PE identity, and queries an
    isolated persistent PyGhidra worker. Cold analysis is refused by default
    so a first-time import cannot silently hold the target stopped; prepare it
    offline first or pass --allow-cold deliberately.
    """
    import json as _json
    from winbox.kdbg.decomp import DecompError, query_decomp

    cfg: Config = ctx.obj["cfg"]
    try:
        result = query_decomp(
            cfg,
            addr=address,
            symbol=symbol,
            module=module,
            rva=rva,
            cursor=cursor,
            before=before,
            after=after,
            full=full,
            binary=str(binary) if binary else "",
            timeout=timeout,
            analysis_timeout=analysis_timeout,
            detail=detail,
            lines=lines,
            assembly=assembly,
            instruction_bytes=instruction_bytes,
            runtime_vas=runtime_vas,
            callers=callers,
            callees=callees,
            allow_cold=allow_cold,
        )
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    # Rich wraps long strings at terminal width, which can insert literal
    # newlines inside JSON string values and corrupt piped output. This command
    # is an API-like evidence surface, so emit the serialized bytes verbatim.
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("decomp-status")
@click.pass_context
def kdbg_decomp_status(ctx: click.Context) -> None:
    """Show Docker/PyGhidra API, JVM, and project-cache status."""
    import json as _json
    from winbox.kdbg.decomp import worker_status

    cfg: Config = ctx.obj["cfg"]
    # This is an API-like JSON surface. Rich wraps long string values at the
    # terminal width, which makes redirected output invalid JSON.
    click.echo(_json.dumps(worker_status(cfg), indent=2))


@kdbg.group("ghidra")
def kdbg_ghidra() -> None:
    """Install and manage the isolated headless Ghidra service."""
    pass


def _ghidra_lifecycle(ctx: click.Context, operation: str, **kwargs) -> None:
    import json as _json
    from winbox.kdbg.decomp import (
        DecompError, install_service, start_service, stop_service, worker_status,
    )

    cfg: Config = ctx.obj["cfg"]
    actions = {
        "install": lambda: install_service(cfg, **kwargs),
        "run": lambda: start_service(cfg),
        "stop": lambda: stop_service(cfg),
        "status": lambda: worker_status(cfg),
    }
    try:
        result = actions[operation]()
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    # Keep every lifecycle command safe to pipe through jq/json.tool even
    # when COLUMNS is tiny. Human-facing errors above still use Rich.
    click.echo(_json.dumps(result, indent=2))


@kdbg_ghidra.command("install")
@click.option("--pull/--no-pull", default=True, help="Refresh the pinned base image.")
@click.pass_context
def kdbg_ghidra_install(ctx: click.Context, pull: bool) -> None:
    """Build the pinned Ghidra + PyGhidra Docker image."""
    _ghidra_lifecycle(ctx, "install", pull=pull)


@kdbg_ghidra.command("run")
@click.pass_context
def kdbg_ghidra_run(ctx: click.Context) -> None:
    """Start the persistent local decompilation API."""
    _ghidra_lifecycle(ctx, "run")


@kdbg_ghidra.command("stop")
@click.pass_context
def kdbg_ghidra_stop(ctx: click.Context) -> None:
    """Stop and remove the managed service container."""
    _ghidra_lifecycle(ctx, "stop")


@kdbg_ghidra.command("status")
@click.pass_context
def kdbg_ghidra_status(ctx: click.Context) -> None:
    """Show image, container, API, JVM, and cache status."""
    _ghidra_lifecycle(ctx, "status")


@kdbg_ghidra.command("cache")
@click.pass_context
def kdbg_ghidra_cache(ctx: click.Context) -> None:
    """List content-keyed binary/project cache usage and LRU age."""
    import json as _json
    from winbox.kdbg.decomp import cache_inventory
    click.echo(_json.dumps(cache_inventory(ctx.obj["cfg"]), indent=2))


@kdbg_ghidra.command("prune")
@click.option("--max-bytes", type=click.IntRange(min=0), default=0)
@click.option("--older-than-days", type=click.FloatRange(min=0), default=0.0)
@click.option("--sha256", "sha256s", multiple=True, help="Select an exact binary digest.")
@click.option("--project", "projects", multiple=True, help="Select an exact project name.")
@click.option("--module", "modules", multiple=True, help="Select an exact module name.")
@click.option("--apply", is_flag=True, help="Delete selected entries; default is dry-run.")
@click.pass_context
def kdbg_ghidra_prune(
    ctx: click.Context, max_bytes: int, older_than_days: float,
    sha256s: tuple[str, ...], projects: tuple[str, ...], modules: tuple[str, ...],
    apply: bool,
) -> None:
    """Preview or apply exact-selector and bounded LRU cache pruning."""
    import json as _json
    from winbox.kdbg.decomp import DecompError, prune_cache
    try:
        result = prune_cache(
            ctx.obj["cfg"], max_bytes=max_bytes,
            older_than_days=older_than_days, sha256=sha256s,
            project=projects, module=modules, dry_run=not apply,
        )
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))


@kdbg_ghidra.command("repair")
@click.option("--sha256", "digest", required=True, help="Exact cached binary digest.")
@click.pass_context
def kdbg_ghidra_repair(ctx: click.Context, digest: str) -> None:
    """Delete and rebuild one exact digest-keyed Ghidra project cache."""
    import json as _json
    from winbox.kdbg.decomp import DecompError, repair_cache
    try:
        result = repair_cache(ctx.obj["cfg"], sha256=digest)
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))


@kdbg_ghidra.command("prepare")
@click.argument("module", default="all")
@click.option(
    "--analysis-timeout", type=click.IntRange(5, 1800), default=900,
    show_default=True,
)
@click.option("--background", is_flag=True, help="Return a durable job token immediately.")
@click.option("--force-enrichment", is_flag=True, help="Re-extract the exact PDB sidecar.")
@click.pass_context
def kdbg_ghidra_prepare(
    ctx: click.Context, module: str, analysis_timeout: int,
    background: bool, force_enrichment: bool,
) -> None:
    """Analyze one cached MODULE (or all) without a debugger stop."""
    import json as _json
    from winbox.kdbg.decomp import (
        DecompError, prepare_decomp, start_prepare_background,
    )
    try:
        if background:
            from winbox.kdbg.decomp.service import _prepare_modules
            selected = _prepare_modules(ctx.obj["cfg"], module)
            result = start_prepare_background(
                ctx.obj["cfg"], modules=selected,
                analysis_timeout=analysis_timeout,
                force_enrichment=force_enrichment,
            )
        else:
            result = prepare_decomp(
                ctx.obj["cfg"], module=module,
                analysis_timeout=analysis_timeout,
                force_enrichment=force_enrichment,
            )
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))


@kdbg_ghidra.command("prepare-status")
@click.argument("token", default="")
@click.pass_context
def kdbg_ghidra_prepare_status(ctx: click.Context, token: str) -> None:
    """Read the latest or token-selected background prepare job."""
    import json as _json
    from winbox.kdbg.decomp import DecompError, prepare_status
    try:
        result = prepare_status(ctx.obj["cfg"], token=token)
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))


@kdbg_ghidra.command("cancel")
@click.option("--request-id", default="", help="Require this active request identity.")
@click.option("--token", default="", help="Cancel this exact background prepare job.")
@click.pass_context
def kdbg_ghidra_cancel(ctx: click.Context, request_id: str, token: str) -> None:
    """Cooperatively cancel the active analysis or decompilation."""
    import json as _json
    from winbox.kdbg.decomp import DecompError, cancel_decomp
    try:
        result = cancel_decomp(
            ctx.obj["cfg"], request_id=request_id, token=token,
        )
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))
