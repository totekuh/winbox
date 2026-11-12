"""Process listing, event logs, and service management MCP tools."""

from __future__ import annotations

import json as _json
import textwrap

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (


    _format_exec_result,
    _guest_errors,
)


@mcp.tool()
def ps(filter: str | None = None, timeout: int = 60) -> str:
    """List processes in the Windows VM with PID, name, path, and memory usage.

    Args:
        filter: Optional filter string. Matches against process name (case-insensitive).
                Example: 'svc' matches svchost.exe, 'lsass' matches lsass.exe.
        timeout: Execution timeout in seconds (default 60).
    """
    filter_repr = repr(filter) if filter else "None"
    script = textwrap.dedent(f"""\
        import json
        import subprocess
        import sys

        filter_str = {filter_repr}

        ps_script = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId, Name, ExecutablePath, WorkingSetSize, VirtualSize | "
            "Sort-Object WorkingSetSize -Descending | "
            "ForEach-Object {{ "
            "  $path = if ($_.ExecutablePath) {{ $_.ExecutablePath }} else {{ $null }}; "
            "  [PSCustomObject]@{{ "
            "    pid = $_.ProcessId; "
            "    name = $_.Name; "
            "    path = $path; "
            "    working_set_mb = [math]::Round($_.WorkingSetSize / 1MB, 1); "
            "    virtual_mb = [math]::Round($_.VirtualSize / 1MB, 1) "
            "  }} "
            "}} | ConvertTo-Json -Depth 1"
        )
        r = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_script],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            sys.exit(r.returncode)

        procs = json.loads(r.stdout)
        if isinstance(procs, dict):
            procs = [procs]
        if filter_str:
            procs = [p for p in procs if filter_str.lower() in p.get('name', '').lower()]
        print(json.dumps(procs, indent=2))
    """)

    result = _mcp_common._exec_python(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def eventlogs(
    log: list[str] | str | None = None,
    since: str = "1h",
    ids: list[int] | None = None,
    provider: str | None = None,
    level: str | None = None,
    max_events: int = 100,
    timeout: int = 60,
) -> str:
    """Query Windows event logs via Get-WinEvent in the VM.

    Returns a JSON array of event objects with TimeCreated, LogName, Level,
    LevelDisplayName, Id, ProviderName, Message. Useful right after running
    a tool to see what Defender / Sysmon / Security audit logged in
    response.

    Args:
        log: Channel name(s). String or list. Default ['Security'].
             Examples: 'System', 'Microsoft-Windows-Sysmon/Operational',
             'Microsoft-Windows-Windows Defender/Operational'.
        since: Time range. 'Nh' / 'Nm' / 'Nd' / 'Nw' or ISO 8601. Default '1h'.
        ids: Event IDs to match (OR'd). Example [4624, 4625].
        provider: Provider name filter.
        level: 'Critical' | 'Error' | 'Warning' | 'Information' | 'Verbose'.
        max_events: Cap on returned events. Default 100.
        timeout: Seconds to wait for Get-WinEvent. Default 60.
    """
    from winbox.eventlogs import (
        EventQuery,
        build_powershell,
        parse_events,
        parse_since,
    )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()

    if log is None:
        logs = ["Security"]
    elif isinstance(log, str):
        logs = [log]
    else:
        logs = list(log)

    try:
        since_dt = parse_since(since)
    except ValueError as e:
        return f"error: {e}"

    try:
        script = build_powershell(
            EventQuery(
                logs=logs,
                since=since_dt,
                ids=list(ids) if ids else [],
                provider=provider,
                level=level,
                max_events=int(max_events),
            )
        )
    except ValueError as e:
        return f"error: {e}"

    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        msg = (result.stderr or result.stdout or "Get-WinEvent failed").strip()
        return f"error (exit {result.exitcode}): {msg}"

    try:
        events = parse_events(result.stdout)
    except (ValueError, _json.JSONDecodeError) as e:
        return f"error: could not parse JSON: {e}"

    return _json.dumps(events, indent=2, default=str)


@mcp.tool()
def eventlogs_clear(
    log: list[str] | str | None = None,
    all_logs: bool = False,
    confirm: bool = False,
    timeout: int = 180,
) -> str:
    """Clear one or more Windows event log channels via wevtutil cl.

    DESTRUCTIVE: cleared logs cannot be recovered. The ``confirm`` flag
    must be set to True or the call is refused without touching the VM.
    Useful for setting up a clean slate before a controlled test.

    Returns a JSON object: ``{cleared, failed, total, errors}``.

    Args:
        log: Channel name(s). String or list of strings. Mutually
             exclusive with all_logs.
        all_logs: Clear EVERY channel reported by 'wevtutil el'. Many
                  channels are read-only / system-protected and will
                  fail; failures are counted but not surfaced
                  individually.
        confirm: Must be True to actually run. Default False is a
                 no-op safety so an LLM cannot accidentally wipe logs.
        timeout: Seconds to wait. Raise for all_logs on busy systems.
    """
    from winbox.eventlogs import build_clear_powershell, parse_clear_result

    if not confirm:
        return (
            "error: refusing to clear logs without confirm=True. "
            "Pass confirm=True to actually run; this is a destructive operation."
        )

    if log is None:
        logs: list[str] = []
    elif isinstance(log, str):
        logs = [log]
    else:
        logs = list(log)

    if all_logs and logs:
        return "error: log and all_logs are mutually exclusive"
    if not all_logs and not logs:
        return "error: either log (channel name) or all_logs=True is required"

    cfg, vm, ga = _mcp_common._ensure_vm_ready()

    try:
        script = build_clear_powershell(logs or None, all_logs=all_logs)
    except ValueError as e:
        return f"error: {e}"

    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        msg = (result.stderr or result.stdout or "wevtutil cl failed").strip()
        return f"error (exit {result.exitcode}): {msg}"

    try:
        info = parse_clear_result(result.stdout)
    except (ValueError, _json.JSONDecodeError) as e:
        return f"error: could not parse JSON: {e}"

    return _json.dumps(info, indent=2)


@mcp.tool()
def service_stop(name: str, timeout: int = 30) -> str:
    """Stop a Windows service.

    Uses sc.exe to stop the service. Useful for unloading drivers,
    stopping EDR agents, etc.

    Args:
        name: Service name (e.g. 'CyProtectDrv' or 'WinDefend').
        timeout: Execution timeout in seconds (default 30).
    """
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec(f"sc.exe stop {name}", timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def service_start(name: str, timeout: int = 30) -> str:
    """Start a Windows service.

    Uses sc.exe to start the service. Useful for loading drivers,
    restarting services after modification, etc.

    Args:
        name: Service name (e.g. 'CyProtectDrv' or 'WinDefend').
        timeout: Execution timeout in seconds (default 30).
    """
    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec(f"sc.exe start {name}", timeout=timeout)
    return _format_exec_result(result)
