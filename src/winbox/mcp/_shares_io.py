"""SMB share file I/O MCP tools — ls, mkdir, write, rm."""

from __future__ import annotations

import json as _json
from pathlib import Path

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (

    _format_exec_result,
    _guest_errors,
)
from winbox.mcp._shares import _validate_share_name
from winbox.validate import check_relative_path


def _validate_share_relpath(path: str) -> str:
    err, normalized = check_relative_path(path)
    if err:
        raise ValueError(err)
    return normalized


def _share_guarded_script(share_name: str, relpath: str, action_lines: str) -> str:
    from winbox.ps import ps_quote
    return (
        f"$base = (Get-SmbShare -Name '{ps_quote(share_name)}' -ErrorAction Stop).Path\n"
        f"$full = [IO.Path]::GetFullPath((Join-Path $base '{ps_quote(relpath)}'))\n"
        "if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {\n"
        "    Write-Error 'Path escapes share boundary'; exit 1\n"
        "}\n"
        f"{action_lines}"
    )


@mcp.tool()
def share_ls(name: str, path: str = "", timeout: int = 30) -> str:
    """List files inside an SMB share's backing folder.

    Returns a JSON array. Each object has: name, length (null for dirs),
    lastWriteTime, isDirectory.

    Args:
        name: Share name.
        path: Relative path within the share (default: root).
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import ps_quote

    _validate_share_name(name)
    json_select = (
        "Select-Object @{N='name';E={$_.Name}}, "
        "@{N='length';E={if($_.PSIsContainer){$null}else{$_.Length}}}, "
        "@{N='lastWriteTime';E={$_.LastWriteTime.ToString('o')}}, "
        "@{N='isDirectory';E={$_.PSIsContainer}} | ConvertTo-Json -Compress"
    )
    if path:
        relpath = _validate_share_relpath(path)
        script = _share_guarded_script(
            name, relpath,
            f"Get-ChildItem -Path $full | {json_select}",
        )
    else:
        script = (
            f"$base = (Get-SmbShare -Name '{ps_quote(name)}' -ErrorAction Stop).Path\n"
            f"Get-ChildItem -Path $base | {json_select}"
        )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def share_mkdir(name: str, path: str, timeout: int = 30) -> str:
    """Create a directory inside an SMB share.

    Args:
        name: Share name.
        path: Relative path for the new directory.
        timeout: Execution timeout in seconds (default 30).
    """
    _validate_share_name(name)
    relpath = _validate_share_relpath(path)

    script = _share_guarded_script(
        name, relpath,
        "New-Item -ItemType Directory -Path $full -Force | Out-Null\n"
        "Write-Host $full",
    )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "share": name,
        "path": result.stdout.strip(),
        "created": True,
    })


@mcp.tool()
def share_write(
    name: str,
    path: str,
    content: str | None = None,
    source: str | None = None,
    timeout: int = 60,
) -> str:
    """Write a file inside an SMB share.

    Provide either content (inline text) or source (Kali-side file path
    to upload via VirtIO-FS). Exactly one must be set.

    Args:
        name: Share name.
        path: Relative path within the share for the target file.
        content: Inline text content (mutually exclusive with source).
        source: Kali-side file path to upload (mutually exclusive with content).
        timeout: Execution timeout in seconds (default 60).
    """
    import base64 as _b64
    import shutil
    from winbox.ps import ps_quote

    if content is None and source is None:
        return "Provide either content or source, not neither."
    if content is not None and source is not None:
        return "content and source are mutually exclusive."

    _validate_share_name(name)
    relpath = _validate_share_relpath(path)

    cfg, vm, ga = _mcp_common._ensure_vm_ready()

    if content is not None:
        content_b64 = _b64.b64encode(content.encode()).decode()
        script = _share_guarded_script(
            name, relpath,
            "$dir = Split-Path $full -Parent\n"
            "if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }\n"
            f"$bytes = [Convert]::FromBase64String('{content_b64}')\n"
            "[IO.File]::WriteAllBytes($full, $bytes)\n"
            "Write-Host $full",
        )
        with _guest_errors(vm):
            result = ga.exec_powershell(script, timeout=timeout)
        if result.exitcode != 0:
            return _format_exec_result(result)

        return _json.dumps({
            "share": name,
            "path": result.stdout.strip(),
            "written": True,
            "source": "inline",
        })

    # source path — stage via VirtIO-FS
    src_path = Path(source)
    if not src_path.exists():
        return f"Source not found on Kali: {source}"

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    staged = cfg.shared_dir / src_path.name
    shutil.copy2(src_path, staged)

    vm_staged = f"Z:\\{src_path.name}"
    script = _share_guarded_script(
        name, relpath,
        "$dir = Split-Path $full -Parent\n"
        "if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }\n"
        f"Copy-Item -Path '{ps_quote(vm_staged)}' -Destination $full -Force -ErrorAction Stop\n"
        "Write-Host $full",
    )
    try:
        with _guest_errors(vm):
            result = ga.exec_powershell(script, timeout=timeout)
    finally:
        staged.unlink(missing_ok=True)

    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "share": name,
        "path": result.stdout.strip(),
        "written": True,
        "source": src_path.name,
    })


@mcp.tool()
def share_rm(
    name: str,
    path: str,
    confirm: bool = False,
    timeout: int = 30,
) -> str:
    """Delete a file or directory inside an SMB share.

    Args:
        name: Share name.
        path: Relative path within the share to delete.
        confirm: Must be True (guards file deletion).
        timeout: Execution timeout in seconds (default 30).
    """
    if not confirm:
        return "confirm=True required. This permanently deletes the file or directory."

    _validate_share_name(name)
    relpath = _validate_share_relpath(path)

    script = _share_guarded_script(
        name, relpath,
        "Remove-Item -Path $full -Recurse -Force -ErrorAction Stop\n"
        "Write-Host $full",
    )

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    with _guest_errors(vm):
        result = ga.exec_powershell(script, timeout=timeout)
    if result.exitcode != 0:
        return _format_exec_result(result)

    return _json.dumps({
        "share": name,
        "path": result.stdout.strip(),
        "removed": True,
    })
