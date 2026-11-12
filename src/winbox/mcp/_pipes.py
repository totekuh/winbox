"""Named-pipe enumeration, inspection, and session I/O tools."""

from __future__ import annotations

import json as _json
import textwrap
from pathlib import Path
from typing import Any

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (


    _format_exec_result,
    _get_state,
    GuestAgentError,
)


def _session_dir(session_id: str) -> Path:
    cfg, _, _ = _get_state()
    return cfg.shared_dir / ".mcp" / "pipes" / session_id


def _poll_result(result_file: Path, timeout: int) -> dict | None:
    """Poll for result.json on the Kali side (VirtIO-FS)."""
    import time as _time

    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if result_file.exists():
            try:
                data = _json.loads(result_file.read_text())
                result_file.unlink(missing_ok=True)
                return data
            except _json.JSONDecodeError:
                pass
        _time.sleep(0.1)
    return None


def _next_seq(session_dir: Path) -> int:
    """Allocate this session's next command sequence number."""
    import fcntl

    seq_file = session_dir / "seq"
    lock_file = session_dir / "seq.lock"
    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            current = int(seq_file.read_text().strip())
        except (OSError, ValueError):
            current = 0
        current += 1
        seq_file.write_text(str(current))
        return current


def _broker_cmd(session_dir: Path, cmd: dict, timeout: int) -> dict | None:
    """Send one command to the in-guest broker and wait for its answer."""
    seq = _next_seq(session_dir)
    payload = dict(cmd)
    payload["seq"] = seq
    (session_dir / f"cmd.{seq}.json").write_text(_json.dumps(payload))
    return _poll_result(session_dir / f"result.{seq}.json", timeout)


def _is_broker_alive(ga, pid: int) -> bool:
    """Check if PID is still a python.exe process (our broker)."""
    try:
        r = ga.exec(f'tasklist /FI "PID eq {pid}" /FI "IMAGENAME eq python.exe" /NH', timeout=5)
        return "python.exe" in r.stdout.lower()
    except GuestAgentError:
        return False


def _recover_orphaned_read(session_dir: Path) -> str | None:
    """Reclaim data from a previous read that the host timed out on."""
    best_seq = None
    best_path = None
    try:
        for name in session_dir.iterdir():
            if name.name.startswith("result.") and name.name.endswith(".json"):
                try:
                    seq = int(name.name[7:-5])
                except ValueError:
                    continue
                if best_seq is None or seq < best_seq:
                    best_seq = seq
                    best_path = name
    except OSError:
        return None
    if best_path is None:
        return None
    try:
        data = _json.loads(best_path.read_text())
    except (OSError, _json.JSONDecodeError):
        return None
    if data.get("ok") and data.get("data_hex"):
        best_path.unlink(missing_ok=True)
        return data["data_hex"]
    return None


@mcp.tool()
def pipe_list(filter: str | None = None, timeout: int = 30) -> str:
    """Enumerate named pipes in the Windows VM matching a pattern.

    Uses Get-ChildItem on \\\\.\\pipe\\ via PowerShell. Returns a JSON array
    of pipe names, sorted alphabetically.

    Args:
        filter: Optional substring filter (case-insensitive). None = all pipes.
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import json
        import subprocess
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        filter_str = (args.get('filter') or '').lower()

        r = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-ChildItem \\\\\\\\.\\\\pipe\\\\ | Select-Object -ExpandProperty Name | Sort-Object'],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            sys.exit(r.returncode)

        pipes = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        if filter_str:
            pipes = [p for p in pipes if filter_str in p.lower()]
        print(json.dumps(pipes))
    """)

    result = _mcp_common._exec_python(script, timeout=timeout, args={"filter": filter})
    return _format_exec_result(result)


@mcp.tool()
def pipe_info(name: str, timeout: int = 30) -> str:
    """Get security and configuration details for a named pipe.

    Returns a JSON object with keys: pipe, mode, end, out_buf, in_buf,
    max_instances, sddl. sddl is null if it could not be retrieved.

    Args:
        name: Pipe name without prefix (e.g. 'lsass' not '\\\\\\\\.\\\\pipe\\\\lsass').
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        name = args['name']
        pipe_path = f'\\\\\\\\.\\\\pipe\\\\{name}'

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.GetNamedPipeInfo.restype = wintypes.BOOL
        kernel32.GetNamedPipeInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityInfo.restype = wintypes.DWORD
        advapi32.GetSecurityInfo.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            pipe_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            print(json.dumps({
                "pipe": pipe_path,
                "error": f"Cannot open (error {err})",
                "sddl": None,
            }))
            sys.exit(1)

        try:
            flags = wintypes.DWORD(0)
            out_buf = wintypes.DWORD(0)
            in_buf = wintypes.DWORD(0)
            max_inst = wintypes.DWORD(0)
            ok = kernel32.GetNamedPipeInfo(
                handle,
                ctypes.byref(flags), ctypes.byref(out_buf),
                ctypes.byref(in_buf), ctypes.byref(max_inst),
            )
            if not ok:
                err = ctypes.get_last_error()
                print(json.dumps({
                    "pipe": pipe_path,
                    "error": f"GetNamedPipeInfo failed (error {err})",
                    "sddl": None,
                }))
                kernel32.CloseHandle(handle)
                sys.exit(1)
            PIPE_TYPE_MESSAGE = 0x4
            PIPE_SERVER_END = 0x1
            mode = "message" if (flags.value & PIPE_TYPE_MESSAGE) else "byte"
            end = "server" if (flags.value & PIPE_SERVER_END) else "client"
            max_i = max_inst.value if max_inst.value != 255 else "unlimited"

            SE_KERNEL_OBJECT = 6
            DACL_SECURITY_INFORMATION = 4
            OWNER_SECURITY_INFORMATION = 1
            GROUP_SECURITY_INFORMATION = 2
            sd_ptr = ctypes.c_void_p()
            sddl = None
            ret = advapi32.GetSecurityInfo(
                handle, SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None, None, None, None,
                ctypes.byref(sd_ptr),
            )
            if ret == 0 and sd_ptr.value:
                sddl_ptr = wintypes.LPWSTR()
                SDDL_REVISION_1 = 1
                advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd_ptr, SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    ctypes.byref(sddl_ptr), None,
                )
                if sddl_ptr.value:
                    sddl = sddl_ptr.value
                    kernel32.LocalFree(sddl_ptr)
                kernel32.LocalFree(sd_ptr)

            print(json.dumps({
                "pipe": pipe_path,
                "mode": mode,
                "end": end,
                "out_buf": out_buf.value,
                "in_buf": in_buf.value,
                "max_instances": max_i,
                "sddl": sddl,
            }))
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _mcp_common._exec_python(script, timeout=timeout, args={"name": name})
    return _format_exec_result(result)


@mcp.tool()
def pipe_send(session_id: str, data_hex: str, timeout: int = 10) -> str:
    """Write bytes to an open pipe session.

    Args:
        session_id: Session ID returned by pipe_open.
        data_hex: Bytes to write as a hex string (e.g. 'deadbeef0a').
        timeout: Seconds to wait for the write to complete (default: 10).
    """
    session_dir = _session_dir(session_id)
    if not session_dir.exists():
        return f"session not found: {session_id}"

    try:
        bytes.fromhex(data_hex)
    except (ValueError, TypeError):
        return f"error: data_hex is not valid hex: {data_hex!r}"

    res = _broker_cmd(session_dir, {"cmd": "write", "data_hex": data_hex}, timeout)
    if res is None:
        return (
            "timeout waiting for write result — the write may still be executed "
            "by the broker; its result is discarded, not returned to a later call."
        )
    if res.get("ok"):
        return f"wrote {res.get('written', 0)} bytes"
    return f"error: {res.get('error')}"


@mcp.tool()
def pipe_recv(session_id: str, size: int, timeout: int = 10) -> str:
    """Read bytes from an open pipe session.

    Returns received bytes as a hex string, or an error message.

    Args:
        session_id: Session ID returned by pipe_open.
        size: Maximum number of bytes to read.
        timeout: Seconds to wait for data (default: 10).
    """
    session_dir = _session_dir(session_id)
    if not session_dir.exists():
        return f"session not found: {session_id}"

    if size < 0:
        return f"error: size must be >= 0, got {size}"

    recovered = _recover_orphaned_read(session_dir)
    if recovered is not None:
        return recovered

    wait_ms = max(500, int((timeout - 1) * 1000))
    res = _broker_cmd(
        session_dir, {"cmd": "read", "size": size, "wait_ms": wait_ms}, timeout
    )
    if res is None:
        return "timeout waiting for read result"
    if res.get("ok"):
        data_hex = res.get("data_hex")
        if data_hex is None:
            return f"error: broker returned no data for a read: {res}"
        return data_hex
    if res.get("timed_out"):
        return f"no data available on the pipe within {timeout}s"
    return f"error: {res.get('error')}"


@mcp.tool()
def pipe_close(session_id: str) -> str:
    """Close an open pipe session and clean up.

    Args:
        session_id: Session ID returned by pipe_open.
    """
    import shutil

    session_dir = _session_dir(session_id)
    if not session_dir.exists():
        return f"session not found: {session_id}"

    broker_pid: int | None = None
    try:
        broker_pid = int((session_dir / "broker.pid").read_text().strip())
    except (OSError, ValueError):
        pass

    res = _broker_cmd(session_dir, {"cmd": "close"}, timeout=5)

    killed: bool | None = None
    if res is None and broker_pid is not None:
        try:
            _, _, ga = _mcp_common._ensure_vm_ready()
            if _is_broker_alive(ga, broker_pid):
                kill = ga.exec_argv(
                    "taskkill.exe", ["/F", "/T", "/PID", str(broker_pid)], timeout=10
                )
                killed = kill.exitcode == 0
            else:
                killed = None
        except Exception:
            killed = False

    shutil.rmtree(session_dir, ignore_errors=True)

    if res is not None:
        return f"closed session {session_id}"
    if killed:
        return (
            f"closed session {session_id} — the broker never acknowledged the "
            f"close and was force-killed (PID {broker_pid}); the pipe handle "
            "is released."
        )
    if broker_pid is None:
        return (
            f"closed session {session_id} locally, but the broker never "
            "acknowledged the close and no broker.pid was recorded, so it "
            "could not be killed. A python.exe may still hold the pipe handle "
            "open in the VM."
        )
    if killed is None:
        return (
            f"closed session {session_id} — the broker (PID {broker_pid}) "
            "is already gone (PID no longer belongs to python.exe); "
            "taskkill skipped to avoid killing an unrelated process."
        )
    return (
        f"closed session {session_id} locally, but the broker (PID "
        f"{broker_pid}) neither acknowledged the close nor could be killed. "
        "It may still hold the pipe handle open in the VM."
    )
