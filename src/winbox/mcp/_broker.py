"""Pipe session broker — pipe_connect and pipe_open with in-guest broker process."""

from __future__ import annotations

import json as _json
import textwrap
from typing import Any

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (


    _format_exec_result,
    _get_state,
    GuestAgentError,
)
from winbox.mcp._pipes import _is_broker_alive, _session_dir


@mcp.tool()
def pipe_connect(name: str, access: str = "read", timeout: int = 30) -> str:
    """Open a handle to a named pipe and return the result.

    Attempts to connect to the pipe with the specified access. Useful for
    testing pipe ACLs, impersonation opportunities, and access control.
    Returns success + handle info, or the Win32 error on failure.

    Args:
        name: Pipe name without prefix (e.g. 'lsass').
        access: Access mode — 'read', 'write', or 'readwrite' (default: 'read').
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        name = args['name']
        access_str = args.get('access', 'read').lower()

        GENERIC_READ  = 0x80000000
        GENERIC_WRITE = 0x40000000
        access_map = {
            'read':      GENERIC_READ,
            'write':     GENERIC_WRITE,
            'readwrite': GENERIC_READ | GENERIC_WRITE,
        }
        desired_access = access_map.get(access_str, GENERIC_READ)

        pipe_path = f'\\\\\\\\.\\\\pipe\\\\{name}'

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            pipe_path, desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            msgs = {
                5:   'ACCESS_DENIED',
                2:   'NOT_FOUND',
                231: 'PIPE_BUSY (all instances in use)',
            }
            msg = msgs.get(err, f'error {err}')
            print(f"FAILED: {pipe_path} [{access_str}] -> {msg}", file=sys.stderr)
            sys.exit(1)

        kernel32.CloseHandle(handle)
        print(f"OK: opened {pipe_path} [{access_str}] successfully")
    """)

    result = _mcp_common._exec_python(script, timeout=timeout, args={"name": name, "access": access})
    return _format_exec_result(result)


_BROKER_SCRIPT = """\
import ctypes
from ctypes import wintypes
import json
import os
import time

script_dir = os.path.dirname(os.path.abspath(__file__))

try:
    with open(os.path.join(script_dir, 'broker.pid'), 'w') as _pf:
        _pf.write(str(os.getpid()))
except OSError:
    pass

config = json.load(open(os.path.join(script_dir, 'config.json')))
name = config['name']
access_str = config.get('access', 'readwrite').lower()

bs = chr(92)
pipe_path = bs * 2 + '.' + bs + 'pipe' + bs + name

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.PeekNamedPipe.restype = wintypes.BOOL
kernel32.PeekNamedPipe.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ  = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

access_map = {
    'read':      GENERIC_READ,
    'write':     GENERIC_WRITE,
    'readwrite': GENERIC_READ | GENERIC_WRITE,
}
desired_access = access_map.get(access_str, GENERIC_READ | GENERIC_WRITE)

status_file = os.path.join(script_dir, 'status.json')
config_file = os.path.join(script_dir, 'config.json')

handle = kernel32.CreateFileW(
    pipe_path, desired_access,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    None, OPEN_EXISTING, 0, None,
)
if handle == INVALID_HANDLE_VALUE:
    err = ctypes.get_last_error()
    msgs = {5: 'ACCESS_DENIED', 2: 'NOT_FOUND', 231: 'PIPE_BUSY'}
    msg = msgs.get(err, f'error {err}')
    with open(status_file, 'w') as f:
        json.dump({'status': 'error', 'error': f'{pipe_path} -> {msg}'}, f)
    raise SystemExit(1)

with open(status_file, 'w') as f:
    json.dump({'status': 'ready'}, f)


def next_command():
    try:
        names = os.listdir(script_dir)
    except OSError:
        return None
    best = None
    for n in names:
        if n.startswith('cmd.') and n.endswith('.json'):
            try:
                seq = int(n[4:-5])
            except ValueError:
                continue
            if best is None or seq < best[0]:
                best = (seq, n)
    return best


def do_read(cmd):
    size = cmd['size']
    wait_ms = cmd.get('wait_ms', 5000)
    avail = wintypes.DWORD(0)
    deadline = time.time() + (wait_ms / 1000.0)
    while True:
        ok = kernel32.PeekNamedPipe(
            handle, None, 0, None, ctypes.byref(avail), None
        )
        if not ok:
            err = ctypes.get_last_error()
            return {'ok': False, 'error': 'PeekNamedPipe failed: error %d' % err}
        if avail.value:
            break
        if time.time() >= deadline:
            return {
                'ok': False,
                'timed_out': True,
                'error': 'no data available within %.1fs' % (wait_ms / 1000.0),
            }
        time.sleep(0.02)

    want = max(0, min(size, avail.value))
    buf = ctypes.create_string_buffer(want)
    nread = wintypes.DWORD(0)
    ok = kernel32.ReadFile(handle, buf, want, ctypes.byref(nread), None)
    if ok:
        return {'ok': True, 'data_hex': buf.raw[:nread.value].hex()}
    err = ctypes.get_last_error()
    return {'ok': False, 'error': 'ReadFile failed: error %d' % err}


while True:
    if not os.path.exists(config_file):
        kernel32.CloseHandle(handle)
        break

    pending = next_command()
    if pending is None:
        time.sleep(0.05)
        continue
    seq, fname = pending
    cmd_path = os.path.join(script_dir, fname)

    try:
        with open(cmd_path) as f:
            cmd = json.load(f)
        os.remove(cmd_path)
    except Exception:
        time.sleep(0.05)
        continue

    action = cmd.get('cmd')
    closing = False

    try:
        if action == 'write':
            try:
                data = bytes.fromhex(cmd['data_hex'])
            except (ValueError, KeyError, TypeError) as e:
                result = {'ok': False, 'error': 'bad write payload: %s' % e}
            else:
                buf  = ctypes.create_string_buffer(data)
                written = wintypes.DWORD(0)
                ok = kernel32.WriteFile(handle, buf, len(data), ctypes.byref(written), None)
                if ok:
                    result = {'ok': True, 'written': written.value}
                else:
                    err = ctypes.get_last_error()
                    result = {'ok': False, 'error': 'WriteFile failed: error %d' % err}

        elif action == 'read':
            result = do_read(cmd)

        elif action == 'close':
            kernel32.CloseHandle(handle)
            result = {'ok': True}
            closing = True

        else:
            result = {'ok': False, 'error': 'unknown command: %s' % action}
    except Exception as e:
        result = {'ok': False, 'error': 'broker dispatch failed: %s' % e}

    result['seq'] = seq
    with open(os.path.join(script_dir, 'result.%d.json' % seq), 'w') as f:
        json.dump(result, f)

    if closing:
        break
"""


@mcp.tool()
def pipe_open(name: str, access: str = "readwrite", timeout: int = 10) -> str:
    """Open a named pipe and return a session ID for subsequent send/recv/close calls.

    Starts a persistent broker process inside the VM that holds the handle open.
    The broker communicates with MCP tools via files on the VirtIO-FS share.

    Args:
        name: Pipe name without prefix (e.g. 'srvsvc').
        access: 'read', 'write', or 'readwrite' (default: 'readwrite').
        timeout: Seconds to wait for broker to start (default: 10).

    Returns:
        session_id string on success, or an error message.
    """
    import time as _time
    import uuid

    cfg, _, _ = _mcp_common._ensure_vm_ready()

    session_id = uuid.uuid4().hex[:12]
    session_dir = cfg.shared_dir / ".mcp" / "pipes" / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    (session_dir / "config.json").write_text(
        _json.dumps({"name": name, "access": access})
    )
    (session_dir / "broker.py").write_text(_BROKER_SCRIPT)

    broker_win = f"Z:\\.mcp\\pipes\\{session_id}\\broker.py"

    spawner = textwrap.dedent("""\
        import subprocess
        import json

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        broker_path = args['broker_path']

        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW  = 0x08000000

        proc = subprocess.Popen(
            ['python.exe', broker_path],
            creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"pid:{proc.pid}")
    """)

    result = _mcp_common._exec_python(spawner, args={"broker_path": broker_win})
    if result["exitcode"] != 0:
        import shutil
        shutil.rmtree(session_dir, ignore_errors=True)
        return f"spawner failed: {result['stderr'].strip()}"

    broker_pid: int | None = None
    for line in result["stdout"].splitlines():
        line = line.strip()
        if line.startswith("pid:"):
            try:
                broker_pid = int(line[4:])
            except ValueError:
                pass
            break
    if broker_pid is not None:
        (session_dir / "broker.pid").write_text(str(broker_pid))

    def _abort(reason: str) -> str:
        import shutil
        pid = broker_pid
        if pid is None:
            try:
                pid = int((session_dir / "broker.pid").read_text().strip())
            except (OSError, ValueError):
                pid = None
        if pid is not None:
            try:
                _, _, ga = _mcp_common._ensure_vm_ready()
                if _is_broker_alive(ga, pid):
                    ga.exec_argv("taskkill.exe", ["/F", "/PID", str(pid)], timeout=5)
            except Exception:
                pass
        shutil.rmtree(session_dir, ignore_errors=True)
        return reason

    status_file = session_dir / "status.json"
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if status_file.exists():
            try:
                status = _json.loads(status_file.read_text())
            except _json.JSONDecodeError:
                _time.sleep(0.1)
                continue
            if status.get("status") == "ready":
                return session_id
            else:
                return _abort(f"broker error: {status.get('error', 'unknown')}")
        _time.sleep(0.1)

    return _abort(f"timeout waiting for broker (session: {session_id})")
