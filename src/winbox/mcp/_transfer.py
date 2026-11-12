"""File transfer and process memory read MCP tools."""

from __future__ import annotations

import textwrap
from pathlib import Path

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (


    _format_exec_result,
    _get_state,
)


@mcp.tool()
def upload(src: str, dst: str | None = None, timeout: int = 60) -> str:
    """Upload a file or directory from Kali to the Windows VM via VirtIO-FS.

    Copies the file (or directory tree) to the shared directory on Kali,
    which is mounted as Z:\\ inside the VM. Optionally copies it to a
    different location in the VM afterwards.

    Args:
        src: Linux path on Kali. May be a file or a directory.
        dst: Optional Windows destination path inside the VM. If omitted, the
             file/directory stays at Z:\\<name>. If provided, it is copied from
             Z:\\ to dst (directories are copied recursively).
        timeout: Execution timeout in seconds for the in-VM copy step (default 60).
    """
    import shutil

    cfg, vm, ga = _mcp_common._ensure_vm_ready() if dst is not None else _get_state()
    src_path = Path(src)

    if not src_path.exists():
        return f"Source not found on Kali: {src}"

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    shared_dest = cfg.shared_dir / src_path.name
    is_dir = src_path.is_dir()

    if is_dir:
        if shared_dest.exists():
            shutil.rmtree(shared_dest)
        shutil.copytree(src_path, shared_dest)
        count = sum(1 for f in shared_dest.rglob("*") if f.is_file())
        total = sum(f.stat().st_size for f in shared_dest.rglob("*") if f.is_file())
    else:
        shutil.copy2(src_path, shared_dest)
        count = 1
        total = shared_dest.stat().st_size

    if dst is None:
        if is_dir:
            return f"Uploaded {src_path.name}/ to Z:\\{src_path.name}\\ ({count} files, {total} bytes)"
        return f"Uploaded {src_path.name} to Z:\\{src_path.name} ({total} bytes)"

    vm_src = f"Z:\\{src_path.name}"

    if is_dir:
        script = textwrap.dedent("""\
            import json
            import os
            import shutil

            args = json.load(open(r'Z:\\.mcp\\args.json'))
            src = args['src']
            dst = args['dst']

            os.makedirs(dst, exist_ok=True)
            shutil.copytree(src, dst, dirs_exist_ok=True)
            print("ok")
        """)
    else:
        script = textwrap.dedent("""\
            import json
            import os
            import shutil

            args = json.load(open(r'Z:\\.mcp\\args.json'))
            src = args['src']
            dst = args['dst']

            dst_dir = os.path.dirname(dst)
            if dst_dir:
                os.makedirs(dst_dir, exist_ok=True)

            shutil.copy2(src, dst)
            print("ok")
        """)

    result = _mcp_common._exec_python(
        script,
        timeout=timeout,
        args={"src": vm_src, "dst": dst},
    )
    if result["exitcode"] != 0:
        stderr = result["stderr"].strip() if result["stderr"] else "unknown error"
        if is_dir:
            return f"Staged at Z:\\{src_path.name}\\ but copy to {dst} failed: {stderr}"
        return f"Uploaded to Z:\\{src_path.name} but copy to {dst} failed: {stderr}"

    if is_dir:
        return f"Uploaded {src_path.name}/ -> {dst} ({count} files, {total} bytes)"
    return f"Uploaded {src_path.name} -> {dst} ({total} bytes)"


@mcp.tool()
def file_copy(src: str, dst: str, timeout: int = 60) -> str:
    """Copy a file within the Windows VM.

    Use for DLL sideloading, planting payloads, staging binaries, etc.
    Both paths are Windows paths inside the VM.
    Z:\\ is the VirtIO-FS share (~/.winbox/shared/ on Kali).

    Args:
        src: Source path (e.g. 'Z:\\\\tools\\\\cytool.exe' or 'C:\\\\Windows\\\\System32\\\\cmd.exe').
        dst: Destination path (e.g. 'C:\\\\temp\\\\cytool.exe').
        timeout: Execution timeout in seconds (default 60).
    """
    script = textwrap.dedent("""\
        import json
        import os
        import shutil
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        src = args['src']
        dst = args['dst']

        if not os.path.exists(src):
            print(f"Source not found: {src}", file=sys.stderr)
            sys.exit(1)

        # Create destination directory if needed
        dst_dir = os.path.dirname(dst)
        if dst_dir:
            os.makedirs(dst_dir, exist_ok=True)

        shutil.copy2(src, dst)
        size = os.path.getsize(dst)
        print(f"Copied {src} -> {dst} ({size} bytes)")
    """)

    result = _mcp_common._exec_python(
        script,
        timeout=timeout,
        args={"src": src, "dst": dst},
    )
    return _format_exec_result(result)


@mcp.tool()
def mem_read(pid: int, address: str, length: int, timeout: int = 30) -> str:
    """Read memory from a process in the Windows VM.

    Enables SeDebugPrivilege, opens the process with PROCESS_VM_READ,
    and calls ReadProcessMemory. Returns the data as a hex string.

    Address is a string (hex like '0x7ff600001000' or decimal) so kernel
    pointers above 2^53 do not lose precision on the JSON wire.
    PPL processes (lsass+RunAsPPL, MsMpEng) still cannot be opened from
    user-mode even with SeDebugPrivilege - use kdbg_read_va for those.

    Args:
        pid: Target process ID.
        address: Memory address (hex like '0x...' or decimal).
        length: Number of bytes to read (capped at 1MB).
        timeout: Execution timeout in seconds (default 30).
    """
    if length <= 0:
        return f"invalid length: {length} (must be > 0)"
    if length > 1024 * 1024:
        return f"invalid length: {length} (max 1MB per read)"
    try:
        addr_int = int(address, 0)
    except (ValueError, TypeError):
        return f"invalid address: {address!r}"
    if addr_int < 0:
        return f"invalid address: {addr_int} (must be >= 0)"

    script = textwrap.dedent(f"""\
        import ctypes
        from ctypes import wintypes
        import sys

        pid = {pid}
        address = {addr_int}
        size = {length}

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.ReadProcessMemory.restype = wintypes.BOOL
        kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
        advapi32.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE, wintypes.BOOL,
            ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD,
            ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD),
        ]

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        token = wintypes.HANDLE(0)
        if advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            try:
                luid = LUID()
                if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                    tp = TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid = luid
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                    advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
                    err = ctypes.get_last_error()
                    if err == 1300:
                        print("warn: SeDebugPrivilege not held (ERROR_NOT_ALL_ASSIGNED)", file=sys.stderr)
                else:
                    print(f"warn: LookupPrivilegeValueW failed: {{ctypes.get_last_error()}}", file=sys.stderr)
            finally:
                kernel32.CloseHandle(token)
        else:
            print(f"warn: OpenProcessToken failed: {{ctypes.get_last_error()}}", file=sys.stderr)

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400

        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            print(f"OpenProcess failed: error {{err}}", file=sys.stderr)
            sys.exit(1)

        try:
            buf = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buf,
                size,
                ctypes.byref(bytes_read),
            )
            if not ok:
                err = ctypes.get_last_error()
                print(f"ReadProcessMemory failed: error {{err}}", file=sys.stderr)
                sys.exit(1)

            data = buf.raw[:bytes_read.value]
            print(data.hex())
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _mcp_common._exec_python(script, timeout=timeout)
    return _format_exec_result(result)
