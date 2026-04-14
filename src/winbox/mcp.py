"""winbox MCP server — vuln research primitives for Windows VM."""

from __future__ import annotations

import json as _json
import textwrap
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from winbox.config import Config
from winbox.vm import VM, VMState, GuestAgent, GuestAgentError

mcp = FastMCP(
    "winbox",
    instructions=(
        "Windows VM execution proxy for vulnerability research. "
        "Run Python code, send IOCTLs, query/set registry, list processes — "
        "all executing inside a Windows Server 2022 VM managed by QEMU/KVM."
    ),
)

# ─── Shared state ───────────────────────────────────────────────────────────

_cfg: Config | None = None
_vm: VM | None = None
_ga: GuestAgent | None = None


def _get_state() -> tuple[Config, VM, GuestAgent]:
    global _cfg, _vm, _ga
    if _cfg is None:
        _cfg = Config.load()
        _vm = VM(_cfg)
        _ga = GuestAgent(_cfg)
    return _cfg, _vm, _ga


def _ensure_vm_ready() -> tuple[Config, VM, GuestAgent]:
    """Ensure VM is running and guest agent is responding. Starts if needed."""
    cfg, vm, ga = _get_state()
    state = vm.state()

    if state == VMState.NOT_FOUND:
        raise RuntimeError("VM not found. Run 'winbox setup' first.")

    if state == VMState.RUNNING:
        if not ga.ping():
            try:
                ga.wait(timeout=60)
            except GuestAgentError:
                raise RuntimeError("Guest agent not responding.")
        return cfg, vm, ga

    if state == VMState.SHUTOFF:
        vm.start()
    elif state == VMState.PAUSED:
        vm.resume()
    elif state == VMState.SAVED:
        vm.start()
    else:
        raise RuntimeError(f"VM in unexpected state: {state.value}")

    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        raise RuntimeError("Guest agent not responding after starting VM.")

    return cfg, vm, ga


# ─── Internal: Python execution ────────────────────────────────────────────

def _exec_python(
    code: str,
    timeout: int = 300,
    args: dict | None = None,
) -> dict:
    """Write Python code to VirtIO-FS and execute in VM.

    If args is provided, writes them as a JSON file that the script can
    read via ``json.load(open(r'Z:\\.mcp\\args.json'))``. This avoids
    all escaping issues when embedding values like device paths.

    Both the script and args.json are removed from the share after the
    call completes, including on timeout/exception — otherwise the
    previous tool call's code (which may include sensitive snippets)
    would sit on the host filesystem until the next invocation.

    Returns dict with exitcode, stdout, stderr.
    """
    cfg, vm, ga = _ensure_vm_ready()

    # Write script to shared filesystem
    script_dir = cfg.shared_dir / ".mcp"
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / "script.py"
    args_path = script_dir / "args.json"
    script_path.write_text(code, encoding="utf-8")

    # Write args as JSON for the script to read
    if args is not None:
        args_path.write_text(_json.dumps(args), encoding="utf-8")

    try:
        result = ga.exec(
            r'python.exe Z:\.mcp\script.py',
            timeout=timeout,
        )
        return {
            "exitcode": result.exitcode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    finally:
        script_path.unlink(missing_ok=True)
        args_path.unlink(missing_ok=True)


# ─── Tool 1: python ────────────────────────────────────────────────────────

@mcp.tool()
def python(code: str, timeout: int = 300) -> str:
    """Execute Python code inside the Windows VM.

    The code runs as Administrator with full access to Win32 APIs via ctypes,
    the registry via winreg, WMI, COM, and everything else Python can do.
    Output is captured from stdout/stderr.

    Args:
        code: Python source code to execute.
        timeout: Execution timeout in seconds (default 300).
    """
    result = _exec_python(code, timeout=timeout)
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 2: ioctl ─────────────────────────────────────────────────────────

@mcp.tool()
def ioctl(
    device: str,
    code: int,
    input_hex: str = "",
    output_size: int = 0,
    timeout: int = 30,
) -> str:
    """Send an IOCTL to a Windows device driver.

    Opens the device with CreateFileW, sends DeviceIoControl with the given
    control code and input buffer, returns the output buffer as hex.

    Args:
        device: Device path, e.g. '\\\\.\\C:' or '\\\\.\\PhysicalDrive0'.
        code: IOCTL control code (integer, e.g. 0x222000).
        input_hex: Input buffer as hex string (e.g. 'deadbeef'). Empty for no input.
        output_size: Expected output buffer size in bytes. 0 for no output.
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        device = args['device']
        ioctl_code = args['code']
        input_hex = args.get('input_hex', '')
        output_size = args.get('output_size', 0)

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            device,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            print(f"CreateFileW failed: error {err}", file=sys.stderr)
            sys.exit(1)

        try:
            in_buf = bytes.fromhex(input_hex) if input_hex else None
            in_size = len(in_buf) if in_buf else 0
            out_buf = ctypes.create_string_buffer(output_size) if output_size > 0 else None
            bytes_returned = wintypes.DWORD(0)

            ok = kernel32.DeviceIoControl(
                handle,
                ioctl_code,
                in_buf, in_size,
                out_buf, output_size,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ok:
                err = ctypes.get_last_error()
                print(f"DeviceIoControl failed: error {err}", file=sys.stderr)
                sys.exit(1)

            returned = bytes_returned.value
            if out_buf and returned > 0:
                print(out_buf.raw[:returned].hex())
            else:
                print(f"ok ({returned} bytes returned)")
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _exec_python(
        script,
        timeout=timeout,
        args={"device": device, "code": code, "input_hex": input_hex, "output_size": output_size},
    )
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 3: reg_query ─────────────────────────────────────────────────────

@mcp.tool()
def reg_query(key: str, value: str | None = None) -> str:
    """Query a Windows registry key or value.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion').
        value: Specific value name to query. If omitted, lists all values under the key.
    """
    if value is not None:
        script = textwrap.dedent(f"""\
            import winreg
            import sys

            key_path = {key!r}
            value_name = {value!r}

            # Parse hive
            hive_map = {{
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKU': winreg.HKEY_USERS,
                'HKEY_USERS': winreg.HKEY_USERS,
            }}
            parts = key_path.split('\\\\', 1)
            hive_name = parts[0].rstrip(':')
            subkey = parts[1] if len(parts) > 1 else ''
            hive = hive_map.get(hive_name.upper())
            if hive is None:
                print(f"Unknown hive: {{hive_name}}", file=sys.stderr)
                sys.exit(1)

            try:
                with winreg.OpenKey(hive, subkey) as k:
                    data, reg_type = winreg.QueryValueEx(k, value_name)
                    type_names = {{
                        winreg.REG_SZ: 'REG_SZ',
                        winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
                        winreg.REG_DWORD: 'REG_DWORD',
                        winreg.REG_QWORD: 'REG_QWORD',
                        winreg.REG_BINARY: 'REG_BINARY',
                        winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
                    }}
                    type_name = type_names.get(reg_type, f'type({{reg_type}})')
                    if reg_type == winreg.REG_BINARY:
                        print(f"{{value_name}} ({{type_name}}): {{data.hex()}}")
                    elif reg_type == winreg.REG_MULTI_SZ:
                        print(f"{{value_name}} ({{type_name}}):")
                        for item in data:
                            print(f"  {{item}}")
                    else:
                        print(f"{{value_name}} ({{type_name}}): {{data}}")
            except FileNotFoundError:
                print(f"Not found: {{key_path}}\\\\{{value_name}}", file=sys.stderr)
                sys.exit(1)
        """)
    else:
        script = textwrap.dedent(f"""\
            import winreg
            import sys

            key_path = {key!r}

            hive_map = {{
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKU': winreg.HKEY_USERS,
                'HKEY_USERS': winreg.HKEY_USERS,
            }}
            parts = key_path.split('\\\\', 1)
            hive_name = parts[0].rstrip(':')
            subkey = parts[1] if len(parts) > 1 else ''
            hive = hive_map.get(hive_name.upper())
            if hive is None:
                print(f"Unknown hive: {{hive_name}}", file=sys.stderr)
                sys.exit(1)

            try:
                with winreg.OpenKey(hive, subkey) as k:
                    # Enumerate values
                    i = 0
                    type_names = {{
                        winreg.REG_SZ: 'REG_SZ',
                        winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
                        winreg.REG_DWORD: 'REG_DWORD',
                        winreg.REG_QWORD: 'REG_QWORD',
                        winreg.REG_BINARY: 'REG_BINARY',
                        winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
                    }}
                    while True:
                        try:
                            name, data, reg_type = winreg.EnumValue(k, i)
                            type_name = type_names.get(reg_type, f'type({{reg_type}})')
                            if reg_type == winreg.REG_BINARY:
                                print(f"{{name}} ({{type_name}}): {{data.hex()}}")
                            else:
                                print(f"{{name}} ({{type_name}}): {{data}}")
                            i += 1
                        except OSError:
                            break
                    if i == 0:
                        print("(no values)")

                    # Enumerate subkeys
                    j = 0
                    subkeys = []
                    while True:
                        try:
                            subkeys.append(winreg.EnumKey(k, j))
                            j += 1
                        except OSError:
                            break
                    if subkeys:
                        print(f"\\nSubkeys ({{j}}):")
                        for sk in subkeys:
                            print(f"  {{sk}}")
            except FileNotFoundError:
                print(f"Key not found: {{key_path}}", file=sys.stderr)
                sys.exit(1)
        """)

    result = _exec_python(script)
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 4: reg_set ───────────────────────────────────────────────────────

@mcp.tool()
def reg_set(
    key: str,
    value: str,
    data: str,
    type: str = "REG_SZ",
) -> str:
    """Set a Windows registry value.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\MyKey'). Created if it doesn't exist.
        value: Value name to set.
        data: Data to write. For REG_DWORD/REG_QWORD pass the integer as a string.
              For REG_BINARY pass hex. For REG_MULTI_SZ pass items separated by '\\n'.
        type: Registry type — REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ.
    """
    script = textwrap.dedent(f"""\
        import winreg
        import sys

        key_path = {key!r}
        value_name = {value!r}
        raw_data = {data!r}
        reg_type_name = {type!r}

        hive_map = {{
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
            'HKCR': winreg.HKEY_CLASSES_ROOT,
            'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
            'HKU': winreg.HKEY_USERS,
            'HKEY_USERS': winreg.HKEY_USERS,
        }}
        type_map = {{
            'REG_SZ': (winreg.REG_SZ, lambda d: d),
            'REG_EXPAND_SZ': (winreg.REG_EXPAND_SZ, lambda d: d),
            'REG_DWORD': (winreg.REG_DWORD, lambda d: int(d)),
            'REG_QWORD': (winreg.REG_QWORD, lambda d: int(d)),
            'REG_BINARY': (winreg.REG_BINARY, lambda d: bytes.fromhex(d)),
            'REG_MULTI_SZ': (winreg.REG_MULTI_SZ, lambda d: d.split('\\n')),
        }}

        parts = key_path.split('\\\\', 1)
        hive_name = parts[0].rstrip(':')
        subkey = parts[1] if len(parts) > 1 else ''
        hive = hive_map.get(hive_name.upper())
        if hive is None:
            print(f"Unknown hive: {{hive_name}}", file=sys.stderr)
            sys.exit(1)

        if reg_type_name not in type_map:
            print(f"Unknown type: {{reg_type_name}}", file=sys.stderr)
            sys.exit(1)

        reg_type, converter = type_map[reg_type_name]
        converted = converter(raw_data)

        with winreg.CreateKey(hive, subkey) as k:
            winreg.SetValueEx(k, value_name, 0, reg_type, converted)
        print(f"Set {{key_path}}\\\\{{value_name}} = {{raw_data}} ({{reg_type_name}})")
    """)

    result = _exec_python(script)
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 5: reg_delete ─────────────────────────────────────────────────────

@mcp.tool()
def reg_delete(key: str, value: str | None = None) -> str:
    """Delete a Windows registry value or entire key.

    If value is provided, deletes that specific value. If omitted,
    deletes the entire key and all its subkeys.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\MyKey').
        value: Specific value name to delete. If omitted, deletes the entire key tree.
    """
    if value is not None:
        script = textwrap.dedent(f"""\
            import winreg
            import sys

            key_path = {key!r}
            value_name = {value!r}

            hive_map = {{
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKU': winreg.HKEY_USERS,
                'HKEY_USERS': winreg.HKEY_USERS,
            }}
            parts = key_path.split('\\\\', 1)
            hive_name = parts[0].rstrip(':')
            subkey = parts[1] if len(parts) > 1 else ''
            hive = hive_map.get(hive_name.upper())
            if hive is None:
                print(f"Unknown hive: {{hive_name}}", file=sys.stderr)
                sys.exit(1)

            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, value_name)
                print(f"Deleted value {{key_path}}\\\\{{value_name}}")
            except FileNotFoundError:
                print(f"Not found: {{key_path}}\\\\{{value_name}}", file=sys.stderr)
                sys.exit(1)
            except PermissionError:
                print(f"Access denied: {{key_path}}\\\\{{value_name}}", file=sys.stderr)
                sys.exit(1)
        """)
    else:
        script = textwrap.dedent(f"""\
            import winreg
            import sys

            key_path = {key!r}

            hive_map = {{
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKU': winreg.HKEY_USERS,
                'HKEY_USERS': winreg.HKEY_USERS,
            }}
            parts = key_path.split('\\\\', 1)
            hive_name = parts[0].rstrip(':')
            subkey = parts[1] if len(parts) > 1 else ''
            hive = hive_map.get(hive_name.upper())
            if hive is None:
                print(f"Unknown hive: {{hive_name}}", file=sys.stderr)
                sys.exit(1)

            def delete_key_tree(hive, subkey):
                try:
                    with winreg.OpenKey(hive, subkey, 0,
                                        winreg.KEY_ALL_ACCESS) as k:
                        while True:
                            try:
                                child = winreg.EnumKey(k, 0)
                                delete_key_tree(hive, f"{{subkey}}\\\\{{child}}")
                            except OSError:
                                break
                    winreg.DeleteKey(hive, subkey)
                except FileNotFoundError:
                    print(f"Not found: {{key_path}}", file=sys.stderr)
                    sys.exit(1)
                except PermissionError:
                    print(f"Access denied: {{key_path}}", file=sys.stderr)
                    sys.exit(1)

            delete_key_tree(hive, subkey)
            print(f"Deleted key {{key_path}}")
        """)

    result = _exec_python(script)
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 6: ps ────────────────────────────────────────────────────────────

@mcp.tool()
def ps(filter: str | None = None) -> str:
    """List processes in the Windows VM with PID, name, path, and memory usage.

    Args:
        filter: Optional filter string. Matches against process name (case-insensitive).
                Example: 'svc' matches svchost.exe, 'lsass' matches lsass.exe.
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

    result = _exec_python(script)
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 6: upload ────────────────────────────────────────────────────────

@mcp.tool()
def upload(src: str, dst: str | None = None) -> str:
    """Upload a file from Kali to the Windows VM via VirtIO-FS.

    Copies the file to the shared directory on Kali, which is mounted
    as Z:\\ inside the VM. Optionally moves it to a different location
    in the VM afterwards.

    Args:
        src: Linux path on Kali (e.g. '/tmp/payload.dll' or '/opt/tools/mimikatz.exe').
        dst: Optional Windows destination path inside the VM. If omitted, the file
             stays at Z:\\<filename>. If provided, the file is copied from Z:\\ to dst.
    """
    import shutil

    cfg, vm, ga = _get_state()
    src_path = Path(src)

    if not src_path.exists():
        return f"Source not found on Kali: {src}"

    # Copy to shared dir (appears as Z:\ in VM)
    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    shared_dest = cfg.shared_dir / src_path.name
    shutil.copy2(src_path, shared_dest)
    size = shared_dest.stat().st_size

    if dst is None:
        return f"Uploaded {src_path.name} to Z:\\{src_path.name} ({size} bytes)"

    # Copy from Z:\ to final destination inside VM
    script = textwrap.dedent("""\
        import json
        import os
        import shutil
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        src = args['src']
        dst = args['dst']

        dst_dir = os.path.dirname(dst)
        if dst_dir:
            os.makedirs(dst_dir, exist_ok=True)

        shutil.copy2(src, dst)
        print(f"ok")
    """)
    vm_src = f"Z:\\{src_path.name}"
    result = _exec_python(
        script,
        args={"src": vm_src, "dst": dst},
    )
    if result["exitcode"] != 0:
        stderr = result["stderr"].strip() if result["stderr"] else "unknown error"
        return f"Uploaded to Z:\\{src_path.name} but copy to {dst} failed: {stderr}"

    return f"Uploaded {src_path.name} -> {dst} ({size} bytes)"


# ─── Tool 7: file_copy ─────────────────────────────────────────────────────

@mcp.tool()
def file_copy(src: str, dst: str) -> str:
    """Copy a file within the Windows VM.

    Use for DLL sideloading, planting payloads, staging binaries, etc.
    Both paths are Windows paths inside the VM.
    Z:\\ is the VirtIO-FS share (~/.winbox/shared/ on Kali).

    Args:
        src: Source path (e.g. 'Z:\\\\tools\\\\cytool.exe' or 'C:\\\\Windows\\\\System32\\\\cmd.exe').
        dst: Destination path (e.g. 'C:\\\\temp\\\\cytool.exe').
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

    result = _exec_python(
        script,
        args={"src": src, "dst": dst},
    )
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 7: mem_read ──────────────────────────────────────────────────────

@mcp.tool()
def mem_read(pid: int, address: int, size: int) -> str:
    """Read memory from a process in the Windows VM.

    Opens the process with PROCESS_VM_READ and calls ReadProcessMemory.
    Returns the data as a hex string.

    Args:
        pid: Target process ID.
        address: Memory address to read from (integer).
        size: Number of bytes to read.
    """
    if size <= 0:
        return f"Invalid size: {size} (must be > 0)"
    if size > 100 * 1024 * 1024:
        return f"Invalid size: {size} (max 100MB per read)"
    if address < 0:
        return f"Invalid address: {address} (must be >= 0)"
    script = textwrap.dedent(f"""\
        import ctypes
        from ctypes import wintypes
        import sys

        pid = {pid}
        address = {address}
        size = {size}

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

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

    result = _exec_python(script)
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Tool 8: service_stop / service_start ───────────────────────────────────

@mcp.tool()
def service_stop(name: str) -> str:
    """Stop a Windows service.

    Uses sc.exe to stop the service. Useful for unloading drivers,
    stopping EDR agents, etc.

    Args:
        name: Service name (e.g. 'CyProtectDrv' or 'WinDefend').
    """
    cfg, vm, ga = _ensure_vm_ready()
    result = ga.exec(f"sc.exe stop {name}", timeout=30)
    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        output += f"\n[stderr]\n{result.stderr}"
    if result.exitcode != 0:
        output += f"\n[exit code: {result.exitcode}]"
    return output or "(no output)"


@mcp.tool()
def service_start(name: str) -> str:
    """Start a Windows service.

    Uses sc.exe to start the service. Useful for loading drivers,
    restarting services after modification, etc.

    Args:
        name: Service name (e.g. 'CyProtectDrv' or 'WinDefend').
    """
    cfg, vm, ga = _ensure_vm_ready()
    result = ga.exec(f"sc.exe start {name}", timeout=30)
    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        output += f"\n[stderr]\n{result.stderr}"
    if result.exitcode != 0:
        output += f"\n[exit code: {result.exitcode}]"
    return output or "(no output)"


# ─── Tool 9: net_isolate / net_unplug / net_connect ─────────────────────────

@mcp.tool()
def net_isolate() -> str:
    """Block internet on the VM by removing the default gateway.

    The NIC stays up, so Kali <-> VM on the libvirt subnet still works
    (guest agent, VirtIO-FS, same-subnet IP traffic). Only traffic via
    the default gateway is blocked. For a full NIC disconnect, use
    net_unplug() instead. Undo with net_connect().
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    ga.exec_powershell(
        "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -Confirm:$false "
        "-ErrorAction SilentlyContinue",
        timeout=15,
    )
    return "Internet isolated — default gateway removed"


@mcp.tool()
def net_unplug() -> str:
    """Unplug the VM's virtual NIC entirely (full air-gap).

    Kills all IP traffic including Kali <-> VM. GA and VirtIO-FS stay
    up over virtio-serial. For internet-only isolation that keeps
    Kali <-> VM working, use net_isolate(). Undo with net_connect().
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    if not vm.net_set_link("down"):
        return "Failed to set link down (no interface found?)"
    return "NIC unplugged — VM is fully air-gapped"


@mcp.tool()
def net_connect() -> str:
    """Restore full network access (undo net_isolate or net_unplug).

    Brings the NIC link up if needed, then runs a full DHCP cycle
    (release + renew) to re-add the default gateway.
    """
    import time

    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"

    if vm.net_link_state() == "down":
        if not vm.net_set_link("up"):
            return "Failed to set link up (no interface found?)"
        ga.exec_powershell(
            "Restart-NetAdapter -Name (Get-NetAdapter | Select -First 1).Name "
            "-Confirm:$false",
            timeout=30,
        )

    try:
        ga.exec("ipconfig /release", timeout=15)
    except GuestAgentError:
        pass
    ga.exec("ipconfig /renew", timeout=30)

    for _ in range(15):
        ip = vm.ip()
        if ip:
            return f"Network connected — IP: {ip}"
        time.sleep(1)
    return "Network connected (DHCP pending)"


# ─── Tool 10: pipe_list / pipe_info / pipe_connect ──────────────────────────

@mcp.tool()
def pipe_list(filter: str = "") -> str:
    """Enumerate named pipes in the Windows VM matching a pattern.

    Uses Get-ChildItem on \\\\.\\pipe\\ via PowerShell. Returns a JSON array
    of pipe names, sorted alphabetically.

    Args:
        filter: Optional substring filter (case-insensitive). Empty = all pipes.
    """
    script = textwrap.dedent("""\
        import json
        import subprocess
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        filter_str = args.get('filter', '').lower()

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

    result = _exec_python(script, args={"filter": filter})
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


@mcp.tool()
def pipe_info(name: str) -> str:
    """Get security and configuration details for a named pipe.

    Returns a JSON object with keys: pipe, mode, end, out_buf, in_buf,
    max_instances, sddl. sddl is null if it could not be retrieved.

    Args:
        name: Pipe name without prefix (e.g. 'lsass' not '\\\\\\\\.\\\\pipe\\\\lsass').
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
            sys.exit(0)

        try:
            # GetNamedPipeInfo
            flags = wintypes.DWORD(0)
            out_buf = wintypes.DWORD(0)
            in_buf = wintypes.DWORD(0)
            max_inst = wintypes.DWORD(0)
            kernel32.GetNamedPipeInfo(
                handle,
                ctypes.byref(flags), ctypes.byref(out_buf),
                ctypes.byref(in_buf), ctypes.byref(max_inst),
            )
            PIPE_TYPE_MESSAGE = 0x4
            PIPE_SERVER_END = 0x1
            mode = "message" if (flags.value & PIPE_TYPE_MESSAGE) else "byte"
            end = "server" if (flags.value & PIPE_SERVER_END) else "client"
            max_i = max_inst.value if max_inst.value != 255 else "unlimited"

            # SDDL
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

    result = _exec_python(script, args={"name": name})
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


@mcp.tool()
def pipe_connect(name: str, access: str = "read") -> str:
    """Open a handle to a named pipe and return the result.

    Attempts to connect to the pipe with the specified access. Useful for
    testing pipe ACLs, impersonation opportunities, and access control.
    Returns success + handle info, or the Win32 error on failure.

    Args:
        name: Pipe name without prefix (e.g. 'lsass').
        access: Access mode — 'read', 'write', or 'readwrite' (default: 'read').
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

    result = _exec_python(script, args={"name": name, "access": access})
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        output += f"\n[stderr]\n{result['stderr']}"
    if result["exitcode"] != 0:
        output += f"\n[exit code: {result['exitcode']}]"
    return output or "(no output)"


# ─── Pipe session broker ────────────────────────────────────────────────────
# Written to Z:\.mcp\pipes\<session_id>\broker.py and run as a detached
# background process that holds the pipe handle open between tool calls.
# IPC is file-based via the VirtIO-FS shared directory.

_BROKER_SCRIPT = """\
import ctypes
from ctypes import wintypes
import json
import os
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
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
cmd_file    = os.path.join(script_dir, 'cmd.json')
result_file = os.path.join(script_dir, 'result.json')

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

while True:
    if not os.path.exists(cmd_file):
        time.sleep(0.05)
        continue

    try:
        with open(cmd_file) as f:
            cmd = json.load(f)
        os.remove(cmd_file)
    except Exception:
        time.sleep(0.05)
        continue

    action = cmd.get('cmd')

    if action == 'write':
        data = bytes.fromhex(cmd['data_hex'])
        buf  = ctypes.create_string_buffer(data)
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(handle, buf, len(data), ctypes.byref(written), None)
        if ok:
            result = {'ok': True, 'written': written.value}
        else:
            err = ctypes.get_last_error()
            result = {'ok': False, 'error': f'WriteFile failed: error {err}'}

    elif action == 'read':
        size = cmd['size']
        buf  = ctypes.create_string_buffer(size)
        nread = wintypes.DWORD(0)
        ok = kernel32.ReadFile(handle, buf, size, ctypes.byref(nread), None)
        if ok:
            result = {'ok': True, 'data_hex': buf.raw[:nread.value].hex()}
        else:
            err = ctypes.get_last_error()
            result = {'ok': False, 'error': f'ReadFile failed: error {err}'}

    elif action == 'close':
        kernel32.CloseHandle(handle)
        with open(result_file, 'w') as f:
            json.dump({'ok': True}, f)
        break

    else:
        result = {'ok': False, 'error': f'unknown command: {action}'}

    with open(result_file, 'w') as f:
        json.dump(result, f)
"""


def _session_dir(session_id: str) -> Path:
    cfg, _, _ = _get_state()
    return cfg.shared_dir / ".mcp" / "pipes" / session_id


def _poll_result(result_file: Path, timeout: int) -> dict | None:
    """Poll for result.json on the Kali side (VirtIO-FS). Returns parsed dict or None on timeout."""
    import time as _time
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        if result_file.exists():
            try:
                data = _json.loads(result_file.read_text())
                result_file.unlink(missing_ok=True)
                return data
            except _json.JSONDecodeError:
                pass  # partial write — retry
        _time.sleep(0.1)
    return None


# ─── Tool 11: pipe_open / pipe_send / pipe_recv / pipe_close ─────────────────

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

    cfg, _, _ = _ensure_vm_ready()

    session_id = uuid.uuid4().hex[:12]
    session_dir = cfg.shared_dir / ".mcp" / "pipes" / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    (session_dir / "config.json").write_text(
        _json.dumps({"name": name, "access": access})
    )
    (session_dir / "broker.py").write_text(_BROKER_SCRIPT)

    # Windows path to broker on Z: (VirtIO-FS)
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

    result = _exec_python(spawner, args={"broker_path": broker_win})
    if result["exitcode"] != 0:
        import shutil
        shutil.rmtree(session_dir, ignore_errors=True)
        return f"spawner failed: {result['stderr'].strip()}"

    # The broker is already running detached in the VM at this point. Parse
    # its PID so we can kill it on any failure path — otherwise a broken
    # pipe_open leaves zombie python.exe processes accumulating forever.
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
        """Kill the orphaned broker (if any) and clean up the session dir."""
        import shutil
        if broker_pid is not None:
            try:
                _, _, ga = _ensure_vm_ready()
                ga.exec_argv("taskkill.exe", ["/F", "/PID", str(broker_pid)], timeout=5)
            except Exception:
                pass  # best-effort — broker may already have exited
        shutil.rmtree(session_dir, ignore_errors=True)
        return reason

    # Poll status.json on Kali side via VirtIO-FS
    status_file = session_dir / "status.json"
    deadline = _time.time() + timeout
    while _time.time() < deadline:
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

    cmd_file    = session_dir / "cmd.json"
    result_file = session_dir / "result.json"
    result_file.unlink(missing_ok=True)
    cmd_file.write_text(_json.dumps({"cmd": "write", "data_hex": data_hex}))

    res = _poll_result(result_file, timeout)
    if res is None:
        return "timeout waiting for write result"
    if res.get("ok"):
        return f"wrote {res['written']} bytes"
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

    cmd_file    = session_dir / "cmd.json"
    result_file = session_dir / "result.json"
    result_file.unlink(missing_ok=True)
    cmd_file.write_text(_json.dumps({"cmd": "read", "size": size}))

    res = _poll_result(result_file, timeout)
    if res is None:
        return "timeout waiting for read result"
    if res.get("ok"):
        return res["data_hex"]
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

    cmd_file    = session_dir / "cmd.json"
    result_file = session_dir / "result.json"
    result_file.unlink(missing_ok=True)
    cmd_file.write_text(_json.dumps({"cmd": "close"}))

    _poll_result(result_file, timeout=5)  # best-effort — broker may already be gone
    shutil.rmtree(session_dir, ignore_errors=True)
    return f"closed session {session_id}"


# ── removed: old pipe_recv(name, size) — superseded by pipe_open/pipe_recv ───


# ─── Tool 12: kdbg_start / kdbg_stop / kdbg_status ─────────────────────────

def _kdbg_hmp(vm_name: str, command: str) -> tuple[int, str, str]:
    """Send an HMP command to the VM's QEMU monitor via virsh."""
    import subprocess as _sp
    r = _sp.run(
        ["virsh", "-c", "qemu:///system",
         "qemu-monitor-command", vm_name, "--hmp", command],
        capture_output=True, text=True, check=False,
    )
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _kdbg_probe(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if something is listening on host:port."""
    import socket as _sk
    try:
        with _sk.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, _sk.timeout):
        return False


@mcp.tool()
def kdbg_start(port: int = 1234, any_interface: bool = False) -> str:
    """Start the QEMU gdb stub for hypervisor-level kernel debug.

    This exposes a gdb remote-protocol endpoint on the Kali host (inside
    the QEMU process) — completely transparent to the guest. No
    KdDebuggerEnabled flag, no bcdedit, no guest-visible artifacts. An
    external gdb client can then attach with `target remote :<port>`
    and set hardware breakpoints at any guest virtual address (kernel
    or userland). Undo with kdbg_stop().

    Args:
        port: TCP port for the gdb stub (default 1234).
        any_interface: Bind to 0.0.0.0 instead of 127.0.0.1. Exposes
            full r/w on guest kernel memory + registers to the LAN —
            opt-in only. Default False (localhost).
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"

    bind = "0.0.0.0" if any_interface else "127.0.0.1"

    if _kdbg_probe("127.0.0.1", port):
        return (
            f"Something is already listening on 127.0.0.1:{port}. "
            "Call kdbg_stop() first, or pick a different port."
        )

    rc, out, err = _kdbg_hmp(cfg.vm_name, f"gdbserver tcp:{bind}:{port}")
    if rc != 0:
        return f"Failed to start gdb stub: {err or out}"
    if "Waiting for gdb connection" not in out:
        return f"Unexpected HMP response: {out}"

    prefix = "[WARNING: 0.0.0.0 — LAN-accessible] " if any_interface else ""
    return (
        f"{prefix}gdb stub listening on {bind}:{port}. "
        f"Attach from Kali: gdb -ex 'set architecture i386:x86-64' "
        f"-ex 'target remote :{port}'"
    )


@mcp.tool()
def kdbg_stop() -> str:
    """Stop the QEMU gdb stub. Any attached gdb session gets EOF."""
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"

    rc, out, err = _kdbg_hmp(cfg.vm_name, "gdbserver none")
    if rc != 0:
        return f"Failed to stop gdb stub: {err or out}"
    return "gdb stub stopped"


@mcp.tool()
def kdbg_status(port: int = 1234) -> str:
    """Show whether the gdb stub is listening.

    Probes 127.0.0.1:<port> with a TCP connect. QEMU's stub only
    accepts one client at a time, so "listening but probe fails" is
    the usual signal that a gdb session is already attached.
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"

    if _kdbg_probe("127.0.0.1", port):
        return f"gdb stub: listening on 127.0.0.1:{port}"
    return f"gdb stub: not running (nothing on 127.0.0.1:{port})"


# ─── Tool 13: kdbg symbol / walker / CR3-read tools ────────────────────────
#
# These wrap the winbox.kdbg package so Claude can drive symbol loads,
# process walks, and cross-CR3 memory reads without shelling out to the CLI.
# Responses are deliberately terse: symbol/struct lookups return single
# numbers, never the full table (30k+ entries would blow the context).

from winbox.kdbg import (
    SymbolStore as _KdbgStore,
    SymbolStoreError as _KdbgStoreError,
    WalkCache as _KdbgWalkCache,
    load_from_ghidra as _kdbg_load_from_ghidra,
    load_nt as _kdbg_load_nt,
    read_virt_cr3 as _kdbg_read_virt_cr3,
    resolve_nt_base as _kdbg_resolve_nt_base,
)
from winbox.kdbg.hmp import HmpError as _KdbgHmpError
from winbox.kdbg.walk import list_modules as _kdbg_list_modules
from winbox.kdbg.walk import list_processes as _kdbg_list_processes


def _kdbg_get_store() -> _KdbgStore:
    cfg, _, _ = _get_state()
    return _KdbgStore(cfg.symbols_dir)


@mcp.tool()
def kdbg_symbols_load(module: str = "nt", from_ghidra: str = "", base: str = "") -> str:
    """Load symbols + struct offsets for a kernel module.

    For ``module='nt'`` (default), pulls ntoskrnl.exe from the running
    VM, fetches ntkrnlmp.pdb from Microsoft's symbol server, extracts
    public symbols and key struct layouts (EPROCESS/KPROCESS/KTHREAD/
    LDR_DATA_TABLE_ENTRY/etc), resolves the live load base via the IDT,
    and persists everything to ``~/.winbox/symbols/``.

    For any other module, supply ``from_ghidra`` with the path to a JSON
    symbol export and optionally ``base`` as a hex address override.

    The map itself is never returned inline — use ``kdbg_sym`` and
    ``kdbg_struct`` for lookups.

    Args:
        module: Module name (default 'nt'). Custom names require from_ghidra.
        from_ghidra: Path to a Ghidra-exported JSON.
        base: Optional hex base address for from_ghidra imports.
    """
    cfg, vm, ga = _ensure_vm_ready()
    store = _kdbg_get_store()

    if from_ghidra:
        from pathlib import Path as _P
        base_int = int(base, 16) if base else None
        info = _kdbg_load_from_ghidra(store, module, _P(from_ghidra), base=base_int)
        return (
            f"loaded {info.module} from {from_ghidra}: "
            f"{info.symbol_count} symbols, {info.type_count} types"
        )

    if module != "nt":
        return f"module {module!r}: automatic fetch only supports 'nt' — supply from_ghidra"

    info = _kdbg_load_nt(cfg, ga, store)
    base_txt = f"base=0x{info.base:x}" if info.base else "base=unresolved"
    return (
        f"nt {info.build}: {info.symbol_count} symbols, {info.type_count} types, {base_txt}"
    )


@mcp.tool()
def kdbg_sym(name: str, search: bool = False, limit: int = 16, rva: bool = False) -> str:
    """Resolve a kernel symbol. Use ``mod!sym`` to pick a module (default nt).

    By default returns the absolute virtual address. Pass ``rva=True`` to
    get the raw RVA (no base required). Pass ``search=True`` with a
    substring pattern to get the first ``limit`` matches.

    Args:
        name: Symbol name (e.g. 'NtCreateFile', 'nt!PsActiveProcessHead').
        search: If True, treat ``name`` as a substring pattern.
        limit: Max results when searching (default 16).
        rva: Return RVA instead of absolute VA.
    """
    store = _kdbg_get_store()
    try:
        module, sym = store.parse_symbol(name)
        if search:
            hits = store.search(sym, module=module, limit=limit)
            if not hits:
                return f"no matches for {name}"
            if rva:
                return "\n".join(f"{module}!{n} 0x{r:x}" for n, r in hits)
            base = store.load(module).get("base") or 0
            return "\n".join(f"{module}!{n} 0x{base + r:x}" for n, r in hits)
        if rva:
            return f"{name} 0x{store.rva(name):x}"
        return f"{name} 0x{store.resolve(name):x}"
    except _KdbgStoreError as e:
        return f"error: {e}"


@mcp.tool()
def kdbg_struct(type_name: str, field: str = "", module: str = "nt") -> str:
    """Return a struct layout or a single field offset from the symbol store.

    Without ``field``, returns the whole struct as a compact list of
    ``name +0xoffset type`` lines. With ``field``, returns just
    ``off=0xN type=...`` for that one member.

    Args:
        type_name: Struct type name (e.g. '_EPROCESS').
        field: Optional field name to look up by itself.
        module: Module the type lives in (default 'nt').
    """
    store = _kdbg_get_store()
    try:
        result = store.struct(type_name, field=field or None, module=module)
    except _KdbgStoreError as e:
        return f"error: {e}"

    if field:
        return f"{module}!{type_name}.{field} off=0x{result['off']:x} type={result.get('type','')}"
    size = result.get("size", 0)
    lines = [f"{module}!{type_name} size=0x{size:x} ({size})"]
    for fname, fdata in sorted(result.get("fields", {}).items(), key=lambda kv: kv[1]["off"]):
        lines.append(f"  +0x{fdata['off']:04x}  {fname}  {fdata.get('type','')}")
    return "\n".join(lines)


@mcp.tool()
def kdbg_ps() -> str:
    """Walk ``PsActiveProcessHead`` and return all running processes.

    Returns one line per process: ``PID  DTB  EPROCESS  Name``. The DTB
    is the ``DirectoryTableBase`` — feed it (or the PID) to
    ``kdbg_read_va`` for cross-process reads.

    Requires ``kdbg_symbols_load`` to have been run first.
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM not running ({vm.state().value})"
    store = _kdbg_get_store()
    try:
        procs = _kdbg_list_processes(cfg.vm_name, store)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return f"error: {e}"
    lines = ["PID     DTB              EPROCESS            Name"]
    for p in procs:
        lines.append(
            f"{p.pid:5d}  0x{p.directory_table_base:012x}  "
            f"0x{p.eprocess:016x}  {p.name}"
        )
    lines.append(f"({len(procs)} processes)")
    return "\n".join(lines)


@mcp.tool()
def kdbg_lm() -> str:
    """Walk ``PsLoadedModuleList`` and return all loaded kernel modules.

    One line per module: ``Base Size Name``. Base is the DllBase VA,
    Size is SizeOfImage. Use this to locate driver images when you need
    to resolve addresses inside non-nt drivers.
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM not running ({vm.state().value})"
    store = _kdbg_get_store()
    try:
        mods = _kdbg_list_modules(cfg.vm_name, store)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return f"error: {e}"
    lines = ["Base              Size        Name"]
    for m in mods:
        lines.append(f"0x{m.base:016x}  0x{m.size:08x}  {m.name}")
    lines.append(f"({len(mods)} modules)")
    return "\n".join(lines)


@mcp.tool()
def kdbg_read_va(pid: int, address: str, length: int) -> str:
    """Read virtual memory from an arbitrary process — the CR3-switching primitive.

    Looks up the target's EPROCESS, grabs its ``DirectoryTableBase``,
    and walks the page tables manually against that CR3 to read
    ``length`` bytes at ``address``. Works regardless of which process
    was scheduled on the CPU when the debug halt happened.

    Returns a hex string of the bytes. Pair with ``kdbg_ps`` to find a
    PID first.

    Args:
        pid: Target process ID (must be in kdbg_ps output).
        address: Virtual address, hex string (e.g. '0x7ff600001000').
        length: Number of bytes to read (capped at 65536).
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM not running ({vm.state().value})"
    if length <= 0:
        return "length must be > 0"
    if length > 65536:
        return f"length {length} too large — cap at 65536"
    try:
        va = int(address, 0)
    except ValueError:
        return f"invalid address: {address!r}"

    store = _kdbg_get_store()
    cache = _KdbgWalkCache()
    try:
        procs = _kdbg_list_processes(cfg.vm_name, store, cache=cache)
    except (_KdbgStoreError, _KdbgHmpError) as e:
        return f"error: {e}"
    target = next((p for p in procs if p.pid == pid), None)
    if target is None:
        return f"pid {pid} not found"

    try:
        data = _kdbg_read_virt_cr3(
            cfg.vm_name, target.directory_table_base, va, length, cache=cache,
        )
    except _KdbgHmpError as e:
        return f"read failed: {e}"
    return f"pid={pid} name={target.name} va=0x{va:x} len={len(data)} hex={data.hex()}"


@mcp.tool()
def kdbg_base_refresh() -> str:
    """Re-resolve and persist the nt load base from the live guest.

    ASLR re-randomizes the kernel base on every reboot. After a VM
    reboot the cached symbol map still has the old base — this call
    re-reads the IDT, computes the fresh base, and updates the store.
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM not running ({vm.state().value})"
    store = _kdbg_get_store()
    try:
        data = store.load("nt")
    except _KdbgStoreError as e:
        return f"error: {e}"
    try:
        base = _kdbg_resolve_nt_base(cfg, data.get("symbols", {}))
    except Exception as e:
        return f"could not resolve nt base: {e}"
    store.set_base("nt", base)
    return f"nt base = 0x{base:x}"


# ─── Entry point ────────────────────────────────────────────────────────────

def run_server() -> None:
    """Start the MCP server on stdio transport."""
    mcp.run(transport="stdio")
