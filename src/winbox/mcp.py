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

    Returns dict with exitcode, stdout, stderr.
    """
    cfg, vm, ga = _ensure_vm_ready()

    # Write script to shared filesystem
    script_dir = cfg.shared_dir / ".mcp"
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / "script.py"
    script_path.write_text(code, encoding="utf-8")

    # Write args as JSON for the script to read
    if args is not None:
        args_path = script_dir / "args.json"
        args_path.write_text(_json.dumps(args), encoding="utf-8")

    # Execute via guest agent
    result = ga.exec(
        r'python.exe Z:\.mcp\script.py',
        timeout=timeout,
    )

    return {
        "exitcode": result.exitcode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


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


# ─── Tool 9: net_isolate / net_connect ──────────────────────────────────────

@mcp.tool()
def net_isolate() -> str:
    """Disconnect the VM from the network (unplug the cable).

    Host-VM channels (guest agent, VirtIO-FS) stay up since they use
    virtio-serial, not the network. Only the NIC is disconnected.
    Undo with net_connect.
    """
    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    if not vm.net_set_link("down"):
        return "Failed to set link down (no interface found?)"
    return "Network isolated — cable unplugged"


@mcp.tool()
def net_connect() -> str:
    """Reconnect the VM to the network (plug the cable back in).

    Automatically restarts the adapter and renews DHCP.
    """
    import time

    cfg, vm, ga = _get_state()
    if vm.state() != VMState.RUNNING:
        return f"VM is not running (state: {vm.state().value})"
    if not vm.net_set_link("up"):
        return "Failed to set link up (no interface found?)"

    # Restart adapter + renew DHCP — Windows doesn't auto-renew after replug
    ga.exec_powershell(
        "Restart-NetAdapter -Name (Get-NetAdapter | Select -First 1).Name "
        "-Confirm:$false",
        timeout=15,
    )
    for _ in range(10):
        ip = vm.ip()
        if ip:
            return f"Network connected — IP: {ip}"
        time.sleep(1)
    return "Network connected (DHCP pending)"


# ─── Tool 10: pipe_list / pipe_info / pipe_connect ──────────────────────────

@mcp.tool()
def pipe_list(filter: str = "") -> str:
    """Enumerate named pipes in the Windows VM matching a pattern.

    Uses Get-ChildItem on \\\\.\\pipe\\ via PowerShell. Returns pipe names,
    one per line, sorted alphabetically.

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
        print(f"{len(pipes)} pipe(s):")
        for p in pipes:
            print(f"  {p}")
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

    Returns the SDDL (DACL/owner/group), pipe mode (byte/message),
    input/output buffer sizes, and current instance count.

    Args:
        name: Pipe name without prefix (e.g. 'lsass' not '\\\\\\\\.\\\\pipe\\\\lsass').
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import subprocess
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
            # Try read-only with no access (just for security query)
            print(f"Cannot open pipe (error {err}) — trying SDDL via PowerShell only")
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'(Get-Acl -Path "\\\\\\\\.${{pipe_path.replace(chr(92)*2+chr(46)+chr(92), chr(92))}}").Sddl'],
                capture_output=True, text=True,
            )
            print(r.stdout.strip() or "(no SDDL)")
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
            print(f"Pipe:       {pipe_path}")
            print(f"Mode:       {mode}")
            print(f"End:        {end}")
            print(f"OutBuf:     {out_buf.value} bytes")
            print(f"InBuf:      {in_buf.value} bytes")
            print(f"MaxInst:    {max_i}")

            # SDDL
            SE_KERNEL_OBJECT = 6
            DACL_SECURITY_INFORMATION = 4
            OWNER_SECURITY_INFORMATION = 1
            GROUP_SECURITY_INFORMATION = 2
            sd_ptr = ctypes.c_void_p()
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
                    print(f"SDDL:       {sddl_ptr.value}")
                    kernel32.LocalFree(sddl_ptr)
                kernel32.LocalFree(sd_ptr)
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


# ─── Entry point ────────────────────────────────────────────────────────────

def run_server() -> None:
    """Start the MCP server on stdio transport."""
    mcp.run(transport="stdio")
