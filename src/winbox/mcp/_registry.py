"""Windows registry tools — reg_query, reg_set, reg_delete."""

from __future__ import annotations

import textwrap

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import _format_exec_result


# ─── Registry helpers (shared across reg_query / reg_set / reg_delete) ────

_REG_HIVE_LOOKUP = '''\
hive_map = {
    'HKLM': winreg.HKEY_LOCAL_MACHINE,
    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
    'HKCU': winreg.HKEY_CURRENT_USER,
    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
    'HKCR': winreg.HKEY_CLASSES_ROOT,
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKU': winreg.HKEY_USERS,
    'HKEY_USERS': winreg.HKEY_USERS,
}
parts = key_path.split('\\\\', 1)
hive_name = parts[0].rstrip(':')
subkey = parts[1] if len(parts) > 1 else ''
hive = hive_map.get(hive_name.upper())
if hive is None:
    print(f"Unknown hive: {hive_name}", file=sys.stderr)
    sys.exit(1)
'''

_REG_TYPE_NAMES = '''\
type_names = {
    winreg.REG_SZ: 'REG_SZ',
    winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
    winreg.REG_DWORD: 'REG_DWORD',
    winreg.REG_QWORD: 'REG_QWORD',
    winreg.REG_BINARY: 'REG_BINARY',
    winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
}
'''

_REG_TYPE_MAP = '''\
type_map = {
    'REG_SZ':        (winreg.REG_SZ,        lambda d: d),
    'REG_EXPAND_SZ': (winreg.REG_EXPAND_SZ, lambda d: d),
    'REG_DWORD':     (winreg.REG_DWORD,     lambda d: int(d, 0)),
    'REG_QWORD':     (winreg.REG_QWORD,     lambda d: int(d, 0)),
    'REG_BINARY':    (winreg.REG_BINARY,    lambda d: bytes.fromhex(d)),
    'REG_MULTI_SZ':  (winreg.REG_MULTI_SZ,  lambda d: d.split('\\n')),
}
'''


@mcp.tool()
def reg_query(key: str, value: str | None = None, timeout: int = 30) -> str:
    """Query a Windows registry key or value.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion').
        value: Specific value name to query. If omitted, lists all values under the key.
        timeout: Execution timeout in seconds (default 30).
    """
    if value is not None:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\nvalue_name = {value!r}\n\n"
            + _REG_HIVE_LOOKUP
            + _REG_TYPE_NAMES
            + textwrap.dedent('''\
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        data, reg_type = winreg.QueryValueEx(k, value_name)
                        type_name = type_names.get(reg_type, f'type({reg_type})')
                        if reg_type == winreg.REG_BINARY:
                            print(f"{value_name} ({type_name}): {data.hex()}")
                        elif reg_type == winreg.REG_MULTI_SZ:
                            print(f"{value_name} ({type_name}):")
                            for item in data:
                                print(f"  {item}")
                        else:
                            print(f"{value_name} ({type_name}): {data}")
                except FileNotFoundError:
                    print(f"Not found: {key_path}\\\\{value_name}", file=sys.stderr)
                    sys.exit(1)
            ''')
        )
    else:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\n\n"
            + _REG_HIVE_LOOKUP
            + _REG_TYPE_NAMES
            + textwrap.dedent('''\
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                name, data, reg_type = winreg.EnumValue(k, i)
                                type_name = type_names.get(reg_type, f'type({reg_type})')
                                if reg_type == winreg.REG_BINARY:
                                    print(f"{name} ({type_name}): {data.hex()}")
                                else:
                                    print(f"{name} ({type_name}): {data}")
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
                            print(f"\\nSubkeys ({j}):")
                            for sk in subkeys:
                                print(f"  {sk}")
                except FileNotFoundError:
                    print(f"Key not found: {key_path}", file=sys.stderr)
                    sys.exit(1)
            ''')
        )

    result = _mcp_common._exec_python(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def reg_set(
    key: str,
    value: str,
    data: str,
    value_type: str = "REG_SZ",
    timeout: int = 30,
) -> str:
    """Set a Windows registry value.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\MyKey'). Created if it doesn't exist.
        value: Value name to set.
        data: Data to write. For REG_DWORD/REG_QWORD pass the integer as a string.
              For REG_BINARY pass hex. For REG_MULTI_SZ pass items separated by '\\n'.
        value_type: Registry type - REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ.
        timeout: Execution timeout in seconds (default 30).
    """
    script = (
        f"import winreg\nimport sys\n\n"
        f"key_path = {key!r}\nvalue_name = {value!r}\n"
        f"raw_data = {data!r}\nreg_type_name = {value_type!r}\n\n"
        + _REG_HIVE_LOOKUP
        + _REG_TYPE_MAP
        + textwrap.dedent('''\
            # Accept the obvious shorthands ("dword", "reg_dword") rather than
            # failing a write over spelling.
            reg_type_name = reg_type_name.strip().upper()
            if not reg_type_name.startswith("REG_"):
                reg_type_name = "REG_" + reg_type_name
            if reg_type_name not in type_map:
                print(
                    f"Unknown type: {reg_type_name}. "
                    f"Expected one of: {', '.join(sorted(type_map))}",
                    file=sys.stderr,
                )
                sys.exit(1)

            reg_type, converter = type_map[reg_type_name]
            try:
                converted = converter(raw_data)
            except (ValueError, OverflowError) as e:
                print(f"Bad data for {reg_type_name}: {raw_data!r} ({e})",
                      file=sys.stderr)
                sys.exit(1)

            try:
                with winreg.CreateKey(hive, subkey) as k:
                    winreg.SetValueEx(k, value_name, 0, reg_type, converted)
            except (ValueError, OverflowError) as e:
                print(f"Bad data for {reg_type_name}: {raw_data!r} ({e})",
                      file=sys.stderr)
                sys.exit(1)
            except FileNotFoundError:
                print(f"Not found: {key_path}", file=sys.stderr)
                sys.exit(1)
            except PermissionError:
                print(f"Access denied: {key_path}", file=sys.stderr)
                sys.exit(1)
            print(f"Set {key_path}\\\\{value_name} = {raw_data} ({reg_type_name})")
        ''')
    )

    result = _mcp_common._exec_python(script, timeout=timeout)
    return _format_exec_result(result)


@mcp.tool()
def reg_delete(key: str, value: str | None = None, timeout: int = 30) -> str:
    """Delete a Windows registry value or entire key.

    If value is provided, deletes that specific value. If omitted,
    deletes the entire key and all its subkeys.

    Args:
        key: Registry key path (e.g. 'HKLM\\\\SOFTWARE\\\\MyKey').
        value: Specific value name to delete. If omitted, deletes the entire key tree.
        timeout: Execution timeout in seconds (default 30).
    """
    if value is not None:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\nvalue_name = {value!r}\n\n"
            + _REG_HIVE_LOOKUP
            + textwrap.dedent('''\
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                        winreg.DeleteValue(k, value_name)
                    print(f"Deleted value {key_path}\\\\{value_name}")
                except FileNotFoundError:
                    print(f"Not found: {key_path}\\\\{value_name}", file=sys.stderr)
                    sys.exit(1)
                except PermissionError:
                    print(f"Access denied: {key_path}\\\\{value_name}", file=sys.stderr)
                    sys.exit(1)
            ''')
        )
    else:
        script = (
            f"import winreg\nimport sys\n\n"
            f"key_path = {key!r}\n\n"
            + _REG_HIVE_LOOKUP
            + textwrap.dedent('''\
                def delete_key_tree(hive, subkey):
                    try:
                        with winreg.OpenKey(hive, subkey, 0,
                                            winreg.KEY_ALL_ACCESS) as k:
                            while True:
                                try:
                                    child = winreg.EnumKey(k, 0)
                                    delete_key_tree(hive, f"{subkey}\\\\{child}")
                                except OSError:
                                    break
                        winreg.DeleteKey(hive, subkey)
                    except FileNotFoundError:
                        print(f"Not found: {key_path}", file=sys.stderr)
                        sys.exit(1)
                    except PermissionError:
                        print(f"Access denied: {key_path}", file=sys.stderr)
                        sys.exit(1)

                delete_key_tree(hive, subkey)
                print(f"Deleted key {key_path}")
            ''')
        )

    result = _mcp_common._exec_python(script, timeout=timeout)
    return _format_exec_result(result)
