"""kdbg — hypervisor-level kernel debug helpers.

Exposes the primitives the CLI and MCP layers use:

    from winbox.kdbg import SymbolStore, load_nt, read_virt_cr3

All VM interaction flows through QEMU HMP (``virsh qemu-monitor-command``)
so it runs alongside an attached gdb client without fighting for the
gdbstub socket.
"""

from __future__ import annotations

from winbox.kdbg.hmp import HmpError, hmp, parse_registers, read_cpu_state
from winbox.kdbg.memory import (
    WalkCache,
    read_phys,
    read_virt_cr3,
    read_virt_current,
    virt_to_phys,
)
from winbox.kdbg.pdb import (
    build_symbol_map,
    build_type_map,
    load_publics,
    load_section_headers,
    load_types,
)
from winbox.kdbg.pe import PdbRef, fetch_pdb, read_pdb_ref
from winbox.kdbg.store import ModuleInfo, SymbolStore, SymbolStoreError
from winbox.kdbg.symbols import (
    LoadedModule,
    SymbolLoadError,
    cached_pdb_path,
    copy_user_module,
    ensure_types_loaded,
    load_module,
    load_nt,
    resolve_nt_base,
)

__all__ = [
    "HmpError",
    "LoadedModule",
    "ModuleInfo",
    "PdbRef",
    "SymbolLoadError",
    "SymbolStore",
    "SymbolStoreError",
    "WalkCache",
    "build_symbol_map",
    "build_type_map",
    "cached_pdb_path",
    "copy_user_module",
    "ensure_types_loaded",
    "fetch_pdb",
    "hmp",
    "load_module",
    "load_nt",
    "load_publics",
    "load_section_headers",
    "load_types",
    "parse_registers",
    "read_cpu_state",
    "read_phys",
    "read_pdb_ref",
    "read_virt_cr3",
    "read_virt_current",
    "resolve_nt_base",
    "virt_to_phys",
]
