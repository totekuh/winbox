"""Bounded, PDB-gated user VAD evidence.

VADs are kernel-owned hostile memory.  This module deliberately reports a
validated range or an explicit failure boundary; it never upgrades a loader
miss into a private/JIT/injected verdict merely because a pointer looked
plausible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from winbox.config import Config
from winbox.kdbg.memory import WalkCache, read_virt_cr3
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.symbols import ensure_types_loaded
from winbox.kdbg.walk import ProcessRecord, find_process


MAX_VADS = 4096
MAX_LOOKUPS = 128
_USER_MAX = 0x0000_7FFF_FFFF_FFFF


class VadError(RuntimeError):
    code = "vad_error"


class VadIncomplete(VadError):
    code = "incomplete_result"
    retryable = True


@dataclass(frozen=True)
class VadRecord:
    node: int
    start: int
    end: int
    flags: int
    vad_type_raw: int
    protection_raw: int
    protection: str | None
    executable: bool | None
    writable: bool | None
    private_memory: bool | None
    kind: str
    pe_header: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "node": f"0x{self.node:016x}",
            "start": f"0x{self.start:016x}",
            "end": f"0x{self.end:016x}",
            "size": self.end - self.start + 1,
            "flags_raw": f"0x{self.flags:08x}",
            "vad_type": {"raw": self.vad_type_raw, "name": _VAD_TYPES.get(self.vad_type_raw)},
            "protection": {
                "raw": self.protection_raw,
                "name": self.protection,
                "executable": self.executable,
                "writable": self.writable,
            },
            "private_memory": self.private_memory,
            "kind": self.kind,
            "pe_header": self.pe_header,
            "provenance": {
                "layout": "exact_nt_pdb",
                "flag_profile": "mmvad_flags_x64_v1",
                "file_backing": "not_attempted",
            },
        }


@dataclass(frozen=True)
class VadWalkResult:
    records: tuple[VadRecord, ...]
    complete: bool
    truncation: dict[str, Any] | None = None

    def public(self) -> dict[str, Any]:
        return {
            "records": [record.public() for record in self.records],
            "returned": len(self.records),
            "complete": self.complete,
            "truncation": self.truncation,
        }


@dataclass(frozen=True)
class _Layout:
    eprocess_vad_root: int
    tree_root: int
    node_left: int
    node_right: int
    node_parent: int
    vad_node: int
    start_low: int
    end_low: int
    start_high: int
    end_high: int
    flags: int


_VAD_TYPES = {
    0: "none",
    1: "device_physical_memory",
    2: "image_map",
    3: "awe",
    4: "write_watch",
    5: "large_pages",
    6: "rotate_physical",
    7: "large_page_section",
}
_PROTECTIONS = {
    0: "no_access", 1: "read_only", 2: "execute", 3: "execute_read",
    4: "read_write", 5: "write_copy", 6: "execute_read_write",
    7: "execute_write_copy",
}


def ensure_vad_layouts(cfg: Config, store: SymbolStore) -> None:
    """Extract VAD types before the caller stops Windows."""
    ensure_types_loaded(cfg, store, (
        "_RTL_AVL_TREE", "_RTL_BALANCED_NODE", "_MMVAD_SHORT", "_MMVAD_FLAGS",
    ))


def _field(store: SymbolStore, type_name: str, name: str, size: int) -> int:
    try:
        value = store.struct(type_name, name)
        offset = value.get("off") if isinstance(value, dict) else None
    except (KeyError, TypeError, SymbolStoreError) as exc:
        raise VadError(f"required exact PDB field missing: {type_name}.{name}") from exc
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise VadError(f"invalid exact PDB offset for {type_name}.{name}")
    try:
        struct_size = int(store.struct(type_name).get("size"))
    except (KeyError, TypeError, ValueError, SymbolStoreError) as exc:
        raise VadError(f"invalid exact PDB layout for {type_name}") from exc
    if struct_size <= 0 or offset + size > struct_size:
        raise VadError(f"implausible exact PDB field {type_name}.{name}")
    return offset


def _layout(store: SymbolStore) -> _Layout:
    architecture = str(store.load("nt").get("architecture") or "")
    if architecture != "x64":
        raise VadError("VAD walker supports only exact x64 nt PDB layouts")
    return _Layout(
        eprocess_vad_root=_field(store, "_EPROCESS", "VadRoot", 8),
        tree_root=_field(store, "_RTL_AVL_TREE", "Root", 8),
        node_left=_field(store, "_RTL_BALANCED_NODE", "Left", 8),
        node_right=_field(store, "_RTL_BALANCED_NODE", "Right", 8),
        node_parent=_field(store, "_RTL_BALANCED_NODE", "ParentValue", 8),
        vad_node=_field(store, "_MMVAD_SHORT", "VadNode", 1),
        start_low=_field(store, "_MMVAD_SHORT", "StartingVpn", 4),
        end_low=_field(store, "_MMVAD_SHORT", "EndingVpn", 4),
        start_high=_field(store, "_MMVAD_SHORT", "StartingVpnHigh", 1),
        end_high=_field(store, "_MMVAD_SHORT", "EndingVpnHigh", 1),
        flags=_field(store, "_MMVAD_SHORT", "u", 4),
    )


def _u64(vm_name: str, cr3: int, address: int, cache: WalkCache) -> int:
    raw = read_virt_cr3(vm_name, cr3, address, 8, cache=cache)
    if len(raw) != 8:
        raise VadError(f"short VAD pointer read at 0x{address:x}")
    return int.from_bytes(raw, "little")


def _bytes(vm_name: str, cr3: int, address: int, size: int, cache: WalkCache) -> bytes:
    raw = read_virt_cr3(vm_name, cr3, address, size, cache=cache)
    if len(raw) != size:
        raise VadError(f"short VAD field read at 0x{address:x}")
    return raw


def _kernel_cr3(vm_name: str, store: SymbolStore, cache: WalkCache) -> int:
    system = find_process(vm_name, store, pid=4, cache=cache)
    if system is None or system.directory_table_base == 0:
        raise VadError("could not establish System process DTB for VAD walk")
    return system.directory_table_base


def _valid_node(pointer: int) -> bool:
    return pointer == 0 or (pointer & 0x7 == 0 and pointer >> 48 == 0xFFFF)


def _record(
    vm_name: str, cr3: int, node: int, layout: _Layout, cache: WalkCache,
    *, target: ProcessRecord | None = None, probe_header: bool = False,
) -> VadRecord:
    base = node - layout.vad_node
    if not _valid_node(base):
        raise VadError(f"invalid VAD base 0x{base:x}")
    raw = _bytes(vm_name, cr3, base, max(
        layout.flags + 4, layout.end_high + 1, layout.start_high + 1,
        layout.end_low + 4, layout.start_low + 4,
    ), cache)
    start_vpn = int.from_bytes(raw[layout.start_low:layout.start_low + 4], "little")
    end_vpn = int.from_bytes(raw[layout.end_low:layout.end_low + 4], "little")
    start = ((raw[layout.start_high] << 32) | start_vpn) << 12
    end = (((raw[layout.end_high] << 32) | end_vpn) << 12) | 0xFFF
    if start > end or end > _USER_MAX:
        raise VadError(f"invalid user VAD range 0x{start:x}-0x{end:x}")
    flags = int.from_bytes(raw[layout.flags:layout.flags + 4], "little")
    vad_type = (flags >> 4) & 0x7
    protection = (flags >> 7) & 0x1F
    private = bool((flags >> 20) & 1)
    protection_name = _PROTECTIONS.get(protection)
    executable = protection_name.startswith("execute") if protection_name else None
    writable = protection_name in {
        "read_write", "write_copy", "execute_read_write", "execute_write_copy",
    } if protection_name else None
    kind = "private" if private else ("image" if vad_type == 2 else "non_private")
    header = None
    if probe_header and target is not None:
        try:
            header = "mz" if _bytes(vm_name, target.directory_table_base, start, 2, cache) == b"MZ" else "not_mz"
        except Exception:
            header = "unreadable"
    return VadRecord(
        node=base, start=start, end=end, flags=flags, vad_type_raw=vad_type,
        protection_raw=protection, protection=protection_name,
        executable=executable, writable=writable, private_memory=private,
        kind=kind, pe_header=header,
    )


def _children(vm_name: str, cr3: int, node: int, layout: _Layout, cache: WalkCache) -> tuple[int, int]:
    left = _u64(vm_name, cr3, node + layout.node_left, cache)
    right = _u64(vm_name, cr3, node + layout.node_right, cache)
    if not _valid_node(left) or not _valid_node(right):
        raise VadError(f"invalid VAD child pointer at 0x{node:x}")
    for child in (left, right):
        if child:
            parent = _u64(vm_name, cr3, child + layout.node_parent, cache) & ~0x3
            if parent != node:
                raise VadError(f"VAD parent backlink mismatch child=0x{child:x} parent=0x{parent:x}")
    return left, right


def _root(vm_name: str, store: SymbolStore, target: ProcessRecord, layout: _Layout,
          cache: WalkCache) -> tuple[int, int]:
    cr3 = _kernel_cr3(vm_name, store, cache)
    # VadRoot embeds RTL_AVL_TREE in EPROCESS.  Root is its first exact-PDB field.
    root = _u64(vm_name, cr3, target.eprocess + layout.eprocess_vad_root + layout.tree_root, cache)
    if not _valid_node(root):
        raise VadError(f"invalid VAD root 0x{root:x}")
    return cr3, root


def list_vads(
    vm_name: str, store: SymbolStore, target: ProcessRecord, *, cache: WalkCache | None = None,
    executable_only: bool = False, limit: int = 256, probe_header: bool = False,
) -> VadWalkResult:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_VADS:
        raise VadError(f"limit must be between 1 and {MAX_VADS}")
    cache = cache or WalkCache()
    layout = _layout(store)
    cr3, root = _root(vm_name, store, target, layout, cache)
    stack: list[int] = []
    records: list[VadRecord] = []
    seen: set[int] = set()
    current = root
    while current or stack:
        while current:
            if current in seen:
                return VadWalkResult(tuple(records), False, {"stage": "tree", "reason": "cycle", "node": f"0x{current:016x}"})
            if len(seen) >= MAX_VADS:
                return VadWalkResult(tuple(records), False, {"stage": "cap", "reason": f"tree cap={MAX_VADS}", "node": f"0x{current:016x}"})
            seen.add(current)
            left, _ = _children(vm_name, cr3, current, layout, cache)
            stack.append(current)
            current = left
        current = stack.pop()
        record = _record(vm_name, cr3, current, layout, cache, target=target, probe_header=probe_header)
        if not executable_only or record.executable is True:
            if len(records) >= limit:
                return VadWalkResult(tuple(records), False, {"stage": "output", "reason": f"limit={limit}", "node": f"0x{current:016x}"})
            records.append(record)
        _, current = _children(vm_name, cr3, current, layout, cache)
    return VadWalkResult(tuple(records), True)


def lookup_vad(
    vm_name: str, store: SymbolStore, target: ProcessRecord, address: int,
    *, cache: WalkCache | None = None, probe_header: bool = False,
) -> VadRecord | None:
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address <= _USER_MAX:
        raise VadError("address must be a canonical user-mode virtual address")
    cache = cache or WalkCache()
    layout = _layout(store)
    cr3, current = _root(vm_name, store, target, layout, cache)
    seen: set[int] = set()
    for _ in range(64):
        if not current:
            return None
        if current in seen:
            raise VadError(f"VAD lookup cycle at 0x{current:x}")
        seen.add(current)
        record = _record(vm_name, cr3, current, layout, cache, target=target, probe_header=probe_header)
        if record.start <= address <= record.end:
            return record
        left, right = _children(vm_name, cr3, current, layout, cache)
        current = left if address < record.start else right
    raise VadError("VAD lookup depth exceeded 64")


def lookup_addresses(
    vm_name: str, store: SymbolStore, target: ProcessRecord, addresses: Iterable[int],
    *, cache: WalkCache | None = None, probe_header: bool = False,
) -> dict[int, VadRecord | None]:
    values = list(addresses)
    if len(values) > MAX_LOOKUPS:
        raise VadError(f"address lookup cap is {MAX_LOOKUPS}")
    cache = cache or WalkCache()
    return {
        value: lookup_vad(vm_name, store, target, value, cache=cache, probe_header=probe_header)
        for value in values
    }
