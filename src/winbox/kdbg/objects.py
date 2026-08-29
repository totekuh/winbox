"""Exact-PDB-gated token and kernel-object evidence.

The first useful relationship surface is the primary token: it is compact,
versioned by the nt PDB, and avoids pretending that a raw access mask makes a
handle exploitable.  Handle-table enumeration is intentionally unavailable on
builds whose public PDB omits the entry union rather than decoding a guessed
private layout.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from winbox.config import Config
from winbox.kdbg.memory import WalkCache, read_virt_cr3
from winbox.kdbg.store import SymbolStore, SymbolStoreError
from winbox.kdbg.symbols import ensure_types_loaded
from winbox.kdbg.walk import ProcessRecord, find_process


class ObjectEvidenceError(RuntimeError):
    code = "object_evidence_error"


MAX_HANDLE_ROWS = 1024


def ensure_object_layouts(cfg: Config, store: SymbolStore) -> None:
    ensure_types_loaded(cfg, store, (
        "_EX_FAST_REF", "_TOKEN", "_SEP_TOKEN_PRIVILEGES", "_HANDLE_TABLE",
        "_OBJECT_HEADER",
    ))


def _field(store: SymbolStore, type_name: str, name: str, size: int) -> int:
    try:
        value = store.struct(type_name, name)
        offset = value.get("off") if isinstance(value, dict) else None
        layout = store.struct(type_name)
        total = layout.get("size") if isinstance(layout, dict) else None
    except (KeyError, TypeError, SymbolStoreError) as exc:
        raise ObjectEvidenceError(f"required exact PDB field missing: {type_name}.{name}") from exc
    if (
        isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
        or isinstance(total, bool) or not isinstance(total, int) or total <= 0
        or offset + size > total
    ):
        raise ObjectEvidenceError(f"invalid exact PDB layout: {type_name}.{name}")
    return offset


def _u64(vm_name: str, cr3: int, address: int, cache: WalkCache) -> int:
    raw = read_virt_cr3(vm_name, cr3, address, 8, cache=cache)
    if len(raw) != 8:
        raise ObjectEvidenceError(f"short object read at 0x{address:x}")
    return int.from_bytes(raw, "little")


def _u32(vm_name: str, cr3: int, address: int, cache: WalkCache) -> int:
    raw = read_virt_cr3(vm_name, cr3, address, 4, cache=cache)
    if len(raw) != 4:
        raise ObjectEvidenceError(f"short object read at 0x{address:x}")
    return int.from_bytes(raw, "little")


def _u8(vm_name: str, cr3: int, address: int, cache: WalkCache) -> int:
    raw = read_virt_cr3(vm_name, cr3, address, 1, cache=cache)
    if len(raw) != 1:
        raise ObjectEvidenceError(f"short object read at 0x{address:x}")
    return raw[0]


def _kernel_cr3(vm_name: str, store: SymbolStore, cache: WalkCache) -> int:
    system = find_process(vm_name, store, pid=4, cache=cache)
    if system is None or system.directory_table_base == 0:
        raise ObjectEvidenceError("could not establish System process DTB")
    return system.directory_table_base


def _canonical_kernel(value: int) -> bool:
    return value != 0 and value & 0x7 == 0 and value >> 48 == 0xFFFF


@dataclass(frozen=True)
class ObjectHeader:
    body: int
    header: int
    pointer_count: int
    handle_count: int
    type_index: int
    info_mask: int
    flags: int

    def public(self) -> dict[str, Any]:
        return {
            "body": f"0x{self.body:016x}",
            "header": f"0x{self.header:016x}",
            "pointer_count": self.pointer_count,
            "handle_count": self.handle_count,
            "type_index": self.type_index,
            "info_mask": f"0x{self.info_mask:02x}",
            "flags": f"0x{self.flags:02x}",
            "type_name": None,
            "provenance": "exact_nt_pdb_header; type name unavailable without a validated ObTypeIndexTable",
        }


def object_header(
    vm_name: str, store: SymbolStore, body: int, *, cache: WalkCache | None = None,
) -> ObjectHeader:
    """Decode an object header only for a caller-proven object body pointer."""
    if isinstance(body, bool) or not isinstance(body, int) or not _canonical_kernel(body):
        raise ObjectEvidenceError("object body must be an aligned canonical kernel pointer")
    cache = cache or WalkCache()
    cr3 = _kernel_cr3(vm_name, store, cache)
    body_offset = _field(store, "_OBJECT_HEADER", "Body", 1)
    pointer_off = _field(store, "_OBJECT_HEADER", "PointerCount", 8)
    handle_off = _field(store, "_OBJECT_HEADER", "HandleCount", 8)
    type_off = _field(store, "_OBJECT_HEADER", "TypeIndex", 1)
    info_off = _field(store, "_OBJECT_HEADER", "InfoMask", 1)
    flags_off = _field(store, "_OBJECT_HEADER", "Flags", 1)
    header = body - body_offset
    if not _canonical_kernel(header):
        raise ObjectEvidenceError("object header underflow")
    pointer_count = _u64(vm_name, cr3, header + pointer_off, cache)
    handle_count = _u64(vm_name, cr3, header + handle_off, cache)
    if pointer_count > (1 << 48) or handle_count > pointer_count:
        raise ObjectEvidenceError("implausible object header reference counts")
    return ObjectHeader(
        body=body, header=header, pointer_count=pointer_count, handle_count=handle_count,
        type_index=_u8(vm_name, cr3, header + type_off, cache),
        info_mask=_u8(vm_name, cr3, header + info_off, cache),
        flags=_u8(vm_name, cr3, header + flags_off, cache),
    )


def token_evidence(
    vm_name: str, store: SymbolStore, target: ProcessRecord, *, cache: WalkCache | None = None,
) -> dict[str, Any]:
    """Return primary-token identity and privilege masks from exact PDB fields."""
    if str(store.load("nt").get("architecture") or "") != "x64":
        raise ObjectEvidenceError("token evidence supports only exact x64 nt PDB layouts")
    cache = cache or WalkCache()
    cr3 = _kernel_cr3(vm_name, store, cache)
    eprocess_token = _field(store, "_EPROCESS", "Token", 8)
    fast_value = _u64(vm_name, cr3, target.eprocess + eprocess_token, cache)
    body = fast_value & ~0xF
    if not _canonical_kernel(body):
        raise ObjectEvidenceError("EPROCESS.Token EX_FAST_REF did not contain a canonical object body")
    token_id = _field(store, "_TOKEN", "TokenId", 8)
    auth_id = _field(store, "_TOKEN", "AuthenticationId", 8)
    session = _field(store, "_TOKEN", "SessionId", 4)
    flags = _field(store, "_TOKEN", "TokenFlags", 4)
    integrity = _field(store, "_TOKEN", "IntegrityLevelIndex", 4)
    in_use = _field(store, "_TOKEN", "TokenInUse", 1)
    privileges = _field(store, "_TOKEN", "Privileges", 24)
    present = _field(store, "_SEP_TOKEN_PRIVILEGES", "Present", 8)
    enabled = _field(store, "_SEP_TOKEN_PRIVILEGES", "Enabled", 8)
    enabled_default = _field(store, "_SEP_TOKEN_PRIVILEGES", "EnabledByDefault", 8)
    header = object_header(vm_name, store, body, cache=cache)
    return {
        "process": {
            "pid": target.pid, "name": target.name,
            "eprocess": f"0x{target.eprocess:016x}",
        },
        "token": {
            "body": f"0x{body:016x}",
            "fast_ref": {"raw": f"0x{fast_value:016x}", "ref_count": fast_value & 0xF},
            "token_id": f"0x{_u64(vm_name, cr3, body + token_id, cache):016x}",
            "authentication_id": f"0x{_u64(vm_name, cr3, body + auth_id, cache):016x}",
            "session_id": _u32(vm_name, cr3, body + session, cache),
            "flags": f"0x{_u32(vm_name, cr3, body + flags, cache):08x}",
            "integrity_level_index": _u32(vm_name, cr3, body + integrity, cache),
            "in_use": bool(_u8(vm_name, cr3, body + in_use, cache)),
            "privileges": {
                "present": f"0x{_u64(vm_name, cr3, body + privileges + present, cache):016x}",
                "enabled": f"0x{_u64(vm_name, cr3, body + privileges + enabled, cache):016x}",
                "enabled_by_default": f"0x{_u64(vm_name, cr3, body + privileges + enabled_default, cache):016x}",
                "names": None,
                "provenance": "raw SEP_TOKEN_PRIVILEGES masks; no guessed LUID-name table",
            },
        },
        "object_header": header.public(),
        "provenance": "exact_nt_pdb",
    }


def handle_table_status(
    vm_name: str, store: SymbolStore, target: ProcessRecord, *, cache: WalkCache | None = None,
) -> dict[str, Any]:
    """Expose a proven table root and fail closed if entry layout is absent.

    Public nt PDBs commonly omit the private HANDLE_TABLE_ENTRY union.  The
    table root is still useful evidence, but enumerating 16-byte slots without
    a build-validated entry definition would be fabricated precision.
    """
    cache = cache or WalkCache()
    cr3 = _kernel_cr3(vm_name, store, cache)
    table_off = _field(store, "_EPROCESS", "ObjectTable", 8)
    table = _u64(vm_name, cr3, target.eprocess + table_off, cache)
    if not _canonical_kernel(table):
        raise ObjectEvidenceError("EPROCESS.ObjectTable did not contain a canonical handle table")
    table_code_off = _field(store, "_HANDLE_TABLE", "TableCode", 8)
    table_code = _u64(vm_name, cr3, table + table_code_off, cache)
    level = table_code & 0x3
    root = table_code & ~0xF
    return {
        "process": {"pid": target.pid, "name": target.name, "eprocess": f"0x{target.eprocess:016x}"},
        "handle_table": {
            "address": f"0x{table:016x}", "table_code": f"0x{table_code:016x}",
            "level": level, "root": f"0x{root:016x}" if root else None,
        },
        "enumeration": {
            "available": False,
            "reason": "public nt PDB does not expose a validated HANDLE_TABLE_ENTRY layout on this build",
            "next_action": "load a build-specific handle-entry layout profile; raw slot decoding is intentionally refused",
        },
        "provenance": "exact_nt_pdb",
    }
