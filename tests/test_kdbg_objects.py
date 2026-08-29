"""Fail-closed object/token evidence contracts."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from winbox.kdbg.objects import ObjectEvidenceError, handle_table_status, token_evidence
from winbox.kdbg.walk import ProcessRecord


BASE = 0xFFFF_8000_0000_0000
SYSTEM = ProcessRecord(4, "System", BASE + 0x1000, 0x12345000, 1)
TARGET = ProcessRecord(100, "sample.exe", BASE + 0x2000, 0x12345000, 2)


class Store:
    def __init__(self):
        self.types = {
            "_EPROCESS": {"size": 0x200, "fields": {"Token": {"off": 0x40}, "ObjectTable": {"off": 0x48}}},
            "_TOKEN": {"size": 0x200, "fields": {
                "TokenId": {"off": 0x10}, "AuthenticationId": {"off": 0x18},
                "SessionId": {"off": 0x20}, "TokenFlags": {"off": 0x24},
                "IntegrityLevelIndex": {"off": 0x28}, "TokenInUse": {"off": 0x2C},
                "Privileges": {"off": 0x30},
            }},
            "_SEP_TOKEN_PRIVILEGES": {"size": 24, "fields": {
                "Present": {"off": 0}, "Enabled": {"off": 8}, "EnabledByDefault": {"off": 16},
            }},
            "_OBJECT_HEADER": {"size": 0x40, "fields": {
                "PointerCount": {"off": 0}, "HandleCount": {"off": 8}, "TypeIndex": {"off": 0x18},
                "InfoMask": {"off": 0x1A}, "Flags": {"off": 0x1B}, "Body": {"off": 0x30},
            }},
            "_HANDLE_TABLE": {"size": 0x80, "fields": {"TableCode": {"off": 8}}},
        }

    def load(self, name):
        return {"architecture": "x64"}

    def struct(self, name, field=None):
        value = self.types[name]
        return value if field is None else value["fields"][field]


@dataclass
class Memory:
    raw: bytearray

    def put(self, va: int, data: bytes) -> None:
        offset = va - BASE
        self.raw[offset:offset + len(data)] = data

    def u64(self, va: int, value: int) -> None:
        self.put(va, value.to_bytes(8, "little"))

    def u32(self, va: int, value: int) -> None:
        self.put(va, value.to_bytes(4, "little"))

    def u8(self, va: int, value: int) -> None:
        self.put(va, bytes([value]))

    def read(self, va: int, length: int) -> bytes:
        offset = va - BASE
        if offset < 0 or offset + length > len(self.raw):
            raise AssertionError(f"unexpected object read 0x{va:x}")
        return bytes(self.raw[offset:offset + length])


def _patch(monkeypatch, memory):
    import winbox.kdbg.objects as objects

    monkeypatch.setattr(objects, "find_process", lambda _vm, _store, *, pid, **_kw: SYSTEM if pid == 4 else None)
    monkeypatch.setattr(objects, "read_virt_cr3", lambda _vm, _cr3, va, length, **_kw: memory.read(va, length))


def _memory() -> tuple[Memory, int]:
    memory = Memory(bytearray(0x10000))
    body = BASE + 0x5000
    header = body - 0x30
    memory.u64(TARGET.eprocess + 0x40, body | 7)
    memory.u64(header, 12)
    memory.u64(header + 8, 3)
    memory.u8(header + 0x18, 5)
    memory.u8(header + 0x1A, 0x80)
    memory.u8(header + 0x1B, 0x40)
    memory.u64(body + 0x10, 0x1111)
    memory.u64(body + 0x18, 0x2222)
    memory.u32(body + 0x20, 1)
    memory.u32(body + 0x24, 0x10)
    memory.u32(body + 0x28, 3)
    memory.u8(body + 0x2C, 1)
    memory.u64(body + 0x30, 0xAA)
    memory.u64(body + 0x38, 0xBB)
    memory.u64(body + 0x40, 0xCC)
    table = BASE + 0x7000
    memory.u64(TARGET.eprocess + 0x48, table)
    memory.u64(table + 8, (BASE + 0x8000) | 1)
    return memory, body


def test_token_evidence_preserves_raw_masks_and_proven_header(monkeypatch):
    memory, body = _memory()
    _patch(monkeypatch, memory)

    result = token_evidence("vm", Store(), TARGET)

    assert result["token"]["body"] == f"0x{body:016x}"
    assert result["token"]["privileges"]["enabled"] == "0x00000000000000bb"
    assert result["object_header"]["type_index"] == 5
    assert result["object_header"]["type_name"] is None


def test_handles_reports_table_root_but_refuses_guessed_entry_slots(monkeypatch):
    memory, _ = _memory()
    _patch(monkeypatch, memory)

    result = handle_table_status("vm", Store(), TARGET)

    assert result["handle_table"]["level"] == 1
    assert result["enumeration"]["available"] is False
    assert "public nt PDB" in result["enumeration"]["reason"]


def test_token_rejects_noncanonical_fast_ref(monkeypatch):
    memory, _ = _memory()
    memory.u64(TARGET.eprocess + 0x40, 0x1234)
    _patch(monkeypatch, memory)

    with pytest.raises(ObjectEvidenceError, match="EX_FAST_REF"):
        token_evidence("vm", Store(), TARGET)
