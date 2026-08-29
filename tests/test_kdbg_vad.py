"""Contract coverage for bounded exact-PDB VAD evidence."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from winbox.kdbg.vad import VadError, list_vads, lookup_vad
from winbox.kdbg.walk import ProcessRecord


_KERNEL = 0xFFFF_8000_0010_0000
_TARGET = ProcessRecord(
    pid=4242, name="target.exe", eprocess=0xFFFF_8000_0020_0000,
    directory_table_base=0x12345000, create_time=1,
)
_SYSTEM = ProcessRecord(
    pid=4, name="System", eprocess=0xFFFF_8000_0000_0000,
    directory_table_base=0x12345000, create_time=1,
)


class Store:
    def __init__(self):
        self.types = {
            "_EPROCESS": {"size": 0x200, "fields": {"VadRoot": {"off": 0x80}}},
            "_RTL_AVL_TREE": {"size": 8, "fields": {"Root": {"off": 0}}},
            "_RTL_BALANCED_NODE": {"size": 24, "fields": {
                "Left": {"off": 0}, "Right": {"off": 8}, "ParentValue": {"off": 16},
            }},
            "_MMVAD_SHORT": {"size": 64, "fields": {
                "VadNode": {"off": 0}, "StartingVpn": {"off": 0x18},
                "EndingVpn": {"off": 0x1C}, "StartingVpnHigh": {"off": 0x20},
                "EndingVpnHigh": {"off": 0x21}, "u": {"off": 0x30},
            }},
        }

    def load(self, name):
        assert name == "nt"
        return {"architecture": "x64"}

    def struct(self, name, field=None):
        value = self.types[name]
        return value if field is None else value["fields"][field]


@dataclass
class Memory:
    data: bytearray
    base: int = 0xFFFF_8000_0000_0000

    def put(self, address: int, raw: bytes) -> None:
        offset = address - self.base
        self.data[offset:offset + len(raw)] = raw

    def u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little"))

    def read(self, address: int, length: int) -> bytes:
        offset = address - self.base
        if offset < 0 or offset + length > len(self.data):
            raise VadError(f"unexpected test read 0x{address:x}")
        return bytes(self.data[offset:offset + length])


def _memory(node: int = _KERNEL + 0x3000) -> Memory:
    memory = Memory(bytearray(0x300000))
    memory.u64(_TARGET.eprocess + 0x80, node)
    raw = bytearray(0x40)
    raw[0x18:0x1C] = (0x40000).to_bytes(4, "little")
    raw[0x1C:0x20] = (0x4000F).to_bytes(4, "little")
    # Private, execute-read-write.  The raw profile is explicit in output.
    raw[0x30:0x34] = ((1 << 20) | (6 << 7)).to_bytes(4, "little")
    memory.put(node, raw)
    return memory


def _patch(monkeypatch, memory: Memory):
    import winbox.kdbg.vad as vad

    monkeypatch.setattr(vad, "find_process", lambda _vm, _store, *, pid, **_kw: _SYSTEM if pid == 4 else None)
    monkeypatch.setattr(vad, "read_virt_cr3", lambda _vm, _cr3, va, length, **_kw: memory.read(va, length))


def test_lookup_vad_returns_proven_private_rwx_range(monkeypatch):
    memory = _memory()
    _patch(monkeypatch, memory)

    record = lookup_vad("vm", Store(), _TARGET, 0x40000123, probe_header=True)

    assert record is not None
    assert record.start == 0x40000000
    assert record.end == 0x4000FFFF
    assert record.kind == "private"
    assert record.executable is True and record.writable is True
    # We didn't map user bytes into the fake backing, so the probe is an
    # explicit failure boundary—not an invented missing PE conclusion.
    assert record.pe_header == "unreadable"


def test_vad_parent_backlink_failure_is_not_silently_walked(monkeypatch):
    node = _KERNEL + 0x3000
    child = _KERNEL + 0x4000
    memory = _memory(node)
    memory.u64(node, child)
    memory.u64(child + 16, _KERNEL + 0x5000)  # not node
    _patch(monkeypatch, memory)

    with pytest.raises(VadError, match="backlink"):
        list_vads("vm", Store(), _TARGET)


def test_vad_map_output_limit_is_explicit_not_a_corruption_claim(monkeypatch):
    root = _KERNEL + 0x3000
    child = _KERNEL + 0x4000
    memory = _memory(root)
    memory.u64(root + 8, child)
    raw = bytearray(0x40)
    raw[0x18:0x1C] = (0x50000).to_bytes(4, "little")
    raw[0x1C:0x20] = (0x5000F).to_bytes(4, "little")
    raw[0x30:0x34] = ((1 << 20) | (6 << 7)).to_bytes(4, "little")
    memory.put(child, raw)
    memory.u64(child + 16, root)
    _patch(monkeypatch, memory)

    walked = list_vads("vm", Store(), _TARGET, limit=1)

    assert walked.complete is False
    assert walked.truncation["stage"] == "output"
    assert len(walked.records) == 1


def test_vad_rejects_non_user_lookup_address(monkeypatch):
    memory = _memory()
    _patch(monkeypatch, memory)
    with pytest.raises(VadError, match="canonical user"):
        lookup_vad("vm", Store(), _TARGET, _KERNEL)
