from __future__ import annotations

import struct
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.client import (
    DecompClient,
    DecompError,
    WORKER_API,
    discover_pyghidra_python,
)
from winbox.kdbg.decomp.identity import (
    IdentityError,
    PeIdentity,
    SectionIdentity,
    parse_live_pe,
    static_bytes_at_rva,
    validate_identity,
)
from winbox.kdbg.decomp.service import (
    _format_result,
    _line_range,
    _nearest_symbol_hint,
    query_decomp,
)
from winbox.kdbg.decomp.worker import (
    WorkerError,
    _attach_mapped_assembly,
    _map_source,
)
from winbox.kdbg.debugger.daemon import DaemonSession, StopState, TargetInfo
from winbox.kdbg.debugger.reader import ReaderError
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.walk import ModuleRecord, UserModuleRecord


def _live_pe(*, timestamp=0x12345678, image_size=0x5000, pdb=True):
    data = bytearray(image_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHI", data, coff, 0x8664, 1, timestamp)
    struct.pack_into("<H", data, coff + 16, 0xF0)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 56, image_size)
    if pdb:
        struct.pack_into("<II", data, optional + 112 + 6 * 8, 0x2000, 28)
        struct.pack_into("<I", data, 0x2000 + 12, 2)
        struct.pack_into("<I", data, 0x2000 + 16, 32)
        struct.pack_into("<I", data, 0x2000 + 20, 0x2100)
        guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
        data[0x2100:0x2104] = b"RSDS"
        data[0x2104:0x2114] = guid.bytes_le
        struct.pack_into("<I", data, 0x2114, 3)
        data[0x2118:0x2120] = b"x.pdb\0\0\0"
        key = guid.hex.upper() + "3"
    else:
        key = None
    return bytes(data), key


def test_parse_live_pe_extracts_codeview_identity():
    image, key = _live_pe()

    def read(address, length):
        base = 0x7FF600000000
        return image[address - base:address - base + length]

    result = parse_live_pe(read, 0x7FF600000000)
    assert result.machine == 0x8664
    assert result.timestamp == 0x12345678
    assert result.image_size == 0x5000
    assert result.preferred_base == 0x140000000
    assert result.pdb_key == key


def test_pyghidra_discovery_preserves_venv_python_symlink(monkeypatch, tmp_path):
    system_python = tmp_path / "system-python"
    system_python.write_text("", encoding="utf-8")
    system_python.chmod(0o755)
    venv_python = tmp_path / "venv-python"
    venv_python.symlink_to(system_python)
    launcher = tmp_path / "pyghidra"
    launcher.write_text(f"#!{venv_python}\n", encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.delenv("WINBOX_PYGHIDRA_PYTHON", raising=False)
    monkeypatch.setattr("winbox.kdbg.decomp.client.shutil.which", lambda _: str(launcher))
    assert discover_pyghidra_python() == venv_python.absolute()
    assert discover_pyghidra_python() != system_python.resolve()


def test_worker_status_reports_busy_lock_as_alive(monkeypatch, tmp_path):
    monkeypatch.setenv("WINBOX_DECOMP_BACKEND", "host")
    client = DecompClient(Config(winbox_dir=tmp_path))
    monkeypatch.setattr(client, "worker_alive", lambda: True)
    monkeypatch.setattr(client, "active_backend", lambda: "host")
    monkeypatch.setattr(client, "active_worker_api", lambda: WORKER_API)
    monkeypatch.setattr(
        client, "call", lambda *a, **k: (_ for _ in ()).throw(DecompError("timed out"))
    )
    monkeypatch.setattr(
        "winbox.kdbg.decomp.client.discover_pyghidra_python",
        lambda: Path("/venv/bin/python"),
    )
    result = client.status()
    assert result["running"] is True
    assert result["responsive"] is False
    assert result["busy"] is True


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda value: value.__class__(**{**value.__dict__, "machine": 0x14C}), "machine"),
        (lambda value: value.__class__(**{**value.__dict__, "timestamp": 9}), "timestamp"),
        (lambda value: value.__class__(**{**value.__dict__, "image_size": 0x6000}), "SizeOfImage"),
        (lambda value: value.__class__(**{**value.__dict__, "pdb_key": "BAD1"}), "PDB"),
    ],
)
def test_validate_identity_fails_closed_on_any_mismatch(mutate, message):
    base = PeIdentity(0x8664, 7, 0x5000, 0x140000000, "GOOD1")
    with pytest.raises(IdentityError, match=message):
        validate_identity(
            base, mutate(base), module_name="same.dll", live_module_size=0x5000
        )


def test_validate_identity_header_fallback_and_zero_timestamp_refusal():
    live = PeIdentity(0x8664, 7, 0x5000, 0x140000000, None)
    static = PeIdentity(0x8664, 7, 0x5000, 0x180000000, None)
    assert validate_identity(
        live, static, module_name="stripped.dll", live_module_size=0x5000
    ) == "pe-headers"
    zero = PeIdentity(0x8664, 0, 0x5000, 0x140000000, None)
    with pytest.raises(IdentityError, match="cannot strongly identify"):
        validate_identity(
            zero, zero, module_name="stripped.dll", live_module_size=0x5000
        )


def test_parse_live_pe_bounds_malformed_headers():
    image, _ = _live_pe()
    broken = bytearray(image)
    struct.pack_into("<I", broken, 0x3C, (1 << 20) + 1)
    with pytest.raises(IdentityError, match="exceeds 1 MiB"):
        parse_live_pe(lambda address, length: bytes(broken[:length]), 0)


def test_static_bytes_at_rva_never_crosses_raw_section(tmp_path):
    binary = tmp_path / "x.bin"
    binary.write_bytes(bytes(range(64)))
    identity = PeIdentity(
        0, 1, 0x1000, 0, None,
        sections=(SectionIdentity(".text", 0x100, 32, 8, 12),),
    )
    assert static_bytes_at_rva(binary, identity, 0x106, 20) == bytes(range(14, 20))
    assert static_bytes_at_rva(binary, identity, 0x200, 4) == b""


class _FakeDaemon:
    def __init__(self, image: bytes):
        self.image = image
        self.calls = []

    def call(self, op, **args):
        self.calls.append((op, args))
        if op == "status":
            return {"target": {"pid": 44, "name": "sample.exe"}}
        if op == "regs":
            return {"rip": "0x7ff600001000"}
        if op == "module_at":
            return {
                "name": "sample.exe", "base": "0x7ff600000000",
                "size": 0x5000, "kind": "user", "full_path": "C:\\sample.exe",
                "inventory": "fresh",
            }
        if op == "mem":
            address = int(args["va"], 0) - 0x7FF600000000
            length = args["length"]
            return {"bytes": self.image[address:address + length].hex()}
        raise AssertionError(op)


class _FakeWorker:
    def __init__(self):
        self.args = None

    def call(self, op, **args):
        self.args = (op, args)
        return {
            "ghidra_image_base": "0x140000000",
            "instructions": [{
                "address": "0x140001000", "bytes": "90", "text": "NOP",
                "current": True,
            }],
            "mapping": {
                "confidence": "exact", "line": 7, "excerpt": [],
                "assembly_truncated": True,
            },
            "function": {"name": "focus"},
            "analysis": {},
        }


def test_query_decomp_composes_rva_identity_and_worker(monkeypatch, tmp_path):
    image, key = _live_pe()
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"not parsed because identity is patched")
    static = PeIdentity(
        0x8664, 0x12345678, 0x5000, 0x140000000, key,
        sha256="a" * 64, file_size=binary.stat().st_size,
        sections=(SectionIdentity(".text", 0x1000, 0x1000, 0, 1),),
    )
    monkeypatch.setattr("winbox.kdbg.decomp.service.parse_static_pe", lambda _: static)
    daemon = _FakeDaemon(image)
    worker = _FakeWorker()
    cfg = Config(winbox_dir=tmp_path)

    result = query_decomp(
        cfg, binary=str(binary), lines="1-22", assembly="mapped",
        daemon_client=daemon, decomp_client=worker,
    )

    assert result["schema"] == "winbox.kdbg-decomp/3"
    assert result["detail"] == "compact"
    assert result["location"]["rva"] == "0x1000"
    assert result["verified"]["identity"] == "pdb-guid-age"
    assert "mapped assembly was truncated at the bounded response limit" in result[
        "warnings"
    ]
    assert "identity" not in result
    assert "module" not in result
    assert worker.args[0] == "decompile"
    assert worker.args[1]["rva"] == 0x1000
    assert worker.args[1]["sha256"] == "a" * 64
    assert worker.args[1]["line_start"] == 1
    assert worker.args[1]["line_end"] == 22
    assert worker.args[1]["assembly"] == "mapped"


def test_query_decomp_rejects_bad_context_before_touching_daemon(tmp_path):
    class Never:
        def call(self, *args, **kwargs):
            raise AssertionError("daemon must not be called")

    with pytest.raises(DecompError, match="before must be between"):
        query_decomp(Config(winbox_dir=tmp_path), before=21, daemon_client=Never())


def test_query_decomp_rejects_bad_detail_before_touching_daemon(tmp_path):
    class Never:
        def call(self, *args, **kwargs):
            raise AssertionError("daemon must not be called")

    with pytest.raises(DecompError, match="detail must be one of"):
        query_decomp(Config(winbox_dir=tmp_path), detail="everything", daemon_client=Never())


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"lines": "0-4"}, "positive ascending"),
        ({"lines": "4-2"}, "positive ascending"),
        ({"lines": "1-2-3"}, "must be N or N-M"),
        ({"lines": "1-101"}, "at most 100"),
        ({"assembly": "everything"}, "assembly must be one of"),
    ],
)
def test_query_decomp_rejects_bad_batch_options_before_daemon(
    tmp_path, kwargs, message
):
    class Never:
        def call(self, *args, **values):
            raise AssertionError("daemon must not be called")

    with pytest.raises(DecompError, match=message):
        query_decomp(Config(winbox_dir=tmp_path), daemon_client=Never(), **kwargs)


@pytest.mark.parametrize(
    "value,expected",
    [("1", (1, 1)), ("1-22", (1, 22)), (" 7 - 9 ", (7, 9)), ("", None)],
)
def test_line_range_parser(value, expected):
    assert _line_range(value) == expected


def test_response_detail_levels_keep_diagnostics_opt_in():
    raw = {
        "target": {"pid": 7, "name": "x.exe"},
        "module": {
            "name": "x.exe", "base": "0x7ff600000000", "size": 0x3000,
            "runtime_va": "0x7ff600001000", "rva": "0x1000",
            "binary": "/symbols/x.exe",
        },
        "identity": {
            "confidence": "pdb-guid-age",
            "live": {"pdb_key": "LIVE1"},
            "static": {"pdb_key": "LIVE1", "sha256": "a" * 64},
            "live_bytes_match": True,
        },
        "runtime_symbol": "x!focus+0x0",
        "symbol_hint": {"name": "focus", "rva": 0x1000},
        "cache_hit": False,
        "ghidra_version": "12.1.3",
        "ghidra_image_base": "0x140000000",
        "ghidra_address": "0x140001000",
        "function": {
            "name": "focus", "signature": "int focus(void)",
            "rva": "0x1000", "offset": "0x0", "source": "analysis",
        },
        "mapping": {
            "confidence": "exact", "kind": "exact", "line": 2,
            "candidate_lines": [2], "distance_bytes": 0, "direction": "overlap",
            "selection": {
                "mode": "lines", "requested": {"start": 1, "end": 2},
                "start": 1, "end": 2, "truncated": False,
            },
            "excerpt": [{
                "line": 2, "text": "return 1;", "relation": "exact",
                "address_ranges": [{"start": "0x140001000", "end": "0x140001000"}],
                "assembly": [{
                    "address": "0x140001000", "bytes": "b801000000",
                    "text": "MOV EAX,0x1",
                }],
            }],
        },
        "assembly_mode": "mapped",
        "instructions": [{
            "address": "0x140001000", "bytes": "b801000000",
            "text": "MOV EAX,0x1", "current": True,
        }],
        "analysis": {"binary_sha256": "a" * 64, "project_cached": True},
        "code": "int focus(void) { return 1; }",
        "warnings": [],
    }

    compact = _format_result(raw, "compact")
    assert compact["location"]["symbol"] == "x!focus+0x0"
    assert compact["assembly"][0]["rva"] == "0x1000"
    assert compact["pseudocode"][0]["rva_ranges"] == [
        {"start": "0x1000", "end": "0x1000"}
    ]
    assert compact["pseudocode"][0]["assembly"][0]["rva"] == "0x1000"
    assert compact["assembly_mode"] == "mapped"
    assert compact["line_selection"]["requested"] == {"start": 1, "end": 2}
    assert compact["rip_mapping"]["kind"] == "exact"
    assert compact["verified"]["live_bytes_match"] is True
    assert compact["code"] == "int focus(void) { return 1; }"
    assert "identity" not in compact
    assert "module" not in compact

    standard = _format_result(raw, "standard")
    assert standard["identity"]["static"]["sha256"] == "a" * 64
    assert standard["analysis"]["project_cached"] is True
    assert _format_result(raw, "diagnostic") is raw


def test_compact_formatter_derives_direction_from_worker_api_one_mapping():
    raw = {
        "target": {"pid": 1, "name": "old.exe"},
        "module": {
            "base": "0x7ff600000000", "runtime_va": "0x7ff600001000",
            "rva": "0x1000",
        },
        "identity": {"confidence": "pdb-guid-age", "live_bytes_match": True},
        "runtime_symbol": "old!entry+0x0",
        "ghidra_image_base": "0x140000000",
        "function": {"name": "entry", "rva": "0x1000", "offset": "0x0"},
        "mapping": {
            "confidence": "nearest", "line": 4,
            "addresses": ["0x140001010"],
            "excerpt": [{"line": 4, "text": "work();", "current": True}],
        },
        "instructions": [],
        "warnings": [],
    }
    compact = _format_result(raw, "compact")
    assert compact["rip_mapping"] == {
        "kind": "nearest-forward",
        "pseudocode_line": 4,
        "candidate_lines": [4],
        "distance_bytes": 0x10,
        "direction": "forward",
        "reason": "RIP has no direct pseudocode token; this is the next mapped statement",
    }
    assert compact["pseudocode"][0]["relation"] == "nearest-forward"


class _FakeAddress:
    def __init__(self, value):
        self.value = value

    def getOffset(self):
        return self.value


class _FakeLine:
    def __init__(self, number):
        self.number = number

    def getLineNumber(self):
        return self.number


class _FakeToken:
    def __init__(self, low, high, line):
        self.low = low
        self.high = high
        self.line = line

    def numChildren(self):
        return 0

    def getMinAddress(self):
        return _FakeAddress(self.low) if self.low is not None else None

    def getMaxAddress(self):
        return _FakeAddress(self.high) if self.high is not None else None

    def getLineParent(self):
        return _FakeLine(self.line)


class _FakeMarkup:
    def __init__(self, *tokens):
        self.tokens = tokens

    def numChildren(self):
        return len(self.tokens)

    def Child(self, index):
        return self.tokens[index]


@pytest.mark.parametrize(
    "target,tokens,expected,direction,distance",
    [
        (0x1000, [(0x1000, 0x1000, 2)], "exact", "overlap", 0),
        (0x1002, [(0x1000, 0x1004, 2)], "range", "overlap", 0),
        (0x1000, [(0x1010, 0x1014, 2)], "nearest-forward", "forward", 0x10),
        (0x1020, [(0x1010, 0x1014, 2)], "nearest-backward", "backward", 0xC),
        (
            0x1000,
            [(0x1000, 0x1002, 2), (0x1000, 0x1004, 3)],
            "ambiguous", "overlap", 0,
        ),
    ],
)
def test_source_mapping_reports_truthful_relationships(
    target, tokens, expected, direction, distance
):
    markup = _FakeMarkup(*(_FakeToken(*token) for token in tokens))
    result = _map_source(
        markup, _FakeAddress(target), "one\ntwo\nthree\nfour", 1, 1
    )
    assert result["kind"] == expected
    assert result["direction"] == direction
    assert result["distance_bytes"] == distance
    assert all("current" not in line for line in result["excerpt"])


def test_source_mapping_reports_unmapped_without_fake_current_line():
    result = _map_source(
        _FakeMarkup(), _FakeAddress(0x1000), "one\ntwo", 1, 1
    )
    assert result["kind"] == "unmapped"
    assert result["line"] is None
    assert result["candidate_lines"] == []
    assert all("relation" not in line for line in result["excerpt"])


def test_source_mapping_absolute_lines_override_context_and_clamp_end():
    markup = _FakeMarkup(_FakeToken(0x1000, 0x1000, 2))
    result = _map_source(
        markup, _FakeAddress(0x1000), "one\ntwo\nthree", 0, 0,
        line_start=1, line_end=22,
    )
    assert [line["line"] for line in result["excerpt"]] == [1, 2, 3]
    assert result["selection"] == {
        "mode": "lines",
        "requested": {"start": 1, "end": 22},
        "start": 1,
        "end": 3,
        "truncated": True,
    }


def test_source_mapping_rejects_start_beyond_function():
    with pytest.raises(WorkerError, match="exceeds function length"):
        _map_source(
            _FakeMarkup(), _FakeAddress(0x1000), "one\ntwo", 0, 0,
            line_start=3, line_end=4,
        )


class _FakeInstruction:
    def __init__(self, address, raw, text):
        self.address = address
        self.raw = raw
        self.text = text

    def getAddress(self):
        return _FakeAddress(self.address)

    def getLength(self):
        return len(self.raw)

    def getBytes(self):
        return self.raw

    def __str__(self):
        return self.text


class _FakeListing:
    def __init__(self, instructions):
        self.instructions = instructions

    def getInstructions(self, body, forward):
        return iter(self.instructions)


class _FakeProgram:
    def __init__(self, instructions):
        self.listing = _FakeListing(instructions)

    def getListing(self):
        return self.listing


class _FakeFunction:
    def getBody(self):
        return object()


def test_mapped_assembly_groups_shared_instructions_and_unmapped_lines():
    instruction = _FakeInstruction(0x1000, b"\x90", "NOP")
    mapping = {"excerpt": [
        {"line": 1, "text": "a();", "address_ranges": [
            {"start": "0x1000", "end": "0x1000"}
        ]},
        {"line": 2, "text": "b();", "address_ranges": [
            {"start": "0x1000", "end": "0x1000"}
        ]},
        {"line": 3, "text": "}"},
    ]}
    assert _attach_mapped_assembly(
        _FakeProgram([instruction]), _FakeFunction(), mapping
    ) is False
    assert mapping["excerpt"][0]["assembly"][0]["address"] == "0x1000"
    assert mapping["excerpt"][1]["assembly"][0]["address"] == "0x1000"
    assert "assembly" not in mapping["excerpt"][2]


def test_mapped_assembly_enforces_association_cap(monkeypatch):
    import winbox.kdbg.decomp.worker as worker_module

    monkeypatch.setattr(worker_module, "MAX_MAPPED_INSTRUCTION_ASSOCIATIONS", 1)
    instructions = [
        _FakeInstruction(0x1000, b"\x90", "NOP"),
        _FakeInstruction(0x1001, b"\x90", "NOP"),
    ]
    mapping = {"excerpt": [{
        "line": 1, "text": "work();", "address_ranges": [
            {"start": "0x1000", "end": "0x1001"}
        ],
    }]}
    assert _attach_mapped_assembly(
        _FakeProgram(instructions), _FakeFunction(), mapping
    ) is True
    assert len(mapping["excerpt"][0]["assembly"]) == 1


def test_symbol_hint_normalizes_kernel_name_and_is_distance_bounded(tmp_path):
    store = SymbolStore(tmp_path / "symbols")
    store.save(
        "nt", "build", image="nt.pdb", symbols={"Near": 0x1000, "After": 0x3000},
        types={}, base=0xFFFFF80000000000, size_of_image=0x100000,
    )
    assert _nearest_symbol_hint(store, "ntoskrnl.exe", 0x1010) == {
        "module": "nt", "name": "Near", "rva": 0x1000, "offset": 0x10,
    }
    assert _nearest_symbol_hint(store, "ntoskrnl.exe", 0x20000) is None


def test_mcp_decomp_serializes_result_and_surfaces_error(monkeypatch, tmp_path):
    import json
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    captured = {}

    def query(*args, **kwargs):
        captured.update(kwargs)
        return {"ok": 1}

    monkeypatch.setattr(package, "query_decomp", query)
    assert json.loads(mcp_module.kdbg_decomp(
        detail="diagnostic", lines="1-22", assembly="mapped"
    )) == {"ok": 1}
    assert captured["detail"] == "diagnostic"
    assert captured["lines"] == "1-22"
    assert captured["assembly"] == "mapped"

    def fail(*args, **kwargs):
        raise DecompError("wrong build")

    monkeypatch.setattr(package, "query_decomp", fail)
    assert mcp_module.kdbg_decomp() == "error: wrong build"


def test_mcp_decomp_status_does_not_require_session(monkeypatch, tmp_path):
    import json
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    monkeypatch.setattr(package, "worker_status", lambda value: {"running": False})
    assert json.loads(mcp_module.kdbg_decomp_status()) == {"running": False}


def test_cli_decomp_emits_machine_safe_unwrapped_json(monkeypatch, tmp_path):
    import json
    import winbox.kdbg.decomp as package
    from click.testing import CliRunner
    from winbox.cli import cli

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr("winbox.cli.Config.load", lambda: cfg)
    captured = {}

    def query(*args, **kwargs):
        captured.update(kwargs)
        return {"pseudocode": [{"line": 1, "text": "x" * 500}]}

    monkeypatch.setattr(package, "query_decomp", query)
    result = CliRunner().invoke(
        cli, ["kdbg", "decomp", "--lines", "1-22", "--assembly", "mapped"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["pseudocode"][0]["text"] == "x" * 500
    assert captured["lines"] == "1-22"
    assert captured["assembly"] == "mapped"


class _Rsp:
    pass


def _session(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    session = DaemonSession(
        cfg, _Rsp(), TargetInfo(5, 0x1000, "x", eprocess=0xFFFF0000),
        SymbolStore(tmp_path / "symbols"),
    )
    session.stop = StopState("02", 0x1000, 0x1000, 5, b"\0" * 256)
    return session


def test_daemon_module_at_uses_fresh_user_loader_walk(monkeypatch, tmp_path):
    session = _session(tmp_path)

    @contextmanager
    def snapshot(*args):
        yield object()

    monkeypatch.setattr("winbox.kdbg.debugger.reader.use_local_rsp", snapshot)
    monkeypatch.setattr(
        "winbox.kdbg.walk.list_user_modules",
        lambda *a, **k: [UserModuleRecord("x.dll", 0x100000, 0x3000, "C:\\x.dll", 9)],
    )
    result = session.op_module_at("0x101234")
    assert result == {
        "name": "x.dll", "base": "0x100000", "size": 0x3000,
        "rva": "0x1234", "kind": "user", "full_path": "C:\\x.dll",
        "loader_entry": "0x9", "inventory": "fresh",
    }
    assert session._last_selected_vcpu is None


def test_daemon_module_at_uses_kernel_walk_and_smallest_overlap(monkeypatch, tmp_path):
    session = _session(tmp_path)

    @contextmanager
    def snapshot(*args):
        yield object()

    monkeypatch.setattr("winbox.kdbg.debugger.reader.use_local_rsp", snapshot)
    monkeypatch.setattr(
        "winbox.kdbg.walk.list_modules",
        lambda *a, **k: [
            ModuleRecord("wide.sys", 0xFFFF800000000000, 0x5000, 1),
            ModuleRecord("narrow.sys", 0xFFFF800000001000, 0x1000, 2),
        ],
    )
    result = session.op_module_at(0xFFFF800000001100)
    assert result["name"] == "narrow.sys"
    assert result["kind"] == "kernel"


def test_daemon_module_walk_restore_failure_poisons_session(monkeypatch, tmp_path):
    session = _session(tmp_path)

    @contextmanager
    def broken(*args):
        yield object()
        raise ReaderError("register restore rejected")

    monkeypatch.setattr("winbox.kdbg.debugger.reader.use_local_rsp", broken)
    monkeypatch.setattr("winbox.kdbg.walk.list_user_modules", lambda *a, **k: [])
    with pytest.raises(RuntimeError, match="module walk failed"):
        session.op_module_at(0x1000)
    assert session._cr3_corrupted is True


def test_daemon_module_at_rejects_unmapped_and_invalid_addresses(monkeypatch, tmp_path):
    session = _session(tmp_path)

    @contextmanager
    def snapshot(*args):
        yield object()

    monkeypatch.setattr("winbox.kdbg.debugger.reader.use_local_rsp", snapshot)
    monkeypatch.setattr("winbox.kdbg.walk.list_user_modules", lambda *a, **k: [])
    with pytest.raises(RuntimeError, match="not inside any live user module"):
        session.op_module_at(0x1000)
    with pytest.raises(ValueError, match="uint64"):
        session.op_module_at(-1)
