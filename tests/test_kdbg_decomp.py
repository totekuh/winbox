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
    _decode_cursor,
    _format_instruction,
    _format_result,
    _line_range,
    _nearest_symbol_hint,
    _resolve_binary,
    query_decomp,
)
from winbox.kdbg.decomp.worker import (
    WorkerError,
    _attach_mapped_assembly,
    _bounded_code_payload,
    _map_source,
    _nearby_instructions,
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


def test_parse_live_pe_can_validate_headers_when_codeview_page_is_discarded():
    image, _ = _live_pe()
    base = 0x7FF600000000

    def read(address, length):
        if address >= base + 0x2000:
            raise RuntimeError("discarded image page")
        return image[address - base:address - base + length]

    result = parse_live_pe(read, base, include_pdb=False)
    assert result.machine == 0x8664
    assert result.timestamp == 0x12345678
    assert result.image_size == 0x5000
    assert result.pdb_key is None


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
            return {
                "target": {"pid": 44, "name": "sample.exe"},
                "state": "halted", "session_id": "session-a", "stop_id": 7,
            }
        if op == "decomp_snapshot":
            return {
                "target": {"pid": 44, "name": "sample.exe"},
                "runtime_va": "0x7ff600001000",
                "session_id": "session-a", "stop_id": 7,
                "module": {
                    "name": "sample.exe", "base": "0x7ff600000000",
                    "size": 0x5000, "kind": "user",
                    "full_path": "C:\\sample.exe", "inventory": "fresh",
                },
            }
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

    assert result["schema"] == "winbox.kdbg-decomp/5"
    assert result["detail"] == "compact"
    assert result["location"]["rva"] == "0x1000"
    assert result["verified"]["identity_method"] == "pdb-guid-age"
    assert result["verified"]["build_identity_match"] is True
    assert result["assembly_fields"] == {
        "instruction_bytes": False, "runtime_vas": False,
    }
    assert "bytes" not in result["assembly"][0]
    assert "va" not in result["assembly"][0]
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

    SymbolStore(cfg.symbols_dir).save(
        "sample", "build", image="sample.pdb", symbols={"focus": 0x1000},
        types={}, base=0x7FF600000000, size_of_image=0x5000,
    )
    query_decomp(
        cfg, symbol="sample!focus", binary=str(binary),
        daemon_client=daemon, decomp_client=worker,
    )
    snapshot_calls = [args for op, args in daemon.calls if op == "decomp_snapshot"]
    assert snapshot_calls[-1] == {"module": "sample", "rva": "0x1000"}


def test_query_decomp_cursor_pages_and_is_bound_to_stop_and_binary(
    monkeypatch, tmp_path
):
    image, key = _live_pe()
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"fixture")
    static = PeIdentity(
        0x8664, 0x12345678, 0x5000, 0x140000000, key,
        sha256="b" * 64, file_size=binary.stat().st_size,
        sections=(SectionIdentity(".text", 0x1000, 0x1000, 0, 1),),
    )
    monkeypatch.setattr("winbox.kdbg.decomp.service.parse_static_pe", lambda _: static)
    daemon = _FakeDaemon(image)

    class PagingWorker(_FakeWorker):
        def call(self, op, **args):
            self.args = (op, args)
            start = args.get("line_start") or 1
            end = args.get("line_end") or 2
            return {
                "ghidra_version": "12.1.3",
                "analysis_profile": "winbox-default-v1",
                "ghidra_image_base": "0x140000000",
                "instructions": [],
                "mapping": {
                    "confidence": "exact", "line": 1, "excerpt": [],
                    "selection": {
                        "mode": "lines", "start": start, "end": end,
                        "total_lines": 10, "has_more": end < 10,
                        "next_start": end + 1 if end < 10 else None,
                    },
                },
                "function": {"name": "focus", "rva": "0x1000"},
                "analysis": {},
            }

    worker = PagingWorker()
    cfg = Config(winbox_dir=tmp_path)
    first = query_decomp(
        cfg, binary=str(binary), lines="1-2",
        daemon_client=daemon, decomp_client=worker,
    )
    assert first["line_selection"]["total_lines"] == 10
    assert first["next_cursor"]

    second = query_decomp(
        cfg, binary=str(binary), cursor=first["next_cursor"],
        daemon_client=daemon, decomp_client=worker,
    )
    assert worker.args[1]["line_start"] == 3
    assert worker.args[1]["line_end"] == 4
    assert second["next_cursor"] != first["next_cursor"]
    snapshot_calls = [args for op, args in daemon.calls if op == "decomp_snapshot"]
    assert snapshot_calls[-1] == {"module": "sample.exe", "rva": "4096"}


def test_query_decomp_rejects_cursor_after_stop_changes(monkeypatch, tmp_path):
    # Cursor validation happens before any expensive static work once the
    # daemon reports a different epoch.
    from winbox.kdbg.decomp.service import _encode_cursor

    cursor = _encode_cursor({
        "module": "sample.exe", "function_rva": 0x1000,
        "next_start": 3, "page_size": 2, "session_id": "old",
        "stop_id": 6, "binary_sha256": "a" * 64,
        "ghidra_version": "12.1.3",
        "analysis_profile": "winbox-default-v1",
    })
    image, _ = _live_pe()
    daemon = _FakeDaemon(image)
    # Snapshot is stop 7; binary lookup then fails unless the epoch is checked
    # immediately. The public error must still identify the stale continuation.
    cfg = Config(winbox_dir=tmp_path)
    with pytest.raises(DecompError, match="no longer matches"):
        query_decomp(cfg, cursor=cursor, daemon_client=daemon, decomp_client=_FakeWorker())


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
    "kwargs,message",
    [
        ({"addr": "0x1", "symbol": "nt!X"}, "mutually exclusive"),
        ({"module": "nt"}, "supplied together"),
        ({"rva": "0x10"}, "supplied together"),
        ({"module": "   ", "rva": "0x10"}, "must not be blank"),
        ({"cursor": "%%%"}, "invalid continuation cursor"),
        ({"cursor": "x" * 4097}, "oversized"),
    ],
)
def test_query_decomp_rejects_invalid_navigation_before_daemon(
    tmp_path, kwargs, message
):
    class Never:
        def call(self, *_args, **_kwargs):
            raise AssertionError("daemon must not be called")

    with pytest.raises(DecompError, match=message):
        query_decomp(
            Config(winbox_dir=tmp_path), daemon_client=Never(),
            decomp_client=Never(), **kwargs,
        )


def test_resolve_binary_never_accepts_guest_path_outside_cache(tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    with pytest.raises(DecompError, match="no cached PE"):
        _resolve_binary(cfg, str(outside), "")

    cfg.symbols_dir.mkdir(parents=True)
    (cfg.symbols_dir / "escape.exe").symlink_to(outside)
    with pytest.raises(DecompError, match="no cached PE"):
        _resolve_binary(cfg, "escape.exe", "")


def test_cursor_decoder_rejects_bool_integer_fields():
    import base64
    import json

    payload = {
        "module": "x.exe", "function_rva": True, "next_start": 2,
        "page_size": 1, "session_id": "s", "stop_id": 1,
        "binary_sha256": "a" * 64, "ghidra_version": "11",
        "analysis_profile": "winbox-default-v1",
    }
    cursor = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    with pytest.raises(DecompError, match="function_rva"):
        _decode_cursor(cursor)


@pytest.mark.parametrize(
    "value,expected",
    [("1", (1, 1)), ("1-22", (1, 22)), (" 7 - 9 ", (7, 9)), ("", None)],
)
def test_line_range_parser(value, expected):
    assert _line_range(value) == expected


def test_response_detail_levels_keep_diagnostics_opt_in():
    raw = {
        "target": {"pid": 7, "name": "x.exe"},
        "stop_epoch": {"session_id": "s", "stop_id": 2},
        "module": {
            "name": "x.exe", "base": "0x7ff600000000", "size": 0x3000,
            "runtime_va": "0x7ff600001000", "rva": "0x1000",
            "binary": "/symbols/x.exe",
        },
        "identity": {
            "confidence": "pdb-guid-age",
            "live": {"pdb_key": "LIVE1"},
            "static": {"pdb_key": "LIVE1", "sha256": "a" * 64},
            "current_instruction_match": "match",
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
        "analysis": {
            "binary_sha256": "a" * 64, "project_cached": True,
            "code_truncated": True,
        },
        "code": "int focus(void) { return 1; }",
        "warnings": [],
    }

    compact = _format_result(raw, "compact")
    assert compact["location"]["symbol"] == "x!focus+0x0"
    assert compact["stop_epoch"] == {"session_id": "s", "stop_id": 2}
    assert compact["code_truncated"] is True
    assert compact["assembly"][0]["rva"] == "0x1000"
    assert compact["pseudocode"][0]["rva_ranges"] == [
        {"start": "0x1000", "end": "0x1000"}
    ]
    assert compact["pseudocode"][0]["assembly"][0]["rva"] == "0x1000"
    assert compact["assembly_mode"] == "mapped"
    assert compact["line_selection"]["requested"] == {"start": 1, "end": 2}
    assert compact["rip_mapping"]["kind"] == "exact"
    assert compact["verified"]["current_instruction_match"] == "match"
    assert compact["verified"]["analyzed_file_sha256"] == "a" * 64
    assert compact["code"] == "int focus(void) { return 1; }"
    assert "identity" not in compact
    assert "module" not in compact

    no_full_payload = dict(raw)
    no_full_payload.pop("code")
    assert "code_truncated" not in _format_result(no_full_payload, "compact")

    standard = _format_result(raw, "standard")
    assert standard["identity"]["static"]["sha256"] == "a" * 64
    assert standard["analysis"]["project_cached"] is True
    assert _format_result(raw, "diagnostic") is raw

    lean = _format_result(
        raw, "compact", instruction_bytes=False, runtime_vas=False,
    )
    assert lean["assembly_fields"] == {
        "instruction_bytes": False, "runtime_vas": False,
    }
    assert lean["assembly"][0] == {
        "text": "MOV EAX,0x1", "rva": "0x1000", "current": True,
    }


def test_compact_formatter_derives_direction_from_worker_api_one_mapping():
    raw = {
        "target": {"pid": 1, "name": "old.exe"},
        "module": {
            "base": "0x7ff600000000", "runtime_va": "0x7ff600001000",
            "rva": "0x1000",
        },
        "identity": {"confidence": "pdb-guid-age", "current_instruction_match": "match"},
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
        "total_lines": 3,
        "has_more": False,
        "next_start": None,
    }


def test_source_mapping_rejects_start_beyond_function():
    with pytest.raises(WorkerError, match="exceeds function length"):
        _map_source(
            _FakeMarkup(), _FakeAddress(0x1000), "one\ntwo", 0, 0,
            line_start=3, line_end=4,
        )


def test_oversized_full_code_is_bounded_without_changing_mapping_input(monkeypatch):
    import winbox.kdbg.decomp.worker as worker_module

    monkeypatch.setattr(worker_module, "MAX_CODE", 16)
    complete = "one\ntwo\nthree\nfour\nfive\n"
    returned, stats = _bounded_code_payload(complete, full=True)
    mapping = _map_source(
        _FakeMarkup(_FakeToken(0x1000, 0x1000, 5)),
        _FakeAddress(0x1000), complete, 0, 0,
    )

    assert len(returned.encode()) <= 16
    assert stats == {
        "code_truncated": True,
        "code_bytes": len(complete.encode()),
        "code_lines": 5,
        "returned_code_bytes": len(returned.encode()),
        "returned_code_lines": len(returned.splitlines()),
    }
    assert mapping["line"] == 5
    assert mapping["excerpt"] == [{
        "line": 5, "text": "five", "address_ranges": [
            {"start": "0x1000", "end": "0x1000"}
        ], "relation": "exact",
    }]


class _FakeInstruction:
    def __init__(self, address, raw, text, flows=()):
        self.address = address
        self.raw = raw
        self.text = text
        self.flows = flows

    def getAddress(self):
        return _FakeAddress(self.address)

    def getLength(self):
        return len(self.raw)

    def getBytes(self):
        return self.raw

    def getFlows(self):
        return [_FakeAddress(value) for value in self.flows]

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
    assert mapping["excerpt"][0]["assembly_complete"] is True
    assert mapping["excerpt"][1]["assembly_complete"] is True


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
    assert mapping["excerpt"][0]["assembly_complete"] is False
    assert mapping["assembly_truncation"] == {
        "first_line": 1,
        "last_line": 1,
        "association_limit": 1,
    }


def test_mapped_assembly_marks_every_later_addressed_line_incomplete(monkeypatch):
    import winbox.kdbg.decomp.worker as worker_module

    monkeypatch.setattr(worker_module, "MAX_MAPPED_INSTRUCTION_ASSOCIATIONS", 1)
    instructions = [
        _FakeInstruction(0x1000, b"\x90", "NOP"),
        _FakeInstruction(0x1001, b"\x90", "NOP"),
        _FakeInstruction(0x1002, b"\x90", "NOP"),
    ]
    mapping = {"excerpt": [
        {"line": line, "text": "work();", "address_ranges": [
            {"start": f"0x{address:x}", "end": f"0x{address:x}"}
        ]}
        for line, address in [(1, 0x1000), (2, 0x1001), (3, 0x1002)]
    ]}

    assert _attach_mapped_assembly(
        _FakeProgram(instructions), _FakeFunction(), mapping
    ) is True
    assert [line["assembly_complete"] for line in mapping["excerpt"]] == [
        True, False, False
    ]
    assert mapping["assembly_truncation"]["first_line"] == 2
    assert mapping["assembly_truncation"]["last_line"] == 3


def test_nearby_instructions_reports_undecoded_gap_without_returning_tail():
    instructions = [
        _FakeInstruction(0x1000, b"\x90", "NOP"),
        _FakeInstruction(0x1001, b"\x90", "NOP"),
        _FakeInstruction(0x1010, b"\x90", "NOP"),
        _FakeInstruction(0x1011, b"\x90", "NOP"),
        _FakeInstruction(0x1020, b"\x90", "RET"),
    ]

    nearby, location = _nearby_instructions(
        _FakeProgram(instructions), _FakeFunction(), _FakeAddress(0x1008)
    )

    assert [item["address"] for item in nearby] == [
        "0x1000", "0x1001", "0x1010", "0x1011"
    ]
    assert all(item["current"] is False for item in nearby)
    assert location == {
        "requested_address": "0x1008",
        "decoded": False,
        "kind": "undecoded-gap",
        "previous_address": "0x1001",
        "next_address": "0x1010",
    }


def test_instruction_flow_targets_have_explicit_static_runtime_coordinates():
    from winbox.kdbg.decomp.worker import _instruction_payload

    payload = _instruction_payload(_FakeInstruction(
        0x140001000, b"\xe8\x00\x00\x00\x00", "CALL 0x140002000",
        flows=(0x140002000,),
    ))
    payload["flow_target_symbols"] = {"0x140002000": "sample!callee"}

    formatted = _format_instruction(payload, 0x140000000, 0x7FF600000000)

    assert formatted["flow_targets"] == [{
        "rva": "0x2000",
        "static_va": "0x140002000",
        "runtime_va": "0x7ff600002000",
        "symbol": "sample!callee",
    }]


def test_symbol_hint_normalizes_kernel_name_and_is_distance_bounded(tmp_path):
    store = SymbolStore(tmp_path / "symbols")
    store.save(
        "nt", "build", image="nt.pdb", symbols={"Near": 0x1000, "After": 0x3000},
        types={}, base=0xFFFFF80000000000, size_of_image=0x100000,
    )
    assert _nearest_symbol_hint(store, "ntoskrnl.exe", 0x1010) == {
        "module": "nt", "name": "Near", "rva": 0x1000, "offset": 0x10,
        "is_function": False,
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
    reply = mcp_module.kdbg_decomp(
        symbol="sample!focus", cursor="opaque", detail="diagnostic",
        lines="1-22", assembly="mapped"
    )
    assert reply["ok"] is True
    assert reply["result"] == {"ok": 1}
    assert captured["symbol"] == "sample!focus"
    assert captured["cursor"] == "opaque"
    assert captured["detail"] == "diagnostic"
    assert captured["lines"] == "1-22"
    assert captured["assembly"] == "mapped"
    assert captured["instruction_bytes"] is False
    assert captured["runtime_vas"] is False

    def fail(*args, **kwargs):
        raise DecompError("wrong build")

    monkeypatch.setattr(package, "query_decomp", fail)
    error = mcp_module.kdbg_decomp()
    assert error["ok"] is False
    assert error["error"] == {
        "code": "identity_mismatch", "message": "wrong build",
        "operation": "kdbg_decomp", "retryable": False,
        "recovery": [
            "Refresh the target module and symbols, then retry with the verified binary."
        ],
    }


def test_mcp_decomp_status_does_not_require_session(monkeypatch, tmp_path):
    import json
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    monkeypatch.setattr(package, "worker_status", lambda value: {"running": False})
    reply = mcp_module.kdbg_decomp_status()
    assert reply["schema"] == "winbox.mcp/1"
    assert reply["result"] == {"running": False}


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
        cli, [
            "kdbg", "decomp", "--module", "sample.exe", "--rva", "0x1000",
            "--lines", "1-22", "--assembly", "mapped",
        ]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["pseudocode"][0]["text"] == "x" * 500
    assert captured["lines"] == "1-22"
    assert captured["assembly"] == "mapped"
    assert captured["module"] == "sample.exe"
    assert captured["rva"] == "0x1000"


@pytest.mark.parametrize(
    "arguments",
    [
        ["kdbg", "decomp-status"],
        ["kdbg", "ghidra", "status"],
        ["kdbg", "ghidra", "run"],
        ["kdbg", "ghidra", "stop"],
        ["kdbg", "ghidra", "install", "--no-pull"],
    ],
)
def test_cli_ghidra_json_survives_narrow_terminal(
    monkeypatch, tmp_path, arguments,
):
    import json
    import winbox.kdbg.decomp as package
    from click.testing import CliRunner
    from winbox.cli import cli

    cfg = Config(winbox_dir=tmp_path)
    payload = {"value": "x" * 500, "nested": {"path": "/a/very/long/path"}}
    monkeypatch.setattr("winbox.cli.Config.load", lambda: cfg)
    monkeypatch.setattr(package, "worker_status", lambda _cfg: payload)
    monkeypatch.setattr(package, "start_service", lambda _cfg: payload)
    monkeypatch.setattr(package, "stop_service", lambda _cfg: payload)
    monkeypatch.setattr(package, "install_service", lambda _cfg, **_kw: payload)

    result = CliRunner(env={"COLUMNS": "20"}).invoke(cli, arguments)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == payload


def test_mcp_context_forwards_bounded_evidence_options(monkeypatch, tmp_path):
    import json
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    captured = {}

    class Client:
        def call(self, op, **kwargs):
            captured.update(op=op, **kwargs)
            return {"schema": "winbox.kdbg-context/1"}

    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    monkeypatch.setattr(mcp_module, "_kdbg_client", lambda _cfg: Client())
    reply = mcp_module.kdbg_context(
        disasm_count=4, stack_qwords=5, bt_depth=2,
        memory=[{"va": "0x1000", "length": 8}],
    )
    result = reply["result"]
    assert result["schema"] == "winbox.kdbg-context/1"
    assert captured == {
        "op": "context", "disasm_count": 4, "stack_qwords": 5,
        "bt_depth": 2, "memory": [{"va": "0x1000", "length": 8}],
    }


def test_cli_context_emits_machine_safe_json(monkeypatch, tmp_path):
    import json
    from click.testing import CliRunner
    from winbox.cli import cli
    import winbox.cli.kdbg as cli_kdbg

    cfg = Config(winbox_dir=tmp_path)
    captured = {}

    class Client:
        def call(self, op, **kwargs):
            captured.update(op=op, **kwargs)
            return {"schema": "winbox.kdbg-context/1", "value": "x" * 500}

    monkeypatch.setattr("winbox.cli.Config.load", lambda: cfg)
    monkeypatch.setattr(cli_kdbg, "_client", lambda _cfg: Client())
    result = CliRunner().invoke(cli, [
        "kdbg", "context", "--disasm-count", "3",
        "--stack-qwords", "4", "--bt-depth", "2",
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["value"] == "x" * 500
    assert captured == {
        "op": "context", "disasm_count": 3,
        "stack_qwords": 4, "bt_depth": 2,
    }


@pytest.mark.parametrize(
    ("arguments", "patch_name", "expected"),
    [
        (["kdbg", "cont-start", "--timeout", "600"], "start_continue", "starting"),
        (["kdbg", "cont-poll", "tok"], "poll_continue", "running"),
        (["kdbg", "cont-cancel", "tok"], "cancel_continue", "cancel_requested"),
    ],
)
def test_cli_async_continue_commands_emit_machine_safe_json(
    monkeypatch, tmp_path, arguments, patch_name, expected,
):
    import json
    import winbox.kdbg.debugger.continue_job as jobs
    from click.testing import CliRunner
    from winbox.cli import cli

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr("winbox.cli.Config.load", lambda: cfg)
    monkeypatch.setattr(
        jobs, patch_name,
        lambda *args, **kwargs: {
            "schema": "winbox.kdbg-cont/1", "token": "tok",
            "state": expected, "active": True, "value": "x" * 500,
        },
    )

    result = CliRunner(env={"COLUMNS": "20"}).invoke(cli, arguments)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["state"] == expected


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
            "loader_entry": "0x9", "inventory": "fresh", "architecture": "x64",
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
