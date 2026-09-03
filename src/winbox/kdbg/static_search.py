"""Bounded offline discovery over an exact cached PE artifact.

This deliberately stays outside the debugger daemon.  It answers the common
"where is the interesting code?" question from the immutable PE staged at
attach time, so discovery never consumes a new RSP stop or relies on a warm
Ghidra project.  Results are leads with explicit static provenance: direct
RIP-relative data references and direct relative calls only.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone import x86
import pefile

from winbox.config import Config
from winbox.kdbg.decomp.client import cache_dir
from winbox.kdbg.decomp.identity import PeIdentity, parse_static_pe
from winbox.kdbg.store import SymbolStore, SymbolStoreError


SCHEMA = "winbox.kdbg-static-search/1"
XREF_SCHEMA = "winbox.kdbg-direct-call-xrefs/1"
MAX_QUERY_CHARS = 256
MAX_RESULTS = 64
MAX_STRING_MATCHES = 64
MAX_VFUNCS = 16
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_INSTRUCTIONS = 2_000_000
MAX_PDATA_ENTRIES = 262_144
MAX_CACHE_METADATA_BYTES = 64 * 1024
MAX_CACHE_METADATA_RECORDS = 10_000


class StaticSearchError(RuntimeError):
    code = "static_search_error"


@dataclass(frozen=True)
class _RuntimeFunction:
    begin: int
    end: int


class _FunctionIndex:
    def __init__(self, entries: Iterable[_RuntimeFunction]) -> None:
        self.entries = tuple(sorted(entries, key=lambda item: item.begin))
        self.begins = tuple(item.begin for item in self.entries)

    def find(self, rva: int) -> _RuntimeFunction | None:
        index = bisect.bisect_right(self.begins, rva) - 1
        if index < 0:
            return None
        entry = self.entries[index]
        return entry if entry.begin <= rva < entry.end else None


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _bounded_text(value: str, limit: int = 260) -> str:
    return value if len(value) <= limit else value[:limit - 3] + "..."


def _validate_module(module: object, *, required: bool = True) -> str:
    if not isinstance(module, str):
        raise StaticSearchError("module must be a string")
    value = module.strip()
    if not value and not required:
        return ""
    if not value or len(value) > 260 or "/" in value or "\\" in value:
        raise StaticSearchError("module must be a safe cached module name")
    return value


def _validate_sha256(value: object) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise StaticSearchError("sha256 must be a lowercase 64-character hexadecimal digest")
    digest = value.strip().lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise StaticSearchError("sha256 must be a lowercase 64-character hexadecimal digest")
    return digest


def _validate_query(query: object) -> str:
    if not isinstance(query, str):
        raise StaticSearchError("query must be a string")
    value = query.strip()
    if not 2 <= len(value) <= MAX_QUERY_CHARS:
        raise StaticSearchError(
            f"query must contain between 2 and {MAX_QUERY_CHARS} characters",
        )
    return value


def _validate_limit(limit: object) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise StaticSearchError("limit must be an integer")
    if not 1 <= limit <= MAX_RESULTS:
        raise StaticSearchError(f"limit must be between 1 and {MAX_RESULTS}")
    return limit


def _aliases(store_name: str, record: dict[str, Any]) -> set[str]:
    values = {store_name}
    for key in ("module", "image"):
        value = record.get(key)
        if isinstance(value, str) and value:
            values.add(value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
    aliases: set[str] = set()
    for value in values:
        folded = value.strip().lower()
        if folded:
            aliases.add(folded)
            aliases.add(Path(folded).stem)
    return aliases


def _select_module(store: SymbolStore, requested: str) -> tuple[str, dict[str, Any]] | None:
    needle = requested.lower()
    stem = Path(needle).stem
    matches: list[tuple[str, dict[str, Any]]] = []
    for store_name in store.list_modules():
        try:
            record = store.load(store_name)
        except (SymbolStoreError, OSError, TypeError, ValueError):
            continue
        aliases = _aliases(store_name, record)
        if needle in aliases or stem in aliases:
            matches.append((store_name, record))
    if not matches:
        return None
    if len(matches) > 1:
        names = ", ".join(name for name, _ in matches[:8])
        raise StaticSearchError(
            f"module {requested!r} is ambiguous across cached artifacts: {names}",
        )
    return matches[0]


def _safe_cache_binary_name(value: object) -> str:
    if not isinstance(value, str):
        return ""
    name = value.strip()
    if (
        not name or len(name) > 260 or name != Path(name).name
        or "/" in name or "\\" in name or "\0" in name
    ):
        return ""
    return name


def _cache_binary_for_digest(root: Path, digest: str) -> Path | None:
    """Find one immutable cache copy without accepting lock/partial files."""
    for directory in (root / "verified-binaries", root / "binaries"):
        try:
            candidates = [directory / digest, *sorted(directory.glob(f"{digest}.*"))]
        except OSError:
            continue
        for path in candidates:
            if (
                path.name.endswith((".lock", ".part"))
                or path.is_symlink() or not path.is_file()
            ):
                continue
            return path
    return None


def _cache_metadata_records(cfg: Config) -> list[tuple[str, dict[str, Any]]]:
    """Read bounded decomp metadata to recover names for symbol-less PEs."""
    root = cache_dir(cfg)
    metadata = root / "metadata"
    try:
        paths = sorted(metadata.glob("*.json"))[:MAX_CACHE_METADATA_RECORDS]
    except OSError:
        return []
    records: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > MAX_CACHE_METADATA_BYTES:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if not isinstance(value, dict):
            continue
        try:
            digest = _validate_sha256(value.get("sha256"))
        except StaticSearchError:
            continue
        name = _safe_cache_binary_name(value.get("binary_name"))
        binary = _cache_binary_for_digest(root, digest) if digest else None
        if not digest or not name or binary is None:
            continue
        records.append((digest, {
            "module": Path(name).stem,
            "image": name,
            "pe_path": str(binary),
            "pe_sha256": digest,
            "artifact_source": "decomp-cache",
        }))
    return records


def _select_cache_module(
    cfg: Config, requested: str, *, sha256: str,
) -> tuple[str, dict[str, Any]]:
    root = cache_dir(cfg)
    if sha256:
        binary = _cache_binary_for_digest(root, sha256)
        if binary is None:
            raise StaticSearchError(
                f"no exact decomp-cache binary matches sha256 {sha256}",
            )
        record = next(
            (value for digest, value in _cache_metadata_records(cfg) if digest == sha256),
            None,
        )
        if record is None:
            record = {
                "module": Path(binary.name).stem,
                "image": binary.name,
                "pe_path": str(binary),
                "pe_sha256": sha256,
                "artifact_source": "decomp-cache",
            }
        return Path(str(record["image"])).stem, record

    needle = requested.lower()
    stem = Path(needle).stem
    matches: list[tuple[str, dict[str, Any]]] = []
    for digest, record in _cache_metadata_records(cfg):
        aliases = _aliases(str(record["module"]), record)
        if needle in aliases or stem in aliases:
            matches.append((digest, record))
    if not matches:
        raise StaticSearchError(
            f"no exact cached PE matches module {requested!r}; no symbol-store "
            "record or named decomp-cache artifact is available",
        )
    unique = {digest: record for digest, record in matches}
    if len(unique) != 1:
        choices = ", ".join(
            f"{record['image']}@{digest[:12]}" for digest, record in list(unique.items())[:8]
        )
        raise StaticSearchError(
            f"module {requested!r} is ambiguous across decomp-cache artifacts: "
            f"{choices}; repeat with sha256=<full digest>",
        )
    _digest, record = next(iter(unique.items()))
    return str(record["module"]), record


def _read_bounded_regular_file(path: Path, *, label: str) -> bytes:
    """Read one non-symlink regular artifact without trusting a prior stat.

    The local symbol cache is normally operator-owned, but these records can
    originate from a target-controlled loader name.  Holding the descriptor
    while checking type/size avoids the easy path-swap and unbounded-read
    failures that would otherwise turn a supposedly offline lookup into a host
    memory pressure primitive.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StaticSearchError(f"{label} is missing or unsafe: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise StaticSearchError(f"{label} is not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise StaticSearchError(
                f"{label} exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB search cap"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            data = handle.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise StaticSearchError(
                f"{label} grew beyond the {MAX_FILE_BYTES // (1024 * 1024)} MiB search cap"
            )
        return data
    except StaticSearchError:
        raise
    except OSError as exc:
        raise StaticSearchError(f"could not read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_exact_artifact(
    cfg: Config, store: SymbolStore, module: str, *, sha256: str,
) -> tuple[str, dict[str, Any], Path, PeIdentity, bytes]:
    if sha256:
        store_name, record = _select_cache_module(cfg, module, sha256=sha256)
    else:
        selected = _select_module(store, module)
        if selected is None:
            store_name, record = _select_cache_module(cfg, module, sha256="")
        else:
            store_name, record = selected
    raw_path = record.get("pe_path")
    expected = str(record.get("pe_sha256") or "").lower()
    if not isinstance(raw_path, str) or not raw_path:
        raise StaticSearchError(f"{store_name!r} has no staged PE artifact")
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise StaticSearchError(f"{store_name!r} has no valid staged PE digest")
    path = Path(raw_path).expanduser()
    try:
        data = _read_bounded_regular_file(path, label=f"{store_name!r} staged PE")
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise StaticSearchError(f"{store_name!r} staged PE digest does not match its record")
    except StaticSearchError:
        raise
    except OSError as exc:
        raise StaticSearchError(f"could not read staged PE for {store_name!r}: {exc}") from exc
    try:
        identity = parse_static_pe(path)
    except Exception as exc:
        raise StaticSearchError(f"could not parse staged PE for {store_name!r}: {exc}") from exc
    if identity.sha256 != expected:
        raise StaticSearchError(f"{store_name!r} staged PE changed while being searched")
    return store_name, record, path, identity, data


def _section_data(data: bytes, identity: PeIdentity, section) -> bytes:
    start = section.raw_offset
    end = start + section.raw_size
    if start < 0 or end < start or end > len(data):
        return b""
    return data[start:end]


def _bytes_at_rva(
    data: bytes, identity: PeIdentity, rva: int, length: int,
) -> bytes | None:
    if rva < 0 or length < 0:
        return None
    for section in identity.sections:
        delta = rva - section.virtual_address
        if delta < 0 or delta + length > section.raw_size:
            continue
        start = section.raw_offset + delta
        end = start + length
        if 0 <= start <= end <= len(data):
            return data[start:end]
    return None


def _rva_to_offset(identity: PeIdentity, rva: int) -> int | None:
    for section in identity.sections:
        delta = rva - section.virtual_address
        if 0 <= delta < section.raw_size:
            return section.raw_offset + delta
    return None


def _data_sections(identity: PeIdentity) -> tuple[Any, ...]:
    return tuple(
        section for section in identity.sections
        if not section.name.lower().startswith(".text")
    )


def _code_sections(identity: PeIdentity) -> tuple[Any, ...]:
    return tuple(
        section for section in identity.sections
        if section.name.lower().startswith(".text")
    )


def _ascii_string(raw: bytes, offset: int) -> tuple[int, str] | None:
    start = raw.rfind(b"\0", 0, offset) + 1
    end = raw.find(b"\0", offset)
    if end < 0:
        end = min(len(raw), start + 512)
    if end <= start:
        return None
    value = raw[start:end].decode("utf-8", errors="replace")
    return start, _bounded_text(value, 260)


def _utf16_string(raw: bytes, offset: int) -> tuple[int, str] | None:
    offset -= offset % 2
    start = offset
    while start >= 2 and raw[start - 2:start] != b"\0\0":
        start -= 2
    end = offset
    limit = min(len(raw) - (len(raw) % 2), start + 512)
    while end + 2 <= limit and raw[end:end + 2] != b"\0\0":
        end += 2
    if end <= start:
        return None
    value = raw[start:end].decode("utf-16le", errors="replace")
    return start, _bounded_text(value, 260)


def _find_strings(data: bytes, identity: PeIdentity, query: str) -> list[dict[str, Any]]:
    needle_ascii = query.encode("utf-8", errors="strict").lower()
    needle_utf16 = query.encode("utf-16le", errors="strict").lower()
    matches: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for section in _data_sections(identity):
        raw = _section_data(data, identity, section)
        lowered = raw.lower()
        for needle, encoding, reader in (
            (needle_ascii, "ascii", _ascii_string),
            (needle_utf16, "utf16", _utf16_string),
        ):
            offset = 0
            while len(matches) < MAX_STRING_MATCHES:
                found = lowered.find(needle, offset)
                if found < 0:
                    break
                offset = found + max(1, len(needle))
                rendered = reader(raw, found)
                if rendered is None:
                    continue
                start, value = rendered
                rva = section.virtual_address + start
                key = (rva, encoding)
                if key in seen:
                    continue
                seen.add(key)
                matches.append({
                    "rva": _hex(rva), "encoding": encoding, "value": value,
                })
    return matches


def _runtime_functions(path: Path, identity: PeIdentity, data: bytes) -> _FunctionIndex:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        rva = int(directory.VirtualAddress)
        size = int(directory.Size)
    except (AttributeError, IndexError, TypeError, ValueError, pefile.PEFormatError) as exc:
        raise StaticSearchError(f"PE exception directory is malformed: {exc}") from exc
    finally:
        try:
            pe.close()
        except (AttributeError, UnboundLocalError):
            pass
    if not rva or not size:
        return _FunctionIndex(())
    if size % 12 or size // 12 > MAX_PDATA_ENTRIES:
        raise StaticSearchError("PE exception directory is outside the static-search cap")
    raw = _bytes_at_rva(data, identity, rva, size)
    if raw is None:
        raise StaticSearchError("PE exception directory is not fully present in the staged file")
    entries: list[_RuntimeFunction] = []
    previous = -1
    for offset in range(0, len(raw), 12):
        begin, end, _unwind = struct.unpack_from("<III", raw, offset)
        if not (begin < end <= identity.image_size) or begin < previous:
            raise StaticSearchError("PE exception directory has invalid function boundaries")
        entries.append(_RuntimeFunction(begin, end))
        previous = begin
    return _FunctionIndex(entries)


def _decoder(identity: PeIdentity) -> capstone.Cs:
    if identity.machine == 0x8664:
        mode = capstone.CS_MODE_64
    elif identity.machine == 0x14C:
        mode = capstone.CS_MODE_32
    else:
        raise StaticSearchError(f"PE machine 0x{identity.machine:04x} is not x86/x64")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, mode)
    decoder.detail = True
    return decoder


def _instruction_iter(data: bytes, identity: PeIdentity):
    decoder = _decoder(identity)
    seen = 0
    for section in _code_sections(identity):
        raw = _section_data(data, identity, section)
        for instruction in decoder.disasm(raw, identity.preferred_base + section.virtual_address):
            seen += 1
            if seen > MAX_INSTRUCTIONS:
                return
            yield instruction


def _instruction_rva(identity: PeIdentity, instruction) -> int:
    return int(instruction.address) - identity.preferred_base


def _rip_target(identity: PeIdentity, instruction) -> int | None:
    if identity.machine != 0x8664:
        return None
    for operand in instruction.operands:
        if operand.type != x86.X86_OP_MEM or operand.mem.base != x86.X86_REG_RIP:
            continue
        target = int(instruction.address) + int(instruction.size) + int(operand.mem.disp)
        rva = target - identity.preferred_base
        if 0 <= rva < identity.image_size:
            return rva
    return None


def _direct_call_target(identity: PeIdentity, instruction) -> int | None:
    if capstone.CS_GRP_CALL not in instruction.groups:
        return None
    for operand in instruction.operands:
        if operand.type == x86.X86_OP_IMM:
            rva = int(operand.imm) - identity.preferred_base
            if 0 <= rva < identity.image_size:
                return rva
    return None


def _function_public(entry: _RuntimeFunction | None) -> dict[str, str] | None:
    if entry is None:
        return None
    return {"rva": _hex(entry.begin), "end": _hex(entry.end)}


def _scan_string_xrefs(
    data: bytes,
    identity: PeIdentity,
    functions: _FunctionIndex,
    strings: list[dict[str, Any]],
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], bool]:
    by_rva = {int(str(item["rva"]), 0): item for item in strings}
    results: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for instruction in _instruction_iter(data, identity):
        target = _rip_target(identity, instruction)
        if target not in by_rva:
            continue
        instruction_rva = _instruction_rva(identity, instruction)
        function = functions.find(instruction_rva)
        if function is None:
            continue
        key = (function.begin, target)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "rva": _hex(function.begin),
            "context": {
                "kind": "direct_string_xref",
                "function_end": _hex(function.end),
                "xref_rva": _hex(instruction_rva),
                "instruction": _bounded_text(
                    f"{instruction.mnemonic} {instruction.op_str}".strip(), 260,
                ),
                "string": by_rva[target],
            },
        })
        if len(results) >= limit:
            return results, True
    return results, False


def _exports(path: Path, query: str, functions: _FunctionIndex) -> list[dict[str, Any]]:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]],
        )
        symbols = list(getattr(pe, "DIRECTORY_ENTRY_EXPORT", object()).symbols)
    except AttributeError:
        return []
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        raise StaticSearchError(f"PE export directory is malformed: {exc}") from exc
    finally:
        try:
            pe.close()
        except (AttributeError, UnboundLocalError):
            pass
    needle = query.lower()
    results: list[dict[str, Any]] = []
    for symbol in symbols:
        raw_name = getattr(symbol, "name", None)
        if not isinstance(raw_name, (bytes, bytearray)):
            continue
        name = raw_name.decode("ascii", errors="replace")
        if needle not in name.lower():
            continue
        rva = int(getattr(symbol, "address", 0))
        if rva <= 0:
            continue
        function = functions.find(rva)
        results.append({
            "rva": _hex(function.begin if function is not None else rva),
            "context": {
                "kind": "export_name",
                "export": name,
                "export_rva": _hex(rva),
                "function": _function_public(function),
            },
        })
    return results


def _rtti_results(
    data: bytes,
    identity: PeIdentity,
    strings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve validated MSVC x64 TypeDescriptor -> COL -> vftable chains."""
    if identity.machine != 0x8664:
        return []
    wanted = [
        item for item in strings
        if str(item.get("value", "")).startswith(".?A")
    ]
    if not wanted:
        return []
    data_sections = _data_sections(identity)
    results: list[dict[str, Any]] = []
    seen_vtables: set[int] = set()
    for string in wanted:
        name_rva = int(str(string["rva"]), 0)
        type_rva = name_rva - 16
        if type_rva < 0:
            continue
        locators: set[int] = set()
        for section in data_sections:
            raw = _section_data(data, identity, section)
            needle = struct.pack("<I", type_rva)
            offset = 0
            while True:
                found = raw.find(needle, offset)
                if found < 0:
                    break
                offset = found + 1
                if found < 12:
                    continue
                col_rva = section.virtual_address + found - 12
                col = _bytes_at_rva(data, identity, col_rva, 24)
                if col is None:
                    continue
                signature, _offset, _cd, type_ref, class_ref, self_ref = struct.unpack("<IIIIII", col)
                if signature not in (0, 1) or type_ref != type_rva:
                    continue
                if not 0 < class_ref < identity.image_size:
                    continue
                if self_ref not in (0, col_rva):
                    continue
                locators.add(col_rva)
        for col_rva in sorted(locators):
            pointer = struct.pack("<Q", identity.preferred_base + col_rva)
            for section in data_sections:
                raw = _section_data(data, identity, section)
                offset = 0
                while True:
                    found = raw.find(pointer, offset)
                    if found < 0:
                        break
                    offset = found + 1
                    vtable_rva = section.virtual_address + found + 8
                    if vtable_rva in seen_vtables:
                        continue
                    vfuncs: list[str] = []
                    for index in range(MAX_VFUNCS):
                        value = _bytes_at_rva(data, identity, vtable_rva + index * 8, 8)
                        if value is None:
                            break
                        target = struct.unpack("<Q", value)[0] - identity.preferred_base
                        if not 0 <= target < identity.image_size:
                            break
                        if not any(
                            section.virtual_address <= target < section.virtual_address + section.raw_size
                            for section in _code_sections(identity)
                        ):
                            break
                        vfuncs.append(_hex(target))
                    if not vfuncs:
                        continue
                    seen_vtables.add(vtable_rva)
                    results.append({
                        "rva": _hex(vtable_rva),
                        "context": {
                            "kind": "msvc_rtti_vtable",
                            "type_name": string["value"],
                            "type_descriptor_rva": _hex(type_rva),
                            "complete_object_locator_rva": _hex(col_rva),
                            "vfunc_rvas": vfuncs,
                        },
                    })
    return results


def _module_public(store_name: str, record: dict[str, Any], identity: PeIdentity) -> dict[str, Any]:
    return {
        "store_name": store_name,
        "image": str(record.get("image") or store_name)[:260],
        "architecture": "x64" if identity.machine == 0x8664 else "x86" if identity.machine == 0x14C else f"0x{identity.machine:04x}",
        "sha256": identity.sha256,
        "image_size": identity.image_size,
        "artifact_source": str(record.get("artifact_source") or "symbols-store"),
    }


def search_cached_module(
    cfg: Config,
    *,
    module: object,
    query: object,
    limit: object = 32,
    sha256: object = "",
) -> dict[str, Any]:
    """Find static string/RTTI/export leads in one exact staged PE artifact."""
    requested_sha256 = _validate_sha256(sha256)
    requested_module = _validate_module(module, required=not requested_sha256)
    requested_query = _validate_query(query)
    requested_limit = _validate_limit(limit)
    store = SymbolStore(cfg.symbols_dir)
    store_name, record, path, identity, data = _load_exact_artifact(
        cfg, store, requested_module, sha256=requested_sha256,
    )
    functions = _runtime_functions(path, identity, data)
    strings = _find_strings(data, identity, requested_query)
    xrefs, truncated = _scan_string_xrefs(
        data, identity, functions, strings, limit=requested_limit,
    )
    rtti = _rtti_results(data, identity, strings)
    exports = _exports(path, requested_query, functions)
    results = (rtti + exports + xrefs)[:requested_limit]
    if len(rtti) + len(exports) + len(xrefs) > requested_limit:
        truncated = True
    return {
        "schema": SCHEMA,
        "module": _module_public(store_name, record, identity),
        "query": requested_query,
        "string_matches": strings,
        "results": results,
        "returned": len(results),
        "truncated": truncated,
        "provenance": {
            "binary": "exact_cached_pe_sha256",
            "execution": "offline_no_vm_stop",
            "string_xrefs": "direct_x64_rip_relative_only",
            "calls": "not_collected",
        },
        "limitations": [
            "string results include only direct RIP-relative xrefs in .text",
            "RTTI results require a validated MSVC x64 TypeDescriptor/COL/vftable chain",
            "mangled-name leads require an exported name; .pdata supplies boundaries, not names",
        ],
    }


def direct_call_xrefs(
    path: Path,
    identity: PeIdentity,
    *,
    rva: int,
    callers: bool = False,
    callees: bool = False,
    limit: int = MAX_RESULTS,
) -> dict[str, Any]:
    """Return bounded static direct-call evidence for a selected function RVA."""
    if not isinstance(callers, bool) or not isinstance(callees, bool):
        raise StaticSearchError("callers and callees must be booleans")
    if not callers and not callees:
        return {"schema": XREF_SCHEMA, "available": True, "callers": [], "callees": []}
    if not isinstance(rva, int) or not 0 <= rva < identity.image_size:
        raise StaticSearchError("function RVA lies outside the exact cached PE")
    if not 1 <= limit <= MAX_RESULTS:
        raise StaticSearchError(f"limit must be between 1 and {MAX_RESULTS}")
    data = _read_bounded_regular_file(path, label="exact cached PE")
    if hashlib.sha256(data).hexdigest() != identity.sha256:
        raise StaticSearchError("exact cached PE changed before direct-call scan")
    functions = _runtime_functions(path, identity, data)
    selected = functions.find(rva)
    if selected is None:
        raise StaticSearchError("selected RVA has no validated x64 .pdata function boundary")
    caller_rows: list[dict[str, Any]] = []
    callee_rows: list[dict[str, Any]] = []
    caller_seen: set[int] = set()
    callee_seen: set[int] = set()
    caller_truncated = callee_truncated = False
    for instruction in _instruction_iter(data, identity):
        target = _direct_call_target(identity, instruction)
        if target is None:
            continue
        instruction_rva = _instruction_rva(identity, instruction)
        source = functions.find(instruction_rva)
        rendered = _bounded_text(f"{instruction.mnemonic} {instruction.op_str}".strip(), 260)
        if callers and target == rva and source is not None and source.begin not in caller_seen:
            caller_seen.add(source.begin)
            caller_rows.append({
                "rva": _hex(source.begin),
                "context": {
                    "kind": "direct_caller", "function_end": _hex(source.end),
                    "call_rva": _hex(instruction_rva), "instruction": rendered,
                    "target_rva": _hex(rva),
                },
            })
            if len(caller_rows) >= limit:
                caller_truncated = True
        if callees and selected.begin <= instruction_rva < selected.end and target not in callee_seen:
            callee_seen.add(target)
            target_function = functions.find(target)
            callee_rows.append({
                "rva": _hex(target_function.begin if target_function is not None else target),
                "context": {
                    "kind": "direct_callee", "call_rva": _hex(instruction_rva),
                    "instruction": rendered, "target_rva": _hex(target),
                    "function": _function_public(target_function),
                },
            })
            if len(callee_rows) >= limit:
                callee_truncated = True
        if (not callers or caller_truncated) and (not callees or callee_truncated):
            break
    return {
        "schema": XREF_SCHEMA,
        "available": True,
        "source_function": _function_public(selected),
        "callers": caller_rows[:limit] if callers else [],
        "callees": callee_rows[:limit] if callees else [],
        "callers_truncated": caller_truncated,
        "callees_truncated": callee_truncated,
        "provenance": "exact_cached_pe_direct_relative_calls_only",
        "limitations": [
            "indirect calls, tail jumps, dynamic dispatch, and unresolved import thunks are not inferred",
        ],
    }
