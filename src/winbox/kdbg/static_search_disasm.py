"""PE section helpers, string search, and disassembly for static search."""

from __future__ import annotations

import struct
from typing import Any

import capstone
from capstone import x86
import pefile

from winbox.kdbg.decomp.identity import PeIdentity
from winbox.kdbg.static_search_types import (
    MAX_INSTRUCTIONS,
    MAX_PDATA_ENTRIES,
    MAX_STRING_MATCHES,
    StaticSearchError,
    _FunctionIndex,
    _RuntimeFunction,
    _bounded_text,
    _hex,
)


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


def _runtime_functions(path, identity: PeIdentity, data: bytes) -> _FunctionIndex:
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
