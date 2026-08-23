"""PE identity parsing and live-vs-static validation.

ASLR makes virtual addresses deliberately unstable.  Code identity does not
come from a filename or a load base: for Microsoft binaries the CodeView
GUID+age is the strongest readily available identity, with image size and PE
timestamp as independent guards.  The parsers here are intentionally small
and bounded so malformed guest memory cannot turn an MCP request into a large
allocation or an unbounded read.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pefile


class IdentityError(RuntimeError):
    """The PE is malformed, unsupported, or does not match live memory."""


MAX_PE_HEADERS = 1 << 20
MAX_DEBUG_DIRECTORY = 4096
MAX_CODEVIEW = 4096


@dataclass(frozen=True)
class SectionIdentity:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def file_offset(self, rva: int) -> int | None:
        delta = rva - self.virtual_address
        if delta < 0 or delta >= self.raw_size:
            return None
        return self.raw_offset + delta


@dataclass(frozen=True)
class PeIdentity:
    machine: int
    timestamp: int
    image_size: int
    preferred_base: int
    pdb_key: str | None
    sha256: str | None = None
    file_size: int | None = None
    sections: tuple[SectionIdentity, ...] = ()

    def public(self) -> dict[str, object]:
        return {
            "machine": f"0x{self.machine:04x}",
            "timestamp": f"0x{self.timestamp:08x}",
            "image_size": self.image_size,
            "preferred_base": f"0x{self.preferred_base:x}",
            "pdb_key": self.pdb_key,
            "sha256": self.sha256,
            "file_size": self.file_size,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_static_pe(path: Path) -> PeIdentity:
    """Return the identity and RVA/file mapping for an on-disk PE."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise IdentityError(f"{path} is not a valid PE: {exc}") from exc
    try:
        machine = int(pe.FILE_HEADER.Machine)
        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
        preferred_base = int(pe.OPTIONAL_HEADER.ImageBase)
        sections = tuple(
            SectionIdentity(
                name=bytes(section.Name).split(b"\0", 1)[0].decode(
                    "ascii", errors="replace"
                ),
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_offset=int(section.PointerToRawData),
                raw_size=int(section.SizeOfRawData),
            )
            for section in pe.sections
        )
        pdb_key = _static_pdb_key(pe)
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise IdentityError(f"{path} has malformed PE headers: {exc}") from exc
    finally:
        pe.close()
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        raise IdentityError(f"cannot stat {path}: {exc}") from exc
    return PeIdentity(
        machine=machine,
        timestamp=timestamp,
        image_size=image_size,
        preferred_base=preferred_base,
        pdb_key=pdb_key,
        sha256=sha256_file(path),
        file_size=file_size,
        sections=sections,
    )


def _static_pdb_key(pe) -> str | None:
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
        )
    except (pefile.PEFormatError, AttributeError, IndexError):
        return None
    for item in getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or ():
        if int(item.struct.Type) != 2 or item.entry is None:
            continue
        entry = item.entry
        if getattr(entry, "CvSignature", None) != b"RSDS":
            continue
        key = getattr(entry, "Signature_String", None)
        if key:
            return str(key).upper()
    return None


def parse_live_pe(read: Callable[[int, int], bytes], base: int) -> PeIdentity:
    """Parse identity fields from a mapped PE using a bounded read callback."""
    first = _read_exact(read, base, 4096, "initial PE headers")
    if first[:2] != b"MZ":
        raise IdentityError(f"module at 0x{base:x} has no MZ header")
    e_lfanew = _u32(first, 0x3C, "e_lfanew")
    if e_lfanew > MAX_PE_HEADERS - 256:
        raise IdentityError(f"PE header offset 0x{e_lfanew:x} exceeds 1 MiB cap")
    needed = e_lfanew + 24
    header = first if needed <= len(first) else _read_exact(
        read, base, needed, "PE signature"
    )
    if header[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise IdentityError(f"module at 0x{base:x} has no PE signature")
    coff = e_lfanew + 4
    machine, section_count, timestamp = struct.unpack_from("<HHI", header, coff)
    optional_size = _u16(header, coff + 16, "optional header size")
    if section_count > 96:
        raise IdentityError(f"implausible PE section count: {section_count}")
    optional = coff + 20
    total_headers = optional + optional_size + section_count * 40
    if total_headers > MAX_PE_HEADERS:
        raise IdentityError(f"PE headers exceed {MAX_PE_HEADERS} byte cap")
    if len(header) < total_headers:
        header = _read_exact(read, base, total_headers, "complete PE headers")
    magic = _u16(header, optional, "optional header magic")
    if magic == 0x20B:
        preferred_base = _u64(header, optional + 24, "PE32+ image base")
        directory = optional + 112
    elif magic == 0x10B:
        preferred_base = _u32(header, optional + 28, "PE32 image base")
        directory = optional + 96
    else:
        raise IdentityError(f"unsupported optional header magic 0x{magic:x}")
    image_size = _u32(header, optional + 56, "SizeOfImage")
    if image_size <= 0 or image_size > (1 << 32):
        raise IdentityError(f"implausible SizeOfImage: {image_size}")

    pdb_key = None
    # IMAGE_DIRECTORY_ENTRY_DEBUG is data-directory index 6.
    debug_slot = directory + 6 * 8
    if debug_slot + 8 <= optional + optional_size:
        debug_rva, debug_size = struct.unpack_from("<II", header, debug_slot)
        if debug_rva and debug_size:
            pdb_key = _read_live_pdb_key(read, base, image_size, debug_rva, debug_size)

    return PeIdentity(
        machine=machine,
        timestamp=timestamp,
        image_size=image_size,
        preferred_base=preferred_base,
        pdb_key=pdb_key,
    )


def _read_live_pdb_key(
    read: Callable[[int, int], bytes],
    base: int,
    image_size: int,
    debug_rva: int,
    debug_size: int,
) -> str | None:
    if debug_rva >= image_size:
        raise IdentityError("debug directory lies outside mapped image")
    size = min(debug_size, MAX_DEBUG_DIRECTORY, image_size - debug_rva)
    directory = _read_exact(read, base + debug_rva, size, "debug directory")
    # IMAGE_DEBUG_DIRECTORY is 28 bytes. Ignore a partial trailing entry.
    for offset in range(0, len(directory) - 27, 28):
        kind = _u32(directory, offset + 12, "debug type")
        if kind != 2:
            continue
        data_size = _u32(directory, offset + 16, "CodeView size")
        data_rva = _u32(directory, offset + 20, "CodeView RVA")
        if data_size < 24 or data_size > MAX_CODEVIEW:
            continue
        if data_rva >= image_size or data_size > image_size - data_rva:
            continue
        codeview = _read_exact(read, base + data_rva, data_size, "CodeView record")
        if codeview[:4] != b"RSDS":
            continue
        guid = uuid.UUID(bytes_le=bytes(codeview[4:20])).hex.upper()
        age = _u32(codeview, 20, "CodeView age")
        return f"{guid}{age:X}"
    return None


def validate_identity(
    live: PeIdentity,
    static: PeIdentity,
    *,
    module_name: str,
    live_module_size: int,
) -> str:
    """Validate an exact mapping and return its confidence label.

    Any concrete disagreement fails closed.  A matching CodeView key is an
    exact build match; stripped third-party images fall back to the PE header
    tuple (machine, timestamp, image size).
    """
    mismatches: list[str] = []
    if live.machine != static.machine:
        mismatches.append(
            f"machine live=0x{live.machine:x} static=0x{static.machine:x}"
        )
    if live.image_size != static.image_size:
        mismatches.append(
            f"SizeOfImage live=0x{live.image_size:x} static=0x{static.image_size:x}"
        )
    if live_module_size and live_module_size != live.image_size:
        mismatches.append(
            f"loader size=0x{live_module_size:x} header=0x{live.image_size:x}"
        )
    if live.timestamp != static.timestamp:
        mismatches.append(
            f"timestamp live=0x{live.timestamp:x} static=0x{static.timestamp:x}"
        )
    if live.pdb_key and static.pdb_key and live.pdb_key != static.pdb_key:
        mismatches.append(f"PDB live={live.pdb_key} static={static.pdb_key}")
    if mismatches:
        raise IdentityError(
            f"cached binary does not match live {module_name}: " + "; ".join(mismatches)
        )
    if live.pdb_key and static.pdb_key:
        return "pdb-guid-age"
    if live.timestamp == 0:
        raise IdentityError(
            f"cannot strongly identify stripped {module_name}: no CodeView key "
            "and PE timestamp is zero"
        )
    return "pe-headers"


def static_bytes_at_rva(path: Path, identity: PeIdentity, rva: int, length: int) -> bytes:
    """Read bytes corresponding to an RVA from a PE's raw section data."""
    if length <= 0:
        return b""
    for section in identity.sections:
        offset = section.file_offset(rva)
        if offset is None:
            continue
        available = section.raw_offset + section.raw_size - offset
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(min(length, available))
    return b""


def _read_exact(
    read: Callable[[int, int], bytes], address: int, length: int, label: str
) -> bytes:
    if length < 0 or length > MAX_PE_HEADERS:
        raise IdentityError(f"invalid {label} read length: {length}")
    try:
        value = read(address, length)
    except Exception as exc:
        raise IdentityError(f"could not read {label} at 0x{address:x}: {exc}") from exc
    if len(value) != length:
        raise IdentityError(
            f"short {label} read at 0x{address:x}: got {len(value)}/{length} bytes"
        )
    return value


def _u16(data: bytes, offset: int, label: str) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as exc:
        raise IdentityError(f"truncated {label}") from exc


def _u32(data: bytes, offset: int, label: str) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as exc:
        raise IdentityError(f"truncated {label}") from exc


def _u64(data: bytes, offset: int, label: str) -> int:
    try:
        return struct.unpack_from("<Q", data, offset)[0]
    except struct.error as exc:
        raise IdentityError(f"truncated {label}") from exc
