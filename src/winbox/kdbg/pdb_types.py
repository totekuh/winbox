"""PDB struct/type extraction from ``llvm-pdbutil dump --types``."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from winbox.kdbg.pdb import PdbError, _run_dump

_log = logging.getLogger(__name__)

NT_DEFAULT_TYPES: tuple[str, ...] = (
    "_EPROCESS",
    "_KPROCESS",
    "_ETHREAD",
    "_KTHREAD",
    "_KWAIT_BLOCK",
    "_DISPATCHER_HEADER",
    "_KMUTANT",
    "_KPRCB",
    "_KTRAP_FRAME",
    "_KPCR",
    "_LIST_ENTRY",
    "_UNICODE_STRING",
    "_LDR_DATA_TABLE_ENTRY",
    "_KLDR_DATA_TABLE_ENTRY",
    "_PEB",
    "_PEB_LDR_DATA",
    "_EWOW64PROCESS",
)


@dataclass
class StructField:
    offset: int
    type_hint: str


@dataclass
class StructLayout:
    size: int
    fields: dict[str, StructField]

    def to_json(self) -> dict:
        return {
            "size": self.size,
            "fields": {
                name: {"off": f.offset, "type": f.type_hint}
                for name, f in self.fields.items()
            },
        }


_TPI_RECORD_RE = re.compile(r"^\s*0x([0-9A-Fa-f]+)\s*\|\s*(LF_\w+)\b")
_STRUCT_NAME_RE = re.compile(r"LF_STRUCTURE \[size = \d+\] `([^`]+)`")
_FIELDLIST_REF_RE = re.compile(r"field list:\s*0x([0-9A-Fa-f]+)")
_SIZEOF_RE = re.compile(r"sizeof\s+(\d+)")
_MEMBER_RE = re.compile(
    r"LF_MEMBER \[name = `([^`]+)`,\s*Type = 0x[0-9A-Fa-f]+"
    r"(?:\s*\(([^)]+)\))?,\s*offset = (\d+)"
)


def parse_types(text: str, wanted: Iterable[str]) -> dict[str, StructLayout]:
    """Extract named struct layouts from ``--types`` dump text."""
    wanted_set = set(wanted)
    field_lists: dict[int, dict[str, StructField]] = {}
    struct_decls: list[tuple[str, int | None, int]] = []

    current_record: str | None = None
    current_record_id: int | None = None
    current_struct_name: str | None = None
    current_struct_flist: int | None = None
    current_struct_size: int | None = None
    current_fieldlist: dict[str, StructField] | None = None

    def finalize_struct() -> None:
        nonlocal current_struct_name, current_struct_flist, current_struct_size
        if current_struct_name and current_struct_name in wanted_set:
            struct_decls.append((
                current_struct_name,
                current_struct_flist,
                current_struct_size or 0,
            ))
        current_struct_name = None
        current_struct_flist = None
        current_struct_size = None

    def finalize_fieldlist() -> None:
        nonlocal current_record_id, current_fieldlist
        if current_record_id is not None and current_fieldlist is not None:
            field_lists[current_record_id] = current_fieldlist
        current_record_id = None
        current_fieldlist = None

    for line in text.splitlines():
        rec_match = _TPI_RECORD_RE.match(line)
        if rec_match:
            if current_record == "LF_STRUCTURE":
                finalize_struct()
            elif current_record == "LF_FIELDLIST":
                finalize_fieldlist()

            current_record = rec_match.group(2)
            rec_id = int(rec_match.group(1), 16)
            if current_record == "LF_FIELDLIST":
                current_record_id = rec_id
                current_fieldlist = {}
            elif current_record == "LF_STRUCTURE":
                struct_match = _STRUCT_NAME_RE.search(line)
                if struct_match:
                    current_struct_name = struct_match.group(1)
            continue

        if current_record == "LF_STRUCTURE" and current_struct_name:
            flist_match = _FIELDLIST_REF_RE.search(line)
            if flist_match:
                current_struct_flist = int(flist_match.group(1), 16)
            size_match = _SIZEOF_RE.search(line)
            if size_match:
                current_struct_size = int(size_match.group(1))
        elif current_record == "LF_FIELDLIST" and current_fieldlist is not None:
            mem_match = _MEMBER_RE.search(line)
            if mem_match:
                name = mem_match.group(1)
                type_hint = (mem_match.group(2) or "").strip()
                offset = int(mem_match.group(3))
                current_fieldlist.setdefault(
                    name, StructField(offset=offset, type_hint=type_hint)
                )

    if current_record == "LF_STRUCTURE":
        finalize_struct()
    elif current_record == "LF_FIELDLIST":
        finalize_fieldlist()

    layouts: dict[str, StructLayout] = {}
    for name, flist_id, sizeof in struct_decls:
        if flist_id is None or sizeof == 0:
            continue
        fields = field_lists.get(flist_id)
        if fields is None:
            continue
        existing = layouts.get(name)
        if existing is None or len(fields) > len(existing.fields):
            layouts[name] = StructLayout(size=sizeof, fields=fields)

    missing = wanted_set - layouts.keys()
    if missing:
        _log.warning(
            "parse_types: %d/%d wanted type(s) not found (%s) — struct map is "
            "incomplete; llvm-pdbutil output may be truncated",
            len(missing), len(wanted_set), ", ".join(sorted(missing)),
        )

    empty = [name for name, layout in layouts.items() if not layout.fields]
    if empty:
        raise ValueError(
            f"parse_types: {len(empty)} type(s) have zero fields after "
            f"parsing ({', '.join(sorted(empty))}). This usually means "
            f"llvm-pdbutil output format drifted and the field-line regex "
            f"no longer matches. Check _MEMBER_RE against current "
            f"llvm-pdbutil --types output."
        )

    sparse = [
        f"{name} (sizeof={layout.size}, {len(layout.fields)} fields)"
        for name, layout in layouts.items()
        if layout.size >= 64 and len(layout.fields) < 3
    ]
    if sparse:
        _log.warning(
            "parse_types: %d type(s) have suspiciously few fields for their "
            "size (%s) — field-line regex may have partially failed; check "
            "_MEMBER_RE against current llvm-pdbutil output",
            len(sparse), "; ".join(sparse),
        )

    return layouts


def load_types(
    pdb_path: Path,
    wanted: Iterable[str] = NT_DEFAULT_TYPES,
) -> dict[str, StructLayout]:
    return parse_types(_run_dump(pdb_path, "--types"), wanted)


def build_type_map(
    pdb_path: Path,
    wanted: Iterable[str] = NT_DEFAULT_TYPES,
) -> dict[str, dict]:
    """One-shot: wanted types, return JSON-ready ``{name: {size, fields}}``."""
    layouts = load_types(pdb_path, wanted)
    return {name: layout.to_json() for name, layout in layouts.items()}
