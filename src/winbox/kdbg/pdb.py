"""PDB symbol + type extraction via ``llvm-pdbutil dump``.

Why text parsing and not a real PDB reader?

* ``llvm-pdbutil`` is packaged everywhere we already run (Kali, Debian,
  Ubuntu) as part of the ``llvm`` tools, so zero extra install burden.
* ``pdbparse``, the Python alternative, has been unmaintained for years
  and has known issues on recent MSVC PDBs.
* We only need a narrow slice of the PDB: public symbols and a handful of
  named structs — neither requires a full PDB reader.

``llvm-pdbutil`` has ``pretty`` (uses Microsoft DIA, Windows-only) and
``dump`` (native LLVM MSF reader, cross-platform). We stick to ``dump``
and parse its text output.

Output discipline: the parser returns ``{name: rva}`` for symbols and
``{type_name: {size, fields}}`` for types. Callers persist the result via
``SymbolStore.save`` and never inline full maps into their response.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


_log = logging.getLogger(__name__)


class PdbError(RuntimeError):
    pass


# Types we extract from nt's PDB by default. The Cortex-engagement agent
# needs EPROCESS for CR3 switching, KPROCESS for DirectoryTableBase,
# KTHREAD for "who was running when the BP fired", LDR_DATA_TABLE_ENTRY
# for kdbg_lm, etc. Keep this list small: each extra type blows up the
# JSON store with little benefit.
NT_DEFAULT_TYPES: tuple[str, ...] = (
    "_EPROCESS",
    "_KPROCESS",
    "_ETHREAD",
    "_KTHREAD",
    "_LIST_ENTRY",
    "_UNICODE_STRING",
    "_LDR_DATA_TABLE_ENTRY",
    "_KLDR_DATA_TABLE_ENTRY",
    # Needed by walk_user_modules — PEB→Ldr→InLoadOrderModuleList walk.
    "_PEB",
    "_PEB_LDR_DATA",
)


@dataclass
class StructField:
    offset: int
    type_hint: str  # Raw type description from llvm-pdbutil (best-effort)


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


def _run_dump(pdb_path: Path, *args: str, timeout: int = 300) -> str:
    """Invoke ``llvm-pdbutil dump`` and return stdout as text.

    We decode as latin-1: publics can contain raw bytes from mangled C++
    literal names that are not valid UTF-8, and the parser operates on
    ASCII markers so lossless byte-to-char mapping is safer than strict
    UTF-8 with ``errors='replace'``.
    """
    try:
        result = subprocess.run(
            ["llvm-pdbutil", "dump", *args, str(pdb_path)],
            capture_output=True, check=False, timeout=timeout,
        )
    except FileNotFoundError as e:
        raise PdbError(
            "llvm-pdbutil not found — install the llvm package"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise PdbError(f"llvm-pdbutil timed out after {timeout}s") from e
    if result.returncode != 0:
        err = result.stderr.decode("latin-1", errors="replace").strip()
        raise PdbError(f"llvm-pdbutil failed: {err}")
    return result.stdout.decode("latin-1", errors="replace")


# ── Section headers ─────────────────────────────────────────────────────

_SECTION_RE = re.compile(r"SECTION HEADER #(\d+)")
_VIRTADDR_RE = re.compile(r"^\s*([0-9A-Fa-f]+)\s+virtual address\s*$")


def parse_section_headers(text: str) -> dict[int, int]:
    """Return ``{section_index_1based: virtual_address}`` parsed from dump text."""
    sections: dict[int, int] = {}
    current: int | None = None
    for line in text.splitlines():
        sec_match = _SECTION_RE.search(line)
        if sec_match:
            current = int(sec_match.group(1))
            continue
        if current is None:
            continue
        va_match = _VIRTADDR_RE.match(line)
        if va_match:
            sections[current] = int(va_match.group(1), 16)
            current = None
    if not sections:
        raise PdbError("no section headers found in llvm-pdbutil output")
    return sections


def load_section_headers(pdb_path: Path) -> dict[int, int]:
    return parse_section_headers(_run_dump(pdb_path, "--section-headers"))


# ── Public symbols ──────────────────────────────────────────────────────

_PUB_RE = re.compile(r"S_PUB32 \[size = \d+\] `([^`]+)`")
_ADDR_RE = re.compile(r"addr\s*=\s*(\d+):(\d+)")


def parse_publics(text: str, sections: dict[int, int]) -> dict[str, int]:
    """Turn ``--publics`` dump text into ``{name: rva}``.

    llvm-pdbutil prints each symbol on two lines::

            0 | S_PUB32 [size = 32] `ZwCreateTimer2`
                flags = function, addr = 0008:2180304

    We walk pairwise: whenever we see a name, the next line that has an
    ``addr =`` binds to it. If a second ``S_PUB32`` name appears before
    the addr line (shouldn't happen with current llvm-pdbutil output,
    but let's be defensive), the newer name displaces the orphan so we
    don't misalign the rest of the stream.
    """
    out: dict[str, int] = {}
    pending_name: str | None = None
    dropped = 0
    for line in text.splitlines():
        pub_match = _PUB_RE.search(line)
        if pub_match:
            pending_name = pub_match.group(1)
            continue
        if pending_name is None:
            continue
        addr_match = _ADDR_RE.search(line)
        if addr_match:
            sec_idx = int(addr_match.group(1))
            sec_off = int(addr_match.group(2))
            sec_va = sections.get(sec_idx)
            if sec_va is not None:
                # Publics with spurious C++ literal names crowd the table; we
                # keep them since filtering would hide legitimate entries.
                out[pending_name] = sec_va + sec_off
            else:
                # Section index not in the headers map. Common causes:
                # truncated llvm-pdbutil output (timeout mid-stream),
                # forward-declared sections in fragments, or genuinely
                # corrupt PDB. Count + warn at end so the caller doesn't
                # silently get a partial symbol table.
                dropped += 1
            pending_name = None
    if dropped:
        # If we got nothing usable, the PDB parse is catastrophically
        # broken — caller MUST not cache this as a successful symbol
        # load. Raise instead of returning an empty dict that looks
        # like "this PDB just has no publics."
        if not out:
            raise PdbError(
                f"parse_publics: all {dropped} symbol(s) dropped due to "
                f"unknown section index — llvm-pdbutil output appears "
                f"truncated or PDB is corrupt"
            )
        # Partial drops with usable symbols: warn loudly via the proper
        # logger so the daemon's stderr/log file captures it. Previous
        # ``print(file=sys.stderr)`` was easy to miss, made test capture
        # awkward, and didn't include a count of accepted symbols for
        # context. Operators tail the daemon log to see this.
        _log.warning(
            "parse_publics dropped %d/%d symbol(s) with unknown section "
            "index — llvm-pdbutil output may be truncated; symbol table "
            "is incomplete",
            dropped, dropped + len(out),
        )
    return out


def load_publics(pdb_path: Path, sections: dict[int, int]) -> dict[str, int]:
    return parse_publics(_run_dump(pdb_path, "--publics"), sections)


# ── Types (structures) ──────────────────────────────────────────────────

_TPI_RECORD_RE = re.compile(r"^\s*0x([0-9A-Fa-f]+)\s*\|\s*(LF_\w+)\b")
_STRUCT_NAME_RE = re.compile(r"LF_STRUCTURE \[size = \d+\] `([^`]+)`")
_FIELDLIST_REF_RE = re.compile(r"field list:\s*0x([0-9A-Fa-f]+)")
_SIZEOF_RE = re.compile(r"sizeof\s+(\d+)")
_MEMBER_RE = re.compile(
    r"LF_MEMBER \[name = `([^`]+)`,\s*Type = 0x[0-9A-Fa-f]+"
    r"(?:\s*\(([^)]+)\))?,\s*offset = (\d+)"
)


def parse_types(text: str, wanted: Iterable[str]) -> dict[str, StructLayout]:
    """Extract named struct layouts from ``--types`` dump text.

    Handles the two-record pattern MSVC emits: a forward-ref
    ``LF_STRUCTURE`` (``sizeof 0``, ``field list: <no type>``) followed by
    the full record with an actual field list id and non-zero sizeof. We
    pick the latter when available.

    The parser is line-oriented and streams, so it stays flat on memory
    even on a 40k-type ntkrnlmp.pdb dump.
    """
    wanted_set = set(wanted)
    # Two-phase: (1) collect LF_FIELDLIST contents keyed by type id;
    # (2) collect full LF_STRUCTURE records and resolve their field list.
    field_lists: dict[int, dict[str, StructField]] = {}
    # Each entry: (name, fieldlist_id_or_None, sizeof)
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
            # A new top-level TPI record starts — close any in-progress one.
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
                # flist / sizeof come on following lines
            continue

        # Continuation lines for the active record
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
                # llvm-pdbutil occasionally emits duplicate members inside
                # union substructures; first wins.
                current_fieldlist.setdefault(
                    name, StructField(offset=offset, type_hint=type_hint)
                )

    # Close any record that was still open at EOF.
    if current_record == "LF_STRUCTURE":
        finalize_struct()
    elif current_record == "LF_FIELDLIST":
        finalize_fieldlist()

    # Resolve: for each wanted struct, prefer the decl with a real field
    # list and non-zero sizeof. Forward refs have flist=None and size=0.
    layouts: dict[str, StructLayout] = {}
    for name, flist_id, sizeof in struct_decls:
        if flist_id is None or sizeof == 0:
            continue
        fields = field_lists.get(flist_id)
        if fields is None:
            continue
        # Some types appear multiple times (inner anon). Keep the first
        # populated one; if a later decl has more fields, prefer that one
        # as it's more likely to be the "real" ntoskrnl layout.
        existing = layouts.get(name)
        if existing is None or len(fields) > len(existing.fields):
            layouts[name] = StructLayout(size=sizeof, fields=fields)

    missing = wanted_set - layouts.keys()
    if missing:
        # Don't raise — better to load partial types than block the whole
        # symbol build. Caller can check what they got via SymbolStore.info.
        pass

    return layouts


def load_types(
    pdb_path: Path,
    wanted: Iterable[str] = NT_DEFAULT_TYPES,
) -> dict[str, StructLayout]:
    return parse_types(_run_dump(pdb_path, "--types"), wanted)


# ── Convenience ─────────────────────────────────────────────────────────


def build_symbol_map(pdb_path: Path) -> dict[str, int]:
    """One-shot: section headers + publics, return {name: rva}."""
    sections = load_section_headers(pdb_path)
    return load_publics(pdb_path, sections)


def build_type_map(
    pdb_path: Path,
    wanted: Iterable[str] = NT_DEFAULT_TYPES,
) -> dict[str, dict]:
    """One-shot: wanted types, return JSON-ready ``{name: {size, fields}}``."""
    layouts = load_types(pdb_path, wanted)
    return {name: layout.to_json() for name, layout in layouts.items()}
