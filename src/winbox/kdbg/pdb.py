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
from dataclasses import dataclass
from pathlib import Path


_log = logging.getLogger(__name__)


class PdbError(RuntimeError):
    pass


def _run_dump(pdb_path: Path, *args: str, timeout: int = 300) -> str:
    """Invoke ``llvm-pdbutil dump`` and return stdout as text."""
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


@dataclass
class PublicSymbols:
    symbols: dict[str, int]
    functions: set[str]


def parse_publics_metadata(text: str, sections: dict[int, int]) -> PublicSymbols:
    """Turn ``--publics`` dump text into ``{name: rva}``."""
    out: dict[str, int] = {}
    functions: set[str] = set()
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
                out[pending_name] = sec_va + sec_off
                if re.search(r"\bfunction\b", line, re.IGNORECASE):
                    functions.add(pending_name)
            else:
                dropped += 1
            pending_name = None
    if dropped:
        if not out:
            raise PdbError(
                f"parse_publics: all {dropped} symbol(s) dropped due to "
                f"unknown section index — llvm-pdbutil output appears "
                f"truncated or PDB is corrupt"
            )
        _log.warning(
            "parse_publics dropped %d/%d symbol(s) with unknown section "
            "index — llvm-pdbutil output may be truncated; symbol table "
            "is incomplete",
            dropped, dropped + len(out),
        )
    return PublicSymbols(out, functions)


def parse_publics(text: str, sections: dict[int, int]) -> dict[str, int]:
    return parse_publics_metadata(text, sections).symbols


def load_publics(pdb_path: Path, sections: dict[int, int]) -> dict[str, int]:
    return parse_publics(_run_dump(pdb_path, "--publics"), sections)


def load_publics_metadata(pdb_path: Path, sections: dict[int, int]) -> PublicSymbols:
    return parse_publics_metadata(_run_dump(pdb_path, "--publics"), sections)


# ── Convenience ─────────────────────────────────────────────────────────


def build_symbol_map(pdb_path: Path) -> dict[str, int]:
    """One-shot: section headers + publics, return {name: rva}."""
    sections = load_section_headers(pdb_path)
    return load_publics(pdb_path, sections)


# ── Re-exports from extracted modules ──────────────────────────────────

from winbox.kdbg.pdb_types import (  # noqa: E402, F401
    NT_DEFAULT_TYPES, StructField, StructLayout,
    build_type_map, load_types, parse_types,
)
from winbox.kdbg.pdb_fpo import (  # noqa: E402, F401
    FpoRecord, load_fpo, parse_fpo,
)
