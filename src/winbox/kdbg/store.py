"""Symbol + struct-offset JSON store for kdbg.

Layout under ``~/.winbox/symbols/``::

    index.json                    # { module_name: active_file, ... }
    nt_<pdb_guid><age>.json       # per-build file (content below)

Per-module file content::

    {
      "module": "nt",
      "build": "<guid><age>",     # opaque identifier, PDB-derived or user-set
      "image": "ntkrnlmp.pdb",    # source filename / hint
      "base": 0xfffff80559000000, # resolved at load-time if available, else null
      "symbols": { "NtCreateFile": 0x123456, ... },       # values are RVAs
      "types":   { "_EPROCESS": { "DirectoryTableBase": {"off": 0x28, "size": 8}, ... } }
    }

The store is append-only from the user's point of view: loading nt twice
for the same build is a no-op, loading a new build rewrites the pointer in
``index.json``.

Symbol lookups never inline the full table — callers get a path + metadata
via ``SymbolStore.info``, or single answers via ``resolve`` / ``struct``.
This matters because ntkrnlmp.pdb has ~30k symbols and dumping them into
an LLM context would be ruinous.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SymbolStoreError(RuntimeError):
    pass


def _atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write ``content`` to ``path`` atomically.

    Naked ``path.write_text`` truncate-then-writes — two parallel callers
    (CLI + MCP, or two MCP tool calls during agent parallelism) interleave
    bytes and corrupt the file. ``tempfile.NamedTemporaryFile`` in the same
    dir + ``os.replace`` gives us atomic rename semantics on POSIX, so a
    concurrent reader sees either the old file or the new file but never
    a half-written one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        # Don't leave .tmp turds around if rename failed.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


@dataclass
class ModuleInfo:
    name: str
    build: str
    path: Path
    base: int | None
    symbol_count: int
    type_count: int


class SymbolStore:
    """File-backed symbol + struct-offset store."""

    INDEX_NAME = "index.json"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    # ── Index management ────────────────────────────────────────────────

    @property
    def index_path(self) -> Path:
        return self.root / self.INDEX_NAME

    def _read_index(self) -> dict[str, str]:
        if not self.index_path.exists():
            return {}
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_index(self, index: dict[str, str]) -> None:
        _atomic_write_text(
            self.index_path,
            json.dumps(index, indent=2, sort_keys=True),
        )

    # ── Save / load ─────────────────────────────────────────────────────

    def save(
        self,
        module: str,
        build: str,
        *,
        image: str,
        symbols: dict[str, int],
        types: dict[str, dict[str, dict[str, int]]],
        base: int | None = None,
        size_of_image: int | None = None,
        filename: str | None = None,
    ) -> Path:
        """Write a module file and register it in the index as current.

        ``size_of_image`` is from the PE optional header — the in-memory
        size of the loaded image in bytes (different from on-disk file
        size; pages are aligned). Used by bt to constrain symbol
        lookups to the module that actually contains a given VA.
        """
        if not module:
            raise SymbolStoreError("module name is empty")
        fname = filename or f"{module}_{build}.json"
        data: dict[str, Any] = {
            "module": module,
            "build": build,
            "image": image,
            "base": base,
            "size_of_image": size_of_image,
            "symbols": symbols,
            "types": types,
        }
        path = self.root / fname
        _atomic_write_text(
            path,
            json.dumps(data, indent=2, sort_keys=True),
        )
        index = self._read_index()
        index[module] = fname
        self._write_index(index)
        return path

    def set_base(self, module: str, base: int) -> None:
        """Update the cached module base without rewriting symbols."""
        path = self._module_path(module)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["base"] = base
        _atomic_write_text(
            path,
            json.dumps(data, indent=2, sort_keys=True),
        )

    def _module_path(self, module: str) -> Path:
        index = self._read_index()
        fname = index.get(module)
        if not fname:
            raise SymbolStoreError(
                f"module {module!r} not loaded — "
                f"run `winbox kdbg symbols {module}` first"
            )
        path = self.root / fname
        if not path.exists():
            raise SymbolStoreError(
                f"index points at {fname} but file is missing"
            )
        return path

    def load(self, module: str) -> dict[str, Any]:
        path = self._module_path(module)
        return json.loads(path.read_text(encoding="utf-8"))

    def info(self, module: str) -> ModuleInfo:
        data = self.load(module)
        return ModuleInfo(
            name=data["module"],
            build=data.get("build", ""),
            path=self._module_path(module),
            base=data.get("base"),
            symbol_count=len(data.get("symbols", {})),
            type_count=len(data.get("types", {})),
        )

    def list_modules(self) -> list[str]:
        return sorted(self._read_index().keys())

    # ── Lookups ─────────────────────────────────────────────────────────

    @staticmethod
    def parse_symbol(name: str, default_module: str = "nt") -> tuple[str, str]:
        """Split 'mod!sym' into (module, sym). Defaults module to nt."""
        if "!" in name:
            mod, _, sym = name.partition("!")
            return mod, sym
        return default_module, name

    def resolve(self, name: str, *, default_module: str = "nt") -> int:
        """Return absolute VA for 'mod!sym'. Requires base to be set."""
        module, sym = self.parse_symbol(name, default_module)
        data = self.load(module)
        rva = data.get("symbols", {}).get(sym)
        if rva is None:
            raise SymbolStoreError(f"symbol not found: {module}!{sym}")
        base = data.get("base")
        if base is None:
            raise SymbolStoreError(
                f"{module} has no base — load with a running VM first"
            )
        return base + rva

    def rva(self, name: str, *, default_module: str = "nt") -> int:
        """Return RVA for 'mod!sym' without requiring a base."""
        module, sym = self.parse_symbol(name, default_module)
        data = self.load(module)
        rva = data.get("symbols", {}).get(sym)
        if rva is None:
            raise SymbolStoreError(f"symbol not found: {module}!{sym}")
        return rva

    def search(
        self,
        pattern: str,
        *,
        module: str = "nt",
        limit: int = 64,
        case_sensitive: bool = False,
    ) -> list[tuple[str, int]]:
        """Substring match on symbol names. Returns [(name, rva)].

        Defaults to case-insensitive — pentest users typically remember
        ``KiSystemCall`` vs ``kisystemcall`` only loosely. Pass
        ``case_sensitive=True`` for exact matching.
        """
        data = self.load(module)
        hits: list[tuple[str, int]] = []
        needle = pattern if case_sensitive else pattern.lower()
        for name, rva in data.get("symbols", {}).items():
            haystack = name if case_sensitive else name.lower()
            if needle in haystack:
                hits.append((name, rva))
                if len(hits) >= limit:
                    break
        return hits

    def struct(self, type_name: str, field: str | None = None, *, module: str = "nt") -> Any:
        """Return struct layout or a single field entry.

        * ``struct('_EPROCESS')``                      -> ``{size, fields}``
        * ``struct('_EPROCESS', 'DirectoryTableBase')`` -> ``{off, type}``
        """
        data = self.load(module)
        layout = data.get("types", {}).get(type_name)
        if layout is None:
            raise SymbolStoreError(f"type not found: {module}!{type_name}")
        if field is None:
            return layout
        entry = layout.get("fields", {}).get(field)
        if entry is None:
            raise SymbolStoreError(
                f"field not found: {module}!{type_name}.{field}"
            )
        return entry
