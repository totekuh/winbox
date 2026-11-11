"""Constants, error type, and validators for static PE search."""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Iterable


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
