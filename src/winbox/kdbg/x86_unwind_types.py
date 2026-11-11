"""Data types for the x86 hybrid stack unwinder."""

from __future__ import annotations

from dataclasses import dataclass


class X86UnwindError(RuntimeError):
    """Missing/corrupt metadata or a stack that cannot be trusted."""


@dataclass(frozen=True)
class X86Module:
    name: str
    base: int
    size: int
    frame_data: tuple[dict, ...] = ()
    function_starts: tuple[int, ...] = ()
    metadata: str | None = None


@dataclass(frozen=True)
class X86Step:
    eip: int
    esp: int
    ebp: int
    ebx: int
    method: str
    confidence: str
    operations: tuple[str, ...]
    metadata: str | None = None
