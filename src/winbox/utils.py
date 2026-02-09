"""Shared utility functions."""

from __future__ import annotations


def human_size(nbytes: int | float) -> str:
    """Convert a byte count to a human-readable string (e.g. '4.7 GB')."""
    size = float(nbytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
