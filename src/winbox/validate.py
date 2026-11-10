"""Shared input validation for CLI and MCP surfaces."""

import re

_SHARE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,20}$")


def check_share_name(name: str) -> str | None:
    if not _SHARE_NAME_RE.match(name):
        return (
            f"Invalid share name: {name!r} "
            "(alphanumeric, hyphens, underscores, dots; max 80 chars)"
        )
    return None


def check_username(username: str) -> str | None:
    if not _USERNAME_RE.match(username):
        return (
            f"Invalid username: {username!r} "
            "(alphanumeric, hyphens, underscores, dots, spaces; max 20 chars)"
        )
    return None


def check_relative_path(path: str) -> tuple[str | None, str]:
    """Validate and normalize a relative path within a share.

    Returns (error_message_or_None, normalized_backslash_path).
    """
    if not path:
        return ("Path cannot be empty", "")
    normalized = path.replace("/", "\\")
    if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("\\"):
        return (f"Path must be relative, not absolute: {path!r}", "")
    for part in normalized.split("\\"):
        if part == "..":
            return (f"Path traversal ('..') not allowed: {path!r}", "")
    if re.search(r'[<>"|?*:]', normalized):
        return (f"Invalid characters in path: {path!r}", "")
    return (None, normalized)
