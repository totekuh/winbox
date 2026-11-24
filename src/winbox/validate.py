"""Shared input validation for CLI and MCP surfaces."""

import re

_SHARE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,20}$")
_DOMAIN_FQDN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$")
_SAM_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,20}$")
_GPO_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,128}$")
_DFS_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")
_UNC_PATH_RE = re.compile(r"^\\\\[^\\]+\\[^\\]+")


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


def check_domain_fqdn(name: str) -> str | None:
    if not name or len(name) > 255 or not _DOMAIN_FQDN_RE.match(name):
        return (
            f"Invalid domain FQDN: {name!r} "
            "(e.g. TESTLAB.LOCAL — alphanumeric labels separated by dots)"
        )
    return None


def check_ad_username(name: str) -> str | None:
    if not _SAM_ACCOUNT_RE.match(name):
        return (
            f"Invalid SAM account name: {name!r} "
            "(alphanumeric, hyphens, underscores, dots, spaces; max 20 chars)"
        )
    return None


def check_ou_dn(dn: str) -> str | None:
    if not dn or not re.match(r"^(OU|DC|CN)=", dn, re.IGNORECASE):
        return (
            f"Invalid distinguished name: {dn!r} "
            "(must start with OU=, DC=, or CN=)"
        )
    return None


def check_gpo_name(name: str) -> str | None:
    if not _GPO_NAME_RE.match(name):
        return (
            f"Invalid GPO name: {name!r} "
            "(alphanumeric, spaces, hyphens, underscores, dots; max 128 chars)"
        )
    return None


def check_dfs_namespace(name: str) -> str | None:
    if not _DFS_NAMESPACE_RE.match(name):
        return (
            f"Invalid DFS namespace name: {name!r} "
            "(alphanumeric, hyphens, underscores, dots; max 80 chars)"
        )
    return None


def check_unc_path(path: str) -> str | None:
    if not _UNC_PATH_RE.match(path):
        return (
            f"Invalid UNC path: {path!r} "
            r"(must start with \\server\share)"
        )
    return None
