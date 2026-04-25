"""winbox — Transparent Windows Execution Proxy for Kali."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Sourced from pyproject.toml so the in-source constant cannot drift past
# the package metadata (it had: "1.2.0" while pyproject said "1.2.1").
try:
    __version__ = _pkg_version("winbox")
except PackageNotFoundError:
    # Editable installs without metadata, or running straight from src/.
    __version__ = "0.0.0+unknown"
