"""PE debug-directory parsing and PDB fetching.

We need two things out of a Windows PE:

1. The CodeView debug entry (``RSDS``) so we know which PDB to fetch from
   Microsoft's public symbol server and can name the cache key:
       https://msdl.microsoft.com/download/symbols/<pdb_name>/<GUID><AGE>/<pdb_name>
2. The ``SizeOfImage`` field — not strictly required for symbol lookup, but
   handy for later sanity checks ("does the module at base X match this
   PDB").

``pefile`` handles the PE parsing; this module is the thin glue around it
and the symbol-server download. ``pefile`` already exposes a
``Signature_String`` on the CodeView entry that matches msdl's exact
URL-segment format (GUID uppercase no-dashes followed by hex age), so we
use that directly instead of rebuilding it.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import pefile


class PeError(RuntimeError):
    pass


IMAGE_DEBUG_TYPE_CODEVIEW = 2


@dataclass
class PdbRef:
    """Identifies a PDB uniquely — matches the msdl URL layout."""

    pdb_name: str       # e.g. "ntkrnlmp.pdb"
    build_key: str      # <GUID uppercase no-dashes><hex age>
    size_of_image: int


def read_pdb_ref(pe_path: Path) -> PdbRef:
    """Parse the PE debug directory and return the CodeView reference.

    Raises ``PeError`` if the PE has no RSDS debug entry — modern Microsoft
    kernel binaries always do, third-party drivers may not.
    """
    pe = pefile.PE(str(pe_path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
    )

    debug_entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or []
    for entry in debug_entries:
        if entry.struct.Type != IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        cv = entry.entry
        if cv is None:
            continue
        if getattr(cv, "CvSignature", None) != b"RSDS":
            continue
        build_key = getattr(cv, "Signature_String", None)
        if not build_key:
            continue
        return PdbRef(
            pdb_name=_decode_pdb_name(cv.PdbFileName),
            build_key=build_key,
            size_of_image=int(pe.OPTIONAL_HEADER.SizeOfImage),
        )

    raise PeError(
        f"{pe_path.name} has no CodeView (RSDS) debug entry — "
        "cannot identify a PDB to fetch"
    )


def _decode_pdb_name(raw: bytes | bytearray | str) -> str:
    """Turn pefile's raw PdbFileName into a basename msdl will accept."""
    if isinstance(raw, (bytes, bytearray)):
        text = raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    else:
        text = str(raw).rstrip("\x00")
    return text.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


# ── Symbol-server fetch ─────────────────────────────────────────────────


SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def pdb_cache_path(ref: PdbRef, cache_root: Path) -> Path:
    """Path where the fetched PDB lives under the cache root."""
    return cache_root / f"{Path(ref.pdb_name).stem}_{ref.build_key}.pdb"


def fetch_pdb(ref: PdbRef, cache_root: Path, *, timeout: int = 120) -> Path:
    """Download the PDB from msdl if not already cached. Return the local path.

    We do not handle the cab-compressed ``.pd_`` variant — Microsoft's
    kernel PDBs on the public server are served uncompressed for years
    now. Falling back to cab-extract would be bloat we don't need yet.

    Streams the response to a ``.part`` file in 64 KiB chunks rather
    than buffering in RAM — kernel PDBs run 25-40 MB, win32k tens of
    MB, large user-mode DLL PDBs into the hundreds. ``resp.read()``
    on small Kali VMs OOM-killed the daemon mid-fetch.

    Validates the final size against ``Content-Length`` (when the
    server provides it) and against ``http.client.IncompleteRead`` so
    a connection drop mid-download can't poison the cache with a
    truncated PDB. ``.part`` files are always cleaned up in a
    ``finally``; only a fully-validated download is renamed into place.
    """
    cache_root.mkdir(parents=True, exist_ok=True)
    dest = pdb_cache_path(ref, cache_root)
    if dest.exists() and dest.stat().st_size > 0:
        return dest

    url = f"{SYMBOL_SERVER}/{ref.pdb_name}/{ref.build_key}/{ref.pdb_name}"
    req = urllib.request.Request(
        url,
        headers={
            # msdl rejects requests without a UA
            "User-Agent": "Microsoft-Symbol-Server/10.0.0.0",
        },
    )
    tmp = dest.with_suffix(dest.suffix + ".part")
    success = False
    try:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                expected = resp.headers.get("Content-Length")
                expected_n = int(expected) if expected and expected.isdigit() else None
                written = 0
                with open(tmp, "wb") as fh:
                    while True:
                        chunk = resp.read(64 * 1024)
                        if not chunk:
                            break
                        fh.write(chunk)
                        written += len(chunk)
            if expected_n is not None and written != expected_n:
                raise PeError(
                    f"truncated PDB from msdl: got {written}/{expected_n} bytes"
                )
            if written == 0:
                raise PeError(f"empty PDB body from msdl for {url}")
        except urllib.error.HTTPError as e:
            raise PeError(
                f"msdl returned HTTP {e.code} for {url} — "
                "symbol not available (wrong build?)"
            ) from e
        except urllib.error.URLError as e:
            raise PeError(f"could not reach msdl: {e.reason}") from e
        except http.client.IncompleteRead as e:
            raise PeError(
                f"connection dropped during PDB fetch from {url}: "
                f"got {len(e.partial)}/{e.expected or '?'} bytes"
            ) from e
        tmp.replace(dest)
        success = True
        return dest
    finally:
        if not success:
            # Don't leave a partial .part lying around: the next call
            # would skip the fetch (dest doesn't exist either, but a
            # future `tmp.replace(dest)` inside another caller's path
            # could trip on a half-written file).
            with suppress(FileNotFoundError):
                tmp.unlink()
