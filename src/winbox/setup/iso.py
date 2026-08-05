"""Windows Evaluation ISO downloader (Server 2022 / Windows 11).

The specific ISO — URL, filename, and truncation floor — comes from the
active :class:`~winbox.osprofile.OSProfile` (``cfg.profile``). The
module-level constants below mirror the Server 2022 profile so existing
callers and tests that import them keep working.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from winbox.osprofile import OS_PROFILES
from winbox.utils import human_size

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

# Server 2022 profile values, re-exported for callers/tests that import
# them directly. The download path itself is profile-driven (see
# `download_iso`), so Win11 builds don't touch these.
EVAL_REDIRECT_URL = OS_PROFILES["server2022"].iso_url
ISO_FILENAME = OS_PROFILES["server2022"].iso_filename


def resolve_download_url(redirect_url: str = EVAL_REDIRECT_URL) -> str:
    """Follow the Microsoft redirect chain to get the direct CDN URL.

    Returns the final URL after all redirects.
    """
    req = urllib.request.Request(redirect_url, method="HEAD")
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) winbox/0.1",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return resp.url
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to resolve download URL: {e}") from e


def get_remote_size(url: str) -> int | None:
    """Get the Content-Length of a remote file, or None if unavailable."""
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "winbox/0.1")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        length = resp.headers.get("Content-Length")
        return int(length) if length else None
    except (urllib.error.URLError, ValueError):
        return None


def download_iso(
    cfg: Config,
    *,
    force: bool = False,
) -> Path:
    """Download the active profile's Windows Evaluation ISO.

    Downloads to ~/.winbox/iso/<profile filename> with resume support and a
    progress bar. Returns the path to the downloaded ISO. The URL, filename,
    and truncation floor all come from ``cfg.profile``.
    """
    profile = cfg.profile
    cfg.iso_dir.mkdir(parents=True, exist_ok=True)
    dest = cfg.iso_dir / profile.iso_filename
    url: str | None = None

    # Already downloaded?
    if dest.exists() and not force:
        remote_size = None
        try:
            console.print("[blue][*][/] Resolving download URL...")
            url = resolve_download_url(profile.iso_url)
            remote_size = get_remote_size(url)
        except RuntimeError:
            pass

        local_size = dest.stat().st_size
        if remote_size and local_size == remote_size:
            console.print(f"[green][+][/] ISO already downloaded: {dest}")
            return dest
        elif remote_size and local_size < remote_size:
            console.print(
                f"[yellow][!][/] Partial download detected "
                f"({human_size(local_size)} / {human_size(remote_size)}), resuming..."
            )
        elif remote_size and local_size > remote_size:
            raise RuntimeError(
                f"Local ISO ({human_size(local_size)}) is larger than remote "
                f"({human_size(remote_size)}). Delete {dest} and re-download, "
                f"or use --force."
            )
        elif not remote_size and local_size >= profile.iso_min_size:
            # Can't verify size against remote, but the eval ISO is several
            # GB; anything below the profile floor is a partial that previous
            # ">1GB" leniency would have happily reused.
            console.print(f"[green][+][/] ISO already downloaded: {dest}")
            return dest

    # Resolve URL if we haven't already
    if url is None:
        console.print("[blue][*][/] Resolving download URL...")
        url = resolve_download_url(profile.iso_url)

    console.print(f"[blue][*][/] Downloading from Microsoft CDN...")

    total_size = get_remote_size(url)
    existing_size = dest.stat().st_size if dest.exists() else 0

    # Build request with Range header for resume
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "winbox/0.1")
    if existing_size > 0 and total_size and existing_size < total_size:
        req.add_header("Range", f"bytes={existing_size}-")
        mode = "ab"  # append
    else:
        existing_size = 0
        mode = "wb"

    # Bound chunked reads so a stalled stream can't hang indefinitely.
    # Setting it on the response's underlying socket directly, rather than
    # via socket.setdefaulttimeout(), so we don't inherit the timeout on
    # any unrelated network ops running in the same process.
    READ_TIMEOUT = 60
    try:
        resp = urllib.request.urlopen(req, timeout=READ_TIMEOUT)
    except urllib.error.URLError as e:
        raise RuntimeError(f"Download failed: {e}") from e

    # Pin the timeout on the actual socket carrying the body, in case the
    # urlopen-level timeout doesn't propagate to subsequent recv() calls
    # (varies by Python version / proxy setup).
    try:
        resp.fp._sock.settimeout(READ_TIMEOUT)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

    # If we requested a Range but server returned 200 (not 206), it sent
    # the full file — switch to overwrite mode to avoid doubling content.
    if existing_size > 0 and resp.status == 200:
        mode = "wb"
        existing_size = 0

    try:
        # Determine total for progress bar
        content_length = resp.headers.get("Content-Length")
        if content_length:
            download_size = int(content_length)
        elif total_size:
            download_size = total_size - existing_size
        else:
            download_size = 0

        progress_total = existing_size + download_size if download_size else None

        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                profile.iso_filename,
                total=progress_total,
                completed=existing_size,
            )

            chunk_size = 1024 * 1024  # 1MB chunks
            with open(dest, mode) as f:
                while True:
                    try:
                        chunk = resp.read(chunk_size)
                    except (socket.timeout, TimeoutError) as e:
                        raise RuntimeError(
                            f"Download stalled (no data for >{READ_TIMEOUT}s). "
                            f"Re-run to resume. {e}"
                        ) from e
                    if not chunk:
                        break
                    f.write(chunk)
                    progress.update(task, advance=len(chunk))
    finally:
        resp.close()

    final_size = dest.stat().st_size
    # Sanity check against the profile's expected minimum ISO size.
    if final_size < profile.iso_min_size:
        raise RuntimeError(
            f"Downloaded ISO appears truncated ({human_size(final_size)}). "
            f"Delete {dest} and retry."
        )
    console.print(f"[green][+][/] Downloaded: {dest} ({human_size(final_size)})")
    return dest
