"""Binary copy helpers for extracting PEs from a running VM via VirtIO-FS."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pefile

from winbox.kdbg.pe import read_pdb_ref

if TYPE_CHECKING:
    from winbox.config import Config
    from winbox.vm import GuestAgent


class SymbolLoadError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def _copy_via_share(
    cfg: Config,
    ga: GuestAgent,
    src_in_vm: str,
    cached_name: str,
    *,
    max_file_size: int | None = None,
) -> Path:
    """Copy a file out of the VM via the VirtIO-FS share."""
    if not src_in_vm or "\0" in src_in_vm:
        raise SymbolLoadError("invalid source module path")
    cfg.symbols_dir.mkdir(parents=True, exist_ok=True)
    if (
        not cached_name
        or cached_name in {".", ".."}
        or any(character in cached_name for character in ("/", "\\", "\0"))
    ):
        raise SymbolLoadError(f"invalid module filename: {cached_name!r}")
    cached = cfg.symbols_dir / cached_name
    if not cached.resolve().is_relative_to(cfg.symbols_dir.resolve()):
        raise SymbolLoadError(f"invalid module filename: {cached_name!r}")

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(16)
    suffix = Path(cached_name).suffix
    if len(suffix) > 16 or any(not (c.isalnum() or c == ".") for c in suffix):
        suffix = ".bin"
    staging_name = f"winbox-kdbg-{token}{suffix}"
    staging = cfg.shared_dir / staging_name
    src_basename = src_in_vm.rsplit("\\", 1)[-1]
    staging_in_vm = f"Z:\\{staging_name}"

    def encoded_path(value: str) -> str:
        return base64.b64encode(value.encode("utf-16-le")).decode("ascii")

    src_encoded = encoded_path(src_in_vm)
    dst_encoded = encoded_path(staging_in_vm)
    script = (
        "$src=[Text.Encoding]::Unicode.GetString("
        f"[Convert]::FromBase64String('{src_encoded}'))\n"
        "$dst=[Text.Encoding]::Unicode.GetString("
        f"[Convert]::FromBase64String('{dst_encoded}'))\n"
        "Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop"
    )
    temporary = cfg.symbols_dir / f".{cached_name}.{token}.part"

    try:
        result = ga.exec_powershell(script, timeout=60)
        if result.exitcode != 0:
            raise SymbolLoadError(
                f"Copy-Item {src_basename} failed: {result.stderr or result.stdout}"
            )
        if not staging.exists():
            raise SymbolLoadError(
                f"{src_basename} did not appear on the share after Copy-Item"
            )
        staged_size = staging.stat().st_size
        if max_file_size is not None and staged_size > max_file_size:
            raise SymbolLoadError(
                f"{src_basename} is {staged_size} bytes; attach staging cap is "
                f"{max_file_size} bytes"
            )
        shutil.copyfile(staging, temporary)
        os.chmod(temporary, 0o600)
        content_sha = _sha256(temporary)
        try:
            build = read_pdb_ref(temporary).build_key
            published_key = f"{build}_{content_sha}"
        except Exception:
            published_key = content_sha
        module_dir = cfg.symbols_dir / "pe" / cached_name.lower()
        module_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(module_dir, 0o700)
        cached = module_dir / f"{published_key}{suffix.lower()}"
        os.replace(temporary, cached)
    finally:
        staging.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)

    return cached


def copy_ntoskrnl(cfg: Config, ga: GuestAgent) -> Path:
    """Copy ``C:\\Windows\\System32\\ntoskrnl.exe`` into the symbol cache."""
    return _copy_via_share(cfg, ga, r"C:\Windows\System32\ntoskrnl.exe", "ntoskrnl.exe")


def copy_user_module(
    cfg: Config,
    ga: GuestAgent,
    vm_path: str,
    cached_name: str,
    *,
    architecture: str = "auto",
    expected_size: int | None = None,
    max_file_size: int | None = None,
) -> Path:
    """Copy any user-mode binary out of the VM into the symbol cache."""
    if architecture not in {"auto", "x86", "x64"}:
        raise SymbolLoadError(f"unsupported module architecture: {architecture!r}")

    candidates = [vm_path]
    if architecture == "x86":
        redirected = re.sub(
            r"(?i)(\\windows\\)system32(?=\\)",
            r"\1SysWOW64",
            vm_path,
            count=1,
        )
        if redirected != vm_path:
            candidates.insert(0, redirected)

    expected_machine = {"x86": 0x014C, "x64": 0x8664}.get(architecture)
    failures: list[str] = []
    for candidate in candidates:
        try:
            copy_kwargs = (
                {"max_file_size": max_file_size}
                if max_file_size is not None else {}
            )
            copied = _copy_via_share(
                cfg, ga, candidate, cached_name, **copy_kwargs,
            )
            pe = None
            try:
                pe = pefile.PE(str(copied), fast_load=True)
                machine = int(pe.FILE_HEADER.Machine)
                image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
            except (OSError, pefile.PEFormatError, AttributeError) as exc:
                raise SymbolLoadError(
                    f"copied module is not a valid PE: {exc}"
                ) from exc
            finally:
                if pe is not None:
                    pe.close()
            if expected_machine is not None and machine != expected_machine:
                raise SymbolLoadError(
                    f"copied {candidate} has PE machine 0x{machine:04x}; "
                    f"expected {architecture} (0x{expected_machine:04x})"
                )
            if expected_size is not None and image_size != expected_size:
                raise SymbolLoadError(
                    f"copied {candidate} has SizeOfImage 0x{image_size:x}; "
                    f"live loader reports 0x{expected_size:x}"
                )
            return copied
        except SymbolLoadError as exc:
            failures.append(str(exc))
    raise SymbolLoadError("; ".join(failures))
