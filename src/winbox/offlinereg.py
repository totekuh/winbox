"""Edit a powered-off VM's registry hives from the host.

Some Windows state cannot be changed from inside the running guest at all.
Defender on Win11 client is the motivating case: once WinDefend has started,
Tamper Protection is enforced by Defender's own kernel components and every
in-guest disable — GP keys, ``Set-MpPreference``, service reconfiguration — is
silently ignored or refused. With the VM shut off none of that is running, and
the hive is just a file inside the disk image.

So the rule for client SKUs is simply: **Defender state changes happen while
the VM is off.** ``winbox setup`` already relied on that; this module is the
same capability made reachable at runtime, so ``winbox av disable`` can undo an
``av enable`` instead of leaving the VM in a state only a rebuild escapes.

Uses ``guestfish`` + ``hivexregedit`` (both from libguestfs-tools) rather than
``virt-customize`` / ``virt-win-reg``, because those auto-inspect the guest OS
and inspection fails on the Win11 image — the installer leaves ``Windows.old``
/ ``$Windows.~BT`` behind, which confuses libguestfs.

**The disk must not be in use.** guestfish opens it read-write; running it
against a live VM risks corruption. :func:`merge_hive` performs no
VM-state check of its own — it only has a disk path, not a domain to
query — so callers are responsible for shutting the VM down first and
confirming it's off before calling in.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

# Hive paths inside the mounted Windows partition.
SYSTEM_HIVE = "/Windows/System32/config/SYSTEM"
SOFTWARE_HIVE = "/Windows/System32/config/SOFTWARE"

# libguestfs needs the direct backend here; the default libvirt backend wants
# to talk to a domain we have deliberately shut down.
_ENV = {"LIBGUESTFS_BACKEND": "direct"}


class OfflineRegistryError(RuntimeError):
    """An offline hive edit could not be completed."""


def _env() -> dict[str, str]:
    return {**os.environ, **_ENV}


def guestfish(disk_path: Path, commands: list[str]) -> None:
    """Run a read-write guestfish script against ``disk_path``.

    ``run`` is prepended automatically; ``commands`` are the statements that
    follow (``mount`` / ``upload`` / ``download`` / ...).
    """
    script = "run\n" + "\n".join(commands) + "\n"
    result = subprocess.run(
        ["guestfish", "--rw", "-a", str(disk_path)],
        input=script, text=True, capture_output=True, env=_env(), check=False,
    )
    if result.returncode != 0:
        msg = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit {result.returncode}"
        )
        raise OfflineRegistryError(f"guestfish failed: {msg}")


def tools_available() -> str | None:
    """Return the name of the first missing tool, or None if both are present."""
    for tool in ("guestfish", "hivexregedit"):
        if shutil.which(tool) is None:
            return tool
    return None


def merge_hive(
    disk_path: Path,
    *,
    hive: str,
    prefix: str,
    reg_body: str,
    win_part: str,
) -> None:
    """Merge a Windows ``.reg`` document into an offline hive.

    Downloads ``hive`` out of ``win_part``, merges ``reg_body`` into it with
    ``hivexregedit`` (a standalone hive edit — no OS inspection), uploads it
    back, and removes the hive's transaction logs so Windows rebuilds them
    rather than replaying stale entries over the edit.

    ``prefix`` is the registry root the ``.reg`` paths are written against,
    e.g. ``HKEY_LOCAL_MACHINE\\SYSTEM``.

    Raises :class:`OfflineRegistryError` on any failure. Unlike the
    best-effort build-time path, a runtime caller has asked for this
    explicitly and needs to know whether it happened.
    """
    missing = tools_available()
    if missing is not None:
        raise OfflineRegistryError(
            f"{missing} not found — install libguestfs-tools. Offline registry "
            f"edits are the only way to change Defender state on a client SKU."
        )

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        local_hive = tmpdir / Path(hive).name
        reg_file = tmpdir / "merge.reg"
        reg_file.write_text(reg_body, encoding="utf-8")

        guestfish(disk_path, [f"mount {win_part} /", f"download {hive} {local_hive}"])
        _require_valid_hive(local_hive, "downloaded")

        merge = subprocess.run(
            ["hivexregedit", "--merge", "--prefix", prefix,
             str(local_hive), str(reg_file)],
            capture_output=True, text=True, check=False,
        )
        if merge.returncode != 0:
            raise OfflineRegistryError(
                f"hivexregedit merge failed: {merge.stderr.strip() or 'unknown error'}"
            )
        # hivexregedit can exit 0 yet leave a truncated/garbage hive. Overwriting
        # the guest's only copy of SYSTEM/SOFTWARE with that — and deleting its
        # transaction logs — BSODs the guest with STATUS_REGISTRY_CORRUPT on
        # next boot, unrecoverable short of a rebuild. Check before we upload.
        _require_valid_hive(local_hive, "merged")

        # Swap the hive in atomically: upload to a sidecar name, drop the logs,
        # then rename over the live hive (rename within the partition is atomic).
        # A kill at any point leaves the original hive intact — before the mv it
        # is untouched; the log removal only makes Windows rebuild them from a
        # consistent hive. The previous "upload straight over the hive, then rm
        # logs" order could leave a half-written hive with its logs already gone.
        staging = f"{hive}.winbox-new"
        guestfish(disk_path, [
            f"mount {win_part} /",
            f"upload {local_hive} {staging}",
            f"rm-f {hive}.LOG1",
            f"rm-f {hive}.LOG2",
            f"mv {staging} {hive}",
        ])


# A Windows registry hive begins with the "regf" magic. A file that doesn't is
# either not a hive or a corrupt/truncated one — either way, unsafe to write
# back over the guest's live hive.
_HIVE_MAGIC = b"regf"


def _require_valid_hive(path: Path, stage: str) -> None:
    """Raise unless ``path`` looks like a real registry hive."""
    try:
        header = path.read_bytes()[:4]
    except OSError as e:
        raise OfflineRegistryError(f"cannot read {stage} hive {path}: {e}") from e
    if header != _HIVE_MAGIC:
        raise OfflineRegistryError(
            f"{stage} hive {path} is not a valid registry hive "
            f"(expected {_HIVE_MAGIC!r} magic, got {header!r}) — refusing to "
            "write it back over the guest's live hive"
        )


def windows_partition(cfg) -> str:
    """The guest's Windows partition device, per the active OS profile.

    ESP=1, MSR=2, Windows=3 on Win11; ESP=1, Windows=2 on Server 2022.
    """
    return f"/dev/sda{cfg.profile.install_partition_id}"
