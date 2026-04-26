"""C++ symbol demangling via ``llvm-undname``.

MS x64 binaries (anything compiled with MSVC) use Microsoft's name
mangling scheme — same one ``UnDecorateSymbolName`` decodes inside
Windows. ``llvm-undname`` is the cross-platform decoder shipped with
LLVM, available on every distro that has the ``llvm`` package.

Why not roll our own: the spec is large, edge-cases are
template-heavy, and we'd ship a maintenance burden. ``llvm-undname``
is faithful to MSVC's output and gets updated upstream.

Caching: a typical session resolves the same handful of symbols many
times (every ``kdbg_bps``, every ``kdbg_bt``). We cache demangled
results in-process per name; the cache is unbounded but bounded in
practice by the symbol set on screen.
"""

from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache


@lru_cache(maxsize=4096)
def demangle(mangled: str) -> str:
    """Return the demangled form of ``mangled``, or the original on failure.

    Never raises. If ``llvm-undname`` is missing or the input doesn't
    look like an MSVC-mangled symbol (no leading ``?``), return as-is.
    Cached to avoid repeated subprocess calls during a session.
    """
    if not mangled or not mangled.startswith("?"):
        return mangled
    if shutil.which("llvm-undname") is None:
        return mangled
    try:
        result = subprocess.run(
            ["llvm-undname"],
            # Trailing newline is required — llvm-undname uses
            # line-buffered stdin and exits silently without one.
            input=(mangled + "\n").encode("utf-8", errors="replace"),
            capture_output=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return mangled
    if result.returncode != 0:
        return mangled
    out = result.stdout.decode("utf-8", errors="replace").strip().splitlines()
    # llvm-undname echoes: <input>\n<demangled>
    # We want the second line; if missing, fall back to original.
    if len(out) >= 2 and out[-1].strip():
        return out[-1].strip()
    return mangled


def pretty_symbol(qualified: str) -> str:
    """Demangle the symbol part of ``module!sym`` while preserving the
    module prefix.

    Examples::

        notepad!?SaveFile@@YA_NPEAUHWND__@@... → notepad!bool SaveFile(...)
        nt!NtCreateFile                       → nt!NtCreateFile (no change)
        plain_va_only                          → plain_va_only

    The module prefix matters for two reasons: (1) it tells the agent
    which symbol store the entry came from, (2) demangling can be
    ambiguous in isolation but the module narrows it.
    """
    if "!" not in qualified:
        return demangle(qualified)
    module, _, sym = qualified.partition("!")
    pretty = demangle(sym)
    if pretty == sym:
        return qualified
    return f"{module}!{pretty}"
