"""Tests for the C++ symbol demangling helper.

Most paths are smoke tests since the actual demangling work is done
by ``llvm-undname`` (a subprocess). We verify graceful behaviour on
edge cases plus the round-trip on a couple of canonical mangled names.
"""

from __future__ import annotations

import shutil
from unittest.mock import patch

import pytest

from winbox.kdbg.demangle import demangle, pretty_symbol


# ── inputs that should pass through unchanged ──────────────────────────


def test_demangle_empty_string_returns_empty():
    assert demangle("") == ""


def test_demangle_unmangled_symbol_passes_through():
    """Names not starting with '?' aren't MS-mangled — return as-is
    rather than burn a subprocess call."""
    # Clear cache from any prior tests
    demangle.cache_clear()
    with patch("subprocess.run") as fake_run:
        result = demangle("NtCreateFile")
        assert result == "NtCreateFile"
        fake_run.assert_not_called()


def test_demangle_handles_missing_llvm_undname():
    """If llvm-undname isn't installed, return the input unchanged."""
    demangle.cache_clear()
    with patch("shutil.which", return_value=None):
        assert demangle("?SaveFile@@YA_NPEAUHWND__@@_NPEBG@Z") == \
            "?SaveFile@@YA_NPEAUHWND__@@_NPEBG@Z"


def test_demangle_handles_subprocess_timeout():
    demangle.cache_clear()
    import subprocess as _sp
    with patch("shutil.which", return_value="/usr/bin/llvm-undname"), \
         patch("subprocess.run", side_effect=_sp.TimeoutExpired("llvm-undname", 5)):
        assert demangle("?Foo@@YAHXZ") == "?Foo@@YAHXZ"


def _fake_undname(stdout: str):
    from unittest.mock import MagicMock
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = stdout.encode("utf-8")
    return proc


def test_demangle_two_line_echo_output():
    """The normal case: llvm-undname echoes the input then the decoded name."""
    demangle.cache_clear()
    with patch("shutil.which", return_value="/usr/bin/llvm-undname"), \
         patch("subprocess.run", return_value=_fake_undname(
             "?Foo@@YAHXZ\nint __cdecl Foo(void)\n")):
        assert demangle("?Foo@@YAHXZ") == "int __cdecl Foo(void)"


def test_demangle_single_line_output_still_decodes():
    """A build/mode that prints ONLY the decoded name (no input echo) must
    still be used — the old len>=2 guard returned the raw mangling here."""
    demangle.cache_clear()
    with patch("shutil.which", return_value="/usr/bin/llvm-undname"), \
         patch("subprocess.run", return_value=_fake_undname(
             "int __cdecl Foo(void)\n")):
        assert demangle("?Foo@@YAHXZ") == "int __cdecl Foo(void)"


def test_demangle_echo_only_no_decode_falls_back():
    """If the only output equals the input (no decode happened), return the
    original rather than a bogus 'decoded' value."""
    demangle.cache_clear()
    with patch("shutil.which", return_value="/usr/bin/llvm-undname"), \
         patch("subprocess.run", return_value=_fake_undname("?Foo@@YAHXZ\n")):
        assert demangle("?Foo@@YAHXZ") == "?Foo@@YAHXZ"


# ── pretty_symbol module-prefix handling ───────────────────────────────


def test_pretty_symbol_keeps_module_prefix():
    """Module prefix is preserved; only the symbol part is demangled."""
    if shutil.which("llvm-undname") is None:
        pytest.skip("llvm-undname not available on this host")
    out = pretty_symbol("notepad!?SaveFile@@YA_NPEAUHWND__@@_NPEBG@Z")
    assert out.startswith("notepad!")
    assert "SaveFile" in out
    assert "?SaveFile" not in out  # demangled


def test_pretty_symbol_no_module_demangles_directly():
    if shutil.which("llvm-undname") is None:
        pytest.skip("llvm-undname not available on this host")
    out = pretty_symbol("?NtCreateFile@@YAHXZ")
    # Should be demangled but no module prefix added
    assert "!" not in out  # no module
    assert "NtCreateFile" in out


def test_pretty_symbol_unmangled_with_module_unchanged():
    """If the symbol part isn't mangled, we don't waste cycles
    trying to demangle and don't change the output."""
    out = pretty_symbol("nt!NtCreateFile")
    assert out == "nt!NtCreateFile"


# ── live demangling (skip if llvm-undname missing) ─────────────────────


def test_demangle_live_savefile():
    if shutil.which("llvm-undname") is None:
        pytest.skip("llvm-undname not available on this host")
    demangle.cache_clear()
    out = demangle("?SaveFile@@YA_NPEAUHWND__@@_NPEBG@Z")
    # Some core elements we expect from the demangled output
    assert "SaveFile" in out
    assert "bool" in out  # _N return type
    assert "HWND" in out
    assert "(" in out  # has parameter list


def test_demangle_caches_result():
    """Second call hits the lru_cache — verifiable by mocking subprocess."""
    if shutil.which("llvm-undname") is None:
        pytest.skip("llvm-undname not available on this host")
    demangle.cache_clear()
    name = "?Foo123@@YAHXZ"
    # First call — let it through to subprocess
    first = demangle(name)
    # Second call — patch subprocess; should not be invoked
    with patch("subprocess.run") as fake_run:
        second = demangle(name)
    assert first == second
    fake_run.assert_not_called()
