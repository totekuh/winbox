"""Tests for the symbols.py orchestrator refactor.

Focused on the bits we just added: cached_pdb_path lookup,
ensure_types_loaded lazy extraction, and the shape of LoadedModule.

The PE+PDB pipeline itself is exercised by the existing test_kdbg_pdb
suite — no need to re-mock llvm-pdbutil here.
"""

from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from winbox.kdbg import symbols
from winbox.kdbg.store import SymbolStore
from winbox.kdbg.symbols import (
    SymbolLoadError,
    cached_pdb_path,
    ensure_types_loaded,
)


class TestResolveNtBaseMzGuard:
    """resolve_nt_base derives nt's base from IDT[0] = KiDivideErrorFault. On
    KVA-Shadow/KPTI guests IDT[0] is the KiDivideErrorFaultShadow trampoline, so
    the computed base is wrong; the MZ-header check turns a silently-wrong base
    into a clean failure."""

    RVA = 0x100000
    BASE = 0xFFFFF80000000000  # page-aligned + canonical-high

    def _cfg(self, tmp_path):
        from types import SimpleNamespace
        return SimpleNamespace(vm_name="winbox", symbols_dir=tmp_path)

    def _idt_entry_for(self, handler: int) -> bytes:
        entry = bytearray(16)
        entry[0:2] = (handler & 0xFFFF).to_bytes(2, "little")
        entry[6:8] = ((handler >> 16) & 0xFFFF).to_bytes(2, "little")
        entry[8:12] = ((handler >> 32) & 0xFFFFFFFF).to_bytes(4, "little")
        return bytes(entry)

    def _patch(self, monkeypatch, tmp_path, *, mz: bytes):
        handler = self.BASE + self.RVA
        idt_base = 0xFFFFF78000000000
        kpcr = 0xFFFFF78000100000
        cr3 = 0x12345000
        store = SymbolStore(tmp_path)
        store.save(
            module="nt", build="TEST", image="nt.pdb",
            symbols={"KiDivideErrorFault": self.RVA},
            types={"_KPCR": {
                "size": 0x200,
                "fields": {"IdtBase": {"off": 0x38, "type": "void*"}},
            }},
            base=self.BASE,
        )
        snapshot = type("Snapshot", (), {
            "cr3_candidates": (cr3,), "kernel_gs_bases": (kpcr,),
        })()
        monkeypatch.setattr(symbols, "debug_snapshot", lambda cfg: nullcontext(snapshot))

        def fake_read(vm, read_cr3, va, size, **kwargs):
            assert read_cr3 in (cr3, cr3 ^ 0x1000)
            if va == kpcr + 0x38:
                return idt_base.to_bytes(8, "little")
            if va == idt_base:
                return self._idt_entry_for(handler)
            if va == self.BASE:
                return mz
            raise AssertionError(f"unexpected read at 0x{va:x}")

        monkeypatch.setattr(symbols, "read_virt_cr3", fake_read)

    def test_valid_mz_returns_base(self, monkeypatch, tmp_path):
        from winbox.kdbg.symbols import resolve_nt_base
        self._patch(monkeypatch, tmp_path, mz=b"MZ")
        assert resolve_nt_base(
            self._cfg(tmp_path), {"KiDivideErrorFault": self.RVA},
        ) == self.BASE

    def test_missing_mz_raises_instead_of_returning_wrong_base(self, monkeypatch, tmp_path):
        from winbox.kdbg.symbols import resolve_nt_base
        # Simulates the KPTI case: the page-aligned/canonical checks pass but
        # the base doesn't point at ntoskrnl.
        self._patch(monkeypatch, tmp_path, mz=b"\x00\x00")
        with pytest.raises(SymbolLoadError, match="header"):
            resolve_nt_base(
                self._cfg(tmp_path), {"KiDivideErrorFault": self.RVA},
            )


def _save_nt(store: SymbolStore, build: str = "ABCD1234", types: dict | None = None) -> None:
    store.save(
        module="nt",
        build=build,
        image="ntkrnlmp.pdb",
        symbols={"NtCreateFile": 0x100},
        types=types or {},
        base=None,
    )


# ── cached_pdb_path ─────────────────────────────────────────────────────


def test_cached_pdb_path_returns_existing_file(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store, build="DEAF")
    pdb_file = tmp_path / "ntkrnlmp_DEAF.pdb"
    pdb_file.write_bytes(b"fake pdb bytes")
    assert cached_pdb_path(_FakeCfg(tmp_path), store, "nt") == pdb_file


def test_cached_pdb_path_raises_when_pdb_missing(tmp_path):
    store = SymbolStore(tmp_path)
    _save_nt(store, build="DEAF")
    with pytest.raises(SymbolLoadError, match="cached PDB missing"):
        cached_pdb_path(_FakeCfg(tmp_path), store, "nt")


def test_cached_pdb_path_raises_when_module_metadata_blank(tmp_path):
    store = SymbolStore(tmp_path)
    # Save a record with empty image/build to simulate a corrupted store.
    store.save(
        module="nt", build="", image="",
        symbols={}, types={}, base=None,
    )
    with pytest.raises(SymbolLoadError, match="no image/build metadata"):
        cached_pdb_path(_FakeCfg(tmp_path), store, "nt")


# ── ensure_types_loaded ─────────────────────────────────────────────────


def test_ensure_types_loaded_noop_when_all_present(tmp_path, monkeypatch):
    """If every requested type is already in the store, do not even open
    the PDB — important because callers (walkers) invoke this on every
    request and the no-op path must be cheap."""
    store = SymbolStore(tmp_path)
    _save_nt(store, types={"_PEB": {"size": 0x100, "fields": {}}})

    called = {"n": 0}

    def fake_load_types(*args, **kwargs):
        called["n"] += 1
        return {}

    monkeypatch.setattr(symbols, "load_types", fake_load_types)
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_PEB"])
    assert called["n"] == 0


def test_ensure_types_loaded_extracts_missing_and_persists(tmp_path, monkeypatch):
    store = SymbolStore(tmp_path)
    _save_nt(store, build="BEEF", types={})
    (tmp_path / "ntkrnlmp_BEEF.pdb").write_bytes(b"fake pdb")

    captured: dict = {}

    class FakeLayout:
        def to_json(self):
            return {"size": 0x60, "fields": {"Ldr": {"off": 0x18, "type": ""}}}

    def fake_load_types(pdb_path, wanted):
        captured["pdb_path"] = pdb_path
        captured["wanted"] = list(wanted)
        return {"_PEB": FakeLayout()}

    monkeypatch.setattr(symbols, "load_types", fake_load_types)
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_PEB", "_PEB_LDR_DATA"])

    # Only the missing types were requested.
    assert captured["wanted"] == ["_PEB", "_PEB_LDR_DATA"]
    assert captured["pdb_path"] == tmp_path / "ntkrnlmp_BEEF.pdb"

    # The extracted layout was persisted.
    data = store.load("nt")
    assert "_PEB" in data["types"]
    assert data["types"]["_PEB"]["fields"]["Ldr"]["off"] == 0x18


def test_ensure_types_loaded_partial_extraction_keeps_others(tmp_path, monkeypatch):
    """If the PDB only has some of the requested types, persist what
    came back and don't error — the walker that needed the missing one
    will surface a more specific failure."""
    store = SymbolStore(tmp_path)
    _save_nt(store, build="CAFE", types={})
    (tmp_path / "ntkrnlmp_CAFE.pdb").write_bytes(b"fake pdb")

    class FakeLayout:
        def to_json(self):
            return {"size": 0x40, "fields": {}}

    def fake_load_types(pdb_path, wanted):
        return {"_PEB": FakeLayout()}  # _PEB_LDR_DATA not returned

    monkeypatch.setattr(symbols, "load_types", fake_load_types)
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_PEB", "_PEB_LDR_DATA"])

    data = store.load("nt")
    assert "_PEB" in data["types"]
    assert "_PEB_LDR_DATA" not in data["types"]


def test_ensure_types_loaded_empty_pdb_response_is_silent(tmp_path, monkeypatch):
    """If the PDB doesn't have any of the requested types, no
    persistence happens but no exception either."""
    store = SymbolStore(tmp_path)
    _save_nt(store, build="DEAD", types={})
    (tmp_path / "ntkrnlmp_DEAD.pdb").write_bytes(b"fake pdb")

    monkeypatch.setattr(symbols, "load_types", lambda pdb_path, wanted: {})
    ensure_types_loaded(_FakeCfg(tmp_path), store, ["_NEVER_HEARD_OF_IT"])

    # Store untouched.
    data = store.load("nt")
    assert data["types"] == {}


# ── copy_user_module path traversal (module name is attacker-controlled) ──


def test_copy_via_share_rejects_path_traversal_in_cached_name(tmp_path):
    """cached_name is derived from a live process's PEB.Ldr BaseDllName —
    a hostile sample can spoof that field to a traversal payload. The
    copy must refuse rather than write outside symbols_dir/shared_dir."""

    class _FakeCfgWithShare:
        def __init__(self, root: Path) -> None:
            self.symbols_dir = root / "symbols"
            self.shared_dir = root / "share"

    class _ExplodingGA:
        def exec_powershell(self, *args, **kwargs):
            raise AssertionError("must not reach the VM for a malicious filename")

    cfg = _FakeCfgWithShare(tmp_path)
    with pytest.raises(SymbolLoadError, match="invalid module filename"):
        symbols._copy_via_share(
            cfg, _ExplodingGA(),
            r"C:\Windows\System32\evil.dll",
            "../../../../etc/cron.d/evil",
        )
    assert not (tmp_path / "etc").exists()


class _CopyCfg:
    def __init__(self, root: Path) -> None:
        self.symbols_dir = root / "symbols"
        self.shared_dir = root / "share"


class _ShareGA:
    """Materialise the generated guest destination in the host share."""

    def __init__(self, cfg: _CopyCfg, payload: bytes = b"PE") -> None:
        self.cfg = cfg
        self.payload = payload
        self.scripts: list[str] = []

    def exec_powershell(self, script: str, **_kwargs):
        self.scripts.append(script)
        encoded = re.findall(r"FromBase64String\('([^']+)'\)", script)
        assert len(encoded) == 2
        destination = base64.b64decode(encoded[1]).decode("utf-16-le")
        (self.cfg.shared_dir / destination.rsplit("\\", 1)[-1]).write_bytes(
            self.payload
        )
        return SimpleNamespace(exitcode=0, stdout="", stderr="")


@pytest.mark.parametrize(
    "cached_name",
    ["", ".", "..", r"..\\evil.dll", "/tmp/evil.dll", "bad\0.dll"],
)
def test_copy_via_share_rejects_all_unsafe_cached_names(tmp_path, cached_name):
    cfg = _CopyCfg(tmp_path)
    with pytest.raises(SymbolLoadError, match="invalid module filename"):
        symbols._copy_via_share(cfg, _ShareGA(cfg), r"C:\safe.dll", cached_name)


@pytest.mark.parametrize("source", ["", "bad\0path"])
def test_copy_via_share_rejects_invalid_source_path(tmp_path, source):
    cfg = _CopyCfg(tmp_path)
    with pytest.raises(SymbolLoadError, match="invalid source module path"):
        symbols._copy_via_share(cfg, _ShareGA(cfg), source, "safe.dll")


def test_copy_via_share_treats_hostile_source_as_data(tmp_path):
    cfg = _CopyCfg(tmp_path)
    ga = _ShareGA(cfg, b"trusted-result")
    source = r"C:\Windows\x'; Remove-Item C:\important; #.dll"

    copied = symbols._copy_via_share(cfg, ga, source, "sample.dll")

    assert copied.read_bytes() == b"trusted-result"
    assert source not in ga.scripts[0]
    assert "Copy-Item -LiteralPath $src" in ga.scripts[0]
    assert "-ErrorAction Stop" in ga.scripts[0]
    assert not list(cfg.shared_dir.iterdir())
    assert not list(cfg.symbols_dir.glob("*.part"))


def test_copy_via_share_uses_unique_staging_for_concurrent_same_name(tmp_path):
    cfg = _CopyCfg(tmp_path)
    ga = _ShareGA(cfg, b"same-build")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: symbols._copy_via_share(
                    cfg, ga, r"C:\Windows\System32\same.dll", "same.dll"
                ),
                range(2),
            )
        )

    assert results == [cfg.symbols_dir / "same.dll"] * 2
    assert results[0].read_bytes() == b"same-build"
    destinations = []
    for script in ga.scripts:
        encoded = re.findall(r"FromBase64String\('([^']+)'\)", script)
        destinations.append(base64.b64decode(encoded[1]).decode("utf-16-le"))
    assert len(set(destinations)) == 2
    assert not list(cfg.shared_dir.iterdir())
    assert not list(cfg.symbols_dir.glob("*.part"))


def test_copy_via_share_cleans_staging_and_partial_on_publish_failure(
    tmp_path, monkeypatch
):
    cfg = _CopyCfg(tmp_path)
    ga = _ShareGA(cfg)
    monkeypatch.setattr(symbols.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("full")))

    with pytest.raises(OSError, match="full"):
        symbols._copy_via_share(cfg, ga, r"C:\safe.dll", "safe.dll")

    assert not list(cfg.shared_dir.iterdir())
    assert not list(cfg.symbols_dir.glob("*.part"))


def test_copy_via_share_propagates_powershell_failure_without_artifacts(tmp_path):
    cfg = _CopyCfg(tmp_path)

    class FailingGA:
        def exec_powershell(self, *_args, **_kwargs):
            return SimpleNamespace(exitcode=1, stdout="", stderr="access denied")

    with pytest.raises(SymbolLoadError, match="access denied"):
        symbols._copy_via_share(cfg, FailingGA(), r"C:\safe.dll", "safe.dll")
    assert not list(cfg.shared_dir.iterdir())
    assert not list(cfg.symbols_dir.glob("*.part"))


# ── Helpers ─────────────────────────────────────────────────────────────


class _FakeCfg:
    """Minimal Config stand-in — symbols.py only reads symbols_dir."""

    def __init__(self, root: Path) -> None:
        self.symbols_dir = root


class TestEnsureNtBaseCurrent:
    """ASLR moves the kernel every boot; the symbol store does not.

    Every kernel walk resolves symbols off the cached nt base, so a base left
    over from a previous boot fails deep in the page-table walk as
    "PDPTE not present" — an error that names the layer that noticed, not the
    cause. Only the base moved: every RVA is still correct, so re-pointing it
    is the whole repair.
    """

    class _Store:
        def __init__(self, data, *, set_base_fails=False):
            self._data = data
            self.rebased = []
            self._fails = set_base_fails

        def load(self, module):
            if module not in self._data:
                raise KeyError(module)
            return self._data[module]

        def set_base(self, module, base):
            if self._fails:
                raise OSError("read-only")
            self.rebased.append((module, base))
            self._data[module]["base"] = base

    def _cfg(self):
        class C:
            vm_name = "winbox"
            symbols_dir = "/tmp/nope"
        return C()

    def _patch_live(self, monkeypatch, value):
        import winbox.kdbg.symbols as sym

        def resolver(cfg, syms):
            if isinstance(value, Exception):
                raise value
            return value

        monkeypatch.setattr(sym, "resolve_nt_base", resolver)

    def test_repoints_a_moved_base(self, monkeypatch):
        from winbox.kdbg.symbols import ensure_nt_base_current

        store = self._Store({"nt": {"base": 0xfffff80000000000, "symbols": {"K": 1}}})
        self._patch_live(monkeypatch, 0xfffff80099999000)

        assert ensure_nt_base_current(self._cfg(), store) is True
        assert store.rebased == [("nt", 0xfffff80099999000)]

    def test_leaves_a_current_base_alone(self, monkeypatch):
        from winbox.kdbg.symbols import ensure_nt_base_current

        store = self._Store({"nt": {"base": 0xfffff80000000000, "symbols": {"K": 1}}})
        self._patch_live(monkeypatch, 0xfffff80000000000)

        assert ensure_nt_base_current(self._cfg(), store) is False
        assert store.rebased == []

    def test_no_symbols_means_nothing_to_compare(self, monkeypatch):
        """resolve_nt_base works backwards from the IDT using a symbol RVA."""
        from winbox.kdbg.symbols import ensure_nt_base_current

        store = self._Store({"nt": {"base": 0xfffff80000000000, "symbols": {}}})
        called = []
        monkeypatch.setattr(
            "winbox.kdbg.symbols.resolve_nt_base",
            lambda *a, **k: called.append(1),
        )

        assert ensure_nt_base_current(self._cfg(), store) is False
        assert called == []

    def test_unloaded_nt_is_not_an_error(self):
        from winbox.kdbg.symbols import ensure_nt_base_current

        assert ensure_nt_base_current(self._cfg(), self._Store({})) is False

    def test_a_failed_probe_leaves_the_store_alone(self, monkeypatch):
        """Never raise: the walk should fail the way it always did, not turn
        into a different error from the repair attempt."""
        from winbox.kdbg.symbols import ensure_nt_base_current

        store = self._Store({"nt": {"base": 0xfffff80000000000, "symbols": {"K": 1}}})
        self._patch_live(monkeypatch, RuntimeError("hmp down"))

        assert ensure_nt_base_current(self._cfg(), store) is False
        assert store.rebased == []

    def test_an_unwritable_store_propagates(self, monkeypatch):
        """Distinct from a failed probe: here we know the base is wrong and
        could not fix it, which the caller should see."""
        from winbox.kdbg.symbols import ensure_nt_base_current

        store = self._Store(
            {"nt": {"base": 0xfffff80000000000, "symbols": {"K": 1}}},
            set_base_fails=True,
        )
        self._patch_live(monkeypatch, 0xfffff80099999000)

        with pytest.raises(OSError):
            ensure_nt_base_current(self._cfg(), store)


class TestWalkerEntryPointsHealFirst:
    """The repair has to happen before anything resolves a kernel symbol."""

    def test_daemon_walks_processes_after_gdbstub_connect(self):
        import inspect

        from winbox.kdbg.debugger import daemon

        src = inspect.getsource(daemon.fork_daemon)
        assert "find_process" in src
        assert src.index("RspClient.connect") < src.index("find_process")

    def test_mcp_and_cli_store_accessors_heal(self):
        import inspect

        import winbox.mcp as mcp_mod
        from winbox.cli import kdbg as cli_kdbg

        assert "ensure_nt_base_current" in inspect.getsource(mcp_mod._kdbg_get_store)
        assert "ensure_nt_base_current" in inspect.getsource(cli_kdbg._get_store)
