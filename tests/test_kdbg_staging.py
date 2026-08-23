"""Unit coverage for immutable pre-attach user artifact manifests."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from winbox.kdbg import staging


class FakeCfg:
    vm_name = "winbox"


def module(name, architecture, base, size, path):
    return SimpleNamespace(
        name=name, architecture=architecture, base=base, size=size,
        full_path=path,
    )


def install_inventory(monkeypatch, modules):
    monkeypatch.setattr(staging, "ensure_types_loaded", lambda *_a, **_k: None)
    monkeypatch.setattr(staging, "debug_snapshot", lambda _cfg: nullcontext())
    monkeypatch.setattr(staging, "find_process", lambda *_a, **_k: object())
    monkeypatch.setattr(staging, "list_user_modules", lambda *_a, **_k: modules)


def test_prepare_manifest_stages_exact_pe_and_enriches_missing_symbols(
    tmp_path, monkeypatch,
):
    modules = [
        module("app.exe", "x64", 0x140000000, 0x5000, r"C:\app.exe"),
        module("ntdll.dll", "x86", 0x77000000, 0x20000,
               r"C:\Windows\System32\ntdll.dll"),
    ]
    install_inventory(monkeypatch, modules)
    app = tmp_path / "app.exe"
    ntdll = tmp_path / "ntdll.dll"
    app.write_bytes(b"app")
    ntdll.write_bytes(b"ntdll")
    paths = iter((app, ntdll))
    monkeypatch.setattr(staging, "copy_user_module", lambda *_a, **_k: next(paths))
    monkeypatch.setattr(staging, "_sha256", lambda path: path.name + "-sha")
    monkeypatch.setattr(
        staging, "read_pdb_ref",
        lambda path: SimpleNamespace(build_key=path.name + "-build"),
    )
    monkeypatch.setattr(staging, "_matching_store_build", lambda *_a: None)
    loaded = []

    def load(*_a, **kwargs):
        loaded.append(kwargs)
        return SimpleNamespace(build=kwargs["pe_path"].name + "-build")

    monkeypatch.setattr(staging, "load_module", load)
    manifest = staging.prepare_user_module_manifest(
        FakeCfg(), object(), object(), 1234,
    )

    assert [item.store_name for item in manifest.modules] == ["app", "ntdll_x86"]
    assert [item.store_build for item in manifest.modules] == [
        "app.exe-build", "ntdll.dll-build",
    ]
    assert len(loaded) == 2
    assert manifest.summary()["staged"] == 2
    assert manifest.summary()["discovered"] == 2
    assert manifest.summary()["symbol_enriched"] == 2
    assert manifest.by_base(0x77000000, "x86").name == "ntdll.dll"


def test_prepare_manifest_keeps_exact_pe_when_pdb_enrichment_fails(
    tmp_path, monkeypatch,
):
    modules = [module("third.dll", "x64", 0x180000000, 0x3000, r"C:\third.dll")]
    install_inventory(monkeypatch, modules)
    path = tmp_path / "third.dll"
    path.write_bytes(b"third-party")
    monkeypatch.setattr(staging, "copy_user_module", lambda *_a, **_k: path)
    monkeypatch.setattr(staging, "_sha256", lambda _p: "f" * 64)
    monkeypatch.setattr(
        staging, "read_pdb_ref", lambda _p: SimpleNamespace(build_key="BUILD"),
    )
    monkeypatch.setattr(staging, "_matching_store_build", lambda *_a: None)
    monkeypatch.setattr(
        staging, "load_module", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("404")),
    )

    manifest = staging.prepare_user_module_manifest(FakeCfg(), object(), object(), 7)

    assert len(manifest.modules) == 1
    assert manifest.modules[0].store_build is None
    assert "404" in manifest.modules[0].symbol_error
    assert manifest.summary()["symbol_failed"] == 1
    assert "third.dll@x64" in manifest.summary()["symbol_failures"][0]
    assert manifest.failures == ()


def test_prepare_manifest_isolates_individual_copy_failure(tmp_path, monkeypatch):
    modules = [
        module("bad.dll", "x64", 0x180000000, 0x3000, r"C:\bad.dll"),
        module("good.dll", "x64", 0x180010000, 0x3000, r"C:\good.dll"),
    ]
    install_inventory(monkeypatch, modules)
    good = tmp_path / "good.dll"
    good.write_bytes(b"good")

    def copy(_cfg, _ga, _path, name, **_kwargs):
        if name == "bad.dll":
            raise RuntimeError("denied")
        return good

    monkeypatch.setattr(staging, "copy_user_module", copy)
    monkeypatch.setattr(staging, "_sha256", lambda _p: "a" * 64)
    monkeypatch.setattr(staging, "read_pdb_ref", lambda _p: (_ for _ in ()).throw(staging.PeError("none")))
    monkeypatch.setattr(staging, "_matching_store_build", lambda *_a: None)

    manifest = staging.prepare_user_module_manifest(FakeCfg(), object(), object(), 8)

    assert [item.name for item in manifest.modules] == ["good.dll"]
    assert [item.name for item in manifest.loader_modules()] == ["bad.dll", "good.dll"]
    assert manifest.summary()["discovered"] == 2
    assert len(manifest.failures) == 1
    assert "bad.dll@x64" in manifest.failures[0]


@pytest.mark.parametrize(
    "modules,message",
    [
        ([module("a", "arm64", 1, 1, "a")], "architecture"),
        ([module("a", "x64", 0, 1, "a")], "base/size"),
        ([module("a", "x86", 0xFFFFF000, 0x2000, "a")], "uint32"),
        ([module("a", "x64", 1, staging.MAX_MODULE_IMAGE_SIZE + 1, "a")], "image size"),
    ],
)
def test_prepare_manifest_rejects_corrupt_or_unbounded_inventory(
    monkeypatch, modules, message,
):
    install_inventory(monkeypatch, modules)
    with pytest.raises(staging.StagingError, match=message):
        staging.prepare_user_module_manifest(FakeCfg(), object(), object(), 9)


def test_manifest_by_base_refuses_ambiguous_identity():
    item = staging.StagedUserModule(
        "a.dll", "C:\\a.dll", "x64", 0x1000, 0x1000,
        "/tmp/a", "a" * 64, "a",
    )
    manifest = staging.UserModuleManifest(1, (item, item))
    assert manifest.by_base(0x1000, "x64") is None


def test_cached_symbol_rebase_failure_keeps_exact_artifact(tmp_path, monkeypatch):
    modules = [module("same.dll", "x64", 0x180000000, 0x3000, r"C:\same.dll")]
    install_inventory(monkeypatch, modules)
    path = tmp_path / "same.dll"
    path.write_bytes(b"same")
    monkeypatch.setattr(staging, "copy_user_module", lambda *_a, **_k: path)
    monkeypatch.setattr(staging, "_sha256", lambda _p: "b" * 64)
    monkeypatch.setattr(
        staging, "read_pdb_ref", lambda _p: SimpleNamespace(build_key="BUILD"),
    )
    monkeypatch.setattr(staging, "_matching_store_build", lambda *_a: "BUILD")
    store = SimpleNamespace(
        set_base=lambda *_a: (_ for _ in ()).throw(OSError("read-only index")),
    )

    manifest = staging.prepare_user_module_manifest(FakeCfg(), object(), store, 10)

    assert manifest.modules[0].store_build == "BUILD"
    assert "read-only index" in manifest.modules[0].symbol_error
    assert manifest.summary()["symbol_failed"] == 0
    assert manifest.summary()["symbol_warning_count"] == 1


def test_failure_details_are_bounded_but_count_is_exact(monkeypatch):
    modules = [
        module(f"m{index}.dll", "x64", 0x180000000 + index * 0x10000,
               0x3000, rf"C:\m{index}.dll")
        for index in range(staging.MAX_FAILURES + 6)
    ]
    install_inventory(monkeypatch, modules)
    monkeypatch.setattr(
        staging, "copy_user_module",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("denied")),
    )

    manifest = staging.prepare_user_module_manifest(FakeCfg(), object(), object(), 11)

    assert manifest.summary()["failed"] == staging.MAX_FAILURES + 6
    assert len(manifest.summary()["failures"]) == 16
    assert len(manifest.failures) == staging.MAX_FAILURES


def test_inventory_failure_and_invalid_pid_are_staging_errors(monkeypatch):
    monkeypatch.setattr(staging, "ensure_types_loaded", lambda *_a, **_k: None)
    monkeypatch.setattr(staging, "debug_snapshot", lambda _cfg: nullcontext())
    monkeypatch.setattr(
        staging, "find_process",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("bad list")),
    )
    with pytest.raises(staging.StagingError, match="loader inventory"):
        staging.prepare_user_module_manifest(FakeCfg(), object(), object(), 12)
    with pytest.raises(staging.StagingError, match="pid must"):
        staging.prepare_user_module_manifest(FakeCfg(), object(), object(), object())


def test_manifest_error_text_is_bounded(tmp_path, monkeypatch):
    modules = [module("bad.dll", "x64", 0x180000000, 0x3000, r"C:\bad.dll")]
    install_inventory(monkeypatch, modules)
    monkeypatch.setattr(
        staging, "copy_user_module",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("x" * 2000)),
    )
    manifest = staging.prepare_user_module_manifest(FakeCfg(), object(), object(), 13)
    assert len(manifest.failures[0]) < 600
