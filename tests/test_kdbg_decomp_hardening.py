from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.cache import cache_inventory, prune_cache, repair_cache
from winbox.kdbg.decomp.client import (
    DecompClient,
    DecompError,
    maintenance_lock,
    maintenance_lock_path,
    open_program_limit,
    WORKER_API,
)
from winbox.kdbg.decomp.docker import DockerManager, project_dir
from winbox.kdbg.decomp.identity import PeIdentity
from winbox.kdbg.decomp.service import _format_instruction, _resolve_verified_binary, _snapshot_binary
from winbox.kdbg.decomp.worker import Worker, WorkerError, _read_request, _recover_function
from winbox.kdbg.pdb import parse_publics_metadata


def test_request_protocol_requires_and_preserves_correlation_id():
    left, right = socket.socketpair()
    try:
        right.sendall(b'{"request_id":"abc123","op":"status","args":{}}\n')
        assert _read_request(left)["request_id"] == "abc123"
    finally:
        left.close()
        right.close()


def test_request_protocol_rejects_missing_or_nonhex_id():
    for raw in (b'{"op":"status","args":{}}\n', b'{"request_id":"XYZ","op":"status","args":{}}\n'):
        left, right = socket.socketpair()
        try:
            right.sendall(raw)
            with pytest.raises(WorkerError, match="request_id"):
                _read_request(left)
        finally:
            left.close()
            right.close()


def test_client_timeout_leaves_bounded_cancellation_marker(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    client = DecompClient(cfg)
    monkeypatch.setattr(client, "worker_alive", lambda: True)
    monkeypatch.setattr(client, "active_backend", lambda: "docker")
    monkeypatch.setattr(client, "active_worker_api", lambda: WORKER_API)
    monkeypatch.setattr(client, "_stage_binary", lambda *_: "/cache/binaries/x.exe")
    monkeypatch.setattr(client, "_exchange", lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("late")))
    with pytest.raises(DecompError, match="communication failed"):
        client.call("decompile", binary="x.exe", sha256="a" * 64)
    markers = list((tmp_path / "decomp" / "cache" / "cancel").iterdir())
    assert len(markers) == 1 and len(markers[0].name) == 32


def test_open_program_limit_is_configurable_and_bounded(monkeypatch):
    monkeypatch.setenv("WINBOX_GHIDRA_OPEN_PROGRAMS", "4")
    assert open_program_limit() == 4
    monkeypatch.setenv("WINBOX_GHIDRA_OPEN_PROGRAMS", "5")
    with pytest.raises(DecompError, match="between 1 and 4"):
        open_program_limit()


def test_snapshot_is_content_addressed_and_immutable(tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    source = tmp_path / "x.exe"
    source.write_bytes(b"first")
    first = _snapshot_binary(cfg, source)
    source.write_bytes(b"second")
    second = _snapshot_binary(cfg, source)
    assert first != second
    assert first.read_bytes() == b"first"
    assert first.stem == hashlib.sha256(b"first").hexdigest()


def test_same_name_candidates_select_live_build(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    wrong, right = tmp_path / "same.exe", tmp_path / "other" / "same.exe"
    right.parent.mkdir()
    wrong.write_bytes(b"wrong")
    right.write_bytes(b"right")
    monkeypatch.setattr(
        "winbox.kdbg.decomp.service._binary_candidates", lambda *_: [wrong, right],
    )
    def parse(path):
        timestamp = 2 if path.read_bytes() == b"right" else 1
        return PeIdentity(0x8664, timestamp, 0x3000, 0x140000000, None,
                          sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr("winbox.kdbg.decomp.service.parse_static_pe", parse)
    live = PeIdentity(0x8664, 2, 0x3000, 0x140000000, None)
    selected, _, confidence = _resolve_verified_binary(
        cfg, "same.exe", "", live, 0x3000,
    )
    assert selected.read_bytes() == b"right"
    assert confidence == "pe-headers"


def test_external_ghidra_flow_does_not_become_negative_rva():
    value = _format_instruction(
        {"address": "0x140001000", "text": "CALL [import]", "flow_targets": ["0x15"]},
        0x140000000, 0x7FF600000000,
    )
    assert "flow_targets" not in value


def test_cache_inventory_and_dry_run_then_apply(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    root = tmp_path / "state" / "decomp" / "cache"
    digest = "a" * 64
    (root / "binaries").mkdir(parents=True)
    (root / "metadata").mkdir()
    (root / "binaries" / f"{digest}.exe").write_bytes(b"1234")
    (root / "metadata" / f"{digest}.json").write_text(json.dumps({
        "sha256": digest, "binary_name": "x.exe", "project_name": "safe_project",
        "last_used": time.time() - 10 * 86400,
    }))
    inventory = cache_inventory(cfg)
    assert inventory["entry_count"] == 1
    preview = prune_cache(cfg, older_than_days=1, dry_run=True)
    assert preview["selected_count"] == 1 and preview["removed_count"] == 0
    monkeypatch.setattr(DecompClient, "worker_alive", lambda self: False)
    applied = prune_cache(cfg, older_than_days=1, dry_run=False)
    assert applied["removed_count"] == 1
    assert not (root / "binaries" / f"{digest}.exe").exists()


def test_cache_apply_refuses_live_worker(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    root = tmp_path / "decomp" / "cache"
    (root / "binaries").mkdir(parents=True)
    (root / "metadata").mkdir()
    digest = "b" * 64
    (root / "binaries" / f"{digest}.exe").write_bytes(b"x")
    (root / "metadata" / f"{digest}.json").write_text(json.dumps({
        "sha256": digest, "project_name": "p_safe", "last_used": 1,
    }))
    monkeypatch.setattr(DecompClient, "worker_alive", lambda self: True)
    with pytest.raises(DecompError, match="stop the Ghidra worker"):
        prune_cache(cfg, older_than_days=1, dry_run=False)
    assert (root / "binaries" / f"{digest}.exe").exists()


def _two_entry_cache(tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    root = tmp_path / "state" / "decomp" / "cache"
    projects = project_dir(cfg)
    (root / "binaries").mkdir(parents=True)
    (root / "metadata").mkdir()
    projects.mkdir(parents=True)
    entries = [
        ("a" * 64, "Alpha.DLL", "project_alpha", b"alpha"),
        ("b" * 64, "beta.exe", "project_beta", b"beta-data"),
    ]
    for digest, module, project, payload in entries:
        (root / "binaries" / f"{digest}.exe").write_bytes(payload)
        (root / "metadata" / f"{digest}.json").write_text(json.dumps({
            "sha256": digest, "binary_name": module, "project_name": project,
            "last_used": time.time(),
        }), encoding="utf-8")
        (projects / f"{project}.gpr").write_bytes(b"project")
    (root / "logs").mkdir()
    (root / "logs" / "worker.log").write_bytes(b"unowned-overhead")
    return cfg, root, projects, entries


def test_cache_inventory_reconciles_owned_overhead_and_unattributed(tmp_path):
    cfg, root, _projects, _entries = _two_entry_cache(tmp_path)

    inventory = cache_inventory(cfg)

    assert inventory["entry_count"] == 2
    assert inventory["owned_bytes"] + inventory["overhead_bytes"] == inventory["total_bytes"]
    assert inventory["overhead_bytes"] == len(b"unowned-overhead")
    assert inventory["unattributed_bytes"] == inventory["overhead_bytes"]
    assert inventory["unattributed_files"] == [{
        "root": "cache", "path": "logs/worker.log",
        "size_bytes": len(b"unowned-overhead"),
    }]
    assert all(not item["path"].startswith("/") for item in inventory["unattributed_files"])
    assert root.as_posix() not in json.dumps(inventory["unattributed_files"])


def test_enrichment_sidecars_are_digest_owned_and_exactly_pruned(monkeypatch, tmp_path):
    cfg, root, _projects, entries = _two_entry_cache(tmp_path)
    digest = entries[0][0]
    owned = []
    for directory in ("enrichment", "enrichment-results"):
        path = root / directory / f"profile_{digest}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(directory.encode())
        owned.append(path)
    unrelated = root / "enrichment" / f"profile_{'b' * 64}.json"
    unrelated.write_bytes(b"keep")

    inventory = cache_inventory(cfg)
    entry = next(item for item in inventory["entries"] if item["sha256"] == digest)
    assert any(item["sha256"] == "b" * 64 for item in inventory["entries"])
    assert entry["size_bytes"] >= sum(path.stat().st_size for path in owned)
    assert not any(
        digest in item["path"] for item in inventory["unattributed_files"]
    )

    monkeypatch.setattr(DecompClient, "worker_alive", lambda _self: False)
    result = prune_cache(cfg, sha256=digest, dry_run=False)
    assert result["removed_count"] == 1
    assert all(not path.exists() for path in owned)
    assert unrelated.read_bytes() == b"keep"


def test_cache_inventory_tolerates_nonfinite_or_malformed_lru_metadata(tmp_path):
    cfg, root, _projects, _entries = _two_entry_cache(tmp_path)
    for digest, value in (("a" * 64, "not-a-time"), ("b" * 64, "NaN")):
        path = root / "metadata" / f"{digest}.json"
        metadata = json.loads(path.read_text(encoding="utf-8"))
        metadata["last_used"] = value
        path.write_text(json.dumps(metadata), encoding="utf-8")
    inventory = cache_inventory(cfg)
    assert inventory["entry_count"] == 2
    assert all(entry["last_used"] is None for entry in inventory["entries"])


def test_unattributed_inventory_is_bounded_and_ignores_symlink_targets(tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    overhead = tmp_path / "state" / "decomp" / "cache" / "overhead"
    overhead.mkdir(parents=True)
    for index in range(105):
        (overhead / f"file-{index:03d}").write_bytes(b"x")
    (overhead / "escape").symlink_to("/etc/passwd")

    inventory = cache_inventory(cfg)

    assert inventory["unattributed_file_count"] == 105
    assert len(inventory["unattributed_files"]) == 100
    assert inventory["unattributed_truncated"] is True
    assert inventory["unattributed_bytes"] == 105
    assert "escape" not in json.dumps(inventory["unattributed_files"])


@pytest.mark.parametrize(
    "selector, expected_digest",
    [
        ({"sha256": ["a" * 64]}, "a" * 64),
        ({"project": ["project_beta"]}, "b" * 64),
        ({"module": ["alpha.dll"]}, "a" * 64),
    ],
)
def test_targeted_cache_selectors_are_exact_and_preview_only(
    tmp_path, selector, expected_digest,
):
    cfg, root, _projects, _entries = _two_entry_cache(tmp_path)

    result = prune_cache(cfg, dry_run=True, **selector)

    assert result["selected_count"] == 1
    assert result["selected"][0]["sha256"] == expected_digest
    assert result["removed_count"] == 0
    assert (root / "binaries" / f"{expected_digest}.exe").exists()


def test_targeted_apply_removes_only_exact_entry_and_preserves_overhead(
    monkeypatch, tmp_path,
):
    cfg, root, projects, _entries = _two_entry_cache(tmp_path)
    monkeypatch.setattr(DecompClient, "worker_alive", lambda self: False)

    result = prune_cache(cfg, sha256=["a" * 64], dry_run=False)

    assert result["removed_count"] == 1
    assert not (root / "binaries" / f"{'a' * 64}.exe").exists()
    assert not (projects / "project_alpha.gpr").exists()
    assert (root / "binaries" / f"{'b' * 64}.exe").exists()
    assert (root / "logs" / "worker.log").exists()


def test_cache_limit_reports_unreclaimable_residual_and_unmatched_selectors(tmp_path):
    cfg, _root, _projects, _entries = _two_entry_cache(tmp_path)

    result = prune_cache(
        cfg, max_bytes=1, module=["missing.dll"], dry_run=True,
    )

    assert result["selected_count"] == 2
    assert result["estimated_remaining_bytes"] == result["estimated_remaining_overhead_bytes"]
    assert result["residual_bytes_above_limit"] == result["estimated_remaining_bytes"] - 1
    assert result["unmatched_selectors"]["module"] == ["missing.dll"]


@pytest.mark.parametrize(
    "selector",
    [
        {"sha256": ["bad"]},
        {"project": ["../escape"]},
        {"module": ["../escape.dll"]},
        {"module": ["bad\0name.dll"]},
    ],
)
def test_targeted_cache_selectors_reject_malformed_input(tmp_path, selector):
    cfg = Config(winbox_dir=tmp_path)
    with pytest.raises(DecompError) as captured:
        prune_cache(cfg, dry_run=True, **selector)
    assert captured.value.code == "invalid_argument"


def test_targeted_cache_selector_rejects_nonlist_wire_shape(tmp_path):
    with pytest.raises(DecompError) as captured:
        prune_cache(Config(winbox_dir=tmp_path), sha256=123, dry_run=True)  # type: ignore[arg-type]
    assert captured.value.code == "invalid_argument"


def test_worker_start_and_applied_prune_share_one_maintenance_lock(
    monkeypatch, tmp_path,
):
    cfg = Config(winbox_dir=tmp_path)
    root = tmp_path / "decomp" / "cache"
    (root / "binaries").mkdir(parents=True)
    (root / "metadata").mkdir()
    digest = "c" * 64
    binary = root / "binaries" / f"{digest}.exe"
    binary.write_bytes(b"live")
    (root / "metadata" / f"{digest}.json").write_text(json.dumps({
        "sha256": digest, "project_name": "p_live", "last_used": 1,
    }))

    manager = DockerManager(cfg)
    startup_entered = threading.Event()
    release_startup = threading.Event()
    worker_live = {"value": False}

    def start(*, wait_seconds):
        startup_entered.set()
        assert release_startup.wait(2)
        worker_live["value"] = True
        return {"started": True}

    monkeypatch.setattr(manager, "_start", start)
    monkeypatch.setattr(
        DecompClient, "worker_alive", lambda self: worker_live["value"],
    )
    start_thread = threading.Thread(target=manager.start)
    outcome = {}

    def apply_prune():
        try:
            prune_cache(cfg, older_than_days=1, dry_run=False)
        except Exception as exc:  # noqa: BLE001 — captured for the assertion
            outcome["error"] = exc

    start_thread.start()
    assert startup_entered.wait(2)
    prune_thread = threading.Thread(target=apply_prune)
    prune_thread.start()
    assert not outcome
    release_startup.set()
    start_thread.join(2)
    prune_thread.join(2)

    assert not start_thread.is_alive()
    assert not prune_thread.is_alive()
    assert isinstance(outcome.get("error"), DecompError)
    assert "stop the Ghidra worker" in str(outcome["error"])
    assert binary.exists()


def test_project_transaction_and_applied_prune_share_lock(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    source = tmp_path / "sample.exe"
    source.write_bytes(b"exact")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    client = DecompClient(cfg)
    transaction_entered = threading.Event()
    release_transaction = threading.Event()
    outcome = {}

    monkeypatch.setattr(DecompClient, "worker_alive", lambda self: True)

    def exchange(payload, *, timeout):
        request_id = json.loads(payload)["request_id"]
        transaction_entered.set()
        assert release_transaction.wait(2)
        return {"ok": True, "request_id": request_id, "result": {"done": True}}

    monkeypatch.setattr(client, "_exchange", exchange)
    query = threading.Thread(target=lambda: client.call(
        "decompile", binary=str(source), sha256=digest, rva=0,
    ))
    query.start()
    assert transaction_entered.wait(2)

    def apply_prune():
        try:
            prune_cache(cfg, max_bytes=1, dry_run=False)
        except Exception as exc:  # noqa: BLE001 — captured for assertion
            outcome["error"] = exc

    pruning = threading.Thread(target=apply_prune)
    pruning.start()
    assert not outcome
    release_transaction.set()
    query.join(2)
    pruning.join(2)

    assert not query.is_alive()
    assert not pruning.is_alive()
    assert isinstance(outcome.get("error"), DecompError)
    assert "stop the Ghidra worker" in str(outcome["error"])


def test_stale_maintenance_file_is_not_treated_as_live_ownership(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    path = maintenance_lock_path(cfg)
    path.parent.mkdir(parents=True)
    path.write_text('{"pid":999999999}\n')

    with maintenance_lock(cfg):
        owner = json.loads(path.read_text())

    assert owner["pid"] == os.getpid()


def test_process_death_releases_maintenance_lock(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        with maintenance_lock(cfg):
            os.write(ready_w, b"1")
            os._exit(0)

    os.close(ready_w)
    try:
        assert os.read(ready_r, 1) == b"1"
    finally:
        os.close(ready_r)
    os.waitpid(pid, 0)
    with maintenance_lock(cfg):
        pass


def test_pdb_public_function_flag_is_preserved():
    text = """
0 | S_PUB32 [size = 32] `RealFunction`
    flags = function, addr = 0001:16
1 | S_PUB32 [size = 32] `PublicData`
    flags = none, addr = 0001:32
"""
    result = parse_publics_metadata(text, {1: 0x1000})
    assert result.symbols == {"RealFunction": 0x1010, "PublicData": 0x1020}
    assert result.functions == {"RealFunction"}


def test_recovery_rejects_nonfunction_pdb_public():
    assert _recover_function(None, None, None, 0x1000, {
        "name": "data", "rva": 0x1000, "offset": 0, "is_function": False,
    }) == (None, "none")


def test_recovery_provenance_survives_worker_reopen(tmp_path):
    first = Worker(tmp_path / "cache", tmp_path / "projects", None)
    first._record_recovery_provenance(
        "a" * 64, 0x1234, "pdb-public-recovery",
        {"name": "Verified", "is_function": True},
    )
    reopened = Worker(tmp_path / "cache", tmp_path / "projects", None)
    assert reopened._recovery_provenance("a" * 64, 0x1234) == "pdb-public-recovery"


def test_new_cache_mcp_tools_use_structured_envelope(monkeypatch, tmp_path):
    import winbox.mcp as mcp_module
    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    inventory = mcp_module.kdbg_decomp_cache()
    assert inventory["ok"] is True
    assert inventory["result"]["schema"] == "winbox.decomp-cache/1"
    invalid = mcp_module.kdbg_decomp_cache_prune()
    assert invalid["ok"] is False
    assert invalid["error"]["code"] == "invalid_argument"


def test_cache_mcp_forwards_exact_selectors(monkeypatch, tmp_path):
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    captured = {}
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)

    def prune(_cfg, **kwargs):
        captured.update(kwargs)
        return {"selected_count": 1}

    monkeypatch.setattr(package, "prune_cache", prune)
    reply = mcp_module.kdbg_decomp_cache_prune(
        sha256=["a" * 64], project=["p_exact"], module=["X.DLL"],
    )
    assert reply["ok"] is True
    assert captured["sha256"] == ["a" * 64]
    assert captured["project"] == ["p_exact"]
    assert captured["module"] == ["X.DLL"]
    assert captured["dry_run"] is True


def test_cache_cli_forwards_repeatable_exact_selectors(monkeypatch, tmp_path):
    import winbox.kdbg.decomp as package
    from click.testing import CliRunner
    from winbox.cli import cli

    cfg = Config(winbox_dir=tmp_path)
    captured = {}
    monkeypatch.setattr("winbox.cli.Config.load", lambda: cfg)

    def prune(_cfg, **kwargs):
        captured.update(kwargs)
        return {"selected_count": 2}

    monkeypatch.setattr(package, "prune_cache", prune)
    result = CliRunner().invoke(cli, [
        "kdbg", "ghidra", "prune",
        "--sha256", "a" * 64, "--sha256", "b" * 64,
        "--project", "p_exact", "--module", "X.DLL",
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["selected_count"] == 2
    assert captured["sha256"] == ("a" * 64, "b" * 64)
    assert captured["project"] == ("p_exact",)
    assert captured["module"] == ("X.DLL",)
    assert captured["dry_run"] is True


class _OpenedProject:
    def close(self):
        pass


def _corrupt_project_worker(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    projects = tmp_path / "projects"
    projects.mkdir()
    source = tmp_path / "sample.exe"
    source.write_bytes(b"exact-binary")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    worker = Worker(cache, projects, None)
    worker.started = True
    worker.ghidra_version = "12.1.3"
    monkeypatch.setattr(worker, "start_ghidra", lambda: None)
    monkeypatch.setattr(worker, "_analyze_opened", lambda *_a, **_k: False)
    from winbox.kdbg.decomp.worker import _project_name
    name = _project_name(worker.ghidra_version, digest)
    (projects / f"{name}.gpr").write_bytes(b"truncated")
    (projects / f"{name}.rep").mkdir()
    (projects / f"{name}.rep" / "broken").write_bytes(b"broken")
    return worker, source, digest, name


def test_corrupt_project_is_reset_and_rebuilt_once(monkeypatch, tmp_path):
    worker, source, digest, name = _corrupt_project_worker(tmp_path, monkeypatch)
    (worker.projects / f"{name}.lock").write_bytes(b"forced-kill-owner")
    (worker.projects / f"{name}.lock~").write_bytes(b"forced-kill-backup")
    calls = iter((RuntimeError("corrupt repository"), _OpenedProject()))

    def enter(*_args):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(worker, "_enter_project", enter)
    opened, cache_hit, recovery = worker._open(source, digest)
    assert isinstance(opened, _OpenedProject)
    assert cache_hit is False
    assert recovery["rebuild"] == "succeeded"
    assert recovery["original_failure"].endswith("corrupt repository")
    assert set(recovery["removed_files"]) == {
        f"{name}.gpr", f"{name}.rep", f"{name}.lock", f"{name}.lock~",
    }
    assert not any(path.exists() for path in worker._project_paths(name))
    assert list((worker.cache / "binaries").glob(f"{digest}.*"))


def test_repository_only_forced_kill_residue_is_reset(monkeypatch, tmp_path):
    worker, source, digest, name = _corrupt_project_worker(tmp_path, monkeypatch)
    (worker.projects / f"{name}.gpr").unlink()
    calls = iter((RuntimeError("malformed repository"), _OpenedProject()))

    def enter(*_args):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(worker, "_enter_project", enter)
    _opened, cache_hit, recovery = worker._open(source, digest)
    assert cache_hit is False
    assert recovery["removed_files"] == [f"{name}.rep"]
    assert recovery["rebuild"] == "succeeded"


def test_corrupt_project_failed_rebuild_is_typed_and_never_loops(monkeypatch, tmp_path):
    worker, source, digest, _name = _corrupt_project_worker(tmp_path, monkeypatch)
    calls = []

    def enter(*_args):
        calls.append(1)
        raise RuntimeError("corrupt" if len(calls) == 1 else "rebuild failed")

    monkeypatch.setattr(worker, "_enter_project", enter)
    with pytest.raises(WorkerError) as captured:
        worker._open(source, digest)
    assert captured.value.code == "cache_rebuild_failed"
    assert len(calls) == 2
    assert captured.value.details["rebuild_failure"] == "rebuild failed"
    assert not any(path.exists() for path in worker._project_paths(_name))


def test_corrupt_project_partial_reset_failure_is_typed(monkeypatch, tmp_path):
    worker, source, digest, name = _corrupt_project_worker(tmp_path, monkeypatch)
    monkeypatch.setattr(
        worker, "_enter_project", lambda *_a: (_ for _ in ()).throw(RuntimeError("corrupt")),
    )
    monkeypatch.setattr(
        "winbox.kdbg.decomp.worker.shutil.rmtree",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(WorkerError) as captured:
        worker._open(source, digest)
    assert captured.value.code == "cache_reset_failed"
    assert not (worker.projects / f"{name}.gpr").exists()
    assert (worker.projects / f"{name}.rep").is_dir()


def test_noncorruption_project_open_failure_is_not_reset(monkeypatch, tmp_path):
    worker, source, digest, name = _corrupt_project_worker(tmp_path, monkeypatch)
    monkeypatch.setattr(
        worker, "_enter_project",
        lambda *_a: (_ for _ in ()).throw(PermissionError("permission denied")),
    )
    with pytest.raises(WorkerError) as captured:
        worker._open(source, digest)
    assert captured.value.code == "project_open_failed"
    assert captured.value.retryable is True
    assert (worker.projects / f"{name}.gpr").exists()


def test_project_reset_refuses_symlink_without_following_it(monkeypatch, tmp_path):
    worker, _source, _digest, name = _corrupt_project_worker(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    (worker.projects / f"{name}.lock").symlink_to(outside)
    with pytest.raises(WorkerError) as captured:
        worker._reset_project(name, reason="corrupt")
    assert captured.value.code == "cache_reset_failed"
    assert outside.read_bytes() == b"keep"


def test_repair_cache_validates_digest_and_forwards_exact_request(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    with pytest.raises(DecompError) as captured:
        repair_cache(cfg, sha256="bad")
    assert captured.value.code == "invalid_argument"
    calls = {}

    def call(self, op, **kwargs):
        calls.update(op=op, **kwargs)
        return {"rebuild": "succeeded"}

    monkeypatch.setattr(DecompClient, "call", call)
    assert repair_cache(cfg, sha256="A" * 64)["rebuild"] == "succeeded"
    assert calls["op"] == "repair"
    assert calls["sha256"] == "a" * 64


def test_repair_cli_and_mcp_forward_exact_digest(monkeypatch, tmp_path):
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module
    from click.testing import CliRunner
    from winbox.cli import cli

    cfg = Config(winbox_dir=tmp_path)
    seen = []
    monkeypatch.setattr("winbox.cli.Config.load", lambda: cfg)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    monkeypatch.setattr(
        package, "repair_cache",
        lambda _cfg, *, sha256: seen.append(sha256) or {"rebuild": "succeeded"},
    )
    result = CliRunner().invoke(cli, [
        "kdbg", "ghidra", "repair", "--sha256", "a" * 64,
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["rebuild"] == "succeeded"
    reply = mcp_module.kdbg_decomp_cache_repair("b" * 64)
    assert reply["ok"] is True
    assert seen == ["a" * 64, "b" * 64]
