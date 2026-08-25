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
from winbox.kdbg.decomp.cache import cache_inventory, prune_cache
from winbox.kdbg.decomp.client import (
    DecompClient,
    DecompError,
    maintenance_lock,
    maintenance_lock_path,
    open_program_limit,
)
from winbox.kdbg.decomp.docker import DockerManager
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
    monkeypatch.setattr(client, "active_worker_api", lambda: "5")
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
