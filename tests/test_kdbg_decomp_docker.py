from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.docker import (
    IMAGE,
    DockerError,
    DockerManager,
    container_name,
)


def _completed(*, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(["docker"], returncode, stdout, stderr)


def test_container_name_is_stable_and_scoped_to_state_root(tmp_path):
    first = Config(winbox_dir=tmp_path / "one")
    same = Config(winbox_dir=tmp_path / "one")
    other = Config(winbox_dir=tmp_path / "two")
    assert container_name(first) == container_name(same)
    assert container_name(first) != container_name(other)
    assert container_name(first).startswith("winbox-ghidra-")


def test_image_and_container_inspection_fail_closed_on_reserved_name(monkeypatch, tmp_path):
    manager = DockerManager(Config(winbox_dir=tmp_path))
    image = [{"Id": "sha256:x", "Config": {"Labels": {}}}]
    monkeypatch.setattr(manager, "_docker", lambda *a, **k: _completed(stdout=json.dumps(image)))
    with pytest.raises(DockerError, match="not an exact"):
        manager.image_info()

    container = [{
        "Id": "x", "State": {"Running": True},
        "Config": {"Image": IMAGE, "Labels": {"io.winbox.component": "someone-else"}},
    }]
    monkeypatch.setattr(
        manager, "_docker", lambda *a, **k: _completed(stdout=json.dumps(container))
    )
    with pytest.raises(DockerError, match="refusing to manage"):
        manager.container_info()


def test_inspection_distinguishes_missing_objects_from_daemon_failure(monkeypatch, tmp_path):
    manager = DockerManager(Config(winbox_dir=tmp_path))
    monkeypatch.setattr(
        manager, "_docker",
        lambda *a, **k: _completed(returncode=1, stderr="No such image: x"),
    )
    assert manager.image_info() is None
    monkeypatch.setattr(
        manager, "_docker",
        lambda *a, **k: _completed(returncode=1, stderr="permission denied"),
    )
    with pytest.raises(DockerError, match="permission denied"):
        manager.image_info()


def test_start_uses_private_hardened_current_uid_container(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    manager = DockerManager(cfg)
    monkeypatch.setattr(manager, "image_info", lambda: {"id": "ok"})
    inspections = iter([None, {"running": True, "status": "running", "image": IMAGE}])
    monkeypatch.setattr(manager, "container_info", lambda: next(inspections))
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == "run":
            path = Path(cfg.winbox_dir) / "decomp" / "decomp.sock"
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(path))
            listener.close()
        return _completed(stdout="container-id\n")

    monkeypatch.setattr(manager, "_docker", docker)
    result = manager.start(wait_seconds=1)
    assert result["started"] is True
    command = calls[0]
    assert command[:2] == ("run", "--detach")
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert ("--cap-drop", "ALL") == command[
        command.index("--cap-drop"):command.index("--cap-drop") + 2
    ]
    assert "no-new-privileges" in command
    assert not any(value.startswith("--publish") or value == "-p" for value in command)
    assert "/run/winbox/decomp.sock" in command


def test_lifecycle_lock_serializes_concurrent_first_starts(monkeypatch, tmp_path):
    manager = DockerManager(Config(winbox_dir=tmp_path / "state"))
    guard = threading.Lock()
    active = 0
    maximum = 0

    def start(*, wait_seconds):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.02)
        with guard:
            active -= 1
        return {"started": True}

    monkeypatch.setattr(manager, "_start", start)
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert list(pool.map(lambda _: manager.start(), range(6))) == [
            {"started": True}
        ] * 6
    assert maximum == 1


def test_install_builds_only_bundled_assets_and_verifies_image(monkeypatch, tmp_path):
    manager = DockerManager(Config(winbox_dir=tmp_path / "state"))
    observed = {}

    def docker(*args, **kwargs):
        context = Path(args[-1])
        observed["dockerfile"] = (context / "Dockerfile").read_text(encoding="utf-8")
        observed["worker"] = (context / "worker.py").read_text(encoding="utf-8")
        return _completed(stdout="built")

    monkeypatch.setattr(manager, "_docker", docker)
    monkeypatch.setattr(
        manager, "image_info",
        lambda: {"id": "sha256:ok", "ghidra_version": "12.1.3"},
    )
    result = manager.install(pull=False)
    assert result["installed"] is True
    assert "GHIDRA_SHA256=" in observed["dockerfile"]
    assert "PYGHIDRA_SHA256=" in observed["dockerfile"]
    assert "Persistent, serialized PyGhidra worker" in observed["worker"]


def test_binary_staging_is_content_addressed_atomic_and_container_relative(tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    source = tmp_path / "odd suffix.$BAD"
    source.write_bytes(b"exact bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    client = DecompClient(cfg)
    translated = client._stage_binary(source, digest)
    assert translated == f"/cache/binaries/{digest}.bin"
    staged = Path(cfg.winbox_dir) / "decomp" / "cache" / translated.removeprefix("/cache/")
    assert staged.read_bytes() == b"exact bytes"
    assert client._stage_binary(source, digest) == translated
    with pytest.raises(DecompError, match="changed before staging"):
        client._stage_binary(source, "0" * 64)


def test_docker_decompile_translates_path_before_transport(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"x")
    digest = hashlib.sha256(b"x").hexdigest()
    client = DecompClient(cfg)
    monkeypatch.setattr(client, "worker_alive", lambda: True)
    captured = {}

    def exchange(payload, **kwargs):
        captured.update(json.loads(payload))
        return {"ok": True, "result": {"fine": True}}

    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.call("decompile", binary=str(binary), sha256=digest)["fine"]
    assert captured["args"]["binary"].startswith("/cache/binaries/")
    assert str(tmp_path) not in captured["args"]["binary"]


def test_invalid_backend_is_rejected_before_any_process(monkeypatch, tmp_path):
    monkeypatch.setenv("WINBOX_DECOMP_BACKEND", "wat")
    with pytest.raises(DecompError, match="must be 'docker' or 'host'"):
        DecompClient(Config(winbox_dir=tmp_path)).status()


def test_legacy_host_worker_is_migrated_before_docker_start(monkeypatch, tmp_path):
    client = DecompClient(Config(winbox_dir=tmp_path))
    backends = iter(["host", None])
    monkeypatch.setattr(client, "active_backend", lambda: next(backends))
    monkeypatch.setattr(client, "worker_alive", lambda: False)
    exchanges = []

    def exchange(payload, **kwargs):
        exchanges.append(json.loads(payload))
        return {"ok": True, "result": {"shutting_down": True}}

    monkeypatch.setattr(client, "_exchange", exchange)
    client.ensure_selected_backend()
    assert exchanges == [{"op": "shutdown", "args": {}}]


def test_mcp_lifecycle_serializes_results_and_errors(monkeypatch, tmp_path):
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    monkeypatch.setattr(package, "install_service", lambda *a, **k: {"installed": True})
    monkeypatch.setattr(package, "start_service", lambda *a, **k: {"started": True})
    monkeypatch.setattr(package, "stop_service", lambda *a, **k: {"stopped": True})
    assert json.loads(mcp_module.kdbg_ghidra_install()) == {"installed": True}
    assert json.loads(mcp_module.kdbg_ghidra_run()) == {"started": True}
    assert json.loads(mcp_module.kdbg_ghidra_stop()) == {"stopped": True}

    monkeypatch.setattr(
        package, "start_service",
        lambda *a, **k: (_ for _ in ()).throw(DecompError("reserved name")),
    )
    assert mcp_module.kdbg_ghidra_run() == "error: reserved name"
