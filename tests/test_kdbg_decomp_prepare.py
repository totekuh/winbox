from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError, WORKER_API
from winbox.kdbg.decomp.enrichment import (
    ANALYSIS_PROFILE,
    _bounded_command,
    build_enrichment,
    parse_rendered_signature,
    parse_symbol_enrichment,
)
from winbox.kdbg.decomp.service import (
    PREPARE_JOB_SCHEMA,
    _process_start_ticks,
    _retain_prepare_jobs,
    _write_prepare_job,
    cancel_decomp,
    cancel_prepare_job,
    prepare_decomp,
    prepare_status,
    start_prepare_background,
)
from winbox.kdbg.decomp.worker import Worker, WorkerError


SYMBOL_DUMP = r"""
  216 | S_GPROC32 [size = 56] `ReflectiveLoader`
        parent = 0, end = 428, addr = 0001:0064, code size = 1306
        type = `0x10BC (unsigned __int64 (void*))`, debug start = 14, debug end = 1296
  432 | S_GPROC32 [size = 48] `unsafe_complex`
        parent = 0, end = 512, addr = 0001:0048, code size = 5
        type = `0x10BE (Widget (std::vector<int>))`, debug start = 0, debug end = 4
  212 | S_LDATA32 [size = 36] `global_bias`
        type = 0x0074 (int), addr = 0003:11433
"""


def test_signature_parser_accepts_only_bounded_primitive_pointer_grammar():
    assert parse_rendered_signature("unsigned __int64 (void*)") == {
        "return": {"base": "unsigned __int64", "const": False, "pointers": 0},
        "parameters": [{"base": "void", "const": False, "pointers": 1}],
        "calling_convention": "cdecl",
    }
    assert parse_rendered_signature("void ()")["parameters"] == []
    assert parse_rendered_signature("int (const char*, unsigned long)") is not None
    assert parse_rendered_signature("Widget (std::vector<int>)") is None
    assert parse_rendered_signature("int (char*, ...)") is None
    assert parse_rendered_signature("int (char*...") is None


def test_bounded_pdb_child_streams_caps_and_reaps_real_processes():
    stdout, stderr, returncode = _bounded_command(
        [sys.executable, "-c", "import sys;sys.stdout.write('ok');sys.stderr.write('warn')"],
        timeout=5, max_stdout=16, max_stderr=4,
    )
    assert (stdout, stderr, returncode) == (b"ok", b"warn", 0)

    with pytest.raises(DecompError) as oversized:
        _bounded_command(
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*65536)"],
            timeout=5, max_stdout=1024,
        )
    assert oversized.value.code == "pdb_enrichment_too_large"

    with pytest.raises(DecompError) as timed_out:
        _bounded_command(
            [sys.executable, "-c", "import time;time.sleep(5)"],
            timeout=0.05, max_stdout=16,
        )
    assert timed_out.value.code == "analysis_timeout"

    cancel = threading.Event()
    threading.Timer(0.05, cancel.set).start()
    with pytest.raises(DecompError) as cancelled:
        _bounded_command(
            [sys.executable, "-c", "import time;time.sleep(5)"],
            timeout=5, max_stdout=16, cancel_requested=cancel.is_set,
        )
    assert cancelled.value.code == "cancelled"


def test_bounded_pdb_child_preserves_bounded_error_output():
    stdout, stderr, returncode = _bounded_command(
        [
            sys.executable, "-c",
            "import sys;sys.stderr.write('E'*10000);raise SystemExit(7)",
        ],
        timeout=5, max_stdout=16, max_stderr=128,
    )
    assert stdout == b""
    assert len(stderr) == 128
    assert returncode == 7


def test_symbol_enrichment_uses_section_rvas_and_rejects_complex_signature():
    functions, globals_ = parse_symbol_enrichment(
        SYMBOL_DUMP, {1: 0x1000, 3: 0x3000},
    )
    assert functions[0x1040]["name"] == "ReflectiveLoader"
    assert functions[0x1040]["signature"]["return"]["base"] == "unsigned __int64"
    assert functions[0x1030] == {"name": "unsafe_complex", "scope": "G"}
    assert globals_[0x3000 + 11433] == {"name": "global_bias", "scope": "L"}


def test_build_enrichment_binds_exact_pe_pdb_and_public_roles(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    pe = tmp_path / "sample.exe"
    pe.write_bytes(b"exact")
    digest = hashlib.sha256(b"exact").hexdigest()
    pdb = tmp_path / "sample.pdb"
    pdb.write_bytes(b"pdb")
    record = {
        "pe_path": str(pe), "pe_sha256": digest, "build": "BUILD1",
        "symbols": {"ReflectiveLoader": 0x1040, "PublicGlobal": 0x4000},
        "function_symbols": ["ReflectiveLoader"],
    }

    class Store:
        def load(self, module):
            assert module == "sample"
            return record

    monkeypatch.setattr(
        "winbox.kdbg.decomp.enrichment.cached_pdb_path", lambda *_a: pdb,
    )
    monkeypatch.setattr(
        "winbox.kdbg.decomp.enrichment.load_section_headers",
        lambda _p: {1: 0x1000, 3: 0x3000},
    )
    monkeypatch.setattr(
        "winbox.kdbg.decomp.enrichment._bounded_symbol_dump",
        lambda _p, **_kwargs: SYMBOL_DUMP,
    )
    path, value = build_enrichment(cfg, Store(), "sample")
    assert path.is_file()
    assert value["binary_sha256"] == digest
    assert value["analysis_profile"] == ANALYSIS_PROFILE
    assert value["functions"][0]["signature"]["parameters"][0]["pointers"] == 1
    assert {item["name"] for item in value["globals"]} == {
        "PublicGlobal", "global_bias",
    }
    # A self-consistent exact sidecar is reused without another PDB dump.
    monkeypatch.setattr(
        "winbox.kdbg.decomp.enrichment._bounded_symbol_dump",
        lambda _p, **_kwargs: (
            _ for _ in ()
        ).throw(AssertionError("unexpected extraction")),
    )
    assert build_enrichment(cfg, Store(), "sample")[1] == value


def test_build_enrichment_rejects_changed_exact_pe(tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    pe = tmp_path / "sample.exe"
    pe.write_bytes(b"changed")

    class Store:
        def load(self, _module):
            return {
                "pe_path": str(pe), "pe_sha256": "a" * 64, "build": "BUILD",
            }

    with pytest.raises(DecompError) as captured:
        build_enrichment(cfg, Store(), "sample")
    assert captured.value.code == "identity_mismatch"


def test_worker_analysis_monitor_handles_cancel_and_timeout(tmp_path):
    worker = Worker(tmp_path / "cache", tmp_path / "projects", None)
    cancel_root = worker.cache / "cancel"
    cancel_root.mkdir(parents=True)
    request_id = "a" * 32

    def cancel_later():
        time.sleep(0.03)
        (cancel_root / request_id).write_text("1")

    threading.Thread(target=cancel_later).start()

    def wait_for_cancel(monitor):
        while not monitor.isCancelled():
            time.sleep(0.005)

    # Use a tiny fake ghidra monitor module for the host-side worker unit.
    import sys
    monitor = type("Monitor", (), {
        "__init__": lambda self: setattr(self, "cancelled", False),
        "cancel": lambda self: setattr(self, "cancelled", True),
        "isCancelled": lambda self: self.cancelled,
    })
    old = {name: sys.modules.get(name) for name in (
        "ghidra", "ghidra.util", "ghidra.util.task",
    )}
    sys.modules["ghidra"] = SimpleNamespace()
    sys.modules["ghidra.util"] = SimpleNamespace()
    sys.modules["ghidra.util.task"] = SimpleNamespace(ConsoleTaskMonitor=monitor)
    try:
        with pytest.raises(WorkerError) as cancelled:
            worker._run_cancellable(
                request_id, 1, wait_for_cancel,
                timeout_code="analysis_timeout", timeout_message="late",
            )
        assert cancelled.value.code == "cancelled"
        with pytest.raises(WorkerError) as timed_out:
            worker._run_cancellable(
                "", 0.03, wait_for_cancel,
                timeout_code="analysis_timeout", timeout_message="late",
            )
        assert timed_out.value.code == "analysis_timeout"
    finally:
        for name, value in old.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def test_worker_prepare_is_offline_and_reports_reuse(monkeypatch, tmp_path):
    source = tmp_path / "sample.exe"
    source.write_bytes(b"sample")
    digest = hashlib.sha256(b"sample").hexdigest()
    worker = Worker(tmp_path / "cache", tmp_path / "projects", None)
    opened = SimpleNamespace(enrichment_summary={"globals_named": 2})
    seen = {}

    def opened_call(binary, sha256, **kwargs):
        seen.update(binary=binary, sha256=sha256, **kwargs)
        return opened, True, None

    monkeypatch.setattr(worker, "_open", opened_call)
    monkeypatch.setattr(worker, "_record_metadata", lambda *_a, **_k: None)
    result = worker.prepare({
        "binary": str(source), "binary_name": "sample.exe", "sha256": digest,
        "analysis_timeout": 30, "enrichment": "sidecar",
        "_request_id": "b" * 32,
    })
    assert result["prepared"] is True
    assert result["cache_hit"] is True
    assert result["enrichment"] == {"globals_named": 2}
    assert seen["analysis_timeout"] == 30
    assert seen["enrichment"] == "sidecar"


def test_worker_decompile_rejects_invalid_analysis_budget(monkeypatch, tmp_path):
    source = tmp_path / "sample.exe"
    source.write_bytes(b"sample")
    digest = hashlib.sha256(b"sample").hexdigest()
    worker = Worker(tmp_path / "cache", tmp_path / "projects", None)
    with pytest.raises(WorkerError) as captured:
        worker.decompile({
            "binary": str(source), "sha256": digest, "rva": 0,
            "analysis_timeout": "not-an-integer",
        })
    assert captured.value.code == "invalid_argument"


def test_enrichment_result_is_atomic_bounded_and_source_auditable(tmp_path):
    worker = Worker(tmp_path / "cache", tmp_path / "projects", None)
    digest = "d" * 64
    stats = {"functions_named": 1, "conflicts": 1}
    events = [
        {
            "kind": "function_name", "rva": 16, "name": "ExactName",
            "source": "exact-pdb-public", "action": "applied",
        },
        {
            "kind": "global_name", "rva": 32, "name": "ExistingName",
            "source": "exact-pdb-private", "action": "conflict",
            "reason": "preserved-existing",
        },
    ]
    relative = worker._record_enrichment_result(digest, "a" * 64, stats, events)
    path = worker.cache / relative
    value = json.loads(path.read_text())
    assert value["binary_sha256"] == digest
    assert value["sidecar_sha256"] == "a" * 64
    assert value["events"] == events
    assert path.stat().st_mode & 0o777 == 0o600


def test_worker_enrichment_sidecar_rejects_symlink_and_oversize(tmp_path):
    worker = Worker(tmp_path / "cache", tmp_path / "projects", None)
    root = worker.cache / "enrichment"
    root.mkdir(parents=True)
    digest = "e" * 64
    valid = root / "valid.json"
    valid.write_text(json.dumps({
        "schema": "winbox.pdb-enrichment/1",
        "revision": 2,
        "analysis_profile": ANALYSIS_PROFILE,
        "binary_sha256": digest,
        "functions": [], "globals": [],
    }))
    linked = root / "linked.json"
    linked.symlink_to(valid)
    with pytest.raises(WorkerError) as unsafe:
        worker._load_enrichment(str(linked), digest)
    assert unsafe.value.code == "invalid_argument"

    oversized = root / "oversized.json"
    oversized.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(WorkerError) as too_large:
        worker._load_enrichment(str(oversized), digest)
    assert too_large.value.code == "invalid_argument"


def test_background_prepare_validates_budget_and_forwards_force(
    monkeypatch, tmp_path,
):
    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(
        "winbox.kdbg.decomp.service._prepare_modules", lambda *_a, **_k: ["sample"],
    )
    with pytest.raises(DecompError) as captured:
        start_prepare_background(cfg, modules=["sample"], analysis_timeout=True)
    assert captured.value.code == "invalid_argument"

    captured_command = {}
    process = SimpleNamespace(pid=1234, wait=lambda: 0)

    def popen(command, **_kwargs):
        captured_command["value"] = command
        return process

    monkeypatch.setattr("winbox.kdbg.decomp.service.subprocess.Popen", popen)
    result = start_prepare_background(
        cfg, modules=["sample"], analysis_timeout=30, force_enrichment=True,
    )
    assert result["force_enrichment"] is True
    assert "--force-enrichment" in captured_command["value"]


def _job_value(token: str, nonce: str, **updates):
    value = {
        "schema": PREPARE_JOB_SCHEMA,
        "token": token, "nonce": nonce, "state": "running",
        "pid": os.getpid(), "process_start_ticks": _process_start_ticks(os.getpid()),
        "started_at": time.time(), "heartbeat_at": time.time(),
        "modules": ["sample"],
    }
    value.update(updates)
    return value


def test_prepare_status_binds_process_start_identity_and_marks_lost(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    token, nonce = "a" * 32, "b" * 32
    path = tmp_path / "decomp" / "prepare-jobs" / f"{token}.json"
    _write_prepare_job(path, _job_value(token, nonce))
    alive = prepare_status(cfg, token=token)
    assert alive["process_liveness"] == "alive"

    stale = _job_value(
        token, nonce, process_start_ticks=1,
        heartbeat_at=time.time() - 30,
    )
    _write_prepare_job(path, stale)
    lost = prepare_status(cfg, token=token)
    assert lost["state"] == "lost"
    assert lost["process_liveness"] == "replaced"
    assert json.loads(path.read_text())["state"] == "lost"


def test_prepare_job_cancel_is_nonce_bound_and_terminal_safe(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    token, nonce = "c" * 32, "d" * 32
    path = tmp_path / "decomp" / "prepare-jobs" / f"{token}.json"
    _write_prepare_job(path, _job_value(token, nonce))
    result = cancel_prepare_job(cfg, token=token)
    marker = json.loads(path.with_suffix(".cancel").read_text())
    assert result["cancel_requested"] is True
    assert marker["token"] == token and marker["nonce"] == nonce
    assert prepare_status(cfg, token=token)["cancellation_state"] == "requested"

    _write_prepare_job(path, _job_value(token, nonce, state="completed"))
    with pytest.raises(DecompError) as finished:
        cancel_prepare_job(cfg, token=token)
    assert finished.value.code == "not_running"
    with pytest.raises(DecompError) as exclusive:
        cancel_decomp(cfg, token=token, request_id="e" * 32)
    assert exclusive.value.code == "invalid_argument"


def test_prepare_job_retention_removes_only_old_terminal_pairs(monkeypatch, tmp_path):
    import winbox.kdbg.decomp.service as service

    cfg = Config(winbox_dir=tmp_path)
    root = tmp_path / "decomp" / "prepare-jobs"
    root.mkdir(parents=True)
    monkeypatch.setattr(service, "PREPARE_JOB_MAX_RETAINED", 2)
    tokens = [f"{index:032x}" for index in range(4)]
    for index, token in enumerate(tokens):
        path = root / f"{token}.json"
        _write_prepare_job(
            path, _job_value(token, "f" * 32, state="completed"),
        )
        path.with_suffix(".log").write_text("log")
        stamp = time.time() + index
        os.utime(path, (stamp, stamp))
    active_token = "9" * 32
    active = root / f"{active_token}.json"
    _write_prepare_job(active, _job_value(active_token, "8" * 32))
    outside = tmp_path / "outside.json"
    outside.write_text("do-not-touch")
    (root / f"{'7' * 32}.json").symlink_to(outside)
    result = _retain_prepare_jobs(cfg)
    assert result["removed_jobs"] == 2
    assert all(not (root / f"{token}.json").exists() for token in tokens[:2])
    assert all((root / f"{token}.json").exists() for token in tokens[2:])
    assert active.exists()
    assert outside.read_text() == "do-not-touch"


def test_prepare_status_detects_dead_real_child_without_pid_reuse(tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
    try:
        token, nonce = "1" * 32, "2" * 32
        path = tmp_path / "decomp" / "prepare-jobs" / f"{token}.json"
        _write_prepare_job(path, _job_value(
            token, nonce, pid=child.pid,
            process_start_ticks=_process_start_ticks(child.pid),
        ))
        assert prepare_status(cfg, token=token)["process_liveness"] == "alive"
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=5)
        value = json.loads(path.read_text())
        value["heartbeat_at"] = time.time() - 30
        _write_prepare_job(path, value)
        assert prepare_status(cfg, token=token)["state"] == "lost"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_prewarmer_token_cancel_forwards_only_its_exact_request(
    monkeypatch, tmp_path,
):
    import winbox.kdbg.decomp.prewarm as prewarm

    token, nonce, request_id = "3" * 32, "4" * 32, "5" * 32
    cfg = Config(winbox_dir=tmp_path)
    forwarded = []

    def fake_prepare(_cfg, **kwargs):
        kwargs["progress"]({
            "module": "sample", "index": 1, "total": 1,
            "request_id": request_id, "state": "module_started",
        })
        deadline = time.monotonic() + 3
        while not kwargs["cancel_requested"]() and time.monotonic() < deadline:
            time.sleep(0.01)
        return {
            "schema": "winbox.decomp-prepare-batch/1", "requested": 1,
            "prepared": 0, "failed": 1, "results": [],
            "failures": [{"module": "sample", "code": "cancelled"}],
        }

    monkeypatch.setattr(prewarm, "prepare_decomp", fake_prepare)
    monkeypatch.setattr(
        prewarm.DecompClient, "request_cancel",
        lambda _self, value: forwarded.append(value),
    )
    monkeypatch.setattr(sys, "argv", [
        "prewarm", "--state-root", str(tmp_path), "--token", token,
        "--nonce", nonce, "--module", "sample", "--analysis-timeout", "30",
    ])

    def request_cancel():
        path = tmp_path / "decomp" / "prepare-jobs" / f"{token}.json"
        deadline = time.monotonic() + 3
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancel_prepare_job(cfg, token=token)

    requester = threading.Thread(target=request_cancel)
    requester.start()
    assert prewarm.main() == 1
    requester.join(timeout=3)
    assert forwarded == [request_id]
    final = prepare_status(cfg, token=token)
    assert final["state"] == "cancelled"
    assert final["cancellation_state"] == "completed"
    assert not (tmp_path / "decomp" / "prepare-jobs" / f"{token}.cancel").exists()


def test_prepare_batch_builds_sidecar_and_calls_worker(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"x")
    digest = hashlib.sha256(b"x").hexdigest()
    sidecar = tmp_path / "sidecar.json"
    sidecar.write_text("{}")
    monkeypatch.setattr(
        "winbox.kdbg.decomp.service._prepare_modules", lambda *_a, **_k: ["sample"],
    )

    class Store:
        def __init__(self, _root): pass
        def load(self, _name):
            return {"pe_path": str(binary), "pe_sha256": digest}

    monkeypatch.setattr("winbox.kdbg.decomp.service.SymbolStore", Store)
    monkeypatch.setattr(
        "winbox.kdbg.decomp.enrichment.build_enrichment",
        lambda *_a, **_k: (sidecar, {"pdb_build": "BUILD"}),
    )
    calls = []

    class Client:
        def __init__(self, _cfg): pass
        def call(self, op, **kwargs):
            calls.append((op, kwargs))
            return {"prepared": True}

    monkeypatch.setattr("winbox.kdbg.decomp.service.DecompClient", Client)
    result = prepare_decomp(cfg, module="sample", analysis_timeout=25)
    assert result["prepared"] == 1
    assert result["failed"] == 0
    assert calls[0][0] == "prepare"
    assert calls[0][1]["analysis_timeout"] == 25
    assert calls[0][1]["enrichment"] == str(sidecar)


def test_cancel_requires_active_identity(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    client = DecompClient(cfg)
    monkeypatch.setattr(client, "_session_liveness", lambda: {
        "current_operation": {
            "request_id": "c" * 32, "op": "prepare", "phase": "analyzing_program",
        },
    })
    markers = []
    monkeypatch.setattr(client, "_cancel_request", markers.append)
    assert client.cancel()["cancel_requested"] is True
    assert markers == ["c" * 32]
    with pytest.raises(DecompError) as captured:
        client.cancel("d" * 32)
    assert captured.value.code == "identity_mismatch"


def test_client_can_bind_one_exact_job_request_identity(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path)
    client = DecompClient(cfg)
    request_id = "6" * 32
    monkeypatch.setattr(client, "worker_alive", lambda: True)

    def exchange(payload, **_kwargs):
        parsed = json.loads(payload)
        assert parsed["request_id"] == request_id
        return {"ok": True, "request_id": request_id, "result": {"bound": True}}

    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.call("status", request_id=request_id)["bound"] is True
    with pytest.raises(DecompError) as invalid:
        client.call("status", request_id="BAD")
    assert invalid.value.code == "invalid_argument"


def test_mcp_prepare_status_and_cancel_use_structured_envelopes(monkeypatch, tmp_path):
    import winbox.kdbg.decomp as package
    import winbox.mcp as mcp_module

    cfg = Config(winbox_dir=tmp_path)
    monkeypatch.setattr(mcp_module, "_kdbg_cfg_only", lambda: cfg)
    monkeypatch.setattr(package, "prepare_decomp", lambda *_a, **_k: {"prepared": 1})
    monkeypatch.setattr(package, "prepare_status", lambda *_a, **_k: {"state": "completed"})
    cancelled = {}
    monkeypatch.setattr(
        package, "cancel_decomp",
        lambda *_a, **kwargs: cancelled.update(kwargs) or {"cancel_requested": True},
    )
    assert mcp_module.kdbg_decomp_prepare("sample")["result"]["prepared"] == 1
    assert mcp_module.kdbg_decomp_prepare_status()["result"]["state"] == "completed"
    assert mcp_module.kdbg_decomp_cancel(token="a" * 32)["result"]["cancel_requested"] is True
    assert cancelled == {"request_id": "", "token": "a" * 32}


def test_worker_api_bumped_for_prepare_protocol():
    assert WORKER_API == "6"
