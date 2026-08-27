from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient
from winbox.kdbg.decomp.cache import cache_inventory, repair_cache
from winbox.kdbg.decomp.docker import DockerError, DockerManager, project_dir
from winbox.kdbg.decomp.enrichment import ANALYSIS_PROFILE, enrichment_path


@pytest.mark.integration
def test_persistent_pyghidra_worker_decompiles_and_reuses_project(tmp_path, request):
    if any(shutil.which(tool) is None for tool in ("gcc", "nm", "strip")):
        pytest.skip("gcc/nm/strip unavailable")
    source = tmp_path / "focus.c"
    binary = tmp_path / "focus"
    source.write_text(
        "volatile int global_bias = 7;\n"
        "volatile int other_bias = 9;\n"
        "__attribute__((noinline)) int focus_me(int x) { return x * 3 + global_bias; }\n"
        "int main(void) { return focus_me(5); }\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", "-O1", "-no-pie", "-o", str(binary), str(source)],
        check=True,
    )
    symbols = subprocess.run(
        ["nm", "-n", str(binary)], check=True, text=True, capture_output=True,
    ).stdout
    address = int(next(line.split()[0] for line in symbols.splitlines() if line.endswith(" focus_me")), 16)
    global_address = int(next(
        line.split()[0] for line in symbols.splitlines() if line.endswith(" global_bias")
    ), 16)
    other_address = int(next(
        line.split()[0] for line in symbols.splitlines() if line.endswith(" other_bias")
    ), 16)
    # Remove ELF names/types so this exercises exact sidecar enrichment rather
    # than merely observing Ghidra's native ELF/DWARF importer reuse them.
    subprocess.run(["strip", "--strip-all", str(binary)], check=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    cfg = Config(winbox_dir=tmp_path / "state")
    client = DecompClient(cfg)
    manager = DockerManager(cfg)
    status = manager.status()
    if not status.get("docker_available") or not status.get("image_installed"):
        pytest.skip("pinned winbox PyGhidra image is not installed")

    def cleanup():
        try:
            manager.stop()
        except DockerError:
            pass

    request.addfinalizer(cleanup)

    sidecar = enrichment_path(cfg, digest)
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(json.dumps({
        "schema": "winbox.pdb-enrichment/1",
        "revision": 2,
        "analysis_profile": ANALYSIS_PROFILE,
        "binary_sha256": digest,
        "pdb_build": "docker-integration-exact",
        "module": "focus",
        "functions": [{
            "rva": address - 0x400000,
            "name": "focus_me",
            "source": "exact-pdb-public",
            "signature_source": "exact-pdb-private",
            "signature": {
                "return": {"base": "int", "const": False, "pointers": 0},
                "parameters": [{"base": "int", "const": False, "pointers": 0}],
                "calling_convention": "cdecl",
            },
        }],
        "globals": [
            {
                "rva": global_address - 0x400000, "name": "global_bias",
                "source": "exact-pdb-private",
            },
            {
                "rva": other_address - 0x400000, "name": "global_bias",
                "source": "exact-pdb-private",
            },
        ],
        "counts": {"functions": 1, "globals": 2, "typed_signatures": 1},
        "truncated": False,
    }))
    prepared = client.call(
        "prepare", binary=str(binary), binary_name="focus",
        sha256=digest, enrichment=str(sidecar), analysis_timeout=60,
        timeout=150,
    )
    assert prepared["prepared"] is True
    assert prepared["enrichment"]["signatures_applied"] == 1
    assert prepared["enrichment"]["globals_named"] >= 2
    provenance = json.loads(
        (cfg.winbox_dir / "decomp" / "cache" / prepared["enrichment"]["provenance_file"])
        .read_text()
    )
    duplicate_events = [
        event for event in provenance["events"]
        if event["kind"] == "global_name" and event["name"] == "global_bias"
    ]
    assert len(duplicate_events) == 2
    assert {event["action"] for event in duplicate_events} == {"applied"}

    first = client.call(
        "decompile", binary=str(binary), sha256=digest,
        rva=address - 0x400000, before=1, after=2, full=True,
        decompile_timeout=30, line_start=1, line_end=20, assembly="mapped",
    )
    warm_started = time.monotonic()
    second = client.call(
        "decompile", binary=str(binary), sha256=digest,
        rva=address - 0x400000, before=0, after=0, full=False,
        decompile_timeout=30,
    )
    warm_elapsed = time.monotonic() - warm_started
    assert first["function"]["name"] == "focus_me"
    assert "int" in first["function"]["signature"]
    assert "* 3" in first["code"] or "*3" in first["code"]
    assert first["assembly_mode"] == "mapped"
    assert first["mapping"]["selection"]["mode"] == "lines"
    assert any(line.get("assembly") for line in first["mapping"]["excerpt"])
    assert second["cache_hit"] is True
    assert second["decompile_cache_hit"] is True
    worker_status = client.status()
    assert worker_status["active_worker_api"] == "6"
    assert worker_status["max_open_programs"] == 2
    assert worker_status["container_info"]["resources"]["memory_bytes"] == 4 * 1024**3
    inventory = cache_inventory(cfg)
    assert inventory["entry_count"] == 1
    assert inventory["entries"][0]["analysis_profile"] == ANALYSIS_PROFILE
    assert first["mapping"]["selection"]["total_lines"] >= 1
    assert second["mapping"]["confidence"] in {"exact", "nearest"}
    assert second["mapping"]["kind"] in {
        "exact", "range", "nearest-forward", "nearest-backward", "ambiguous"
    }
    assert warm_elapsed < 5.0
    def query(_):
        return client.call(
            "decompile", binary=str(binary), sha256=digest,
            rva=address - 0x400000, before=0, after=0, full=False,
            decompile_timeout=30,
        )["function"]["name"]

    concurrent_started = time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(query, range(8))) == ["focus_me"] * 8
    assert time.monotonic() - concurrent_started < 20.0

    with pytest.raises(Exception, match="sha256"):
        client.call(
            "decompile", binary=str(binary), sha256="bad",
            rva=address - 0x400000,
        )
    assert client.status()["running"] is True
    client.call("shutdown", start=False, timeout=5)

    # The JVM is disposable, the analyzed Ghidra project is durable.
    restarted = DecompClient(cfg)
    third = restarted.call(
        "decompile", binary=str(binary), sha256=digest,
        rva=address - 0x400000, before=0, after=0, full=False,
        decompile_timeout=30,
    )
    assert third["cache_hit"] is True
    restarted.call("shutdown", start=False, timeout=5)

    # A malformed durable project is deleted exactly and rebuilt from the
    # retained content-addressed binary.
    entry = cache_inventory(cfg)["entries"][0]
    project = project_dir(cfg) / f"{entry['project_name']}.gpr"
    project.write_bytes(b"truncated-ghidra-project")
    (project.with_suffix(".rep") / "project.prp").write_bytes(
        b"malformed-ghidra-repository-properties"
    )
    recovered = DecompClient(cfg).call(
        "decompile", binary=str(binary), sha256=digest,
        rva=address - 0x400000, before=0, after=0, full=False,
        decompile_timeout=30,
    )
    assert recovered["analysis"]["cache_recovery"]["rebuild"] == "succeeded"
    assert set(recovered["analysis"]["cache_recovery"]["removed_files"]) >= {
        f"{entry['project_name']}.gpr", f"{entry['project_name']}.rep",
    }
    repaired = repair_cache(cfg, sha256=digest)
    assert repaired["rebuild"] == "succeeded"
    assert repaired["binary_retained"] is True
    assert set(repaired["removed_files"]) >= {
        f"{entry['project_name']}.gpr", f"{entry['project_name']}.rep",
    }

    # A later exact source cannot overwrite already imported non-default
    # evidence. It is recorded as a conflict and the first exact names remain.
    changed = json.loads(sidecar.read_text())
    changed["functions"][0]["name"] = "hostile_function_override"
    for item in changed["globals"]:
        item["name"] = "hostile_global_override"
    sidecar.write_text(json.dumps(changed))
    conflicted = DecompClient(cfg).call(
        "prepare", binary=str(binary), binary_name="focus",
        sha256=digest, enrichment=str(sidecar), analysis_timeout=60,
        timeout=150,
    )
    assert conflicted["enrichment"]["conflicts"] >= 2
    preserved = DecompClient(cfg).call(
        "decompile", binary=str(binary), binary_name="focus",
        sha256=digest, rva=address - 0x400000,
        decompile_timeout=30, analysis_timeout=60, full=True, timeout=150,
    )
    assert preserved["function"]["name"] == "focus_me"
    DecompClient(cfg).call("shutdown", start=False, timeout=5)
