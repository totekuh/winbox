from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient
from winbox.kdbg.decomp.docker import DockerError, DockerManager


@pytest.mark.integration
def test_persistent_pyghidra_worker_decompiles_and_reuses_project(tmp_path, request):
    if shutil.which("gcc") is None or shutil.which("nm") is None:
        pytest.skip("gcc/nm unavailable")
    source = tmp_path / "focus.c"
    binary = tmp_path / "focus"
    source.write_text(
        "__attribute__((noinline)) int focus_me(int x) { return x * 3 + 7; }\n"
        "int main(void) { return focus_me(5); }\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", "-O1", "-g", "-no-pie", "-o", str(binary), str(source)],
        check=True,
    )
    symbols = subprocess.run(
        ["nm", "-n", str(binary)], check=True, text=True, capture_output=True,
    ).stdout
    address = int(next(line.split()[0] for line in symbols.splitlines() if line.endswith(" focus_me")), 16)
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
    assert "* 3" in first["code"] or "*3" in first["code"]
    assert first["assembly_mode"] == "mapped"
    assert first["mapping"]["selection"]["mode"] == "lines"
    assert any(line.get("assembly") for line in first["mapping"]["excerpt"])
    assert second["cache_hit"] is True
    assert second["decompile_cache_hit"] is True
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
