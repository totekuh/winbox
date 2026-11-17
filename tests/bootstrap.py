"""VM bootstrap for integration tests — direct Python API calls.

Ensures a fully prepared winbox VM exists before integration tests run.
Called from the ``bootstrapped_vm`` session fixture in conftest.py.

Two paths:
1. ``integration-ready`` snapshot exists → restore + start (~2 min)
2. Anything else → destroy, run setup pipeline, CET prepare, snapshot (~20 min)

Uses winbox internals directly — no subprocess calls to the CLI.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from winbox.config import Config
from winbox.kdbg.cet import prepare as prepare_cet
from winbox.kdbg.debugger.reader import stop_reader
from winbox.kdbg.store import SymbolStore
from winbox.setup import installer
from winbox.setup.iso import download_iso
from winbox.vm import VM, GuestAgent, VMState
from winbox.vm.virsh import virsh_run

SNAPSHOT_READY = "integration-ready"


class BootstrapError(RuntimeError):
    def __init__(self, stage: str, message: str):
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[bootstrap {ts}] {msg}", flush=True)


def _wait_stopped(vm: VM, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while vm.state() == VMState.RUNNING and time.monotonic() < deadline:
        time.sleep(2)
    if vm.state() == VMState.RUNNING:
        vm.force_stop()


def _resolve_iso(cfg: Config) -> str:
    cached = cfg.iso_dir / cfg.profile.iso_filename
    if cached.exists() and cached.stat().st_size >= cfg.profile.iso_min_size:
        _log(f"using cached ISO: {cached}")
        return str(cached)
    _log("downloading Windows ISO")
    return str(download_iso(cfg))


def _setup_pipeline(cfg: Config) -> None:
    """Run the 4-phase setup pipeline (mirrors src/winbox/cli/setup.py:193-235)."""
    iso_path = _resolve_iso(cfg)

    # Phase 1 — ISO install
    _log("phase 1: ISO install")
    installer.create_directories(cfg)
    installer.grant_libvirt_access(cfg)
    installer.download_virtio_iso(cfg)
    installer.download_openssh(cfg)
    installer.download_winfsp(cfg)
    installer.download_python(cfg)
    installer.download_python_embed(cfg)
    installer.download_runex(cfg)
    installer.download_x64dbg(cfg)
    installer.extract_virtiofs(cfg)
    installer.generate_ssh_keypair(cfg)
    installer.build_unattend_image(cfg, desktop=False)
    installer.create_disk(cfg)
    installer.run_virt_install(cfg, iso_path)

    _log("waiting for Windows install to complete (up to 20 min)")
    vm = VM(cfg)
    if not vm.wait_shutdown(timeout=1200):
        raise BootstrapError("setup", "Windows install timed out — VM did not shut down")
    _log("phase 1 complete")

    # Phase 2 — Offline provisioning
    _log("phase 2: offline provisioning")
    installer.provision_vm_disk(cfg)

    # Phase 3 — Online provisioning (boots VM, runs provision.ps1 via GA)
    _log("phase 3: online provisioning")
    installer.boot_for_provisioning(cfg)

    # Phase 4 — Network filter + clean snapshot
    _log("phase 4: nwfilter + snapshot")
    installer.register_nwfilter(cfg)
    installer.attach_default_filter(cfg)
    installer.create_clean_snapshot(cfg)
    _log("setup pipeline complete")


def _prepare_cet(cfg: Config) -> None:
    """Start VM, disable CET, reboot for changes to take effect."""
    vm = VM(cfg)
    vm.start()
    ga = GuestAgent(cfg)
    _log("waiting for guest agent")
    ga.wait(timeout=420)

    _log("disabling CET")
    stop_reader(cfg)
    prepare_cet(cfg, ga)

    _log("rebooting for CET changes")
    try:
        ga.exec("shutdown /r /t 0", timeout=10)
    except Exception:
        pass
    time.sleep(15)
    ga.wait(timeout=420)
    _log("CET disabled, VM rebooted")


def _create_ready_snapshot(cfg: Config) -> None:
    """Shut down and snapshot for fast future restores."""
    vm = VM(cfg)
    ga = GuestAgent(cfg)
    _log(f"creating '{SNAPSHOT_READY}' snapshot")
    ga.shutdown()
    _wait_stopped(vm)
    vm.snapshot_create(SNAPSHOT_READY)

    _log("starting VM from snapshot")
    vm.start()
    ga.wait(timeout=420)


def restore_snapshot(name: str) -> None:
    """Restore a named snapshot and start the VM."""
    cfg = Config.load()
    vm = VM(cfg)
    _log(f"restoring snapshot '{name}'")
    vm.snapshot_revert(name)
    vm.start()
    GuestAgent(cfg).wait(timeout=420)


def _fresh_setup() -> None:
    """Destroy everything and build from scratch."""
    winbox_dir = Path.home() / ".winbox"
    cfg = Config(winbox_dir=winbox_dir)

    # Destroy existing VM
    try:
        vm = VM(cfg)
        if vm.exists():
            _log("destroying existing VM")
            vm.destroy()
    except Exception:
        pass

    # Persist config
    winbox_dir.mkdir(parents=True, exist_ok=True)
    cfg.persist("VM_OS", "server2022")
    cfg.persist("VM_DISPLAY", "vnc")
    cfg = Config.load()

    _setup_pipeline(cfg)
    _prepare_cet(cfg)
    _create_ready_snapshot(cfg)


def clean_stale_kdbg() -> None:
    """Stop leftover reader, clear stale nt base, reset pagewalk override."""
    try:
        cfg = Config.load()
    except Exception:
        return
    try:
        stop_reader(cfg)
    except Exception:
        pass
    try:
        from winbox.kdbg.debugger.daemon import force_stop_daemon
        force_stop_daemon(cfg)
    except Exception:
        pass
    try:
        store = SymbolStore(cfg.symbols_dir)
        if "nt" in store.list_modules():
            data = store.load("nt")
            if data.get("base") is not None:
                store.set_base("nt", 0)
                _log("cleared stale nt base from symbol store")
    except Exception:
        pass
    try:
        config_path = cfg.winbox_dir / "config"
        if config_path.exists():
            lines = config_path.read_text().splitlines()
            cleaned = [l for l in lines if not l.startswith("KDBG_PAGEWALK=")]
            if len(cleaned) != len(lines):
                config_path.write_text("\n".join(cleaned) + "\n" if cleaned else "")
                _log("removed stale KDBG_PAGEWALK override from config")
    except Exception:
        pass


def bootstrap() -> None:
    """Get from any VM state to a fully ready integration test environment."""
    started = time.monotonic()
    _log("starting")

    # Fast path: integration-ready snapshot exists
    try:
        cfg = Config.load()
        vm = VM(cfg)
        if SNAPSHOT_READY in vm.snapshot_list():
            _log(f"found '{SNAPSHOT_READY}' snapshot")
            vm.snapshot_revert(SNAPSHOT_READY)
            vm.start()
            ga = GuestAgent(cfg)
            ga.wait(timeout=420)
            elapsed = time.monotonic() - started
            _log(f"ready (restored in {elapsed:.0f}s)")
            return
    except Exception:
        pass

    # Cold path
    _fresh_setup()
    elapsed = time.monotonic() - started
    _log(f"ready (fresh setup in {elapsed:.0f}s)")
