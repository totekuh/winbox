"""Tests for winbox.vm — VMState enum and disk_usage."""

from pathlib import Path

import pytest

from winbox.config import Config
from winbox.vm import VM, VMState


class TestVMState:
    def test_all_states_have_string_values(self):
        assert VMState.RUNNING.value == "running"
        assert VMState.SHUTOFF.value == "shut off"
        assert VMState.PAUSED.value == "paused"
        assert VMState.SAVED.value == "saved"
        assert VMState.NOT_FOUND.value == "not found"
        assert VMState.UNKNOWN.value == "unknown"

    def test_state_count(self):
        assert len(VMState) == 6

    def test_states_are_unique(self):
        values = [s.value for s in VMState]
        assert len(values) == len(set(values))


class TestVMDiskUsage:
    @pytest.fixture
    def vm(self, tmp_path):
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.winbox_dir.mkdir(parents=True)
        return VM(cfg)

    def test_no_disk(self, vm):
        assert vm.disk_usage() is None

    def test_small_disk(self, vm):
        vm.cfg.disk_path.write_bytes(b"\x00" * 512)
        result = vm.disk_usage()
        assert result is not None
        assert "B" in result

    def test_mb_disk(self, vm):
        # Create a sparse-ish file by seeking
        with open(vm.cfg.disk_path, "wb") as f:
            f.seek(2 * 1024 * 1024 - 1)
            f.write(b"\x00")
        result = vm.disk_usage()
        assert result is not None
        assert "MB" in result
