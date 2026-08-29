"""Non-queueing admission and timing contracts for expensive kdbg work."""

from __future__ import annotations

import pytest

from winbox.config import Config
from winbox.kdbg.admission import OperationBusyError, active_admission, admit_operation
from winbox.kdbg.decomp.client import DecompClient, DecompError


def test_admission_is_immediate_visible_and_cleans_up(tmp_path):
    root = tmp_path / "runtime"
    with admit_operation(
        root, "reader", operation="snapshot", owner="persistent_reader",
        details={"vm_name": "winbox"},
    ) as lease:
        active = active_admission(root, "reader")
        assert active and active["id"] == lease.token
        assert active["operation"] == "snapshot"
        with pytest.raises(OperationBusyError) as captured:
            with admit_operation(
                root, "reader", operation="snapshot", owner="persistent_reader",
            ):
                pytest.fail("busy admission must never queue")
        assert captured.value.code == "busy"
        assert captured.value.details["active"]["id"] == lease.token
        metadata = lease.metadata()
        assert metadata["admission"] == "accepted"
        assert metadata["queue_delay_ms"] == 0.0
    assert active_admission(root, "reader") is None


def test_decomp_client_reports_busy_without_touching_the_worker(monkeypatch, tmp_path):
    cfg = Config(winbox_dir=tmp_path / "state")
    client = DecompClient(cfg)
    monkeypatch.setattr(client, "_call", lambda *_args, **_kwargs: {"ok": True})

    with admit_operation(
        tmp_path / "state" / "decomp", "decomp-api6",
        operation="prepare", owner="decomp_worker",
    ):
        with pytest.raises(DecompError) as captured:
            client.call("prepare", binary_name="sample.exe", sha256="a" * 64)
    assert captured.value.code == "busy"
    assert captured.value.retryable is True
    assert captured.value.details["requested_operation"] == "prepare"

    result = client.call("prepare", binary_name="sample.exe", sha256="a" * 64)
    assert result["operation_metadata"]["operation"] == "prepare"
    assert result["operation_metadata"]["admission"] == "accepted"
