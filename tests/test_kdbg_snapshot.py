"""Compatibility tests for the retired HMP snapshot API."""

from __future__ import annotations

from contextlib import contextmanager
import importlib

from winbox.kdbg import hmp as exported_hmp_function
import winbox.kdbg.debugger.reader as reader

hmp_mod = importlib.import_module("winbox.kdbg.hmp")


def test_paused_snapshot_delegates_to_rsp_reader(monkeypatch):
    events: list[tuple[str, str]] = []
    marker = object()

    @contextmanager
    def snapshot(vm_name):
        events.append(("enter", vm_name))
        try:
            yield marker
        finally:
            events.append(("exit", vm_name))

    monkeypatch.setattr(reader, "debug_snapshot_for_vm", snapshot)
    monkeypatch.setattr(
        hmp_mod, "hmp", lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("compatibility snapshot must not issue HMP")
        ),
    )
    with hmp_mod.paused_snapshot("box") as result:
        assert result is marker
    assert events == [("enter", "box"), ("exit", "box")]


def test_hmp_snapshot_operation_delegates_to_rsp_decorator(monkeypatch):
    events: list[str] = []

    @contextmanager
    def snapshot(vm_name):
        events.append(f"enter:{vm_name}")
        try:
            yield
        finally:
            events.append(f"exit:{vm_name}")

    monkeypatch.setattr(reader, "debug_snapshot_for_vm", snapshot)

    @hmp_mod.snapshot_operation
    def operation(vm_name, value):
        events.append(f"call:{value}")
        return value * 2

    assert operation("box", 21) == 42
    assert events == ["enter:box", "call:21", "exit:box"]


def test_public_hmp_export_remains_the_command_function():
    assert callable(exported_hmp_function)
