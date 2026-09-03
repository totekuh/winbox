"""Durable breakpoint-intent storage and validation."""

from __future__ import annotations

import json

import pytest

from winbox.config import Config
from winbox.kdbg.breakpoint_intent import (
    BreakpointIntentError,
    BreakpointIntentStore,
)


def _store(tmp_path) -> BreakpointIntentStore:
    return BreakpointIntentStore(Config(winbox_dir=tmp_path / ".winbox"))


def test_add_list_remove_preserves_only_symbolic_breakpoint_state(tmp_path):
    store = _store(tmp_path)
    saved = store.add(
        "MpEngine.DLL+0x00B52C40",
        condition="rcx != 0",
        actions=["rip", "ascii(rcx,96)"],
    )

    assert saved == {
        "id": 0,
        "target": "mpengine.dll+0xb52c40",
        "mode": "hw",
        "condition": "rcx != 0",
        "wp_type": None,
        "wp_size": 1,
        "actions": ["rip", "ascii(rcx,96)"],
        "created_at": saved["created_at"],
    }
    inventory = store.inventory()
    assert inventory["count"] == 1
    assert inventory["intents"] == [saved]
    assert "0x7ff" not in store.path.read_text(encoding="utf-8")
    assert store.path.stat().st_mode & 0o077 == 0

    removed = store.remove(0)
    assert removed["removed"] == saved
    assert removed["remaining"] == 0
    assert store.inventory()["intents"] == []


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target": "0x7ff700001000"}, r"module\+0xoffset"),
        ({"target": "mpengine+4096"}, r"module\+0xoffset"),
        ({"target": "mpengine+0x10", "condition": "rax === 1"}, "condition"),
        ({"target": "mpengine+0x10", "actions": [7]}, r"action\[0\]"),
        ({"target": "mpengine+0x10", "wp_type": "execute"}, "wp_type"),
    ],
)
def test_invalid_intents_are_rejected_before_publication(tmp_path, kwargs, message):
    store = _store(tmp_path)
    with pytest.raises(BreakpointIntentError, match=message):
        store.add(**kwargs)
    assert not store.path.exists()


def test_identical_intent_is_not_installed_twice_on_a_later_attach(tmp_path):
    store = _store(tmp_path)
    store.add("mpengine+0x10", wp_type="write", wp_size=4)
    with pytest.raises(BreakpointIntentError, match="identical"):
        store.add("MPENGINE+0x0010", wp_type="write", wp_size=4)
    assert store.inventory()["count"] == 1


def test_corrupt_store_fails_closed(tmp_path):
    store = _store(tmp_path)
    store.root.mkdir(parents=True)
    store.path.write_text(json.dumps({"schema": "wrong", "intents": []}))
    with pytest.raises(BreakpointIntentError, match="schema"):
        store.inventory()


def test_missing_id_is_not_silently_ignored(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(BreakpointIntentError, match="was not found"):
        store.remove(4)
