from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from winbox.kdbg.decomp.locking import exclusive_file_lock, _process_lock


def test_exclusive_file_lock_creates_lock_with_pid(tmp_path):
    lock_path = tmp_path / "test.lock"
    with exclusive_file_lock(lock_path):
        content = json.loads(lock_path.read_text(encoding="ascii"))
        assert content == {"pid": os.getpid()}


def test_exclusive_file_lock_is_reentrant(tmp_path):
    lock_path = tmp_path / "test.lock"
    inner_ran = False
    with exclusive_file_lock(lock_path):
        with exclusive_file_lock(lock_path):
            inner_ran = True
    assert inner_ran
    assert lock_path.exists()
    handle = lock_path.open("rb")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def test_exclusive_file_lock_serializes_threads(tmp_path):
    lock_path = tmp_path / "test.lock"
    guard = threading.Lock()
    active = 0
    maximum = 0

    def work(_):
        nonlocal active, maximum
        with exclusive_file_lock(lock_path):
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.02)
            with guard:
                active -= 1

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(work, range(8)))
    assert maximum == 1


def test_exclusive_file_lock_creates_parent_dirs(tmp_path):
    lock_path = tmp_path / "deep" / "nested" / "test.lock"
    with exclusive_file_lock(lock_path):
        pass
    parent = lock_path.parent
    assert parent.is_dir()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700


def test_process_lock_deduplication(tmp_path):
    path = tmp_path / "test.lock"
    lock1 = _process_lock(path)
    lock2 = _process_lock(path)
    assert lock1 is lock2
