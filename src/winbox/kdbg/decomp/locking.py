"""Process- and thread-safe file locks for decompiler cache ownership."""

from __future__ import annotations

import fcntl
import json
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


_registry_guard = threading.Lock()
_process_locks: dict[str, threading.RLock] = {}
_thread_state = threading.local()


def _process_lock(path: Path) -> threading.RLock:
    key = str(path)
    with _registry_guard:
        return _process_locks.setdefault(key, threading.RLock())


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Take a re-entrant flock without treating a stale file as ownership.

    ``flock`` ownership, not the continued existence or contents of ``path``,
    is authoritative. The per-path ``RLock`` supplies the thread semantics
    that process-scoped flock alone does not, while the thread-local depth
    prevents nested lifecycle helpers from deadlocking on a second open file
    description for the same inode.
    """
    path = path.expanduser().absolute()
    key = str(path)
    process_lock = _process_lock(path)
    with process_lock:
        held = getattr(_thread_state, "held", None)
        if held is None:
            held = {}
            _thread_state.held = held
        current = held.get(key)
        if current is not None:
            handle, depth = current
            held[key] = (handle, depth + 1)
            try:
                yield
            finally:
                if depth:
                    held[key] = (handle, depth)
                else:
                    held.pop(key, None)
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        handle = path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            handle.truncate()
            handle.write(json.dumps({"pid": os.getpid()}).encode("ascii") + b"\n")
            handle.flush()
            held[key] = (handle, 1)
            try:
                yield
            finally:
                held.pop(key, None)
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
