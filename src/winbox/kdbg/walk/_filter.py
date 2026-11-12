"""Thread selection, filtering, and sorting."""

from __future__ import annotations

from winbox.kdbg.walk._records import (
    ThreadFilterError,
    ThreadRecord,
    ThreadSelection,
    _KTHREAD_STATES,
    _KWAIT_REASONS,
)


_THREAD_SORTS = {
    "tid", "state", "wait", "priority", "context-switches", "start",
    "win32-start", "create-time",
}


def _enum_filter(value: str | int | None, names: dict[int, str], label: str) -> int | None:
    """Parse a raw or symbolic scheduler filter without version guessing."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ThreadFilterError(f"{label} must be a raw byte or known enum name")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        try:
            parsed = int(text, 0)
        except ValueError:
            wanted = "".join(char for char in text.casefold() if char.isalnum())
            matches = [
                raw for raw, name in names.items()
                if "".join(char for char in name.casefold() if char.isalnum()) == wanted
            ]
            if len(matches) != 1:
                choices = ", ".join(names.values())
                raise ThreadFilterError(
                    f"invalid {label} {value!r}; use a raw byte or one of: {choices}"
                )
            return matches[0]
    else:
        raise ThreadFilterError(f"{label} must be a raw byte or known enum name")
    if not 0 <= parsed <= 0xFF:
        raise ThreadFilterError(f"{label} raw value must be between 0 and 255")
    return parsed


def select_threads(
    threads: list[ThreadRecord],
    *,
    state: str | int | None = None,
    wait_reason: str | int | None = None,
    sort: str = "tid",
    limit: int = 256,
) -> ThreadSelection:
    """Filter/sort a raw thread walk and intentionally bound returned rows."""
    wanted_state = _enum_filter(state, _KTHREAD_STATES, "state")
    wanted_wait = _enum_filter(wait_reason, _KWAIT_REASONS, "wait_reason")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1024:
        raise ThreadFilterError("limit must be an integer between 1 and 1024")
    sort = sort.strip().lower()
    if sort not in _THREAD_SORTS:
        choices = ", ".join(sorted(_THREAD_SORTS))
        raise ThreadFilterError(f"sort must be one of: {choices}")

    state_counts: dict[str, int] = {}
    wait_counts: dict[str, int] = {}
    for thread in threads:
        state_key = thread.state_name or f"unknown({thread.state})"
        state_counts[state_key] = state_counts.get(state_key, 0) + 1
        if thread.state == 5:
            wait_key = thread.wait_reason_name or f"unknown({thread.wait_reason})"
            wait_counts[wait_key] = wait_counts.get(wait_key, 0) + 1

    matched = [
        thread for thread in threads
        if (wanted_state is None or thread.state == wanted_state)
        and (
            wanted_wait is None
            or (thread.state == 5 and thread.wait_reason == wanted_wait)
        )
    ]
    if sort == "tid":
        matched.sort(key=lambda thread: (thread.tid, thread.ethread))
    elif sort == "state":
        matched.sort(key=lambda thread: (thread.state, thread.tid, thread.ethread))
    elif sort == "wait":
        matched.sort(key=lambda thread: (thread.state != 5, thread.wait_reason, thread.tid))
    elif sort == "priority":
        matched.sort(key=lambda thread: (-thread.priority, thread.tid, thread.ethread))
    elif sort == "context-switches":
        matched.sort(key=lambda thread: (-thread.context_switches, thread.tid, thread.ethread))
    elif sort == "start":
        matched.sort(key=lambda thread: (thread.start_address, thread.tid, thread.ethread))
    elif sort == "win32-start":
        matched.sort(key=lambda thread: (thread.win32_start_address, thread.tid, thread.ethread))
    else:  # create-time
        matched.sort(key=lambda thread: (thread.create_time, thread.tid, thread.ethread))

    return ThreadSelection(
        threads=tuple(matched[:limit]),
        total_count=len(threads),
        matched_count=len(matched),
        filtered_out=len(threads) - len(matched),
        output_truncated=len(matched) > limit,
        state_counts=state_counts,
        wait_reason_counts=wait_counts,
    )
