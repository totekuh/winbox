"""PDB layout validation, compat shims, thread/wait layout, and kernel CR3."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from winbox.kdbg.debugger.reader import current_snapshot
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import (
    PageWalkError,
    WalkCache,
    read_cstr,
    read_u32,
    read_u64,
    read_unicode_string,
    read_virt_cr3,
)
from winbox.kdbg.store import SymbolStoreError

from winbox.kdbg.walk._records import (
    _MAX_PDB_STRUCT_SIZE,
    _ProcessSpan,
    _ThreadField,
    _ThreadLayout,
    _WaitLayout,
)

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore

logger = logging.getLogger(__name__)


_kernel_cr3_by_vm: dict[str, int] = {}
_kernel_cr3_lock = threading.Lock()


def _read_u64(vm_name: str, cr3: int, va: int, cache: WalkCache) -> int:
    return read_u64(vm_name, cr3, va, cache)


def _read_u32(vm_name: str, cr3: int, va: int, cache: WalkCache) -> int:
    return read_u32(vm_name, cr3, va, cache)


def _read_cstr(
    vm_name: str,
    cr3: int,
    va: int,
    length: int,
    cache: WalkCache,
) -> str:
    return read_cstr(vm_name, cr3, va, length, cache)


def _read_unicode_string(
    vm_name: str,
    cr3: int,
    va: int,
    store: SymbolStore,
    cache: WalkCache,
) -> str:
    layout = _layout_struct(store, "_UNICODE_STRING")
    return read_unicode_string(
        vm_name, cr3, va,
        length_off=_layout_field(layout, "_UNICODE_STRING", "Length", 2).offset,
        buffer_off=_layout_field(layout, "_UNICODE_STRING", "Buffer", 8).offset,
        cache=cache,
    )


def _layout_int(raw: object, label: str, *, maximum: int = _MAX_PDB_STRUCT_SIZE) -> int:
    if isinstance(raw, bool):
        raise SymbolStoreError(f"invalid {label} in nt types")
    try:
        value = int(raw, 0) if isinstance(raw, str) else int(raw)
    except (TypeError, ValueError) as exc:
        raise SymbolStoreError(f"invalid {label} in nt types") from exc
    if not 0 <= value <= maximum:
        raise SymbolStoreError(f"implausible {label} 0x{value:x} in nt types")
    return value


def _layout_struct(store: SymbolStore, name: str) -> dict[str, Any]:
    try:
        layout = store.struct(name)
    except (KeyError, TypeError, ValueError, SymbolStoreError) as exc:
        raise SymbolStoreError(
            f"{name} is absent or malformed in nt types — re-run `winbox kdbg symbols`"
        ) from exc
    if not isinstance(layout, dict) or not isinstance(layout.get("fields"), dict):
        raise SymbolStoreError(f"invalid {name} layout in nt types")
    size = _layout_int(layout.get("size"), f"{name}.size")
    if size == 0:
        raise SymbolStoreError(f"invalid zero {name}.size in nt types")
    return layout


def _field_declared_width(entry: object) -> int | None:
    if not isinstance(entry, dict):
        return None
    hint = entry.get("type")
    if not isinstance(hint, str) or not hint.strip():
        return None
    normalized = " ".join(hint.casefold().replace("*", " * ").split())
    if "[" in normalized or "]" in normalized:
        return None
    if "*" in normalized:
        return 8
    if "__int64" in normalized or "long long" in normalized:
        return 8
    if "short" in normalized or "wchar_t" in normalized:
        return 2
    if "char" in normalized or "bool" in normalized:
        return 1
    if "long" in normalized or normalized in {"int", "unsigned int"}:
        return 4
    return None


def _layout_field(
    layout: dict[str, Any],
    struct_name: str,
    field_name: str,
    size: int,
    *,
    base: int = 0,
) -> _ThreadField:
    fields = layout.get("fields")
    entry = fields.get(field_name) if isinstance(fields, dict) else None
    if not isinstance(entry, dict) or "off" not in entry:
        raise SymbolStoreError(
            f"{struct_name}.{field_name} is absent from nt types — "
            "re-run `winbox kdbg symbols`"
        )
    relative_offset = _layout_int(entry.get("off"), f"{struct_name}.{field_name}.off")
    struct_size = _layout_int(layout.get("size"), f"{struct_name}.size")
    if size <= 0 or relative_offset + size > struct_size:
        raise SymbolStoreError(f"invalid {struct_name}.{field_name} span in nt types")
    declared_width = _field_declared_width(entry)
    if declared_width is not None and declared_width != size:
        raise SymbolStoreError(
            f"{struct_name}.{field_name} declares {declared_width} bytes, "
            f"expected {size}"
        )
    offset = relative_offset + base
    if offset < base or offset > _MAX_PDB_STRUCT_SIZE:
        raise SymbolStoreError(f"invalid {struct_name}.{field_name} offset in nt types")
    return _ThreadField(field_name, offset, size)


def _require_x64_four_level_store(store: SymbolStore) -> None:
    load = getattr(store, "load", None)
    if not callable(load):
        return
    try:
        data = load("nt")
    except (OSError, ValueError, TypeError, SymbolStoreError) as exc:
        raise SymbolStoreError("cannot validate nt symbol-store architecture") from exc
    if not isinstance(data, dict):
        raise SymbolStoreError("invalid nt symbol-store record")
    architecture = str(data.get("architecture") or "").casefold()
    if architecture not in {"x64", "amd64"}:
        raise SymbolStoreError(
            f"unsupported nt symbol-store architecture {architecture or 'unknown'!r}; "
            "this walker requires x64 four-level paging"
        )


def _thread_field(
    struct: dict,
    struct_name: str,
    field_name: str,
    size: int,
    *,
    base: int = 0,
) -> _ThreadField:
    return _layout_field(struct, struct_name, field_name, size, base=base)


def _compact_spans(fields: list[_ThreadField]) -> tuple[_ProcessSpan, ...]:
    spans: list[_ProcessSpan] = []
    for field in sorted(fields, key=lambda value: value.offset):
        if spans and field.offset <= spans[-1].start + spans[-1].size + 32:
            previous = spans[-1]
            end = max(previous.start + previous.size, field.offset + field.size)
            spans[-1] = _ProcessSpan(previous.start, end - previous.start)
        else:
            spans.append(_ProcessSpan(field.offset, field.size))
    return tuple(spans)


def _thread_layout(store: SymbolStore) -> _ThreadLayout:
    _require_x64_four_level_store(store)
    eproc = _layout_struct(store, "_EPROCESS")
    ethread = _layout_struct(store, "_ETHREAD")
    kthread = _layout_struct(store, "_KTHREAD")
    thread_list_head = _layout_field(
        eproc, "_EPROCESS", "ThreadListHead", 16,
    ).offset

    pcb = _layout_field(eproc, "_EPROCESS", "Pcb", 1)
    eprocess_pcb = pcb.offset
    if eprocess_pcb != 0:
        raise SymbolStoreError(
            f"unsupported _EPROCESS.Pcb offset 0x{eprocess_pcb:x} — "
            "refusing to equate PKPROCESS with EPROCESS"
        )

    tcb = _layout_field(ethread, "_ETHREAD", "Tcb", 1).offset
    if tcb != 0:
        raise SymbolStoreError(
            f"unsupported _ETHREAD.Tcb offset 0x{tcb:x} — refusing to guess KTHREAD base"
        )
    ethread_size = _layout_int(ethread.get("size"), "_ETHREAD.size")
    kthread_size = _layout_int(kthread.get("size"), "_KTHREAD.size")
    if kthread_size > ethread_size:
        raise SymbolStoreError("_KTHREAD exceeds _ETHREAD in nt types")

    fields = {
        "thread_list_entry": _thread_field(
            ethread, "_ETHREAD", "ThreadListEntry", 16,
        ),
        "cid": _thread_field(ethread, "_ETHREAD", "Cid", 16),
        "start_address": _thread_field(ethread, "_ETHREAD", "StartAddress", 8),
        "win32_start_address": _thread_field(
            ethread, "_ETHREAD", "Win32StartAddress", 8,
        ),
        "create_time": _thread_field(ethread, "_ETHREAD", "CreateTime", 8),
        "exit_status": _thread_field(ethread, "_ETHREAD", "ExitStatus", 4),
        "state": _thread_field(kthread, "_KTHREAD", "State", 1, base=tcb),
        "wait_reason": _thread_field(
            kthread, "_KTHREAD", "WaitReason", 1, base=tcb,
        ),
        "priority": _thread_field(kthread, "_KTHREAD", "Priority", 1, base=tcb),
        "base_priority": _thread_field(
            kthread, "_KTHREAD", "BasePriority", 1, base=tcb,
        ),
        "context_switches": _thread_field(
            kthread, "_KTHREAD", "ContextSwitches", 4, base=tcb,
        ),
        "teb": _thread_field(kthread, "_KTHREAD", "Teb", 8, base=tcb),
        "kernel_stack": _thread_field(
            kthread, "_KTHREAD", "KernelStack", 8, base=tcb,
        ),
        "stack_limit": _thread_field(
            kthread, "_KTHREAD", "StackLimit", 8, base=tcb,
        ),
        "stack_base": _thread_field(
            kthread, "_KTHREAD", "StackBase", 8, base=tcb,
        ),
        "process": _thread_field(kthread, "_KTHREAD", "Process", 8, base=tcb),
    }
    return _ThreadLayout(
        thread_list_head=thread_list_head,
        thread_list_entry=fields["thread_list_entry"].offset,
        eprocess_pcb=eprocess_pcb,
        fields=fields,
        spans=_compact_spans(list(fields.values())),
    )


def _wait_layout(store: SymbolStore) -> _WaitLayout:
    thread = _thread_layout(store)
    kthread = _layout_struct(store, "_KTHREAD")
    wait_block = _layout_struct(store, "_KWAIT_BLOCK")
    header = _layout_struct(store, "_DISPATCHER_HEADER")
    mutant = _layout_struct(store, "_KMUTANT")
    return _WaitLayout(
        thread=thread,
        wait_block_list=_layout_field(kthread, "_KTHREAD", "WaitBlockList", 8),
        embedded_wait_block=_layout_field(kthread, "_KTHREAD", "WaitBlock", 1).offset,
        wait_block_thread=_layout_field(wait_block, "_KWAIT_BLOCK", "Thread", 8),
        wait_block_object=_layout_field(wait_block, "_KWAIT_BLOCK", "Object", 8),
        dispatcher_type=_layout_field(header, "_DISPATCHER_HEADER", "Type", 1),
        mutant_owner_thread=_layout_field(mutant, "_KMUTANT", "OwnerThread", 8),
    )


def _is_kernel_pointer(value: int) -> bool:
    return value != 0 and value & 0x7 == 0 and value >> 48 == 0xFFFF


def _cpu_cr3(vm_name: str) -> int:
    snapshot = current_snapshot(vm_name)
    if snapshot is None:
        raise HmpError("no active RSP snapshot for CR3 read")
    return snapshot.current_cr3


def _cpu_cr3_candidates(vm_name: str) -> list[int]:
    snapshot = current_snapshot(vm_name)
    if snapshot is None:
        raise HmpError("no active RSP snapshot for vCPU CR3 reads")
    candidates = list(snapshot.cr3_candidates)
    if not candidates:
        raise HmpError("gdbstub returned no vCPU CR3 candidates")
    return candidates


def _cached_kernel_cr3(vm_name: str) -> int | None:
    with _kernel_cr3_lock:
        return _kernel_cr3_by_vm.get(vm_name)


def _remember_kernel_cr3(vm_name: str, cr3: int) -> None:
    if cr3 == 0 or cr3 & 0xFFF or cr3 >= (1 << 52):
        return
    with _kernel_cr3_lock:
        _kernel_cr3_by_vm[vm_name] = cr3


def _forget_kernel_cr3(vm_name: str, cr3: int | None = None) -> None:
    with _kernel_cr3_lock:
        if cr3 is None or _kernel_cr3_by_vm.get(vm_name) == cr3:
            _kernel_cr3_by_vm.pop(vm_name, None)


def _kernel_read_candidates(vm_name: str, explicit_cr3: int | None) -> list[int]:
    if explicit_cr3 is not None:
        sampled = [explicit_cr3]
    else:
        sampled = _cpu_cr3_candidates(vm_name)

    candidates: list[int] = []
    for candidate in sampled:
        for variant in (candidate, candidate ^ 0x1000):
            if variant not in candidates:
                candidates.append(variant)
    return candidates


def _read_kernel_list_head(
    vm_name: str,
    head: int,
    explicit_cr3: int | None,
) -> tuple[int, int, WalkCache]:
    def valid_flink(flink: int) -> bool:
        return (
            flink not in (0, head)
            and flink & 0x7 == 0
            and flink >> 48 == 0xFFFF
        )

    cached = None if explicit_cr3 is not None else _cached_kernel_cr3(vm_name)
    last_error: HmpError | None = None
    if cached is not None:
        for candidate in (cached, cached ^ 0x1000):
            candidate_cache = WalkCache()
            try:
                flink = _read_u64(vm_name, candidate, head, candidate_cache)
            except (HmpError, PageWalkError) as exc:
                last_error = exc
                continue
            if not valid_flink(flink):
                last_error = HmpError(
                    f"invalid kernel list pointer 0x{flink:x} via CR3 0x{candidate:x}"
                )
                continue
            return candidate, flink, candidate_cache
        _forget_kernel_cr3(vm_name, cached)

    for candidate in _kernel_read_candidates(vm_name, explicit_cr3):
        candidate_cache = WalkCache()
        try:
            flink = _read_u64(vm_name, candidate, head, candidate_cache)
        except (HmpError, PageWalkError) as exc:
            last_error = exc
            continue
        if not valid_flink(flink):
            last_error = HmpError(
                f"invalid kernel list pointer 0x{flink:x} via CR3 0x{candidate:x}"
            )
            continue
        return candidate, flink, candidate_cache
    if last_error is not None:
        raise last_error
    raise HmpError("no kernel CR3 candidates available")
