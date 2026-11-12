"""Process list walking via PsActiveProcessHead."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Iterator

from winbox.kdbg.debugger.reader import snapshot_operation
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import PageWalkError, WalkCache, read_virt_cr3

from winbox.kdbg.walk._records import (
    MAX_PROCESSES,
    ProcessRecord,
    ProcessWalkResult,
    ProcessWalkTruncation,
    _ProcessLayout,
)
from winbox.kdbg.walk import _layout
from winbox.kdbg.walk._records import _ProcessSpan

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore

logger = logging.getLogger(__name__)


def _process_layout(store: SymbolStore) -> _ProcessLayout:
    _layout._require_x64_four_level_store(store)
    eproc = _layout._layout_struct(store, "_EPROCESS")
    kproc = _layout._layout_struct(store, "_KPROCESS")
    pcb = _layout._layout_field(eproc, "_EPROCESS", "Pcb", 1)
    if pcb.offset != 0:
        raise HmpError(
            f"unsupported _EPROCESS.Pcb offset 0x{pcb.offset:x} — "
            "refusing to treat PKPROCESS offsets as EPROCESS offsets"
        )
    active_links = _layout._layout_field(eproc, "_EPROCESS", "ActiveProcessLinks", 16).offset
    image_name = _layout._layout_field(eproc, "_EPROCESS", "ImageFileName", 15).offset
    pid = _layout._layout_field(eproc, "_EPROCESS", "UniqueProcessId", 8).offset
    dtb = _layout._layout_field(kproc, "_KPROCESS", "DirectoryTableBase", 8).offset
    kproc_fields = kproc["fields"]
    raw_user_dtb = kproc_fields.get("UserDirectoryTableBase", {}).get("off")
    user_dtb = (
        _layout._layout_field(kproc, "_KPROCESS", "UserDirectoryTableBase", 8).offset
        if raw_user_dtb is not None else None
    )
    eproc_fields = eproc["fields"]
    raw_create_time = eproc_fields.get("CreateTime", {}).get("off")
    raw_exit_time = eproc_fields.get("ExitTime", {}).get("off")
    create_time = (
        _layout._layout_field(eproc, "_EPROCESS", "CreateTime", 8).offset
        if raw_create_time is not None else None
    )
    exit_time = (
        _layout._layout_field(eproc, "_EPROCESS", "ExitTime", 8).offset
        if raw_exit_time is not None else None
    )

    fields = [(active_links, 16), (image_name, 15), (pid, 8), (dtb, 8)]
    if user_dtb is not None:
        fields.append((user_dtb, 8))
    if create_time is not None:
        fields.append((create_time, 8))
    if exit_time is not None:
        fields.append((exit_time, 8))
    field_start = min(offset for offset, _ in fields)
    field_end = max(offset + size for offset, size in fields)
    eproc_size = _layout._layout_int(eproc.get("size"), "_EPROCESS.size")
    if field_start < 0 or field_end <= field_start:
        raise HmpError("invalid negative/empty EPROCESS field span")
    if field_end > eproc_size:
        raise HmpError(
            f"EPROCESS field span 0x{field_start:x}-0x{field_end:x} exceeds "
            f"struct size 0x{eproc_size:x}"
        )
    if field_end - field_start > 0x10000:
        raise HmpError(
            f"EPROCESS field span is implausibly large: 0x{field_end - field_start:x}"
        )

    spans: list[_ProcessSpan] = []
    for offset, size in sorted(fields):
        if spans and offset <= spans[-1].start + spans[-1].size + 32:
            previous = spans[-1]
            end = max(previous.start + previous.size, offset + size)
            spans[-1] = _ProcessSpan(previous.start, end - previous.start)
        else:
            spans.append(_ProcessSpan(offset, size))
    return _ProcessLayout(
        active_links=active_links,
        image_name=image_name,
        pid=pid,
        dtb=dtb,
        user_dtb=user_dtb,
        create_time=create_time,
        exit_time=exit_time,
        spans=tuple(spans),
    )


def _read_process_entry(
    vm_name: str,
    cr3: int,
    eprocess: int,
    layout: _ProcessLayout,
    cache: WalkCache,
) -> tuple[ProcessRecord, int]:
    chunks: list[tuple[_ProcessSpan, bytes]] = []
    for span in layout.spans:
        raw = read_virt_cr3(
            vm_name, cr3, eprocess + span.start, span.size, cache=cache,
        )
        if len(raw) != span.size:
            raise HmpError(
                f"short EPROCESS read at 0x{eprocess + span.start:x}: "
                f"expected {span.size}, got {len(raw)}"
            )
        chunks.append((span, raw))

    def field(offset: int, size: int) -> bytes:
        for span, raw in chunks:
            if span.start <= offset and offset + size <= span.start + span.size:
                start = offset - span.start
                return raw[start:start + size]
        raise HmpError(f"EPROCESS field at +0x{offset:x} is outside read spans")

    pid = int.from_bytes(field(layout.pid, 8), "little")
    dtb = int.from_bytes(field(layout.dtb, 8), "little")
    name = field(layout.image_name, 15).split(b"\x00", 1)[0].decode(
        "latin-1", errors="replace",
    )
    next_flink = int.from_bytes(field(layout.active_links, 8), "little")
    user_dtb = 0
    if layout.user_dtb is not None:
        raw_user_dtb = int.from_bytes(field(layout.user_dtb, 8), "little")
        if (
            raw_user_dtb != 0
            and (raw_user_dtb & 0xFFF) == 0
            and raw_user_dtb < (1 << 52)
        ):
            user_dtb = raw_user_dtb
    create_time = (
        int.from_bytes(field(layout.create_time, 8), "little")
        if layout.create_time is not None else 0
    )
    exit_time = (
        int.from_bytes(field(layout.exit_time, 8), "little")
        if layout.exit_time is not None else 0
    )
    return ProcessRecord(
        pid=pid,
        name=name,
        eprocess=eprocess,
        directory_table_base=dtb,
        user_directory_table_base=user_dtb,
        create_time=create_time,
        exit_time=exit_time,
    ), next_flink


def _iter_processes(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> Iterator[ProcessRecord]:
    explicit_cr3 = cr3
    head = store.resolve("PsActiveProcessHead")
    layout = _process_layout(store)
    cr3, flink, cache = _layout._read_kernel_list_head(vm_name, head, explicit_cr3)
    count = 0
    seen: set[int] = set()
    while flink != head and flink != 0 and count < MAX_PROCESSES:
        if flink in seen:
            break
        seen.add(flink)
        eproc = flink - layout.active_links
        try:
            record, next_flink = _read_process_entry(
                vm_name, cr3, eproc, layout, cache,
            )
        except (HmpError, PageWalkError) as e:
            logger.warning(
                "list_processes: walk truncated at EPROCESS 0x%x (%d returned): %s",
                eproc, count, e,
            )
            break
        count += 1
        if count == 1 and record.pid == 4 and record.directory_table_base != cr3:
            cr3 = record.directory_table_base
            cache = WalkCache()
        if record.pid == 4 and explicit_cr3 is None:
            _layout._remember_kernel_cr3(vm_name, record.directory_table_base)
        yield record
        flink = next_flink
    if count >= MAX_PROCESSES:
        logger.warning(
            "list_processes: hit MAX_PROCESSES=%d cap; result is truncated",
            MAX_PROCESSES,
        )


@snapshot_operation
def list_processes(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ProcessRecord]:
    """Walk ``PsActiveProcessHead`` and return every live process."""
    return list(_iter_processes(vm_name, store, cr3=cr3, cache=cache))


@snapshot_operation
def list_processes_detailed(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> ProcessWalkResult:
    head = store.resolve("PsActiveProcessHead")
    layout = _process_layout(store)
    cr3, flink, cache = _layout._read_kernel_list_head(vm_name, head, cr3)
    records: list[ProcessRecord] = []
    seen: set[int] = set()

    def partial(
        stage: str, reason: str, *, link: int | None = None, eprocess: int | None = None,
    ) -> ProcessWalkResult:
        return ProcessWalkResult(
            records, False, reason,
            ProcessWalkTruncation(
                stage=stage, reason=reason, returned=len(records),
                link=link, eprocess=eprocess,
            ),
        )

    while flink != head:
        if flink == 0:
            return partial("link", "PsActiveProcessHead contained a null link", link=flink)
        if not _layout._is_kernel_pointer(flink):
            return partial("link", f"invalid EPROCESS list pointer 0x{flink:x}", link=flink)
        if flink in seen:
            return partial("link", f"cycle detected at EPROCESS list entry 0x{flink:x}", link=flink)
        if len(records) >= MAX_PROCESSES:
            return partial("cap", f"hit MAX_PROCESSES={MAX_PROCESSES}", link=flink)
        seen.add(flink)
        eprocess = flink - layout.active_links
        if not _layout._is_kernel_pointer(eprocess):
            return partial(
                "entry", f"invalid EPROCESS pointer 0x{eprocess:x}",
                link=flink, eprocess=eprocess,
            )
        try:
            record, flink = _read_process_entry(vm_name, cr3, eprocess, layout, cache)
        except (HmpError, PageWalkError) as exc:
            return partial("entry", str(exc), link=flink, eprocess=eprocess)
        records.append(record)
        if len(records) == 1 and record.pid == 4 and record.directory_table_base != cr3:
            cr3 = record.directory_table_base
            cache = WalkCache()
        if record.pid == 4 and cr3 is not None:
            _layout._remember_kernel_cr3(vm_name, record.directory_table_base)
    return ProcessWalkResult(records, True)


@snapshot_operation
def find_process(
    vm_name: str,
    store: SymbolStore,
    *,
    pid: int | None = None,
    name: str | None = None,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> ProcessRecord | None:
    wanted_name = name.lower()[:15] if name is not None else None
    for proc in _iter_processes(vm_name, store, cr3=cr3, cache=cache):
        if pid is not None and proc.pid == pid:
            return proc
        if wanted_name is not None and proc.name.lower() == wanted_name:
            return proc
    return None


@snapshot_operation
def read_process_identity(
    vm_name: str,
    store: SymbolStore,
    *,
    eprocess: int,
    cache: WalkCache | None = None,
) -> ProcessRecord:
    if not isinstance(eprocess, int) or eprocess <= 0:
        raise HmpError("invalid captured EPROCESS address")
    layout = _process_layout(store)
    head = store.resolve("PsActiveProcessHead")
    kernel_cr3, _, selected_cache = _layout._read_kernel_list_head(vm_name, head, None)
    record, _ = _read_process_entry(
        vm_name, kernel_cr3, eprocess, layout, cache or selected_cache,
    )
    return record
