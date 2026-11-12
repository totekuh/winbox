"""Thread start attribution and current-vCPU mapping."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from winbox.kdbg.debugger.reader import current_snapshot, snapshot_operation
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import PageWalkError, WalkCache, read_virt_cr3
from winbox.kdbg.store import SymbolStoreError

from winbox.kdbg.walk._records import (
    CurrentVcpuRecord,
    ModuleRecord,
    ProcessRecord,
    ThreadAddressAttribution,
    ThreadRecord,
    ThreadStartAttribution,
    UserModuleRecord,
    _ThreadField,
)
from winbox.kdbg.walk import _layout
from winbox.kdbg.walk import _processes
from winbox.kdbg.walk import _modules as _walk_modules_mod

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore


def _module_containing(address: int, modules: list[ModuleRecord | UserModuleRecord]):
    for module in modules:
        if module.base <= address < module.base + module.size:
            return module
    return None


def _symbol_store_names(module: ModuleRecord | UserModuleRecord, *, kernel: bool) -> tuple[str, ...]:
    stem = module.name.rsplit(".", 1)[0].casefold()
    if kernel and module.name.casefold() in {"ntoskrnl.exe", "ntkrnlmp.exe"}:
        return ("nt", stem)
    if isinstance(module, UserModuleRecord) and module.architecture == "x86":
        return (f"{stem}_x86", stem)
    return (stem,)


def _nearest_symbol(store: SymbolStore, module: ModuleRecord | UserModuleRecord, rva: int, *, kernel: bool) -> tuple[str, int] | None:
    list_known = getattr(store, "list_modules", None)
    load = getattr(store, "load", None)
    if not callable(list_known) or not callable(load):
        return None
    try:
        available = {str(name).casefold() for name in list_known()}
    except (OSError, SymbolStoreError):
        return None
    for name in _symbol_store_names(module, kernel=kernel):
        if name.casefold() not in available:
            continue
        try:
            symbols = load(name).get("symbols", {})
        except (OSError, SymbolStoreError, ValueError, TypeError):
            continue
        nearest: tuple[int, str] | None = None
        for symbol, raw_rva in symbols.items():
            try:
                symbol_rva = int(raw_rva)
            except (TypeError, ValueError):
                continue
            if 0 <= symbol_rva <= rva and (
                nearest is None or symbol_rva > nearest[0]
            ):
                nearest = (symbol_rva, str(symbol))
        if nearest is not None:
            return nearest[1], rva - nearest[0]
    return None


def _attribute_thread_address(
    address: int,
    *,
    kernel_modules: list[ModuleRecord],
    user_modules: list[UserModuleRecord],
    store: SymbolStore,
) -> ThreadAddressAttribution:
    if address == 0:
        return ThreadAddressAttribution(address=0, mapping="null")
    kernel = address >> 48 == 0xFFFF
    module = _module_containing(address, kernel_modules if kernel else user_modules)
    if module is None:
        return ThreadAddressAttribution(
            address=address,
            mapping="kernel_unmapped" if kernel else "user_not_in_loader_module",
        )
    rva = address - module.base
    symbol = _nearest_symbol(store, module, rva, kernel=kernel)
    return ThreadAddressAttribution(
        address=address,
        mapping="kernel_module" if kernel else "user_module",
        module=module.name,
        module_base=module.base,
        module_size=module.size,
        rva=rva,
        architecture=None if kernel else module.architecture,
        symbol=symbol[0] if symbol is not None else None,
        symbol_offset=symbol[1] if symbol is not None else None,
    )


@snapshot_operation
def resolve_thread_start_addresses(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    threads: list[ThreadRecord] | tuple[ThreadRecord, ...],
    *,
    cache: WalkCache | None = None,
    kernel_modules: list[ModuleRecord] | None = None,
    user_modules: list[UserModuleRecord] | None = None,
) -> tuple[dict[int, ThreadStartAttribution], tuple[str, ...]]:
    cache = cache or WalkCache()
    warnings: list[str] = []
    if kernel_modules is None:
        try:
            kernel_modules = _walk_modules_mod.list_modules(vm_name, store, cache=cache)
        except (HmpError, PageWalkError, SymbolStoreError) as exc:
            kernel_modules = []
            warnings.append(f"kernel module attribution unavailable: {exc}")
    if user_modules is None:
        try:
            user_modules = _walk_modules_mod.list_user_modules(vm_name, store, target, cache=cache)
        except (HmpError, PageWalkError, SymbolStoreError) as exc:
            user_modules = []
            warnings.append(f"user module attribution unavailable: {exc}")
    resolved: dict[int, ThreadStartAttribution] = {}
    unmatched_user_addresses: list[int] = []
    for thread in threads:
        start = _attribute_thread_address(
            thread.start_address, kernel_modules=kernel_modules,
            user_modules=user_modules, store=store,
        )
        win32_start = _attribute_thread_address(
            thread.win32_start_address, kernel_modules=kernel_modules,
            user_modules=user_modules, store=store,
        )
        resolved[thread.ethread] = ThreadStartAttribution(start, win32_start)
        for value in (start, win32_start):
            if value.mapping == "user_not_in_loader_module" and value.address not in unmatched_user_addresses:
                unmatched_user_addresses.append(value.address)

    vad_by_address: dict[int, Any] = {}
    if unmatched_user_addresses:
        if len(unmatched_user_addresses) > 128:
            warnings.append(
                f"VAD enrichment limited to 128 of {len(unmatched_user_addresses)} unmatched user starts"
            )
        try:
            from winbox.kdbg.vad import VadError, lookup_addresses

            vad_by_address = lookup_addresses(
                vm_name, store, target, unmatched_user_addresses[:128], cache=cache,
            )
        except (
            VadError, HmpError, PageWalkError, SymbolStoreError,
            AttributeError, KeyError, TypeError, ValueError,
        ) as exc:
            warnings.append(f"VAD enrichment unavailable: {exc}")

    def add_vad(value: ThreadAddressAttribution) -> ThreadAddressAttribution:
        if value.mapping != "user_not_in_loader_module":
            return value
        if value.address not in vad_by_address:
            return replace(value, vad={"status": "not_checked"})
        record = vad_by_address[value.address]
        return replace(value, vad={
            "status": "not_found" if record is None else "mapped",
            "record": None if record is None else record.public(),
        })

    return {
        ethread: ThreadStartAttribution(
            add_vad(value.start_address), add_vad(value.win32_start_address),
        )
        for ethread, value in resolved.items()
    }, tuple(warnings)


@dataclass(frozen=True)
class _CurrentVcpuLayout:
    kpcr_self: _ThreadField
    kpcr_current_prcb: _ThreadField
    kprcb_current_thread: _ThreadField


def _current_vcpu_layout(store: SymbolStore) -> _CurrentVcpuLayout:
    kpcr = store.struct("_KPCR")
    kprcb = store.struct("_KPRCB")
    return _CurrentVcpuLayout(
        kpcr_self=_layout._thread_field(kpcr, "_KPCR", "Self", 8),
        kpcr_current_prcb=_layout._thread_field(kpcr, "_KPCR", "CurrentPrcb", 8),
        kprcb_current_thread=_layout._thread_field(
            kprcb, "_KPRCB", "CurrentThread", 8,
        ),
    )


@snapshot_operation
def list_current_vcpu_threads(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    threads: list[ThreadRecord] | tuple[ThreadRecord, ...] = (),
    cache: WalkCache | None = None,
) -> list[CurrentVcpuRecord]:
    snapshot = current_snapshot(vm_name)
    if snapshot is None:
        raise HmpError("no active RSP snapshot for current-vCPU walk")
    per_vcpu = tuple(getattr(snapshot, "vcpu_kernel_gs_bases", ()))
    if not per_vcpu:
        return []
    layout = _current_vcpu_layout(store)
    thread_layout = _layout._thread_layout(store)
    process_layout = _processes._process_layout(store)
    process_head = store.resolve("PsActiveProcessHead")
    kernel_cr3, _, selected_cache = _layout._read_kernel_list_head(vm_name, process_head, None)
    cache = cache or selected_cache
    target_threads = {thread.ethread: thread for thread in threads}
    results: list[CurrentVcpuRecord] = []

    for raw_vcpu, raw_candidates in per_vcpu:
        try:
            vcpu = int(raw_vcpu)
            candidates = tuple(int(candidate) for candidate in raw_candidates)
        except (TypeError, ValueError):
            continue
        errors: list[str] = []
        resolved: CurrentVcpuRecord | None = None
        for kpcr in candidates:
            try:
                if not _layout._is_kernel_pointer(kpcr):
                    raise HmpError(f"invalid KPCR candidate 0x{kpcr:x}")
                if _layout._read_u64(vm_name, kernel_cr3, kpcr + layout.kpcr_self.offset, cache) != kpcr:
                    raise HmpError("KPCR self pointer mismatch")
                prcb = _layout._read_u64(
                    vm_name, kernel_cr3, kpcr + layout.kpcr_current_prcb.offset, cache,
                )
                if not _layout._is_kernel_pointer(prcb):
                    raise HmpError(f"invalid KPRCB pointer 0x{prcb:x}")
                ethread = _layout._read_u64(
                    vm_name, kernel_cr3, prcb + layout.kprcb_current_thread.offset, cache,
                )
                if not _layout._is_kernel_pointer(ethread):
                    raise HmpError(f"invalid current ETHREAD pointer 0x{ethread:x}")
                owner = _layout._read_u64(
                    vm_name, kernel_cr3, ethread + thread_layout.fields["process"].offset, cache,
                )
                if not _layout._is_kernel_pointer(owner):
                    raise HmpError(f"invalid KTHREAD.Process pointer 0x{owner:x}")
                process, _ = _processes._read_process_entry(
                    vm_name, kernel_cr3, owner, process_layout, cache,
                )
                if process.eprocess != owner or process.pid < 0:
                    raise HmpError("current KTHREAD owner identity is invalid")
                cid = read_virt_cr3(
                    vm_name, kernel_cr3, ethread + thread_layout.fields["cid"].offset,
                    16, cache=cache,
                )
                if len(cid) != 16:
                    raise HmpError("short current ETHREAD CLIENT_ID read")
                client_pid = int.from_bytes(cid[:8], "little")
                tid = int.from_bytes(cid[8:], "little")
                if process.pid == 0:
                    if client_pid != 0 or tid != 0:
                        raise HmpError("idle ETHREAD CLIENT_ID is not zero")
                    resolved = CurrentVcpuRecord(
                        vcpu=vcpu,
                        status="idle",
                        ethread=ethread,
                        eprocess=owner,
                        pid=0,
                        process_name=process.name,
                        tid=0,
                    )
                    break
                if client_pid != process.pid or tid == 0:
                    raise HmpError("current ETHREAD CLIENT_ID does not match owning process")
                listed = target_threads.get(ethread)
                in_target = owner == target.eprocess
                if in_target and (listed is None or listed.tid != tid):
                    raise HmpError("current target ETHREAD is absent from validated ThreadListHead")
                resolved = CurrentVcpuRecord(
                    vcpu=vcpu,
                    status="current",
                    ethread=ethread,
                    eprocess=owner,
                    pid=process.pid,
                    process_name=process.name,
                    tid=tid,
                    in_target_process=in_target,
                )
                break
            except (HmpError, PageWalkError, SymbolStoreError) as exc:
                errors.append(f"0x{kpcr:x}: {exc}")
        if resolved is None:
            results.append(CurrentVcpuRecord(
                vcpu=vcpu,
                status="unavailable",
                reason="; ".join(errors[:2])[:512] or "no KPCR candidate",
            ))
        else:
            results.append(resolved)
    return results
