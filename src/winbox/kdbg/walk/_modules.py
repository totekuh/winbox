"""Kernel and user-mode module list walking."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from winbox.kdbg.debugger.reader import snapshot_operation
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.memory import PageWalkError, WalkCache, read_virt_cr3
from winbox.kdbg.store import SymbolStoreError

from winbox.kdbg.walk._records import (
    MAX_MODULES,
    MAX_USER_MODULES,
    ModuleRecord,
    ProcessRecord,
    UserModuleRecord,
)
from winbox.kdbg.walk import _layout

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore

logger = logging.getLogger(__name__)


@snapshot_operation
def list_modules(
    vm_name: str,
    store: SymbolStore,
    *,
    cr3: int | None = None,
    cache: WalkCache | None = None,
) -> list[ModuleRecord]:
    """Walk ``PsLoadedModuleList`` and return every loaded kernel module."""
    _layout._require_x64_four_level_store(store)
    explicit_cr3 = cr3
    head = store.resolve("PsLoadedModuleList")
    ldr = _layout._layout_struct(store, "_KLDR_DATA_TABLE_ENTRY")
    inload_off = _layout._layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", 16).offset
    dll_base_off = _layout._layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "DllBase", 8).offset
    size_off = _layout._layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "SizeOfImage", 4).offset
    base_name_off = _layout._layout_field(ldr, "_KLDR_DATA_TABLE_ENTRY", "BaseDllName", 16).offset

    cr3, flink, cache = _layout._read_kernel_list_head(vm_name, head, explicit_cr3)
    results: list[ModuleRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_MODULES:
        if flink in seen:
            break
        seen.add(flink)
        entry = flink - inload_off
        try:
            base = _layout._read_u64(vm_name, cr3, entry + dll_base_off, cache)
            size = _layout._read_u32(vm_name, cr3, entry + size_off, cache)
            name = _layout._read_unicode_string(vm_name, cr3, entry + base_name_off, store, cache)
        except (HmpError, PageWalkError) as e:
            logger.warning(
                "list_modules: walk truncated at LDR_DATA_TABLE_ENTRY 0x%x (%d returned): %s",
                entry, len(results), e,
            )
            break
        results.append(ModuleRecord(name=name, base=base, size=size, entry=entry))
        flink = _layout._read_u64(vm_name, cr3, flink, cache)
    if len(results) >= MAX_MODULES:
        logger.warning(
            "list_modules: hit MAX_MODULES=%d cap; result is truncated",
            MAX_MODULES,
        )
    return results


def is_wow64(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    cache: WalkCache | None = None,
) -> bool:
    if cache is None:
        cache = WalkCache()
    try:
        return _wow64_peb(vm_name, store, target, cache) != 0
    except (HmpError, PageWalkError, SymbolStoreError):
        return False


def _wow64_peb(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    cache: WalkCache,
) -> int:
    eproc = store.struct("_EPROCESS")["fields"]
    wow64_off = eproc.get("WoW64Process", {}).get("off")
    if wow64_off is None:
        raise SymbolStoreError("_EPROCESS.WoW64Process is absent from nt types")
    wow64 = _layout._read_u64(
        vm_name, target.directory_table_base,
        target.eprocess + int(wow64_off), cache,
    )
    if wow64 == 0:
        return 0
    wow_fields = store.struct("_EWOW64PROCESS")["fields"]
    peb_off = wow_fields.get("Peb", {}).get("off")
    if peb_off is None:
        raise SymbolStoreError("_EWOW64PROCESS.Peb is absent from nt types")
    peb32 = _layout._read_u64(
        vm_name, target.directory_table_base, wow64 + int(peb_off), cache,
    )
    if peb32 >= (1 << 32):
        raise PageWalkError(f"invalid WoW64 PEB pointer 0x{peb32:x}")
    return peb32


def _read_unicode_string32(
    vm_name: str, cr3: int, va: int, cache: WalkCache,
) -> str:
    header = read_virt_cr3(vm_name, cr3, va, 8, cache=cache)
    if len(header) != 8:
        raise PageWalkError("short UNICODE_STRING32 header")
    length = int.from_bytes(header[0:2], "little")
    maximum = int.from_bytes(header[2:4], "little")
    buffer = int.from_bytes(header[4:8], "little")
    if length == 0:
        return ""
    if length & 1 or length > maximum or length > 0x2000 or buffer == 0:
        raise PageWalkError(
            f"invalid UNICODE_STRING32 length={length} maximum={maximum}"
        )
    raw = read_virt_cr3(vm_name, cr3, buffer, length, cache=cache)
    if len(raw) != length:
        raise PageWalkError(f"short UNICODE_STRING32 payload {len(raw)}/{length}")
    return raw.decode("utf-16-le", errors="replace")


def _list_wow64_modules(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    cache: WalkCache,
    *,
    limit: int,
) -> list[UserModuleRecord]:
    peb = _wow64_peb(vm_name, store, target, cache)
    if peb == 0 or limit <= 0:
        return []
    cr3 = target.directory_table_base
    ldr = _layout._read_u32(vm_name, cr3, peb + 0x0C, cache)
    if ldr == 0:
        return []
    head = ldr + 0x0C
    flink = _layout._read_u32(vm_name, cr3, head, cache)
    results: list[UserModuleRecord] = []
    seen: set[int] = set()
    while flink not in (0, head) and len(results) < limit:
        if flink in seen or flink >= (1 << 32):
            break
        seen.add(flink)
        entry = flink
        try:
            base = _layout._read_u32(vm_name, cr3, entry + 0x18, cache)
            size = _layout._read_u32(vm_name, cr3, entry + 0x20, cache)
            full = _read_unicode_string32(vm_name, cr3, entry + 0x24, cache)
            name = _read_unicode_string32(vm_name, cr3, entry + 0x2C, cache)
            next_flink = _layout._read_u32(vm_name, cr3, flink, cache)
        except (HmpError, PageWalkError) as exc:
            logger.warning(
                "list_user_modules: WoW64 walk truncated at 0x%x in pid %d: %s",
                entry, target.pid, exc,
            )
            break
        if base:
            results.append(UserModuleRecord(
                name=name, base=base, size=size, full_path=full, entry=entry,
                architecture="x86",
            ))
        flink = next_flink
    return results


@snapshot_operation
def list_user_modules(
    vm_name: str,
    store: SymbolStore,
    target: ProcessRecord,
    *,
    cache: WalkCache | None = None,
) -> list[UserModuleRecord]:
    _layout._require_x64_four_level_store(store)
    if cache is None:
        cache = WalkCache()
    target_cr3 = target.directory_table_base

    eproc_fields = store.struct("_EPROCESS")["fields"]
    peb_off = eproc_fields["Peb"]["off"]

    peb_fields = store.struct("_PEB")["fields"]
    ldr_field_off = peb_fields["Ldr"]["off"]

    ldrdata_fields = store.struct("_PEB_LDR_DATA")["fields"]
    inload_head_off = ldrdata_fields["InLoadOrderModuleList"]["off"]

    ldr_fields = store.struct("_LDR_DATA_TABLE_ENTRY")["fields"]
    inload_off = ldr_fields.get("InLoadOrderLinks", {}).get("off", 0)
    dll_base_off = ldr_fields["DllBase"]["off"]
    size_off = ldr_fields["SizeOfImage"]["off"]
    base_name_off = ldr_fields["BaseDllName"]["off"]
    full_name_off = ldr_fields["FullDllName"]["off"]

    peb_va = _layout._read_u64(vm_name, target_cr3, target.eprocess + peb_off, cache)
    if peb_va == 0:
        return []

    ldr_va = _layout._read_u64(vm_name, target_cr3, peb_va + ldr_field_off, cache)
    if ldr_va == 0:
        return []

    head = ldr_va + inload_head_off
    try:
        flink = _layout._read_u64(vm_name, target_cr3, head, cache)
    except (HmpError, PageWalkError) as e:
        logger.warning(
            "list_user_modules: could not read PEB.Ldr list head for pid %d: %s",
            target.pid, e,
        )
        return []

    results: list[UserModuleRecord] = []
    seen: set[int] = set()
    while flink != head and flink != 0 and len(results) < MAX_USER_MODULES:
        if flink in seen:
            break
        seen.add(flink)
        entry = flink - inload_off
        try:
            base = _layout._read_u64(vm_name, target_cr3, entry + dll_base_off, cache)
            size = _layout._read_u32(vm_name, target_cr3, entry + size_off, cache)
            name = _layout._read_unicode_string(
                vm_name, target_cr3, entry + base_name_off, store, cache,
            )
            full = _layout._read_unicode_string(
                vm_name, target_cr3, entry + full_name_off, store, cache,
            )
        except (HmpError, PageWalkError) as e:
            logger.warning(
                "list_user_modules: walk truncated at LDR_DATA_TABLE_ENTRY 0x%x "
                "in pid %d (%d returned): %s",
                entry, target.pid, len(results), e,
            )
            break
        if base != 0:
            results.append(UserModuleRecord(
                name=name, base=base, size=size, full_path=full, entry=entry,
                architecture="x64",
            ))
        flink = _layout._read_u64(vm_name, target_cr3, flink, cache)
    if len(results) >= MAX_USER_MODULES:
        logger.warning(
            "list_user_modules: hit MAX_USER_MODULES=%d cap; result is truncated",
            MAX_USER_MODULES,
        )
    if len(results) < MAX_USER_MODULES:
        try:
            wow64_modules = _list_wow64_modules(
                vm_name, store, target, cache,
                limit=MAX_USER_MODULES - len(results),
            )
            x86_identities = {
                (module.base, module.name.casefold()) for module in wow64_modules
            }
            results = [
                module for module in results
                if (module.base, module.name.casefold()) not in x86_identities
            ]
            results.extend(wow64_modules)
        except SymbolStoreError:
            pass
    return results
