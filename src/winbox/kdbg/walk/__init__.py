"""Windows-aware kernel walkers — re-export facade."""

from winbox.kdbg.walk._records import (  # noqa: F401
    MAX_MODULES,
    MAX_PROCESSES,
    MAX_THREADS_PER_PROCESS,
    MAX_USER_MODULES,
    CurrentVcpuRecord,
    ModuleRecord,
    ProcessRecord,
    ProcessWalkResult,
    ProcessWalkTruncation,
    ThreadAddressAttribution,
    ThreadFilterError,
    ThreadRecord,
    ThreadSelection,
    ThreadStartAttribution,
    UserModuleRecord,
    ThreadWalkIncomplete,
    ThreadWalkResult,
    ThreadWalkTruncation,
    _KTHREAD_STATES,
    _KWAIT_REASONS,
    _MAX_PDB_STRUCT_SIZE,
    _ProcessLayout,
    _ProcessSpan,
    _ThreadField,
    _ThreadLayout,
    _WaitLayout,
    thread_walk_truncation,
)
from winbox.kdbg.walk._filter import (  # noqa: F401
    _enum_filter,
    select_threads,
)
from winbox.kdbg.walk._layout import (  # noqa: F401
    _cached_kernel_cr3,
    _compact_spans,
    _cpu_cr3,
    _cpu_cr3_candidates,
    _field_declared_width,
    _forget_kernel_cr3,
    _is_kernel_pointer,
    _kernel_cr3_by_vm,
    _kernel_cr3_lock,
    _kernel_read_candidates,
    _layout_field,
    _layout_int,
    _layout_struct,
    _read_cstr,
    _read_kernel_list_head,
    _read_u32,
    _read_u64,
    _read_unicode_string,
    _remember_kernel_cr3,
    _require_x64_four_level_store,
    _thread_field,
    _thread_layout,
    _wait_layout,
)
from winbox.kdbg.walk._processes import (  # noqa: F401
    _iter_processes,
    _process_layout,
    _read_process_entry,
    find_process,
    list_processes,
    list_processes_detailed,
    read_process_identity,
)
from winbox.kdbg.walk._threads import (  # noqa: F401
    _read_thread_entry,
    list_threads,
)
from winbox.kdbg.walk._wait import (  # noqa: F401
    resolve_thread_wait_objects,
)
from winbox.kdbg.walk._modules import (  # noqa: F401
    is_wow64,
    list_modules,
    list_user_modules,
)
from winbox.kdbg.walk._attribution import (  # noqa: F401
    _CurrentVcpuLayout,
    _current_vcpu_layout,
    list_current_vcpu_threads,
    resolve_thread_start_addresses,
)

# Re-export memory primitives since tests access them via walk module
from winbox.kdbg.memory import read_virt_cr3, WalkCache, PageWalkError  # noqa: F401
from winbox.kdbg.hmp import HmpError  # noqa: F401
from winbox.kdbg.store import SymbolStoreError  # noqa: F401
# Re-export current_snapshot since tests patch it on the walk module
from winbox.kdbg.debugger.reader import current_snapshot  # noqa: F401
