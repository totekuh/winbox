"""Context inspection, module resolution, liveness probe, decomp snapshot."""

from __future__ import annotations

import struct
import time
from typing import Any

from winbox.kdbg.debugger.daemon._helpers import _decode_regs


class _ContextMixin:
    """op_context, module resolution, target liveness, decomp snapshot."""

    def op_context(
        self,
        disasm_count: int = 8,
        stack_qwords: int = 16,
        bt_depth: int = 8,
        memory: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return bounded, epoch-consistent evidence for the current stop."""
        stop = self._require_stop_epoch()

        def bounded(name: str, value: Any, maximum: int) -> int:
            if isinstance(value, bool):
                raise ValueError(f"{name} must be an integer")
            try:
                parsed = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not 0 <= parsed <= maximum:
                raise ValueError(f"{name} must be between 0 and {maximum}")
            return parsed

        disasm_count = bounded("disasm_count", disasm_count, 32)
        stack_qwords = bounded("stack_qwords", stack_qwords, 32)
        bt_depth = bounded("bt_depth", bt_depth, 16)
        epoch = {"session_id": self.session_id, "stop_id": self.stop_id}
        response: dict[str, Any] = {
            "schema": "winbox.kdbg-context/1",
            "state": "halted",
            "stop_epoch": epoch,
            "target": {
                "pid": self.target.pid,
                "name": self.target.name,
                "dtb": f"0x{self.target.dtb:x}",
            },
            "stop": self._stop_summary(),
            "location": {
                "va": f"0x{stop.rip:x}",
                "symbol": self._best_symbol_for_va(stop.rip),
            },
            "registers": _decode_regs(stop.raw_regs),
        }

        assembly: list[dict[str, Any]] = []
        if disasm_count:
            try:
                import capstone
                raw = bytes.fromhex(self.op_mem(
                    stop.rip, min(15 * disasm_count, 480), **epoch
                )["bytes"])
                mode = (
                    capstone.CS_MODE_32 if self._is_x86_stop()
                    else capstone.CS_MODE_64
                )
                md = capstone.Cs(capstone.CS_ARCH_X86, mode)
                md.detail = True
                for instruction in md.disasm(raw, stop.rip):
                    item = {
                        "va": f"0x{instruction.address:x}",
                        "bytes": instruction.bytes.hex(),
                        "mnemonic": instruction.mnemonic,
                        "op_str": instruction.op_str,
                    }
                    if any(group in (
                        capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP
                    ) for group in instruction.groups):
                        for operand in instruction.operands:
                            if operand.type == capstone.x86.X86_OP_IMM:
                                item["target_va"] = f"0x{operand.imm:x}"
                                symbol = self._best_symbol_for_va(operand.imm)
                                if symbol:
                                    item["target_symbol"] = symbol
                                break
                    assembly.append(item)
                    if len(assembly) >= disasm_count:
                        break
            except Exception as exc:
                response["assembly_error"] = str(exc)
        response["assembly"] = assembly

        rsp_va = struct.unpack_from("<Q", stop.raw_regs, 7 * 8)[0]
        stack_width = 4 if self._is_x86_stop() else 8
        scan_qwords = stack_qwords
        stack_raw = b""
        if scan_qwords:
            try:
                stack_raw = bytes.fromhex(self.op_mem(
                    rsp_va, scan_qwords * stack_width, **epoch
                )["bytes"])
            except Exception as exc:
                response["stack_error"] = str(exc)
        stack_register = "esp" if stack_width == 4 else "rsp"
        stack_entries = [
            {
                "offset": f"{stack_register}+0x{offset:02x}",
                "va": f"0x{rsp_va + offset:x}",
                "value": f"0x{int.from_bytes(stack_raw[offset:offset + stack_width], 'little'):0{stack_width * 2}x}",
            }
            for offset in range(
                0, min(len(stack_raw), stack_qwords * stack_width), stack_width
            )
        ]
        response["stack"] = {
            "rsp": f"0x{rsp_va:x}",
            "sp": f"0x{rsp_va:x}",
            "stack_register": stack_register,
            "architecture": "x86" if stack_width == 4 else "x64",
            "word_size": stack_width,
            "entries": stack_entries,
        }
        response["stack"]["dwords" if stack_width == 4 else "qwords"] = stack_entries
        response["backtrace"] = (
            self._unwind_backtrace(bt_depth) if bt_depth else {
                "rsp": f"0x{rsp_va:x}",
                "method": (
                    "windows-x86-hybrid" if self._is_x86_stop()
                    else "windows-x64-pdata"
                ),
                "complete": False, "frames": [],
            }
        )

        bps = self.op_bp_list()["bps"]
        response["breakpoints"] = {
            "total": len(bps), "truncated": len(bps) > 32, "items": bps[:32]
        }

        requests = memory or []
        if not isinstance(requests, list) or len(requests) > 4:
            raise ValueError("memory must contain at most 4 read objects")
        reads = []
        total = 0
        for request in requests:
            if not isinstance(request, dict) or set(request) - {"va", "length"}:
                raise ValueError("each memory read must contain only va and length")
            if request.get("va") in (None, ""):
                raise ValueError("each memory read requires va")
            length = bounded("memory length", request.get("length", 64), 256)
            total += length
            if total > 1024:
                raise ValueError("combined memory reads may not exceed 1024 bytes")
            reads.append(self.op_mem(
                request.get("va"), length, **epoch
            ))
        if reads:
            response["memory"] = reads
        return response

    def _unwind_user_modules(self):
        """Use the immutable attach inventory for unwind when available."""
        if self.module_manifest is None:
            return self._live_modules("user")
        from types import SimpleNamespace
        return [
            SimpleNamespace(
                name=module.name,
                base=module.base,
                size=module.size,
                full_path=module.full_path,
                entry=0,
                architecture=module.architecture,
            )
            for module in self.module_manifest.loader_modules()
        ]

    def _live_modules(self, kind: str):
        """Return one fresh loader inventory while preserving RSP state."""
        from types import SimpleNamespace
        from winbox.kdbg.debugger.reader import use_local_rsp
        from winbox.kdbg.memory import WalkCache
        from winbox.kdbg.walk import ProcessRecord, list_modules, list_user_modules

        vcpu = self._pick_vcpu()
        stop = SimpleNamespace(thread=vcpu)
        target = ProcessRecord(
            pid=self.target.pid,
            name=self.target.name,
            eprocess=self.target.eprocess,
            directory_table_base=self.target.dtb,
            user_directory_table_base=self.target.user_dtb,
        )
        walk_completed = False
        try:
            with use_local_rsp(self.cfg.vm_name, self.rsp, stop, pagewalk=self.cfg.kdbg_pagewalk):
                cache = WalkCache()
                if kind == "kernel":
                    modules = list_modules(
                        self.cfg.vm_name, self.store, cache=cache,
                    )
                else:
                    modules = list_user_modules(
                        self.cfg.vm_name, self.store, target, cache=cache,
                    )
                walk_completed = True
                return modules
        except Exception as exc:
            if walk_completed:
                self._cr3_corrupted = True
            raise RuntimeError(f"live module walk failed: {exc}") from exc
        finally:
            self._last_selected_vcpu = None

    def _probe_target_liveness(self) -> dict[str, Any]:
        """Classify the originally captured EPROCESS without PID rebinding."""
        from types import SimpleNamespace
        from winbox.kdbg.debugger.reader import use_local_rsp
        from winbox.kdbg.memory import WalkCache
        from winbox.kdbg.walk import find_process, read_process_identity

        wall_clock = getattr(time, "time", None)
        checked_at = wall_clock() if callable(wall_clock) else 0.0
        result: dict[str, Any] = {
            "state": "unknown", "checked": True, "checked_at": checked_at,
            "pid": self.target.pid,
            "captured_eprocess": f"0x{self.target.eprocess:x}",
            "identity": "create_time" if self.target.create_time else "eprocess",
            "advisory": True,
        }
        if self.target.eprocess <= 0:
            result["reason"] = "attach identity lacks EPROCESS evidence"
            self._last_target_liveness = result
            return result
        if self.run_state != "halted" or self.stop is None:
            result["reason"] = f"probe requires halted state (state={self.run_state})"
            self._last_target_liveness = result
            return result
        vcpu = self._pick_vcpu()
        stop = SimpleNamespace(thread=vcpu)
        direct = None
        current = None
        errors = []
        try:
            with use_local_rsp(self.cfg.vm_name, self.rsp, stop, pagewalk=self.cfg.kdbg_pagewalk):
                cache = WalkCache()
                try:
                    direct = read_process_identity(
                        self.cfg.vm_name, self.store,
                        eprocess=self.target.eprocess, cache=cache,
                    )
                except Exception as exc:
                    errors.append(f"captured EPROCESS read: {type(exc).__name__}: {exc}")
                try:
                    current = find_process(
                        self.cfg.vm_name, self.store, pid=self.target.pid,
                        cache=WalkCache(),
                    )
                except Exception as exc:
                    errors.append(f"active process walk: {type(exc).__name__}: {exc}")
        except Exception as exc:
            errors.append(f"snapshot probe: {type(exc).__name__}: {exc}")
        finally:
            self._last_selected_vcpu = None

        same_direct = bool(
            direct is not None
            and direct.eprocess == self.target.eprocess
            and direct.pid == self.target.pid
            and (
                not self.target.create_time or not direct.create_time
                or direct.create_time == self.target.create_time
            )
        )
        same_current = bool(
            current is not None
            and current.eprocess == self.target.eprocess
            and (
                not self.target.create_time or not current.create_time
                or current.create_time == self.target.create_time
            )
        )
        if current is not None and not same_current:
            result.update({
                "state": "gone", "reason": "pid_reused",
                "replacement": {
                    "eprocess": f"0x{current.eprocess:x}",
                    "create_time": (
                        f"0x{current.create_time:x}" if current.create_time else None
                    ),
                    "name": current.name,
                },
            })
        elif same_current:
            exit_time = max(
                int(getattr(current, "exit_time", 0) or 0),
                int(getattr(direct, "exit_time", 0) or 0),
            )
            if exit_time:
                result.update({
                    "state": "exiting", "reason": "exit_time_set",
                    "exit_time": f"0x{exit_time:x}",
                })
            else:
                result.update({"state": "alive", "reason": "identity_active"})
        elif current is None and same_direct and int(getattr(direct, "exit_time", 0) or 0):
            result.update({
                "state": "exiting", "reason": "unlinked_exit_time_set",
                "exit_time": f"0x{direct.exit_time:x}",
            })
        elif current is None and not errors:
            result.update({"state": "gone", "reason": "not_in_active_process_list"})
        elif current is None and direct is not None and not same_direct:
            result.update({"state": "gone", "reason": "captured_eprocess_reused"})
        if errors:
            result["probe_errors"] = [error[:512] for error in errors[:4]]
        self._last_target_liveness = result
        return result

    @staticmethod
    def _module_payload(module, *, kind: str, va: int) -> dict[str, Any]:
        payload = {
            "name": module.name,
            "base": f"0x{module.base:x}",
            "size": module.size,
            "rva": f"0x{va - module.base:x}",
            "kind": kind,
            "full_path": getattr(module, "full_path", ""),
            "loader_entry": f"0x{module.entry:x}",
            "inventory": "fresh",
        }
        if kind == "user":
            payload["architecture"] = getattr(module, "architecture", "x64")
        return payload

    def op_module_at(
        self,
        va: int | str,
        session_id: str | None = None,
        stop_id: int | None = None,
    ) -> dict[str, Any]:
        """Resolve a live VA against a fresh loader-list snapshot."""
        self._require_stop_epoch(session_id, stop_id)
        if isinstance(va, str):
            try:
                va = int(va, 0)
            except ValueError as exc:
                raise ValueError(f"invalid virtual address: {va!r}") from exc
        if va < 0 or va >= (1 << 64):
            raise ValueError(f"virtual address outside uint64 range: {va}")

        kind = "kernel" if (va >> 47) == 0x1FFFF else "user"
        modules = self._live_modules(kind)

        matches = [m for m in modules if m.base <= va < m.base + m.size]
        if not matches:
            raise RuntimeError(
                f"0x{va:x} is not inside any live {kind} module "
                f"({len(modules)} loader entries checked)"
            )
        module = min(matches, key=lambda item: item.size)
        return self._module_payload(module, kind=kind, va=va)

    def op_decomp_snapshot(
        self,
        va: int | str | None = None,
        module: str = "",
        rva: int | str | None = None,
    ) -> dict[str, Any]:
        """Atomically bind an address and live module to one stop epoch."""
        stop = self._require_stop_epoch()
        if bool(module) != (rva is not None and rva != ""):
            raise ValueError("module and rva must be supplied together")
        if module and va not in (None, ""):
            raise ValueError("va and module+rva are mutually exclusive")
        module_payload = None
        if module:
            module = module.strip()
            if not module:
                raise ValueError("module must not be blank")
            try:
                rva_value = int(rva, 0) if isinstance(rva, str) else int(rva)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid RVA: {rva!r}") from exc
            if rva_value < 0 or rva_value >= (1 << 32):
                raise ValueError(f"RVA outside supported PE range: {rva_value}")
            wanted = module.lower()
            wanted_arch = None
            if "@" in wanted:
                wanted, _, wanted_arch = wanted.rpartition("@")
                if wanted_arch not in {"x86", "x64"}:
                    raise ValueError("module architecture must be @x86 or @x64")
            wanted_stem = wanted.rsplit(".", 1)[0]
            selected_pair = None
            kernel_name = (
                wanted == "nt" or wanted.startswith("ntoskrnl")
                or wanted.startswith("ntkrnl")
            )
            for kind in (("kernel", "user") if kernel_name else ("user", "kernel")):
                matches = []
                for candidate in self._live_modules(kind):
                    if wanted_arch and getattr(candidate, "architecture", "x64") != wanted_arch:
                        continue
                    name = str(candidate.name).lower()
                    stem = name.rsplit(".", 1)[0]
                    if name == wanted or stem == wanted_stem:
                        matches.append(candidate)
                exact = [item for item in matches if str(item.name).lower() == wanted]
                if len(exact) == 1:
                    selected_pair = (kind, exact[0])
                    break
                if len(matches) == 1:
                    selected_pair = (kind, matches[0])
                    break
                if len(matches) > 1:
                    names = ", ".join(sorted(str(item.name) for item in matches))
                    raise RuntimeError(f"ambiguous live module {module!r}: {names}")
            if selected_pair is None:
                raise RuntimeError(f"live module not found: {module!r}")
            kind, selected_module = selected_pair
            if rva_value >= selected_module.size:
                raise ValueError(
                    f"RVA 0x{rva_value:x} outside {selected_module.name} "
                    f"(size 0x{selected_module.size:x})"
                )
            runtime_va = selected_module.base + rva_value
            module_payload = self._module_payload(
                selected_module, kind=kind, va=runtime_va
            )
        else:
            runtime_va = stop.rip if va in (None, "") else va
        if isinstance(runtime_va, str):
            try:
                runtime_va = int(runtime_va, 0)
            except ValueError as exc:
                raise ValueError(f"invalid virtual address: {runtime_va!r}") from exc
        if runtime_va < 0 or runtime_va >= (1 << 64):
            raise ValueError(f"virtual address outside uint64 range: {runtime_va}")
        if module_payload is None:
            module_payload = self.op_module_at(
                runtime_va, session_id=self.session_id, stop_id=self.stop_id
            )
        return {
            "session_id": self.session_id,
            "stop_id": self.stop_id,
            "state": self.run_state,
            "runtime_va": f"0x{runtime_va:x}",
            "rip": f"0x{stop.rip:x}",
            "target": {
                "pid": self.target.pid,
                "dtb": f"0x{self.target.dtb:x}",
                "name": self.target.name,
            },
            "module": module_payload,
        }
