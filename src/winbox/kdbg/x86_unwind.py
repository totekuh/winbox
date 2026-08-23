"""Conservative Windows x86 stack unwinding for WoW64 stops.

x86 has no universal PE ``.pdata`` contract equivalent to Windows x64.
Trustworthy walks therefore combine exact-build PDB FPO/frame records with
strict frame-pointer and prologue fallbacks.  Raw stack scanning is exposed
only as candidates and never silently promoted to frames unless a PDB frame
program explicitly requests ``.raSearch``.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Callable


class X86UnwindError(RuntimeError):
    """Missing/corrupt metadata or a stack that cannot be trusted."""


@dataclass(frozen=True)
class X86Module:
    name: str
    base: int
    size: int
    frame_data: tuple[dict, ...] = ()
    function_starts: tuple[int, ...] = ()
    metadata: str | None = None


@dataclass(frozen=True)
class X86Step:
    eip: int
    esp: int
    ebp: int
    ebx: int
    method: str
    confidence: str
    operations: tuple[str, ...]
    metadata: str | None = None


class X86HybridUnwinder:
    """Apply PDB FPO, EBP chains, then bounded prologue analysis."""

    MAX_STACK_ADVANCE = 16 * 1024 * 1024
    MAX_FRAME_DISTANCE = 1 * 1024 * 1024
    MAX_RA_SEARCH_DWORDS = 256
    MAX_PROLOG_BYTES = 512
    MAX_PROLOG_INSNS = 128

    def __init__(
        self,
        modules: list[X86Module],
        read: Callable[[int, int], bytes],
        symbolicate: Callable[[int], str | None],
    ) -> None:
        self.modules = sorted(modules, key=lambda item: (item.base, item.size))
        self.read = read
        self.symbolicate = symbolicate

    def module_at(self, address: int) -> X86Module | None:
        matches = [
            module for module in self.modules
            if module.base <= address < module.base + module.size
        ]
        return min(matches, key=lambda item: item.size) if matches else None

    def _u32(self, address: int) -> int:
        if not 0 <= address <= 0xFFFFFFFF - 3:
            raise X86UnwindError(f"x86 stack address outside uint32: 0x{address:x}")
        raw = self.read(address, 4)
        if len(raw) != 4:
            raise X86UnwindError(f"short x86 stack read at 0x{address:x}")
        return int.from_bytes(raw, "little")

    def _valid_return(self, address: int) -> bool:
        return address != 0 and self.module_at(address) is not None

    def _record(self, module: X86Module, eip: int) -> dict | None:
        rva = eip - module.base
        candidates: list[dict] = []
        for record in module.frame_data:
            try:
                start = int(record["rva"])
                size = int(record["code_size"])
            except (KeyError, TypeError, ValueError) as exc:
                raise X86UnwindError(
                    f"malformed FPO record in {module.name}: {exc}"
                ) from exc
            if start < 0 or size <= 0 or start + size > module.size:
                raise X86UnwindError(
                    f"out-of-bounds FPO record in {module.name}: "
                    f"rva=0x{start:x} size=0x{size:x}"
                )
            if start <= rva < start + size:
                candidates.append(record)
        if not candidates:
            return None
        # Later prologue/epilogue state records are more specific. At an
        # identical RVA, modern frame data is authoritative over old FPO.
        return max(candidates, key=lambda item: (
            int(item["rva"]), item.get("source") == "pdb-frame-data",
        ))

    def _ebp_step(
        self, esp: int, ebp: int, ebx: int, *, source: str, metadata: str | None,
    ) -> X86Step:
        if ebp & 3 or ebp < esp or ebp - esp > self.MAX_FRAME_DISTANCE:
            raise X86UnwindError(f"invalid EBP frame root 0x{ebp:x} for ESP 0x{esp:x}")
        next_ebp = self._u32(ebp)
        caller = self._u32(ebp + 4)
        if not self._valid_return(caller):
            raise X86UnwindError(f"EBP return 0x{caller:x} is outside x86 modules")
        if next_ebp and (
            next_ebp & 3 or next_ebp <= ebp
            or next_ebp - ebp > self.MAX_FRAME_DISTANCE
        ):
            raise X86UnwindError(
                f"non-monotonic EBP chain 0x{ebp:x} -> 0x{next_ebp:x}"
            )
        return X86Step(
            caller, ebp + 8, next_ebp, ebx, source, "high",
            (f"caller eip=[ebp+4]", f"caller ebp=[0x{ebp:x}]"), metadata,
        )

    def _search_return(self, start: int) -> tuple[int, int, bool]:
        first_valid: tuple[int, int] | None = None
        for index in range(self.MAX_RA_SEARCH_DWORDS):
            slot = start + index * 4
            value = self._u32(slot)
            if not self._valid_return(value):
                continue
            if first_valid is None:
                first_valid = (slot, value)
            if self._looks_like_call_return(value):
                return slot, value, True
        if first_valid is not None:
            return first_valid[0], first_valid[1], False
        raise X86UnwindError(
            f"PDB .raSearch found no module-backed return within "
            f"{self.MAX_RA_SEARCH_DWORDS * 4} bytes"
        )

    def _looks_like_call_return(self, address: int) -> bool:
        module = self.module_at(address)
        if module is None:
            return False
        before = min(8, address - module.base)
        if before <= 0:
            return False
        try:
            raw = self.read(address - before, before)
            import capstone
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            decoder.detail = True
            for start in range(len(raw)):
                instruction = next(decoder.disasm(
                    raw[start:], address - before + start, count=1,
                ), None)
                if instruction is not None and (
                    instruction.address + instruction.size == address
                    and capstone.CS_GRP_CALL in instruction.groups
                ):
                    return True
        except Exception:
            return False
        return False

    def _metadata_step(
        self, module: X86Module, record: dict,
        esp: int, ebp: int, ebx: int, callee_params: int,
    ) -> X86Step:
        recipe = str(record.get("recipe", "unsupported"))
        source = str(record.get("source", "pdb-fpo"))
        metadata = module.metadata
        if recipe == "ebp-frame":
            return self._ebp_step(
                esp, ebp, ebx, source=source, metadata=metadata,
            )
        if recipe == "ebx-frame":
            if ebx & 3 or ebx < esp or ebx - esp > self.MAX_FRAME_DISTANCE:
                raise X86UnwindError(f"invalid EBX frame root 0x{ebx:x}")
            next_ebx = self._u32(ebx)
            caller = self._u32(ebx + 4)
            next_ebp = self._u32(ebp) if ebp else 0
            if not self._valid_return(caller):
                raise X86UnwindError(f"EBX return 0x{caller:x} is outside x86 modules")
            return X86Step(
                caller, ebx + 8, next_ebp, next_ebx, source, "high",
                ("caller eip=[ebx+4]", "caller ebx=[ebx]"), metadata,
            )
        if recipe == "fpo-stack":
            locals_size = int(record.get("locals_size", 0))
            saved_size = int(record.get("saved_regs_size", 0))
            params_size = int(record.get("params_size", 0))
            if min(locals_size, saved_size, params_size, callee_params) < 0:
                raise X86UnwindError("negative old-FPO stack size")
            # Windows frame walkers represent a caller's ESP at the point
            # immediately before CALL, after that caller pushed its callee's
            # arguments. Thus the *previous/callee* record's parameter size,
            # not the current function's, precedes this frame's locals and
            # saved registers. The current params become callee_params for
            # the next iteration.
            ret_slot = esp + callee_params + locals_size + saved_size
            if ret_slot - esp > self.MAX_FRAME_DISTANCE:
                raise X86UnwindError("old-FPO frame exceeds distance cap")
            caller = self._u32(ret_slot)
            if not self._valid_return(caller):
                raise X86UnwindError(
                    f"old-FPO return 0x{caller:x} is outside x86 modules"
                )
            return X86Step(
                caller, ret_slot + 4, ebp, ebx,
                source, "high",
                (f"return slot esp+0x{ret_slot - esp:x}",
                 f"frame params 0x{params_size:x}"), metadata,
            )
        if recipe in {"ra-search", "ra-search-start"}:
            locals_size = int(record.get("locals_size", 0))
            saved_size = int(record.get("saved_regs_size", 0))
            if min(locals_size, saved_size, callee_params) < 0:
                raise X86UnwindError("negative frame-data stack size")
            alignment = int(record.get("alignment", 0))
            if alignment:
                if ebp & 3 or ebp < esp or ebp - esp > self.MAX_FRAME_DISTANCE:
                    raise X86UnwindError(
                        "aligned .raSearch requires a valid EBP frame root"
                    )
                search_start = ebp + 4
            else:
                search_start = esp + callee_params + locals_size + saved_size
            if search_start - esp > self.MAX_FRAME_DISTANCE:
                raise X86UnwindError(".raSearch start exceeds distance cap")
            slot, caller, callsite = self._search_return(search_start)
            next_ebp = ebp
            if recipe == "ra-search" and alignment:
                if slot < 4:
                    raise X86UnwindError("aligned .raSearch lacks saved EBP slot")
                next_ebp = self._u32(slot - 4)
            return X86Step(
                caller, slot + 4, next_ebp, ebx, source,
                "high" if callsite else "medium",
                (f"PDB .raSearch esp+0x{slot - esp:x}",
                 "call-site validated" if callsite else "module-range validated"),
                metadata,
            )
        raise X86UnwindError(f"unsupported PDB frame recipe {recipe!r}")

    def _prolog_step(
        self, module: X86Module, eip: int, esp: int, ebp: int, ebx: int,
    ) -> X86Step:
        rva = eip - module.base
        starts = module.function_starts
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0:
            raise X86UnwindError("no verified function start before EIP")
        start_rva = starts[index]
        distance = rva - start_rva
        if distance > self.MAX_PROLOG_BYTES:
            raise X86UnwindError("EIP is beyond bounded prologue-analysis window")
        raw = self.read(module.base + start_rva, distance)
        if len(raw) != distance:
            raise X86UnwindError("short function prologue read")
        try:
            import capstone
            from capstone import x86
        except ImportError as exc:  # pragma: no cover - required dependency
            raise X86UnwindError("capstone is required for x86 prologue analysis") from exc
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoder.detail = True
        delta = 0
        saved_ebp = False
        cursor = module.base + start_rva
        count = 0
        for instruction in decoder.disasm(raw, cursor):
            count += 1
            if count > self.MAX_PROLOG_INSNS:
                raise X86UnwindError("prologue instruction cap exceeded")
            cursor = instruction.address + instruction.size
            if instruction.mnemonic == "push":
                delta += 4
                if instruction.op_str == "ebp":
                    saved_ebp = True
                continue
            if instruction.mnemonic == "pop":
                delta -= 4
                if delta < 0:
                    raise X86UnwindError("prologue POP underflow")
                continue
            operands = instruction.operands
            if instruction.mnemonic in {"sub", "add"} and len(operands) == 2:
                if (
                    operands[0].type == x86.X86_OP_REG
                    and instruction.reg_name(operands[0].reg) == "esp"
                    and operands[1].type == x86.X86_OP_IMM
                ):
                    amount = int(operands[1].imm)
                    delta += amount if instruction.mnemonic == "sub" else -amount
                    if delta < 0 or delta > self.MAX_FRAME_DISTANCE:
                        raise X86UnwindError("implausible prologue stack delta")
                    continue
            if any(group in instruction.groups for group in (
                capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP, capstone.CS_GRP_RET,
            )):
                raise X86UnwindError("control flow precedes EIP in prologue window")
            try:
                _, written = instruction.regs_access()
            except capstone.CsError as exc:
                raise X86UnwindError(
                    "cannot determine prologue register effects"
                ) from exc
            if x86.X86_REG_ESP in written:
                raise X86UnwindError(
                    f"unsupported stack-pointer write in {instruction.mnemonic}"
                )
            if instruction.mnemonic in {"leave", "enter"}:
                raise X86UnwindError(f"unsupported prologue {instruction.mnemonic}")
        if cursor != eip:
            raise X86UnwindError("EIP is not on a decoded instruction boundary")
        ret_slot = esp + delta
        caller = self._u32(ret_slot)
        if not self._valid_return(caller):
            raise X86UnwindError(
                f"prologue return 0x{caller:x} is outside x86 modules"
            )
        next_ebp = self._u32(ret_slot - 4) if saved_ebp else ebp
        return X86Step(
            caller, ret_slot + 4, next_ebp, ebx,
            "instruction-prolog", "medium",
            (f"simulated {count} straight-line instructions",
             f"stack delta 0x{delta:x}"), module.metadata,
        )

    def unwind(
        self, eip: int, esp: int, ebp: int, ebx: int, depth: int,
    ) -> dict:
        initial_esp = esp
        frames: list[dict] = []
        visited: set[tuple[int, int, int]] = set()
        error: str | None = None
        complete = False
        callee_params = 0
        for index in range(depth):
            if eip == 0:
                complete = True
                break
            key = (eip, esp, ebp)
            if key in visited:
                error = "x86 unwind loop detected"
                break
            visited.add(key)
            module = self.module_at(eip)
            if module is None:
                error = f"0x{eip:x} is outside every live x86 module"
                break
            frame = {
                "index": index, "addr": f"0x{eip:x}", "rsp": f"0x{esp:x}",
                "esp": f"0x{esp:x}",
                "sym": self.symbolicate(eip), "module": module.name,
                "rva": f"0x{eip - module.base:x}", "architecture": "x86",
            }
            frames.append(frame)
            failures: list[str] = []
            step: X86Step | None = None
            record = None
            if module.frame_data:
                try:
                    record = self._record(module, eip)
                except X86UnwindError as exc:
                    # Corrupt cached metadata must not crash the daemon or be
                    # partially trusted. Keep its reason in the structured
                    # result and try independent EBP/prologue evidence.
                    failures.append(f"PDB: {exc}")
            if record is not None:
                try:
                    step = self._metadata_step(
                        module, record, esp, ebp, ebx, callee_params,
                    )
                except X86UnwindError as exc:
                    failures.append(f"PDB: {exc}")
            if step is None:
                try:
                    step = self._ebp_step(
                        esp, ebp, ebx, source="ebp-chain", metadata=None,
                    )
                except X86UnwindError as exc:
                    failures.append(f"EBP: {exc}")
            if step is None and module.function_starts:
                try:
                    step = self._prolog_step(module, eip, esp, ebp, ebx)
                except X86UnwindError as exc:
                    failures.append(f"prologue: {exc}")
            if step is None:
                error = f"{module.name}+0x{eip - module.base:x}: " + "; ".join(failures)
                break
            frame["unwind"] = step.method
            frame["confidence"] = step.confidence
            if step.metadata:
                frame["metadata"] = step.metadata
            frame["operations"] = list(step.operations)
            if step.esp <= esp or step.esp - initial_esp > self.MAX_STACK_ADVANCE:
                error = f"implausible caller ESP 0x{step.esp:x}"
                break
            try:
                callee_params = int(record.get("params_size", 0)) if record else 0
            except (TypeError, ValueError):
                error = "malformed PDB params_size"
                break
            if not 0 <= callee_params <= self.MAX_FRAME_DISTANCE:
                error = f"implausible PDB parameter size 0x{callee_params:x}"
                break
            eip, esp, ebp, ebx = step.eip, step.esp, step.ebp, step.ebx
        else:
            error = f"depth limit {depth} reached"

        candidates = self.candidates(esp)
        result = {
            "rsp": f"0x{initial_esp:x}", "method": "windows-x86-hybrid",
            "esp": f"0x{initial_esp:x}", "sp": f"0x{initial_esp:x}",
            "architecture": "x86",
            "complete": complete, "frames": frames, "candidates": candidates,
        }
        if error:
            result["error"] = error
        return result

    def candidates(self, esp: int, *, scan_dwords: int = 64, limit: int = 16) -> list[dict]:
        """Return explicitly speculative stack addresses, bounded and separate."""
        output: list[dict] = []
        seen: set[int] = set()
        for index in range(min(scan_dwords, self.MAX_RA_SEARCH_DWORDS)):
            try:
                value = self._u32(esp + index * 4)
            except X86UnwindError:
                break
            module = self.module_at(value)
            if module is None or value in seen:
                continue
            seen.add(value)
            output.append({
                "stack_va": f"0x{esp + index * 4:x}",
                "address": f"0x{value:x}", "module": module.name,
                "rva": f"0x{value - module.base:x}",
                "sym": self.symbolicate(value), "confidence": "candidate",
            })
            if len(output) >= limit:
                break
        return output
