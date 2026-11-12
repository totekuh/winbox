"""WoW64 x86 stack unwinding + x86→x64 transition stitching."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from winbox.kdbg.debugger.daemon._helpers import (
    _normalize_module_name,
    _stored_module_identity,
)


class _UnwindX86Mixin:
    """x86 frame walking and WoW64 x86→x64 transition stitching."""

    def _unwind_x86_backtrace(self, depth: int) -> dict[str, Any]:
        """Unwind a WoW64 stack without requiring the native kernel view."""
        stop = self._require_stop_epoch()
        epoch = {"session_id": self.session_id, "stop_id": self.stop_id}
        eip = stop.rip & 0xFFFFFFFF
        esp = struct.unpack_from("<Q", stop.raw_regs, 7 * 8)[0] & 0xFFFFFFFF
        ebp = struct.unpack_from("<Q", stop.raw_regs, 6 * 8)[0] & 0xFFFFFFFF
        ebx = struct.unpack_from("<Q", stop.raw_regs, 1 * 8)[0] & 0xFFFFFFFF
        pages: dict[int, bytes] = {}

        def live_read(va: int, length: int) -> bytes:
            if va < 0 or length < 0 or va + length > (1 << 32):
                raise RuntimeError(
                    f"x86 live read outside uint32: 0x{va:x}+0x{length:x}"
                )
            output = bytearray()
            while length:
                page = va & ~0xFFF
                offset = va - page
                take = min(length, 0x1000 - offset)
                if page not in pages:
                    pages[page] = bytes.fromhex(
                        self.op_mem(page, 0x1000, **epoch)["bytes"]
                    )
                chunk = pages[page][offset:offset + take]
                if len(chunk) != take:
                    raise RuntimeError(f"short x86 live page at 0x{page:x}")
                output.extend(chunk)
                va += take
                length -= take
            return bytes(output)

        result = self._unwind_x86_context(
            eip, esp, ebp, ebx, depth, live_read,
        )
        if self.module_manifest is not None and len(result.get("frames") or []) < depth:
            self._stitch_wow64_x64(
                result, depth=depth, live_read=live_read,
            )
        return result

    def _stitch_wow64_x64(
        self, result: dict[str, Any], *, depth: int, live_read,
    ) -> None:
        """Append the exact suspended native chain at an arbitrary x86 stop."""
        del live_read  # x86 reader is deliberately uint32-bounded
        frames = result.get("frames") or []
        assert self.module_manifest is not None
        bridge_entries = [
            entry for entry in self.module_manifest.modules
            if entry.architecture == "x64"
            and _normalize_module_name(entry.name) == "wow64cpu"
        ]
        if len(bridge_entries) != 1:
            result["transition_error"] = (
                "attach manifest does not contain one exact x64 wow64cpu.dll"
            )
            return
        bridge = bridge_entries[0]
        try:
            from winbox.kdbg.decomp.identity import sha256_file
            from winbox.kdbg.wow64_transition import (
                Wow64TransitionError,
                derive_native_trap_layout,
                derive_transition_layout,
                recover_native_trap_context,
            )

            path = Path(bridge.pe_path).resolve(strict=True)
            if sha256_file(path).lower() != bridge.pe_sha256.lower():
                raise Wow64TransitionError("exact wow64cpu PE hash changed after attach")
            if not bridge.store_build:
                raise Wow64TransitionError("exact wow64cpu PDB was not enriched")
            record = self.store.load_build(bridge.store_name, bridge.store_build)
            if (
                str(record.get("pe_sha256") or "").lower()
                != bridge.pe_sha256.lower()
            ):
                raise Wow64TransitionError("wow64cpu PDB record is not bound to PE")
            transition_layout = derive_transition_layout(
                path, record.get("symbols") or {},
            )
            trap_layout = derive_native_trap_layout(self.store.struct)
            stop = self._require_stop_epoch()
            epoch = {"session_id": self.session_id, "stop_id": self.stop_id}

            def native_read(va: int, length: int) -> bytes:
                if (
                    va < 0 or length < 0 or length > 1 << 20
                    or va + length > (1 << 64)
                ):
                    raise Wow64TransitionError(
                        f"native context read out of bounds: 0x{va:x}+0x{length:x}"
                    )
                return bytes.fromhex(
                    self.op_mem(va, length, **epoch)["bytes"]
                )

            x64_ranges = [
                (entry.base, entry.base + entry.size)
                for entry in self.module_manifest.modules
                if entry.architecture == "x64"
            ]
            context = recover_native_trap_context(
                trap_layout, stop.raw_regs, native_read,
                expected_process=self.target.eprocess,
                is_x64_code=lambda address: any(
                    start <= address < end for start, end in x64_ranges
                ),
                is_bridge_code=lambda address: (
                    bridge.base <= address < bridge.base + bridge.size
                ),
            )
            remaining = depth - len(frames)
            native_result = self._unwind_backtrace(
                remaining + 1, x64_context=context, allow_transition=False,
            )
            recovered = native_result.get("frames") or []
            if len(recovered) < 2:
                raise Wow64TransitionError(
                    native_result.get("error")
                    or "persisted bridge unwind returned fewer than two frames"
                )
            if any(
                _normalize_module_name(str(recovered[index].get("module", "")))
                != "wow64cpu"
                for index in (0, 1)
            ):
                raise Wow64TransitionError(
                    "persisted trap does not unwind into suspended wow64cpu code"
                )
            native_frames = recovered[1:remaining + 1]
            if not native_frames:
                raise Wow64TransitionError("no suspended native frames remain")
            first_rsp = int(str(native_frames[0].get("rsp", "0")), 0)
            if not context.stack_limit <= first_rsp < context.stack_base:
                raise Wow64TransitionError(
                    "recovered native caller lies outside TEB stack"
                )
        except Exception as exc:
            result["transition_error"] = f"{type(exc).__name__}: {exc}"
            return

        x86_error = result.pop("error", None)
        first_native_index = len(frames)
        for frame in native_frames:
            copied = dict(frame)
            copied["index"] = len(frames)
            if copied["index"] == first_native_index:
                copied["boundary"] = "wow64-x86-to-x64"
            frames.append(copied)
        result["method"] = "windows-wow64-mixed"
        result["architecture"] = "mixed-x86-x64"
        result["complete"] = bool(native_result.get("complete"))
        result["transition"] = {
            "direction": "x86-to-x64",
            "module": bridge.name,
            "build": bridge.store_build,
            "layout": transition_layout.derivation,
            "context_source": context.source,
            "kpcr": f"0x{context.kpcr:x}",
            "thread": f"0x{context.thread:x}",
            "trap_frame": f"0x{context.trap_frame:x}",
            "persisted_rip": f"0x{context.rip:x}",
            "persisted_rsp": f"0x{context.rsp:x}",
            "x86_frame_count": first_native_index,
            "x64_frame_count": len(native_frames),
            "discarded_historical_frames": 1,
        }
        if x86_error:
            result["x86_error"] = x86_error
        if native_result.get("error"):
            native_error = str(native_result["error"])
            result["error"] = (
                f"depth limit {depth} reached"
                if native_error.startswith("depth limit ") else native_error
            )

    def _unwind_x86_context(
        self, eip: int, esp: int, ebp: int, ebx: int, depth: int, live_read,
    ) -> dict[str, Any]:
        """Unwind one saved x86 context through exact manifest artifacts."""
        from winbox.kdbg.x86_unwind import X86HybridUnwinder, X86Module

        sources: list[tuple[str, Any, dict[str, Any]]] = []
        if self.module_manifest is not None:
            for entry in self.module_manifest.modules:
                if entry.architecture != "x86":
                    continue
                record: dict[str, Any] = {}
                if entry.store_build:
                    try:
                        candidate = self.store.load_build(
                            entry.store_name, entry.store_build,
                        )
                        if (
                            str(candidate.get("pe_sha256") or "").lower()
                            == entry.pe_sha256.lower()
                        ):
                            record = candidate
                    except Exception:
                        pass
                sources.append((entry.store_name, entry, record))
        else:
            try:
                store_names = self.store.list_modules()
            except Exception as exc:
                return {
                    "rsp": f"0x{esp:x}", "method": "windows-x86-hybrid",
                    "complete": False, "frames": [], "candidates": [],
                    "error": f"x86 symbol inventory failed: {exc}",
                }
            from types import SimpleNamespace
            for store_name in store_names:
                try:
                    record = self.store.load(store_name)
                except Exception:
                    continue
                _, architecture = _stored_module_identity(store_name, record)
                if architecture != "x86":
                    continue
                path_value = str(record.get("pe_path") or "")
                sources.append((store_name, SimpleNamespace(
                    name=_stored_module_identity(store_name, record)[0]
                    + Path(path_value).suffix.lower(),
                    base=int(record.get("base") or 0),
                    size=int(record.get("size_of_image") or 0),
                    pe_path=path_value,
                    pe_sha256=str(record.get("pe_sha256") or ""),
                ), record))

        modules: list[X86Module] = []
        relevant_errors: list[str] = []
        for store_name, entry, record in sources:
            relevant = False
            try:
                from winbox.kdbg.decomp.identity import (
                    IdentityError,
                    parse_live_pe,
                    parse_static_pe,
                    sha256_file,
                    validate_identity,
                )
                base = int(entry.base)
                size = int(entry.size)
                relevant = base <= eip < base + size
                if (
                    base <= 0 or size <= 0 or base > 0xFFFFFFFF
                    or base + size > (1 << 32)
                ):
                    raise RuntimeError("symbol store has invalid x86 base/size")
                path_value = entry.pe_path
                expected_sha = entry.pe_sha256
                if not path_value or not expected_sha:
                    raise RuntimeError("symbol store has no hash-bound PE")
                path = Path(path_value).resolve(strict=True)
                if sha256_file(path).lower() != str(expected_sha).lower():
                    raise RuntimeError("cached PE hash mismatch")
                static = parse_static_pe(path)
                try:
                    live = parse_live_pe(live_read, base)
                except IdentityError:
                    live = parse_live_pe(live_read, base, include_pdb=False)
                display_name = str(entry.name)
                confidence = validate_identity(
                    live, static, module_name=display_name,
                    live_module_size=size,
                )
                if static.machine != 0x014C:
                    raise RuntimeError(
                        f"cached PE machine 0x{static.machine:04x} is not x86"
                    )
                raw_frames = record.get("frame_data") or ()
                frame_data = tuple(raw_frames) if isinstance(raw_frames, list) else ()
                if not isinstance(raw_frames, (list, tuple)):
                    relevant_errors.append(
                        f"{store_name}: frame_data store field is not a list"
                    )
                names = set(record.get("function_symbols") or [])
                symbols = record.get("symbols") or {}
                starts: set[int] = set()
                for name in names:
                    try:
                        value = int(symbols[name])
                    except (KeyError, TypeError, ValueError):
                        continue
                    if 0 <= value < size:
                        starts.add(value)
                modules.append(X86Module(
                    name=display_name, base=base, size=size,
                    frame_data=frame_data,
                    function_starts=tuple(sorted(starts)),
                    metadata=(
                        f"verified-pdb:{confidence}:attach-manifest:"
                        f"{self.module_manifest.staging_policy}"
                        if record else f"verified-pe:{confidence}:attach-manifest:"
                        f"{self.module_manifest.staging_policy}"
                    ) if self.module_manifest is not None else (
                        f"verified-pdb:{confidence}"
                    ),
                ))
            except Exception as exc:
                if relevant:
                    relevant_errors.append(f"{store_name}: {exc}")

        unwinder = X86HybridUnwinder(
            modules, live_read, self._best_symbol_for_va,
        )
        result = unwinder.unwind(eip, esp, ebp, ebx, depth)
        if relevant_errors:
            result["metadata_errors"] = relevant_errors[:16]
            if not result["frames"]:
                result["error"] = "; ".join(relevant_errors[:4])
        return result
