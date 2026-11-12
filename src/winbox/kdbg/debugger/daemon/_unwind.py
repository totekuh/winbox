"""Stack unwinding — x64 PE pdata + WoW64 x86 bridge (x64→x86 direction)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from winbox.kdbg.debugger.daemon._helpers import (
    _GPR_NAMES,
    _normalize_module_name,
)
from winbox.kdbg.debugger.daemon._types import StopState


class _UnwindMixin:
    """x64 PE unwind + WoW64 x64→x86 transition stitching."""

    def op_bt(self, depth: int = 8) -> dict[str, Any]:
        """Unwind x64 PE metadata or a WoW64 x86 hybrid call chain."""
        if self.stop is None:
            raise RuntimeError("not halted; cont first")
        depth = max(1, min(int(depth), 64))
        return self._unwind_backtrace(depth)

    def _unwind_backtrace(
        self,
        depth: int,
        *,
        x64_context: Any | None = None,
        allow_transition: bool = True,
    ) -> dict[str, Any]:
        """Epoch-stable, bounded live-image unwind implementation."""
        if x64_context is None and self._is_x86_stop():
            return self._unwind_x86_backtrace(depth)
        from winbox.kdbg.unwind import PeX64Unwinder, UnwindError

        stop = self._require_stop_epoch()
        epoch = {"session_id": self.session_id, "stop_id": self.stop_id}
        if x64_context is None:
            registers = {
                name: struct.unpack_from("<Q", stop.raw_regs, index * 8)[0]
                for index, name in enumerate(_GPR_NAMES)
            }
            rip = stop.rip
            rsp = registers["rsp"]
        else:
            registers = dict(x64_context.registers)
            rip = int(x64_context.rip)
            rsp = int(x64_context.rsp)
        initial_rsp = rsp

        pages: dict[int, bytes] = {}

        def live_read(va: int, length: int) -> bytes:
            if length < 0 or length > 16 * 1024 * 1024:
                raise UnwindError(f"live unwind read out of bounds: {length}")
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
                    raise UnwindError(f"short live page at 0x{page:x}")
                output.extend(chunk)
                va += take
                length -= take
            return bytes(output)

        def verified_static_reader(module):
            """Use a cached PE only after matching it to the live image."""
            from winbox.kdbg.decomp.identity import (
                IdentityError,
                parse_live_pe,
                parse_static_pe,
                sha256_file,
                validate_identity,
            )

            if self.module_manifest is not None:
                manifest_entry = self.module_manifest.by_base(
                    module.base, getattr(module, "architecture", "x64"),
                )
                if manifest_entry is None:
                    raise UnwindError(
                        f"{module.name} has no exact attach-manifest artifact"
                    )
                raw_path = manifest_entry.pe_path
                expected_sha = manifest_entry.pe_sha256
                artifact_source = (
                    f"attach-manifest:{self.module_manifest.staging_policy}:"
                    f"{manifest_entry.artifact_source}"
                )
            else:
                stem = str(module.name).rsplit(".", 1)[0].lower()
                if stem.startswith("ntoskrnl") or stem.startswith("ntkrnl"):
                    store_name = "nt"
                else:
                    store_name = stem
                    if getattr(module, "architecture", "x64") == "x86":
                        store_name += "_x86"
                record = self.store.load(store_name)
                raw_path = record.get("pe_path")
                expected_sha = record.get("pe_sha256")
                artifact_source = "symbol-store"
            if not raw_path or not expected_sha:
                raise UnwindError(
                    f"live unwind metadata is unavailable and {module.name} "
                    "has no hash-bound exact PE"
                )
            path = Path(raw_path).resolve(strict=True)
            digest = sha256_file(path)
            if digest.lower() != str(expected_sha).lower():
                raise UnwindError(f"cached PE hash mismatch for {module.name}")
            static = parse_static_pe(path)
            identity_warning = None
            try:
                live = parse_live_pe(live_read, module.base)
            except IdentityError as exc:
                live = parse_live_pe(live_read, module.base, include_pdb=False)
                identity_warning = f"live CodeView unavailable: {exc}"
            confidence = validate_identity(
                live, static, module_name=module.name,
                live_module_size=module.size,
            )
            first_section = min(
                (section.virtual_address for section in static.sections),
                default=0x1000,
            )

            def read_static(va: int, length: int) -> bytes:
                rva = va - module.base
                if rva < 0 or length < 0 or rva + length > static.image_size:
                    raise UnwindError("static unwind read lies outside image")
                if rva < first_section:
                    if rva + length > first_section:
                        raise UnwindError("static unwind read crosses PE headers")
                    with path.open("rb") as handle:
                        handle.seek(rva)
                        data = handle.read(length)
                else:
                    selected = next(
                        (section for section in static.sections
                         if section.file_offset(rva) is not None),
                        None,
                    )
                    if selected is None:
                        raise UnwindError(f"RVA 0x{rva:x} has no static bytes")
                    offset = selected.file_offset(rva)
                    assert offset is not None
                    available = selected.raw_offset + selected.raw_size - offset
                    if length > available:
                        raise UnwindError("static unwind read crosses section data")
                    with path.open("rb") as handle:
                        handle.seek(offset)
                        data = handle.read(length)
                if len(data) != length:
                    raise UnwindError(f"short cached PE read: {len(data)}/{length}")
                return data

            return read_static, confidence, identity_warning, artifact_source

        try:
            kernel_modules = (
                [] if x64_context is not None else [
                    (module, "kernel") for module in self._live_modules("kernel")
                ]
            )
            modules = kernel_modules + [
                (module, "user") for module in self._unwind_user_modules()
            ]
        except Exception as exc:
            return {
                "rsp": f"0x{rsp:x}", "method": "windows-x64-pdata",
                "complete": False, "error": f"module inventory failed: {exc}",
                "frames": [],
            }

        unwinders: dict[tuple[int, int], tuple[PeX64Unwinder, str]] = {}
        frames: list[dict[str, Any]] = []
        visited: set[tuple[int, int]] = set()
        error: str | None = None
        complete = False
        for frame_index in range(depth):
            if rip == 0:
                complete = True
                break
            key = (rip, rsp)
            if key in visited:
                error = "unwind loop detected"
                break
            visited.add(key)
            matches = [
                (module, kind) for module, kind in modules
                if module.base <= rip < module.base + module.size
            ]
            if not matches:
                error = f"0x{rip:x} is outside every live module"
                break
            module, kind = min(matches, key=lambda item: item[0].size)
            frame = {
                "index": frame_index,
                "addr": f"0x{rip:x}",
                "rsp": f"0x{rsp:x}",
                "sym": self._best_symbol_for_va(rip),
                "module": module.name,
                "rva": f"0x{rip - module.base:x}",
                "architecture": getattr(module, "architecture", "x64"),
            }
            frames.append(frame)
            if getattr(module, "architecture", "x64") != "x64":
                error = "x86 WoW64 stack unwinding is not supported by the x64 unwinder"
                break
            try:
                cache_key = (module.base, module.size)
                cached = unwinders.get(cache_key)
                if cached is None:
                    try:
                        unwinder = PeX64Unwinder(
                            module.base, module.size, live_read,
                        )
                        metadata_source = "live-image"
                    except (UnwindError, RuntimeError) as live_exc:
                        static_read, confidence, identity_warning, artifact_source = (
                            verified_static_reader(module)
                        )
                        unwinder = PeX64Unwinder(
                            module.base, module.size, static_read,
                        )
                        metadata_source = (
                            f"verified-static:{confidence}:{artifact_source}"
                        )
                        frame["live_metadata_error"] = str(live_exc)
                        if identity_warning:
                            frame["identity_warning"] = identity_warning
                    unwinders[cache_key] = (unwinder, metadata_source)
                else:
                    unwinder, metadata_source = cached
                step = unwinder.unwind(rip, rsp, registers, live_read)
                frame["unwind"] = "leaf" if step.leaf else "pdata"
                frame["metadata"] = metadata_source
                if step.operations:
                    frame["operations"] = list(step.operations)
            except (UnwindError, RuntimeError) as exc:
                error = f"{module.name}+0x{rip - module.base:x}: {exc}"
                break
            if step.rsp <= rsp or step.rsp - initial_rsp > 16 * 1024 * 1024:
                error = f"implausible caller RSP 0x{step.rsp:x}"
                break
            rip, rsp, registers = step.rip, step.rsp, step.registers
        else:
            complete = False
            error = f"depth limit {depth} reached"

        result: dict[str, Any] = {
            "rsp": f"0x{initial_rsp:x}",
            "method": "windows-x64-pdata",
            "complete": complete,
            "frames": frames,
        }
        if error:
            result["error"] = error
        if (
            allow_transition and self.module_manifest is not None
            and len(frames) < depth
        ):
            self._stitch_wow64_x86(
                result, depth=depth, live_read=live_read,
            )
        return result

    def _is_x86_stop(self) -> bool:
        """True for the Windows WoW64 compatibility-mode code selector."""
        if self.stop is None or len(self.stop.raw_regs) < 144:
            return False
        cs = struct.unpack_from("<I", self.stop.raw_regs, 140)[0] & 0xFFFF
        return cs == 0x23

    def _stitch_wow64_x86(
        self, result: dict[str, Any], *, depth: int, live_read,
    ) -> None:
        """Append a validated saved x86 chain at an active native bridge stop."""
        frames = result.get("frames") or []
        if not any(
            _normalize_module_name(str(frame.get("module", ""))) == "wow64cpu"
            for frame in frames
        ):
            return
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
                derive_transition_layout,
                recover_x86_context,
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
            layout = derive_transition_layout(path, record.get("symbols") or {})
            x86_ranges = [
                (entry.base, entry.base + entry.size)
                for entry in self.module_manifest.modules
                if entry.architecture == "x86"
            ]
            context = recover_x86_context(
                layout, self._require_stop_epoch().raw_regs, live_read,
                lambda address: any(start <= address < end for start, end in x86_ranges),
            )
            remaining = depth - len(frames)
            x86_result = self._unwind_x86_context(
                context.eip, context.esp, context.ebp, context.ebx,
                remaining, live_read,
            )
            x86_frames = x86_result.get("frames") or []
            if not x86_frames:
                raise Wow64TransitionError(
                    x86_result.get("error") or "saved x86 unwind returned no frames"
                )
        except Exception as exc:
            result["transition_error"] = f"{type(exc).__name__}: {exc}"
            return

        native_error = result.pop("error", None)
        first_x86_index = len(frames)
        for frame in x86_frames:
            copied = dict(frame)
            copied["index"] = len(frames)
            if copied["index"] == first_x86_index:
                copied["boundary"] = "wow64-x64-to-x86"
            frames.append(copied)
        result["method"] = "windows-wow64-mixed"
        result["architecture"] = "mixed-x64-x86"
        result["complete"] = bool(x86_result.get("complete"))
        result["transition"] = {
            "direction": "x64-to-x86",
            "module": bridge.name,
            "build": bridge.store_build,
            "layout": layout.derivation,
            "context_source": context.source,
            "context_va": f"0x{context.context_va:x}",
            "saved_eip": f"0x{context.eip:x}",
            "saved_esp": f"0x{context.esp:x}",
            "native_frame_count": len(frames) - len(x86_frames),
            "x86_frame_count": len(x86_frames),
        }
        if native_error:
            result["native_error"] = native_error
        if x86_result.get("error"):
            result["error"] = x86_result["error"]
        if x86_result.get("candidates"):
            result["candidates"] = x86_result["candidates"]
        if x86_result.get("metadata_errors"):
            result["metadata_errors"] = x86_result["metadata_errors"]
