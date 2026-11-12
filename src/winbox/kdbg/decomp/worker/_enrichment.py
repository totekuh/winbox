"""PDB enrichment loading and application mixin for the Ghidra worker."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import time
from pathlib import Path

from winbox.kdbg.decomp.worker._common import (
    ANALYSIS_PROFILE,
    ENRICHMENT_REVISION,
    MAX_ENRICHMENT_BYTES,
    MAX_ENRICHMENT_EVENTS,
    MAX_ENRICHMENT_RECORDS,
    WorkerError,
)


class _EnrichmentMixin:
    """Enrichment methods extracted from Worker — mixed back in by _worker.py."""

    cache: Path

    def _load_enrichment(self, value: str, digest: str) -> tuple[str, dict] | None:
        if not value:
            return None
        path = Path(value)
        try:
            resolved = path.resolve(strict=True)
            root = (self.cache / "enrichment").resolve(strict=True)
        except OSError as exc:
            raise WorkerError(
                "exact PDB enrichment sidecar is missing",
                code="prerequisite_missing",
            ) from exc
        if path.is_symlink() or not resolved.is_file() or not resolved.is_relative_to(root):
            raise WorkerError("unsafe PDB enrichment path", code="invalid_argument")
        if resolved.stat().st_size > MAX_ENRICHMENT_BYTES:
            raise WorkerError("PDB enrichment sidecar exceeds size cap", code="invalid_argument")
        try:
            raw = resolved.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerError("invalid PDB enrichment sidecar", code="invalid_argument") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != "winbox.pdb-enrichment/1"
            or payload.get("revision") != ENRICHMENT_REVISION
            or payload.get("analysis_profile") != ANALYSIS_PROFILE
            or payload.get("binary_sha256") != digest
        ):
            raise WorkerError("PDB enrichment identity mismatch", code="identity_mismatch")
        for field in ("functions", "globals"):
            records = payload.get(field)
            if not isinstance(records, list) or len(records) > MAX_ENRICHMENT_RECORDS:
                raise WorkerError(f"invalid bounded enrichment {field}", code="invalid_argument")
            for record in records:
                if not isinstance(record, dict):
                    raise WorkerError(f"invalid enrichment {field} record", code="invalid_argument")
                name = record.get("name")
                rva = record.get("rva")
                if (
                    not isinstance(name, str) or not 1 <= len(name) <= 512 or "\0" in name
                    or isinstance(rva, bool) or not isinstance(rva, int)
                    or not 0 <= rva < (1 << 32)
                ):
                    raise WorkerError(f"invalid enrichment {field} identity", code="invalid_argument")
        return hashlib.sha256(raw).hexdigest(), payload

    @staticmethod
    def _safe_symbol_name(value: str, rva: int) -> str:
        safe = re.sub(r"[^A-Za-z0-9_?$@]", "_", value[:200])
        if not safe or safe[0].isdigit():
            safe = f"winbox_{rva:x}_{safe}"
        return safe

    @staticmethod
    def _signature_type(spec: dict, manager):
        from ghidra.program.model import data as types
        classes = {
            "void": types.VoidDataType,
            "bool": types.BooleanDataType,
            "char": types.CharDataType,
            "signed char": types.SignedCharDataType,
            "unsigned char": types.UnsignedCharDataType,
            "short": types.ShortDataType,
            "unsigned short": types.UnsignedShortDataType,
            "int": types.IntegerDataType,
            "unsigned int": types.UnsignedIntegerDataType,
            "long": types.LongDataType,
            "unsigned long": types.UnsignedLongDataType,
            "__int64": types.LongLongDataType,
            "unsigned __int64": types.UnsignedLongLongDataType,
            "float": types.FloatDataType,
            "double": types.DoubleDataType,
            "wchar_t": types.WideCharDataType,
        }
        if not isinstance(spec, dict) or spec.get("base") not in classes:
            raise ValueError("unsupported signature type")
        pointers = spec.get("pointers", 0)
        if isinstance(pointers, bool) or not isinstance(pointers, int) or not 0 <= pointers <= 2:
            raise ValueError("invalid pointer depth")
        value = classes[spec["base"]](manager)
        for _ in range(pointers):
            value = types.PointerDataType(value, manager)
        return value

    def _apply_signature(self, program, function, signature: dict, name: str) -> bool:
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl
        from ghidra.program.model.symbol import SourceType
        if function.getSignatureSource() not in (SourceType.DEFAULT, SourceType.ANALYSIS):
            return False
        manager = program.getDataTypeManager()
        definition = FunctionDefinitionDataType(name, manager)
        definition.setReturnType(self._signature_type(signature.get("return"), manager))
        parameters = [
            ParameterDefinitionImpl(
                f"param_{index + 1}", self._signature_type(spec, manager), None,
            )
            for index, spec in enumerate(signature.get("parameters") or [])
        ]
        definition.setArguments(parameters)
        command = ApplyFunctionSignatureCmd(
            function.getEntryPoint(), definition, SourceType.IMPORTED,
        )
        return bool(command.applyTo(program))

    def _enrichment_result_path(self, digest: str) -> Path:
        return (
            self.cache / "enrichment-results"
            / f"{ANALYSIS_PROFILE}_{digest}.json"
        )

    def _record_enrichment_result(
        self, digest: str, sidecar_sha256: str, stats: dict, events: list[dict],
    ) -> str:
        """Atomically persist every bounded enrichment decision and its source."""
        if len(events) > MAX_ENRICHMENT_EVENTS:
            raise WorkerError(
                "enrichment result exceeds bounded event cap",
                code="invalid_argument",
            )
        path = self._enrichment_result_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "winbox.ghidra-enrichment-provenance/1",
            "analysis_profile": ANALYSIS_PROFILE,
            "binary_sha256": digest,
            "sidecar_sha256": sidecar_sha256,
            "recorded_at": time.time(),
            "summary": stats,
            "events": events,
        }
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, separators=(",", ":")), encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise WorkerError(
                "could not persist exact PDB enrichment provenance",
                code="cache_write_failed", retryable=True,
            ) from exc
        return str(path.relative_to(self.cache))

    def _apply_enrichment(self, opened, digest: str, value: str) -> dict | None:
        loaded = self._load_enrichment(value, digest)
        if loaded is None:
            return None
        key, payload = loaded
        if opened.enrichment_key == key:
            return opened.enrichment_summary
        self._phase("enriching_program")
        from ghidra.program.model.symbol import SourceType
        program = opened.program
        base = int(program.getImageBase().getOffset())
        space = program.getAddressFactory().getDefaultAddressSpace()
        memory = program.getMemory()
        manager = program.getFunctionManager()
        symbols = program.getSymbolTable()
        stats = {
            "schema": "winbox.ghidra-enrichment-result/1",
            "pdb_build": str(payload.get("pdb_build") or "")[:64],
            "functions_named": 0, "signatures_applied": 0,
            "globals_named": 0, "reused": 0, "conflicts": 0,
            "invalid": 0, "truncated": bool(payload.get("truncated")),
        }
        events: list[dict] = []

        def event(item: dict, kind: str, action: str, **details) -> None:
            value = {
                "kind": kind, "rva": item["rva"],
                "name": str(item["name"])[:512],
                "source": str(item.get("source") or "exact-pdb")[:64],
                "action": action,
            }
            value.update(details)
            events.append(value)
        commit = False
        transaction = program.startTransaction("winbox exact PDB enrichment")
        try:
            for item in payload["functions"]:
                rva = item["rva"]
                address = space.getAddress(base + rva)
                if not memory.contains(address):
                    stats["invalid"] += 1
                    event(item, "function_name", "invalid", reason="outside-memory")
                    continue
                safe_name = self._safe_symbol_name(item["name"], rva)
                function = manager.getFunctionAt(address)
                if function is None:
                    if program.getListing().getInstructionAt(address) is None:
                        opened.api.disassemble(address)
                    try:
                        function = opened.api.createFunction(address, safe_name)
                    except Exception:
                        function = opened.api.createFunction(
                            address, f"{safe_name}__rva_{rva:x}",
                        )
                if function is None:
                    stats["conflicts"] += 1
                    event(item, "function_name", "conflict", reason="create-failed")
                    continue
                current_name = str(function.getName())
                source = function.getSymbol().getSource()
                if current_name == safe_name:
                    stats["reused"] += 1
                    event(item, "function_name", "reused")
                elif source in (SourceType.DEFAULT, SourceType.ANALYSIS):
                    try:
                        function.setName(safe_name, SourceType.IMPORTED)
                        applied_name = safe_name
                    except Exception:
                        applied_name = f"{safe_name}__rva_{rva:x}"
                        function.setName(applied_name, SourceType.IMPORTED)
                    stats["functions_named"] += 1
                    event(
                        item, "function_name", "applied",
                        applied_name=applied_name[:512],
                    )
                else:
                    stats["conflicts"] += 1
                    event(
                        item, "function_name", "conflict",
                        reason="preserved-existing", existing=current_name[:512],
                    )
                if isinstance(item.get("signature"), dict):
                    signature_item = dict(item)
                    signature_item["source"] = item.get(
                        "signature_source", item.get("source", "exact-pdb"),
                    )
                    try:
                        if self._apply_signature(program, function, item["signature"], safe_name):
                            stats["signatures_applied"] += 1
                            event(signature_item, "function_signature", "applied")
                        else:
                            stats["conflicts"] += 1
                            event(
                                signature_item, "function_signature", "conflict",
                                reason="preserved-existing",
                            )
                    except Exception:
                        stats["invalid"] += 1
                        event(
                            signature_item, "function_signature", "invalid",
                            reason="signature-application-failed",
                        )
            for item in payload["globals"]:
                rva = item["rva"]
                address = space.getAddress(base + rva)
                if not memory.contains(address):
                    stats["invalid"] += 1
                    event(item, "global_name", "invalid", reason="outside-memory")
                    continue
                safe_name = self._safe_symbol_name(item["name"], rva)
                primary = symbols.getPrimarySymbol(address)
                existing = next((
                    symbol for symbol in symbols.getSymbols(address)
                    if str(symbol.getName()) == safe_name
                ), None)
                if existing is not None and (
                    primary is None or primary.getSource() in (
                        SourceType.DEFAULT, SourceType.ANALYSIS,
                    )
                ):
                    existing.setPrimary()
                    stats["reused"] += 1
                    event(item, "global_name", "reused", applied_name=safe_name)
                elif primary is not None and str(primary.getName()) == safe_name:
                    stats["reused"] += 1
                    event(item, "global_name", "reused")
                elif primary is None or primary.getSource() in (
                    SourceType.DEFAULT, SourceType.ANALYSIS,
                ):
                    applied_name = safe_name
                    try:
                        created = symbols.createLabel(
                            address, applied_name, SourceType.IMPORTED,
                        )
                    except Exception:
                        applied_name = f"{safe_name}__rva_{rva:x}"
                        created = symbols.createLabel(
                            address, applied_name, SourceType.IMPORTED,
                        )
                    created.setPrimary()
                    stats["globals_named"] += 1
                    event(
                        item, "global_name", "applied",
                        applied_name=applied_name[:512],
                    )
                else:
                    stats["conflicts"] += 1
                    event(
                        item, "global_name", "conflict",
                        reason="preserved-existing",
                        existing=str(primary.getName())[:512],
                    )
            commit = True
        finally:
            program.endTransaction(transaction, commit)
        stats["event_count"] = len(events)
        stats["provenance_file"] = self._record_enrichment_result(
            digest, key, stats, events,
        )
        opened.decompile_cache.clear()
        opened.enrichment_key = key
        opened.enrichment_summary = stats
        return stats
