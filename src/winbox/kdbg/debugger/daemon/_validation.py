"""Module base validation and breakpoint intent resolution."""

from __future__ import annotations

import sys
from typing import Any

from winbox.config import Config
from winbox.kdbg import SymbolStore, SymbolStoreError
from winbox.kdbg.debugger.daemon._types import DaemonError
from winbox.kdbg.debugger.daemon._helpers import (
    _normalize_module_name,
    _stored_module_identity,
)


def _validate_module_bases(
    cfg: Config,
    rsp: "RspClient",
    target,
    store: SymbolStore,
) -> None:
    """Verify cached module bases match what's actually loaded in target.

    The check has THREE failure modes to distinguish:

    1. Module is loaded in target but its base differs from our cached
       value -> STALE (ASLR moved it across a VM reboot, or symbols
       loaded against a different process). Forces a clear error
       naming the affected modules.

    2. Module is in our store but NOT loaded in this target -> SKIP.
       The store is global across the whole VM; entries from a
       different process are perfectly fine, just irrelevant to this
       target.

    3. Special-case ``nt`` (the kernel): not in PEB.Ldr -- re-derive
       its live base from the IDT and compare against the cached value.
       Mismatch -> stale. Failure to derive is logged and skipped.
    """
    try:
        modules = store.list_modules()
    except Exception:
        return

    if "nt" in modules:
        try:
            nt_data = store.load("nt")
        except Exception:
            nt_data = None
        cached_nt_base = (nt_data or {}).get("base")
        nt_syms = (nt_data or {}).get("symbols") or {}
        if nt_syms:
            from winbox.kdbg.hmp import HmpError
            from winbox.kdbg.symbols import SymbolLoadError, resolve_nt_base
            try:
                live_nt_base = resolve_nt_base(
                    cfg, nt_syms, kernel_cr3=target.dtb,
                )
            except (HmpError, SymbolLoadError, OSError) as e:
                print(
                    f"warning: could not validate nt base "
                    f"({type(e).__name__}: {e}); skipping nt staleness check",
                    file=sys.stderr,
                )
            else:
                if live_nt_base != cached_nt_base:
                    store.set_base("nt", live_nt_base)
                    if cached_nt_base:
                        print(
                            f"note: nt base moved 0x{cached_nt_base:x} -> "
                            f"0x{live_nt_base:x} (ASLR, typically a VM reboot); "
                            f"refreshed automatically",
                            file=sys.stderr,
                        )

    candidates: list[tuple[str, int, tuple[str, str]]] = []
    for mod_name in modules:
        if mod_name == "nt":
            continue
        try:
            data = store.load(mod_name)
        except Exception:
            continue
        base = data.get("base")
        if not base:
            continue
        candidates.append(
            (mod_name, base, _stored_module_identity(mod_name, data))
        )

    if not candidates:
        return

    from winbox.kdbg import ensure_types_loaded
    from winbox.kdbg.hmp import HmpError
    from winbox.kdbg.walk import list_user_modules
    try:
        ensure_types_loaded(cfg, store, ["_PEB", "_PEB_LDR_DATA"], module="nt")
        loaded = list_user_modules(cfg.vm_name, store, target)
    except (HmpError, OSError, RuntimeError, LookupError, SymbolStoreError) as e:
        print(
            f"warning: PEB.Ldr walk failed: {type(e).__name__}: {e}; "
            "cannot validate user-mode module bases for stale state",
            file=sys.stderr,
        )
        return

    target_loaded: dict[tuple[str, str], int] = {
        (
            _normalize_module_name(m.name),
            str(getattr(m, "architecture", "x64")).lower(),
        ): m.base
        for m in loaded
    }

    stale: list[tuple[str, int, int]] = []
    for mod_name, cached_base, identity in candidates:
        actual_base = target_loaded.get(identity)
        if actual_base is None:
            continue
        if actual_base != cached_base:
            stale.append((mod_name, cached_base, actual_base))

    if stale:
        repaired: list[str] = []
        failed: list[str] = []
        for name, cached, actual in stale:
            try:
                store.set_base(name, actual)
            except Exception as e:
                failed.append(f"{name} ({type(e).__name__}: {e})")
            else:
                repaired.append(f"{name} 0x{cached:x} -> 0x{actual:x}")

        if repaired:
            print(
                f"note: refreshed {len(repaired)} stale module base(s) for "
                f"{target.name} after ASLR: {', '.join(repaired)}",
                file=sys.stderr,
            )
        if failed:
            raise DaemonError(
                f"stale module bases for {target.name} could not be "
                f"refreshed: {', '.join(failed)}. Re-run "
                f"kdbg_user_symbols_load for each before retrying."
            )


def _validated_breakpoint_intents(
    intents: object,
) -> list[dict[str, Any]] | None:
    """Validate a parent-side intent snapshot before QEMU is touched."""
    if intents is None:
        return None
    if not isinstance(intents, (list, tuple)):
        raise DaemonError("breakpoint intents must be a bounded list")
    from winbox.kdbg.breakpoint_intent import MAX_INTENTS, normalize_spec

    if len(intents) > MAX_INTENTS:
        raise DaemonError(f"breakpoint intent snapshot exceeds cap {MAX_INTENTS}")
    validated: list[dict[str, Any]] = []
    seen: set[int] = set()
    for raw in intents:
        if not isinstance(raw, dict):
            raise DaemonError("breakpoint intent snapshot contains a non-object record")
        intent_id = raw.get("id")
        if (
            isinstance(intent_id, bool)
            or not isinstance(intent_id, int)
            or intent_id < 0
            or intent_id in seen
        ):
            raise DaemonError("breakpoint intent snapshot contains an invalid id")
        seen.add(intent_id)
        try:
            spec = normalize_spec(
                raw.get("target"), mode=raw.get("mode"),
                condition=raw.get("condition"), wp_type=raw.get("wp_type"),
                wp_size=raw.get("wp_size"), actions=raw.get("actions"),
            )
        except Exception as exc:
            raise DaemonError(f"invalid breakpoint intent {intent_id}: {exc}") from exc
        validated.append({"id": intent_id, **spec})
    return validated


def _apply_breakpoint_intents(
    session,
    intents: list[dict[str, Any]],
) -> dict[str, Any]:
    """Resolve and install one explicit intent snapshot inside a fresh stop."""
    records: list[dict[str, Any]] = []
    installed = unresolved = failed = 0
    for intent in intents:
        args = {
            key: intent[key]
            for key in ("target", "mode", "condition", "wp_type", "wp_size", "actions")
        }
        reply = session.handle_op("bp_add", args)
        record: dict[str, Any] = {
            "intent_id": intent["id"],
            "target": intent["target"],
        }
        if reply.get("ok") is True:
            installed += 1
            record.update({"status": "installed", "breakpoint": reply["result"]})
        else:
            message = str(reply.get("error") or "breakpoint installation failed")
            manifest_miss = any(
                marker in message
                for marker in (
                    "staged user-module manifest", "is not in this session",
                    "is ambiguous", "lies outside",
                )
            )
            status = "unresolved" if manifest_miss else "install_failed"
            if manifest_miss:
                unresolved += 1
            else:
                failed += 1
            record.update({"status": status, "error": message})
            if reply.get("error_info") is not None:
                record["error_info"] = reply["error_info"]
        records.append(record)
    return {
        "schema": "winbox.kdbg-breakpoint-intent-application/1",
        "requested": len(intents),
        "installed": installed,
        "unresolved": unresolved,
        "failed": failed,
        "results": records,
    }
