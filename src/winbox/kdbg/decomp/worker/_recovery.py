"""PDB-guided function recovery for the Ghidra worker."""

from __future__ import annotations

import re


def _recover_function(api, program, address, rva: int, hint):
    """Create one missed function only from a close, verified PDB public RVA."""
    if not isinstance(hint, dict) or hint.get("is_function") is not True:
        return None, "none"
    try:
        hint_rva = int(hint["rva"])
        offset = int(hint["offset"])
    except (KeyError, TypeError, ValueError):
        return None, "none"
    if hint_rva < 0 or hint_rva > rva or offset > 64 * 1024:
        return None, "none"
    image_base = int(program.getImageBase().getOffset())
    hint_address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
        image_base + hint_rva
    )
    memory = program.getMemory()
    if not memory.contains(hint_address):
        return None, "none"
    block = memory.getBlock(hint_address)
    if block is None or not block.isExecute():
        return None, "none"
    manager = program.getFunctionManager()
    existing = manager.getFunctionContaining(hint_address)
    if existing is not None and existing.getBody().contains(address):
        return existing, "pdb-public-existing"

    raw_name = str(hint.get("name") or f"winbox_{hint_rva:x}")[:200]
    safe_name = re.sub(r"[^A-Za-z0-9_?$@]", "_", raw_name)
    if not safe_name or safe_name[0].isdigit():
        safe_name = f"winbox_{hint_rva:x}_{safe_name}"
    success = False
    transaction = program.startTransaction("winbox PDB function recovery")
    try:
        if program.getListing().getInstructionAt(hint_address) is None:
            api.disassemble(hint_address)
        function = manager.getFunctionAt(hint_address)
        if function is None:
            function = api.createFunction(hint_address, safe_name)
        success = function is not None
    finally:
        program.endTransaction(transaction, success)
    if function is not None and function.getBody().contains(address):
        return function, "pdb-public-recovery"

    instruction = program.getListing().getInstructionContaining(address)
    if instruction is None:
        success = False
        transaction = program.startTransaction("winbox instruction disassembly")
        try:
            success = bool(api.disassemble(address))
        finally:
            program.endTransaction(transaction, success)
        instruction = program.getListing().getInstructionContaining(address)
    if instruction is None:
        return None, "none"
    split_address = instruction.getAddress()
    split_name = f"{safe_name}__winbox_at_{rva:x}"
    success = False
    transaction = program.startTransaction("winbox instruction function recovery")
    try:
        function = manager.getFunctionContaining(split_address)
        if function is None:
            function = api.createFunction(split_address, split_name)
        success = function is not None
    finally:
        program.endTransaction(transaction, success)
    if function is not None and function.getBody().contains(address):
        return function, "pdb-public-split-recovery"
    return None, "none"
