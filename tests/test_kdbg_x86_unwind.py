"""Hermetic tests for the conservative WoW64 x86 hybrid unwinder."""

from __future__ import annotations

import struct

import pytest

from winbox.kdbg.x86_unwind import X86HybridUnwinder, X86Module


BASE = 0x10000000
CALLER = BASE + 0x700
STACK = 0x00100000


class Memory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}

    def put(self, address: int, data: bytes) -> None:
        self.bytes.update({address + i: value for i, value in enumerate(data)})

    def u32(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<I", value))

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.bytes.get(address + i, 0) for i in range(length))


def module(*, records=(), starts=()) -> X86Module:
    return X86Module(
        "sample.dll", BASE, 0x10000, tuple(records), tuple(starts),
        "verified-pdb:exact",
    )


def unwind(memory: Memory, mod: X86Module, *, eip=BASE + 0x110,
           esp=STACK, ebp=0, ebx=0, depth=1):
    engine = X86HybridUnwinder(
        [mod], memory.read, lambda va: f"sample!{va - BASE:x}",
    )
    return engine.unwind(eip, esp, ebp, ebx, depth)


def test_old_fpo_uses_normalized_locals_saved_regs_and_params():
    record = {
        "rva": 0x100, "code_size": 0x40, "recipe": "fpo-stack",
        "source": "pdb-old-fpo", "locals_size": 8,
        "saved_regs_size": 4, "params_size": 12,
    }
    memory = Memory()
    memory.u32(STACK + 12, CALLER)

    result = unwind(memory, module(records=[record]))

    assert result["frames"][0]["unwind"] == "pdb-old-fpo"
    assert result["frames"][0]["confidence"] == "high"
    assert result["frames"][0]["metadata"] == "verified-pdb:exact"
    assert result["error"] == "depth limit 1 reached"
    assert "return slot esp+0xc" in result["frames"][0]["operations"]


def test_old_fpo_applies_parameters_to_its_caller_not_itself():
    records = [
        {
            "rva": 0x100, "code_size": 0x40, "recipe": "fpo-stack",
            "source": "pdb-old-fpo", "locals_size": 0,
            "saved_regs_size": 0, "params_size": 8,
        },
        {
            "rva": 0x700, "code_size": 0x40, "recipe": "fpo-stack",
            "source": "pdb-old-fpo", "locals_size": 0,
            "saved_regs_size": 0, "params_size": 0,
        },
    ]
    memory = Memory()
    memory.u32(STACK, CALLER)
    memory.u32(STACK + 12, BASE + 0x900)

    result = unwind(memory, module(records=records), depth=2)

    assert "return slot esp+0x0" in result["frames"][0]["operations"]
    assert result["frames"][1]["rsp"] == f"0x{STACK + 4:x}"
    assert "return slot esp+0x8" in result["frames"][1]["operations"]


def test_valid_ebp_chain_is_used_when_pdb_recipe_is_unsupported():
    record = {
        "rva": 0x100, "code_size": 0x40, "recipe": "unsupported",
        "source": "pdb-frame-data",
    }
    memory = Memory()
    memory.u32(STACK + 0x20, STACK + 0x40)
    memory.u32(STACK + 0x24, CALLER)

    result = unwind(memory, module(records=[record]), ebp=STACK + 0x20)

    frame = result["frames"][0]
    assert frame["unwind"] == "ebp-chain"
    assert frame["confidence"] == "high"


@pytest.mark.parametrize("next_ebp", [STACK + 0x20, STACK + 0x10, STACK + 3])
def test_non_monotonic_or_unaligned_ebp_chain_fails_truthfully(next_ebp):
    memory = Memory()
    memory.u32(STACK + 0x20, next_ebp)
    memory.u32(STACK + 0x24, CALLER)

    result = unwind(memory, module(), ebp=STACK + 0x20)

    assert "non-monotonic EBP chain" in result["error"]
    assert "unwind" not in result["frames"][0]


def test_pdb_ra_search_prefers_a_callsite_backed_return_address():
    record = {
        "rva": 0x100, "code_size": 0x40, "recipe": "ra-search",
        "source": "pdb-frame-data", "alignment": 0,
    }
    memory = Memory()
    memory.u32(STACK, BASE + 0x500)  # merely module-backed
    memory.u32(STACK + 4, CALLER)
    memory.put(CALLER - 5, b"\xe8\x00\x00\x00\x00")

    result = unwind(memory, module(records=[record]))

    frame = result["frames"][0]
    assert frame["unwind"] == "pdb-frame-data"
    assert frame["confidence"] == "high"
    assert "PDB .raSearch esp+0x4" in frame["operations"]
    assert "call-site validated" in frame["operations"]


def test_instruction_prologue_fallback_simulates_stack_delta():
    memory = Memory()
    # push ebp; mov ebp,esp; sub esp,0x10; current EIP
    prologue = b"\x55\x89\xe5\x83\xec\x10"
    memory.put(BASE + 0x100, prologue)
    memory.u32(STACK + 16, 0xDEADBEEF)  # saved EBP
    memory.u32(STACK + 20, CALLER)

    result = unwind(
        memory, module(starts=[0x100]), eip=BASE + 0x100 + len(prologue),
        ebp=0,
    )

    frame = result["frames"][0]
    assert frame["unwind"] == "instruction-prolog"
    assert frame["confidence"] == "medium"
    assert "stack delta 0x14" in frame["operations"]


def test_instruction_prologue_rejects_lossy_esp_alignment():
    memory = Memory()
    # and esp,0xfffffff0 changes ESP by a value that cannot be reconstructed
    # from the current register alone; treating it as a no-op invents frames.
    memory.put(BASE + 0x100, b"\x83\xe4\xf0")
    memory.u32(STACK, CALLER)

    result = unwind(
        memory, module(starts=[0x100]), eip=BASE + 0x103,
    )

    assert "unsupported stack-pointer write in and" in result["error"]
    assert "unwind" not in result["frames"][0]


def test_raw_stack_hits_remain_candidates_not_frames():
    memory = Memory()
    memory.u32(STACK, CALLER)

    result = unwind(memory, module())

    assert "unwind" not in result["frames"][0]
    assert result["candidates"][0]["address"] == f"0x{CALLER:x}"
    assert result["candidates"][0]["confidence"] == "candidate"


@pytest.mark.parametrize(
    "record,error",
    [
        ({"rva": -1, "code_size": 4}, "out-of-bounds FPO"),
        ({"rva": 0xFFF0, "code_size": 0x20}, "out-of-bounds FPO"),
        ({"rva": "wat", "code_size": 4}, "malformed FPO"),
    ],
)
def test_malformed_or_out_of_bounds_metadata_fails_closed(record, error):
    result = unwind(Memory(), module(records=[record]))
    assert error in result["error"]
    assert "unwind" not in result["frames"][0]


def test_short_stack_read_and_uint32_overflow_are_bounded():
    mod = module()
    engine = X86HybridUnwinder([mod], lambda _va, _n: b"\x00", lambda _va: None)
    result = engine.unwind(BASE + 0x110, STACK, STACK + 0x20, 0, 1)
    assert "short x86 stack read" in result["error"]

    result = engine.unwind(BASE + 0x110, 0xFFFFFFFE, 0xFFFFFFFE, 0, 1)
    assert "outside uint32" in result["error"] or "invalid EBP" in result["error"]


def test_candidates_are_deduplicated_and_limited():
    memory = Memory()
    for index in range(64):
        memory.u32(STACK + index * 4, BASE + 0x500 + (index % 20) * 4)
    engine = X86HybridUnwinder([module()], memory.read, lambda _va: None)

    candidates = engine.candidates(STACK)

    assert len(candidates) == 16
    assert len({item["address"] for item in candidates}) == 16
