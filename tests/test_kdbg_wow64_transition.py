"""Hermetic tests for exact-build WoW64 transition recovery."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from winbox.kdbg import wow64_transition as transition


RUN = bytes.fromhex(
    "654c8b242530000000"  # mov r12, qword ptr gs:[0x30]
    "4d8bac2488140000"    # mov r13, qword ptr [r12+0x1488]
    "4981c580000000"      # add r13, 0x80
    "c3"
)
RETURN = bytes.fromhex(
    "4987e6"              # xchg r14, rsp
    "458b06"              # mov r8d, [r14]
    "4983c604"            # add r14, 4
    "4589453c"            # mov [r13+0x3c], r8d
    "45897548"            # mov [r13+0x48], r14d
    "41895d28"            # mov [r13+0x28], ebx
    "41896d38"            # mov [r13+0x38], ebp
    "c3"
)


class FakePe:
    FILE_HEADER = SimpleNamespace(Machine=0x8664)
    OPTIONAL_HEADER = SimpleNamespace(SizeOfImage=0x4000)

    def __init__(self, returned=RETURN):
        self.returned = returned

    def get_data(self, rva, size):
        raw = RUN if rva == 0x1000 else self.returned
        return (raw + b"\xcc" * size)[:size]

    def close(self):
        pass


def test_layout_is_derived_from_exact_instruction_relationships(monkeypatch):
    monkeypatch.setattr(transition.pefile, "PE", lambda *_a, **_k: FakePe())
    layout = transition.derive_transition_layout(
        object(), {"RunSimulatedCode": 0x1000, "CpupReturnFromSimulatedCode": 0x2000},
    )
    assert layout.cpu_area_teb_offset == 0x1488
    assert layout.context_bias == 0x80
    assert (layout.eip_offset, layout.esp_offset) == (0x3C, 0x48)
    assert (layout.ebp_offset, layout.ebx_offset) == (0x38, 0x28)


def test_layout_rejects_changed_return_bridge(monkeypatch):
    monkeypatch.setattr(
        transition.pefile, "PE", lambda *_a, **_k: FakePe(returned=b"\xc3"),
    )
    with pytest.raises(transition.Wow64TransitionError, match="swaps"):
        transition.derive_transition_layout(
            object(), {"RunSimulatedCode": 0x1000, "CpupReturnFromSimulatedCode": 0x2000},
        )


def layout():
    return transition.Wow64TransitionLayout(
        0x1000, 0x2000, 0x1488, 0x80, 0x3C, 0x48, 0x38, 0x28,
    )


def test_context_recovers_from_live_r13():
    blob = bytearray(608)
    blob[13 * 8:14 * 8] = (0x50000).to_bytes(8, "little")
    memory = {
        0x5003C: (0x772C875C).to_bytes(4, "little"),
        0x50048: (0x74EFAC).to_bytes(4, "little"),
        0x50038: (0x74EFCC).to_bytes(4, "little"),
        0x50028: (0x1234).to_bytes(4, "little"),
    }
    context = transition.recover_x86_context(
        layout(), bytes(blob), lambda va, _n: memory[va],
        lambda va: 0x77000000 <= va < 0x78000000,
    )
    assert context.source == "r13"
    assert context.eip == 0x772C875C
    assert context.esp == 0x74EFAC


def test_context_falls_back_to_validated_teb_cpu_area():
    blob = bytearray(608)
    blob[172:180] = (0x70000000).to_bytes(8, "little")
    context_va = 0x71000080
    memory = {
        0x70000030: (0x70000000).to_bytes(8, "little"),
        0x70001488: (0x71000000).to_bytes(8, "little"),
        context_va + 0x3C: (0x772C875C).to_bytes(4, "little"),
        context_va + 0x48: (0x74EFAC).to_bytes(4, "little"),
        context_va + 0x38: (0).to_bytes(4, "little"),
        context_va + 0x28: (0).to_bytes(4, "little"),
    }
    context = transition.recover_x86_context(
        layout(), bytes(blob), lambda va, _n: memory[va], lambda _va: True,
    )
    assert context.source == "teb64-cpu-area"
    assert context.context_va == context_va


@pytest.mark.parametrize("eip,esp", [(0x1000, 0x74EFAC), (0x772C875C, 3)])
def test_context_rejects_untrusted_code_or_stack(eip, esp):
    blob = bytearray(608)
    blob[13 * 8:14 * 8] = (0x50000).to_bytes(8, "little")
    values = {0x5003C: eip, 0x50048: esp, 0x50038: 0, 0x50028: 0}
    with pytest.raises(transition.Wow64TransitionError):
        transition.recover_x86_context(
            layout(), bytes(blob),
            lambda va, _n: values[va].to_bytes(4, "little"),
            lambda va: va >= 0x70000000,
        )


def native_structs():
    def record(size, **fields):
        return {
            "size": size,
            "fields": {
                name: {"off": offset, "type": ""}
                for name, offset in fields.items()
            },
        }

    return {
        "_KPCR": record(0x100, Self=0x18, CurrentPrcb=0x20),
        "_KPRCB": record(0x200, CurrentThread=0x08),
        "_KTHREAD": record(
            0x500, StackLimit=0x30, StackBase=0x38, TrapFrame=0x90,
            Teb=0xF0, Process=0x220,
        ),
        "_KTRAP_FRAME": record(
            0x190, Rax=0x30, Rcx=0x38, Rdx=0x40, R8=0x48, R9=0x50,
            R10=0x58, R11=0x60, Rbx=0x140, Rdi=0x148, Rsi=0x150,
            Rbp=0x158, Rip=0x168, SegCs=0x170, Rsp=0x180,
        ),
    }


def native_fixture():
    layout = transition.derive_native_trap_layout(
        lambda name: native_structs()[name],
    )
    kpcr = 0xFFFF800000100000
    prcb = 0xFFFF800000200000
    thread = 0xFFFF800000300000
    trap = 0xFFFF800000401000
    teb = 0x700000
    process = 0xFFFF800000500000
    memory = {}

    def put(address, value, width=8):
        raw = int(value).to_bytes(width, "little")
        memory.update({address + index: byte for index, byte in enumerate(raw)})

    put(kpcr + 0x18, kpcr)
    put(kpcr + 0x20, prcb)
    put(prcb + 0x08, thread)
    put(thread + 0x30, trap - 0x1000)
    put(thread + 0x38, trap + 0x1000)
    put(thread + 0x90, trap)
    put(thread + 0xF0, teb)
    put(thread + 0x220, process)
    put(teb + 0x08, 0x720000)
    put(teb + 0x10, 0x710000)
    put(teb + 0x30, teb)
    for index, (_name, offset) in enumerate(layout.trap_registers, 1):
        put(trap + offset, index)
    put(trap + 0x168, 0x180001000)
    put(trap + 0x170, 0x33, 2)
    put(trap + 0x180, 0x718008)
    raw = bytearray(608)
    raw[180:188] = kpcr.to_bytes(8, "little")

    def read(address, length):
        return bytes(memory[address + index] for index in range(length))

    return layout, raw, memory, put, read, process, trap


def test_native_layout_and_current_kthread_trap_recovery():
    layout, raw, _memory, _put, read, process, trap = native_fixture()

    context = transition.recover_native_trap_context(
        layout, bytes(raw), read, expected_process=process,
        is_x64_code=lambda va: 0x180000000 <= va < 0x180010000,
        is_bridge_code=lambda va: va == 0x180001000,
    )

    assert context.source == "current-kthread-trap-frame"
    assert context.trap_frame == trap
    assert context.rip == 0x180001000
    assert context.rsp == 0x718008
    assert context.registers["rax"] == 1
    assert context.registers["r15"] == 0


@pytest.mark.parametrize(
    "corrupt,message",
    [
        ("process", "another process"),
        ("teb", "TEB self"),
        ("cs", "not x64"),
        ("rsp", "outside native"),
        ("bridge", "not in exact"),
    ],
)
def test_native_trap_recovery_fails_closed(corrupt, message):
    layout, raw, _memory, put, read, process, trap = native_fixture()
    bridge = lambda va: va == 0x180001000
    if corrupt == "process":
        put(0xFFFF800000300000 + 0x220, process + 0x1000)
    elif corrupt == "teb":
        put(0x700000 + 0x30, 0)
    elif corrupt == "cs":
        put(trap + 0x170, 0x23, 2)
    elif corrupt == "rsp":
        put(trap + 0x180, 0x700000)
    else:
        bridge = lambda _va: False

    with pytest.raises(transition.Wow64TransitionError, match=message):
        transition.recover_native_trap_context(
            layout, bytes(raw), read, expected_process=process,
            is_x64_code=lambda _va: True, is_bridge_code=bridge,
        )


def test_native_layout_rejects_missing_or_out_of_bounds_pdb_fields():
    records = native_structs()
    del records["_KTHREAD"]["fields"]["TrapFrame"]
    with pytest.raises(transition.Wow64TransitionError, match="TrapFrame"):
        transition.derive_native_trap_layout(lambda name: records[name])

    records = native_structs()
    records["_KPCR"]["fields"]["Self"]["off"] = 0x100
    with pytest.raises(transition.Wow64TransitionError, match="invalid"):
        transition.derive_native_trap_layout(lambda name: records[name])
