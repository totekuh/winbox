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
