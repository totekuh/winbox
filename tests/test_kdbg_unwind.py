"""Synthetic PE32+/.pdata tests for the live Windows x64 unwinder."""

from __future__ import annotations

import struct

import pytest

from winbox.kdbg.unwind import PeX64Unwinder, UnwindError


BASE = 0x180000000


def _image(*, code: bytes, begin: int = 0x1000, end: int = 0x1100) -> bytearray:
    data = bytearray(0x5000)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe + 4, 0x8664)
    struct.pack_into("<H", data, pe + 20, 0xF0)
    optional = pe + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 56, len(data))
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 3 * 8, 0x2000, 12)
    struct.pack_into("<III", data, 0x2000, begin, end, 0x3000)
    data[0x3000:0x3000 + len(code)] = code
    return data


def _reader(image: bytes, stack: dict[int, int]):
    def read(va: int, length: int) -> bytes:
        if BASE <= va and va + length <= BASE + len(image):
            offset = va - BASE
            return bytes(image[offset:offset + length])
        output = bytearray()
        for current in range(va, va + length):
            qword = current & ~7
            if qword not in stack:
                raise UnwindError(f"unmapped test byte 0x{current:x}")
            output.append(stack[qword].to_bytes(8, "little")[current - qword])
        return bytes(output)
    return read


def test_alloc_small_unwinds_to_real_return_slot():
    # Version 1, prolog 5, one code: at prolog offset 4 undo 0x20 bytes.
    image = _image(code=bytes([1, 5, 1, 0, 4, (3 << 4) | 2, 0, 0]))
    rsp = 0x100000
    caller = BASE + 0x1050
    read = _reader(image, {rsp + 0x20: caller})
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + 0x1020, rsp, {"rsp": rsp}, read,
    )
    assert step.rip == caller
    assert step.rsp == rsp + 0x28
    assert step.operations == ("dealloc 0x20",)


def test_partial_prolog_skips_operation_not_executed_yet():
    image = _image(code=bytes([1, 5, 1, 0, 4, (3 << 4) | 2, 0, 0]))
    rsp = 0x100000
    caller = BASE + 0x1070
    read = _reader(image, {rsp: caller})
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + 0x1002, rsp, {"rsp": rsp}, read,
    )
    assert (step.rip, step.rsp, step.operations) == (caller, rsp + 8, ())


def test_push_nonvolatile_restores_register_then_return_address():
    image = _image(code=bytes([1, 2, 1, 0, 1, (3 << 4) | 0, 0, 0]))
    rsp = 0x200000
    read = _reader(image, {rsp: 0xBEEF, rsp + 8: BASE + 0x1090})
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + 0x1020, rsp, {"rsp": rsp, "rbx": 0}, read,
    )
    assert step.registers["rbx"] == 0xBEEF
    assert step.rip == BASE + 0x1090
    assert step.rsp == rsp + 16


def test_no_runtime_function_is_a_leaf_pop():
    image = _image(code=bytes([1, 0, 0, 0]))
    rsp = 0x300000
    read = _reader(image, {rsp: BASE + 0x1020})
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + 0x1500, rsp, {"rsp": rsp}, read,
    )
    assert step.leaf is True
    assert step.operations == ("leaf",)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda image: image.__setitem__(slice(0, 2), b"ZZ"), "MZ"),
        (lambda image: struct.pack_into("<H", image, 0x80 + 4, 0x14C), "not x64"),
        (lambda image: struct.pack_into("<I", image, 0x80 + 24 + 112 + 3 * 8 + 4, 13), "entry-aligned"),
    ],
)
def test_malformed_image_metadata_fails_closed(mutate, message):
    image = _image(code=bytes([1, 0, 0, 0]))
    mutate(image)
    read = _reader(image, {})
    with pytest.raises(UnwindError, match=message):
        PeX64Unwinder(BASE, len(image), read)


def test_truncated_unwind_operand_fails_closed():
    # ALLOC_LARGE needs another slot but CountOfCodes says one.
    image = _image(code=bytes([1, 5, 1, 0, 4, 1, 0, 0]))
    rsp = 0x400000
    read = _reader(image, {rsp: 0})
    unwinder = PeX64Unwinder(BASE, len(image), read)
    with pytest.raises(UnwindError, match="truncated"):
        unwinder.unwind(BASE + 0x1020, rsp, {"rsp": rsp}, read)


@pytest.mark.parametrize("info", [0, 1])
def test_machine_frame_restores_saved_rip_and_rsp(info):
    image = _image(code=bytes([1, 5, 1, 0, 4, (info << 4) | 10, 0, 0]))
    rsp = 0x500000
    caller = BASE + 0x1500
    old_rsp = 0x700000
    stack = {
        rsp + (8 if info else 0): caller,
        rsp + (32 if info else 24): old_rsp,
    }
    read = _reader(image, stack)
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + 0x1020, rsp, {"rsp": rsp}, read,
    )
    assert step.rip == caller
    assert step.rsp == old_rsp
    assert step.operations == (
        "machine-frame-error" if info else "machine-frame",
    )


def test_v2_long_epilog_descriptor_is_skipped_in_function_body():
    # First slot: size 0x0a, EPILOG info=0 (long). Second raw slot encodes
    # offset 0x19e. The ordinary ALLOC_SMALL code follows it.
    image = _image(code=bytes([
        2, 5, 3, 0,
        0x0A, 0x06, 0x9E, 0x10,
        4, (3 << 4) | 2, 0, 0,
    ]), end=0x2000)
    rsp = 0x600000
    caller = BASE + 0x1500
    read = _reader(image, {rsp + 0x20: caller})
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + 0x1100, rsp, {"rsp": rsp}, read,
    )
    assert step.rip == caller
    assert step.operations == ("dealloc 0x20",)


def test_v2_epilog_ret_is_simulated_from_current_instruction():
    image = _image(code=bytes([
        2, 5, 3, 0,
        0x0A, 0x06, 0x9E, 0x10,
        4, (3 << 4) | 2, 0, 0,
    ]), end=0x2000)
    epilog = 0x2000 - 0x19E
    image[epilog] = 0xC3
    rsp = 0x610000
    caller = BASE + 0x1500
    read = _reader(image, {rsp: caller})
    # End - 0x19e is the encoded epilog start.
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + epilog, rsp, {"rsp": rsp}, read,
    )
    assert step.rip == caller
    assert step.rsp == rsp + 8
    assert step.operations == ("epilog ret",)


def test_v2_epilog_add_pop_ret_restores_stack_and_register():
    # Compact descriptor: epilog size and offset are both six bytes.
    image = _image(code=bytes([
        2, 5, 2, 0,
        6, 0x16,
        4, (3 << 4) | 2,
    ]), end=0x2000)
    epilog = 0x2000 - 6
    image[epilog:epilog + 6] = b"\x48\x83\xc4\x20\x5b\xc3"
    rsp = 0x620000
    caller = BASE + 0x1500
    read = _reader(image, {rsp + 0x20: 0xBEEF, rsp + 0x28: caller})
    step = PeX64Unwinder(BASE, len(image), read).unwind(
        BASE + epilog, rsp, {"rsp": rsp, "rbx": 0}, read,
    )
    assert step.rip == caller
    assert step.rsp == rsp + 0x30
    assert step.registers["rbx"] == 0xBEEF


def test_daemon_backtrace_integrates_live_modules_pdata_and_stack(monkeypatch):
    """Daemon-level integration: inventory -> live PE -> xdata -> stack."""
    from types import SimpleNamespace

    from tests.test_kdbg_daemon import _blob, _make_session
    from winbox.kdbg.debugger.daemon import StopState

    image = _image(code=bytes([1, 5, 1, 0, 4, (3 << 4) | 2, 0, 0]))
    stack_page = 0x700000
    initial_rsp = stack_page + 0x100
    caller = BASE + 0x1500  # in-image leaf (no RUNTIME_FUNCTION)
    stack = bytearray(0x1000)
    struct.pack_into("<Q", stack, initial_rsp + 0x20 - stack_page, caller)
    struct.pack_into("<Q", stack, initial_rsp + 0x28 - stack_page, 0)

    session = _make_session()
    session.stop = StopState(
        vcpu="02", rip=BASE + 0x1020, cr3=0x12345000, signal=5,
        raw_regs=_blob(rip=BASE + 0x1020, rsp=initial_rsp),
    )
    session.run_state = "halted"
    module = SimpleNamespace(
        name="sample.exe", base=BASE, size=len(image), entry=0x1234,
        full_path=r"C:\sample.exe", architecture="x64",
    )
    monkeypatch.setattr(
        session, "_live_modules",
        lambda kind: [module] if kind == "user" else [],
    )

    def op_mem(va, length, **epoch):
        if BASE <= va and va + length <= BASE + len(image):
            raw = image[va - BASE:va - BASE + length]
        elif stack_page <= va and va + length <= stack_page + len(stack):
            raw = stack[va - stack_page:va - stack_page + length]
        else:
            raise RuntimeError(f"unexpected live read 0x{va:x}+0x{length:x}")
        return {"va": f"0x{va:x}", "bytes": bytes(raw).hex()}

    monkeypatch.setattr(session, "op_mem", op_mem)
    result = session.op_bt(depth=3)
    assert result["method"] == "windows-x64-pdata"
    assert result["complete"] is True
    assert [frame["addr"] for frame in result["frames"]] == [
        f"0x{BASE + 0x1020:x}", f"0x{caller:x}",
    ]
    assert [frame["unwind"] for frame in result["frames"]] == ["pdata", "leaf"]
