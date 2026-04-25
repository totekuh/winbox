"""Tests for winbox.kdbg.gdbstub — the RSP client skeleton.

Today only the framing primitives and connect/disconnect are implemented;
the higher-level methods are roadmap stubs that should raise
``NotImplementedError``. These tests pin the contract so the next
contributor can fill in `read_registers` etc. without breaking the shape.
"""

from __future__ import annotations

import socket
import threading

import pytest

from winbox.kdbg.gdbstub import GdbStubClient, GdbStubError


def test_checksum_known_vector():
    # GDB docs: "$qSupported#" payload is 'qSupported', checksum 0x37 hex 0x37
    # We just verify the basic mod-256 sum.
    assert GdbStubClient._checksum(b"qSupported") == "37"
    assert GdbStubClient._checksum(b"") == "00"
    assert GdbStubClient._checksum(b"\xff" * 4) == "fc"


def test_connect_to_nothing_raises():
    """No gdbstub listening on a random ephemeral port -> GdbStubError."""
    with pytest.raises(GdbStubError, match="could not connect"):
        GdbStubClient.connect("127.0.0.1", 1, timeout=0.1)


def test_send_packet_frames_and_checksums():
    """Round-trip: a fake server reads one packet, asserts the framing."""
    received: list[bytes] = []
    ready = threading.Event()

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port_holder.append(srv.getsockname()[1])
        ready.set()
        conn, _ = srv.accept()
        with conn:
            data = conn.recv(64)
        received.append(data)
        srv.close()

    port_holder: list[int] = []
    t = threading.Thread(target=server, daemon=True)
    t.start()
    ready.wait(2.0)

    with GdbStubClient.connect("127.0.0.1", port_holder[0], timeout=2.0) as gdb:
        gdb.send_packet("qSupported")

    t.join(2.0)
    assert received == [b"$qSupported#37"]


def test_higher_level_methods_are_stubs():
    """K1: the placeholder methods exist with the planned shape but raise.
    Removing this test means the implementations have landed."""
    # Use a dummy socket for instantiation; we never actually connect.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client = GdbStubClient(sock)
        for method, args in [
            ("recv_packet", ()),
            ("read_registers", ()),
            ("single_step", ()),
            ("cont", ()),
            ("set_hw_breakpoint", (0xfffff80012345678,)),
            ("remove_hw_breakpoint", (0xfffff80012345678,)),
        ]:
            with pytest.raises(NotImplementedError):
                getattr(client, method)(*args)
    finally:
        sock.close()


def test_disconnect_idempotent():
    """Calling disconnect twice must not raise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = GdbStubClient(sock)
    client.disconnect()
    client.disconnect()  # no-op
