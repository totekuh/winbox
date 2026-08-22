"""Socket-level integration coverage for batched breakpoint evaluation."""

from __future__ import annotations

import json
import socket
import struct
import threading

from winbox.kdbg.debugger.daemon import DaemonSession, TargetInfo
from winbox.kdbg.debugger.protocol import decode, encode, read_line, request
from winbox.kdbg.debugger.rsp import StopReply


_CR3_OFFSET = 204
_BLOB_LEN = 608
_BP_VA = 0xFFFFF80608628780
_TARGET_DTB = 0x4D6BB000


def _blob() -> bytes:
    blob = bytearray(_BLOB_LEN)
    struct.pack_into("<Q", blob, 16, 0x1000)  # rcx
    struct.pack_into("<Q", blob, 24, 0x2000)  # rdx
    struct.pack_into("<Q", blob, 128, _BP_VA)
    struct.pack_into("<Q", blob, _CR3_OFFSET, _TARGET_DTB)
    return bytes(blob)


class _BatchRsp:
    """RSP stand-in with real readiness fds for the daemon select loop."""

    def __init__(self) -> None:
        self._sock, self._stub = socket.socketpair()
        self._inbuf = bytearray()
        self.regs_blob = _blob()
        self.continued = 0
        self.g_cr3s: list[int] = []
        self.memory = {0x1000: 0x11, 0x2000: 0x22}

    def cont(self) -> None:
        self.continued += 1
        # First stop is the action bp. It auto-continues, then a non-trap
        # signal ends op_cont so the socket client gets its reply.
        self._stub.sendall(b"T05" if self.continued == 1 else b"T02")

    def wait_for_stop(self, *, timeout=None):
        self._sock.settimeout(timeout)
        raw = self._sock.recv(3)
        signal = 5 if raw == b"T05" else 2
        return StopReply(signal=signal, thread="01", stop_kind=None, raw=raw.decode())

    def select_thread(self, thread: str, *, op: str = "g") -> None:
        pass

    def read_registers(self) -> bytes:
        return self.regs_blob

    def read_memory(self, va: int, length: int) -> bytes:
        return self.memory[va].to_bytes(length, "little")

    def insert_breakpoint(self, addr, *, kind=1, hardware=False, wp_type=None):
        pass

    def remove_breakpoint(self, addr, *, kind=1, hardware=False, wp_type=None):
        pass

    def _exchange(self, body: bytes, *, timeout=None) -> bytes:
        if body.startswith(b"G"):
            self.regs_blob = bytes.fromhex(body[1:].decode("ascii"))
            self.g_cr3s.append(
                struct.unpack_from("<Q", self.regs_blob, _CR3_OFFSET)[0]
            )
        return b"OK"

    def close(self) -> None:
        self._sock.close()
        self._stub.close()


class _Store:
    def resolve(self, name: str) -> int:
        assert name == "nt!BatchTarget"
        return _BP_VA

    def list_modules(self) -> list[str]:
        return ["nt"]

    def load(self, name: str) -> dict:
        return {"module": "nt", "base": 0, "symbols": {}, "types": {}}


class _Cfg:
    vm_name = "winbox"

    def __init__(self, root_dir) -> None:
        self.root_dir = root_dir


def _call(path, op: str, **args):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(str(path))
        client.sendall(encode(request(op, **args)))
        return decode(read_line(client))
    finally:
        client.close()


def test_socket_protocol_batches_condition_and_actions_into_one_g_pair(tmp_path):
    rsp = _BatchRsp()
    session = DaemonSession(
        cfg=_Cfg(tmp_path),
        rsp=rsp,
        target=TargetInfo(
            pid=4584, dtb=_TARGET_DTB, name="target.exe",
        ),
        store=_Store(),
    )
    sock_path = tmp_path / "batch.sock"
    listen = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listen.bind(str(sock_path))
    listen.listen(4)
    server = threading.Thread(target=session.serve, args=(listen,), daemon=True)
    server.start()

    try:
        added = _call(
            sock_path,
            "bp_add",
            target="nt!BatchTarget",
            condition="[rcx] == 0x11",
            actions=["[rdx]", "poi(rcx)"],
        )
        assert added["ok"], added

        stopped = _call(sock_path, "cont", timeout=2.0)
        assert stopped["ok"], stopped
        assert stopped["result"]["reason"] == "signal"

        trace_reply = _call(sock_path, "bp_trace", id=added["result"]["id"])
        assert trace_reply["ok"], trace_reply
        entries = trace_reply["result"]["entries"]
        assert len(entries) == 1
        assert entries[0]["values"] == {
            "[rdx]": "0x22",
            "poi(rcx)": "0x11",
        }
        # Predicate + two actions crossed the real daemon socket and still
        # emitted only one masquerade/restore pair.
        assert rsp.g_cr3s == [_TARGET_DTB, _TARGET_DTB]
        assert rsp.continued == 2
        assert json.loads(open(added["result"]["trace_path"]).readline()) == entries[0]
    finally:
        session._shutdown_requested = True
        server.join(timeout=2)
        listen.close()
        rsp.close()

