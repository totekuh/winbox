"""DNS sinkhole / fake-internet primitives for malware detonation.

A zero-dependency UDP DNS server that answers EVERY A query with a single
sink IP (the Kali bridge address by default) and logs every queried name.
The query log is the primary artifact: when a sample is detonated in the
isolated VM, the C2 domains it tries to resolve land here without the
sample ever reaching the real internet.

This module is the implementation (packet codec, server loop, process
management). The CLI in ``winbox.cli.sinkhole`` stays thin and delegates
here — mirrors the kdbg / eventlogs CLI-vs-impl split.

DNS wire format is hand-rolled against RFC 1035; no dnslib/dnspython.
"""

from __future__ import annotations

import ipaddress
import signal
import socket
import socketserver
import struct
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from winbox.config import Config


# DNS record / class constants (RFC 1035).
QTYPE_A = 1
QTYPE_AAAA = 28
QCLASS_IN = 1

DEFAULT_TTL = 60
DNS_PORT = 53

# Printed by serve() once the socket is bound; start() polls the server log
# for it to confirm readiness before reporting success.
READY_MARKER = "[sinkhole] serving"


# ─── paths ───────────────────────────────────────────────────────────────────


def sinkhole_dir(cfg: Config) -> Path:
    """Directory holding the query log + pidfile."""
    return cfg.winbox_dir / "sinkhole"


def query_log_path(cfg: Config) -> Path:
    """Greppable log of every DNS query the sinkhole answered.

    THIS is the primary C2-domain artifact.
    """
    return sinkhole_dir(cfg) / "queries.log"


def pidfile_path(cfg: Config) -> Path:
    return sinkhole_dir(cfg) / "sinkhole.pid"


def server_log_path(cfg: Config) -> Path:
    """stdout/stderr of the detached server process (crash diagnostics)."""
    return sinkhole_dir(cfg) / "sinkhole.log"


def inetsim_conf_path(cfg: Config) -> Path:
    return sinkhole_dir(cfg) / "inetsim.conf"


def inetsim_data_dir(cfg: Config) -> Path:
    return sinkhole_dir(cfg) / "inetsim"


# ─── DNS wire codec ────────────────────────────────────────────────────────────


def _encode_name(name: str) -> bytes:
    """Encode a dotted name into the DNS label sequence (RFC 1035 §3.1)."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        lab = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        out.append(len(lab))
        out += lab
    out.append(0)  # root terminator
    return bytes(out)


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at ``offset``.

    Returns (name, offset_just_after_the_name_in_the_question). Compression
    pointers are followed for decoding but the returned offset always points
    past the first pointer / terminator in the linear scan, matching how a
    question section advances.
    """
    labels: list[str] = []
    pos = offset
    jumped = False
    end = offset
    guard = 0
    while True:
        guard += 1
        if guard > 128:
            raise ValueError("malformed name (too many labels / pointer loop)")
        if pos >= len(data):
            raise ValueError("truncated name")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            # Compression pointer (2 bytes).
            if pos + 1 >= len(data):
                raise ValueError("truncated compression pointer")
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            continue
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        pos += 1
        if pos + length > len(data):
            raise ValueError("truncated label")
        labels.append(data[pos : pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), end


class DNSQuery:
    """A parsed DNS query: just the first question + the header id/flags."""

    __slots__ = ("txid", "flags", "qname", "qtype", "qclass", "question")

    def __init__(self, txid: int, flags: int, qname: str, qtype: int,
                 qclass: int, question: bytes) -> None:
        self.txid = txid
        self.flags = flags
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass
        self.question = question  # raw question section bytes (for echo-back)


def parse_query(data: bytes) -> DNSQuery:
    """Parse a DNS request packet, extracting the first question.

    Raises ValueError on anything we can't make sense of so the server can
    drop the packet rather than crash.
    """
    if len(data) < 12:
        raise ValueError("packet shorter than DNS header")
    txid, flags, qdcount = struct.unpack_from("!HHH", data, 0)
    # ancount/nscount/arcount at offsets 6/8/10 — ignored for requests.
    if qdcount < 1:
        raise ValueError("no question in packet")
    qname, after_name = _decode_name(data, 12)
    if after_name + 4 > len(data):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", data, after_name)
    question = data[12 : after_name + 4]
    return DNSQuery(txid, flags, qname, qtype, qclass, question)


def build_response(query: DNSQuery, sink_ip: str, *, ttl: int = DEFAULT_TTL) -> bytes:
    """Build a DNS answer for ``query`` pointing A records at ``sink_ip``.

    * A queries  -> single A record => sink_ip, with ``ttl``.
    * AAAA       -> NODATA (answer count 0, NOERROR) so the resolver falls
                    back to the A record instead of getting a bogus IPv6.
    * other types-> NODATA NOERROR (we only sink names, not record types).

    The question section is echoed back verbatim (so the qname round-trips
    exactly as the client sent it, compression and all).
    """
    # Response flags: QR=1, copy opcode from request, AA=1, RD copied, RA=1,
    # RCODE=0 (NOERROR).
    opcode = (query.flags >> 11) & 0xF
    rd = (query.flags >> 8) & 0x1
    resp_flags = 0x8000 | (opcode << 11) | 0x0400 | (rd << 8) | 0x0080

    answer = b""
    ancount = 0
    if query.qclass == QCLASS_IN and query.qtype == QTYPE_A:
        # Name pointer to the question (offset 12 from start of message).
        rdata = ipaddress.IPv4Address(sink_ip).packed
        answer = (
            b"\xc0\x0c"  # pointer to qname at offset 12
            + struct.pack("!HHIH", QTYPE_A, QCLASS_IN, ttl, len(rdata))
            + rdata
        )
        ancount = 1

    header = struct.pack(
        "!HHHHHH",
        query.txid,
        resp_flags,
        1,        # qdcount
        ancount,  # ancount
        0,        # nscount
        0,        # arcount
    )
    return header + query.question + answer


def qtype_name(qtype: int) -> str:
    """Human-readable record type for the query log."""
    return {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
        16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
    }.get(qtype, f"TYPE{qtype}")


# ─── query logging ─────────────────────────────────────────────────────────────


def format_log_line(qname: str, qtype: int, client_ip: str,
                     *, when: datetime | None = None) -> str:
    """Build one greppable query-log line.

    Format (tab-aligned, one query per line)::

        2026-06-10T14:03:11  c2.evil.example  A  192.168.122.203

    Columns: ISO-8601 timestamp, qname, qtype, client IP.
    """
    ts = (when or datetime.now()).strftime("%Y-%m-%dT%H:%M:%S")
    name = _sanitize_qname(qname) if qname else "."
    return f"{ts}\t{name}\t{qtype_name(qtype)}\t{client_ip}"


def _sanitize_qname(name: str) -> str:
    """Escape control characters in a guest-controlled DNS name before it goes
    into the tab-separated log.

    DNS labels may carry arbitrary octets, and ``_decode_name`` passes tab/
    newline through literally. Unescaped, a malicious A query could embed a
    newline and forge whole log lines (or a tab and shift columns). Replace
    anything non-printable — or a literal tab — with a ``\\xNN`` escape."""
    return "".join(
        c if (c.isprintable() and c != "\t") else f"\\x{ord(c):02x}"
        for c in name
    )


def append_log(path: Path, line: str) -> None:
    """Append a single line to the query log (line-buffered, flushed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()


# ─── server ────────────────────────────────────────────────────────────────────


class _SinkholeHandler(socketserver.BaseRequestHandler):
    """Answers one UDP datagram. Server carries sink_ip / ttl / log path."""

    def handle(self) -> None:  # pragma: no cover - exercised via integration
        data, sock = self.request
        server: SinkholeServer = self.server  # type: ignore[assignment]
        client_ip = self.client_address[0]
        try:
            query = parse_query(data)
        except ValueError:
            return  # silently drop garbage
        try:
            append_log(
                server.log_file,
                format_log_line(query.qname, query.qtype, client_ip),
            )
        except OSError:
            pass  # never let a logging failure kill resolution
        resp = build_response(query, server.sink_ip, ttl=server.ttl)
        try:
            sock.sendto(resp, self.client_address)
        except OSError:
            pass


class SinkholeServer(socketserver.UDPServer):
    """UDP DNS server bound to ``bind_ip``:``port`` answering A => sink_ip."""

    allow_reuse_address = True

    def __init__(self, bind_ip: str, port: int, sink_ip: str,
                 log_file: Path, *, ttl: int = DEFAULT_TTL) -> None:
        # Validate up front. build_response() does IPv4Address(sink_ip) per A
        # query outside the handler's try/except, so a non-IPv4 sink_ip (an
        # IPv6 literal or hostname in cfg.host_ip) would raise on every query
        # and the sinkhole would silently answer nothing while reporting itself
        # as serving. Fail at construction instead — start() surfaces it.
        try:
            ipaddress.IPv4Address(sink_ip)
        except ipaddress.AddressValueError as e:
            raise ValueError(
                f"sinkhole sink_ip {sink_ip!r} is not a valid IPv4 address: {e}"
            ) from e
        self.sink_ip = sink_ip
        self.log_file = log_file
        self.ttl = ttl
        super().__init__((bind_ip, port), _SinkholeHandler)


def serve(cfg: Config, *, sink_ip: str | None = None,
          bind_ip: str | None = None, port: int = DNS_PORT,
          ttl: int = DEFAULT_TTL) -> None:
    """Run the DNS sinkhole in the FOREGROUND until SIGTERM/SIGINT.

    Blocks. Used both directly (foreground debugging) and as the body of the
    detached server process launched by ``winbox sinkhole start``.
    """
    bind = bind_ip or cfg.host_ip
    sink = sink_ip or cfg.host_ip
    log_file = query_log_path(cfg)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    server = SinkholeServer(bind, port, sink, log_file, ttl=ttl)

    # Announce that the socket is bound. `start` polls the server log for this
    # marker to know the server is actually serving before reporting success
    # (a bind probe can't tell — SO_REUSEADDR lets it co-bind on UDP).
    print(f"{READY_MARKER} on {bind}:{port}", flush=True)

    def _shutdown(signum, frame):  # noqa: ANN001
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


from winbox.sinkhole_proc import (  # noqa: E402, F401
    _is_sinkhole_proc,
    build_inetsim_conf,
    inetsim_installed,
    is_running,
    line_count,
    pid_alive,
    port_in_use,
    read_pidfile,
    read_port,
    stop,
    try_bind,
    wait_ready,
    write_inetsim_conf,
    write_pidfile,
)
