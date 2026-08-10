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
import os
import signal
import socket
import socketserver
import struct
import time
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


# ─── process / pidfile management ───────────────────────────────────────────────


def read_pidfile(cfg: Config) -> int | None:
    """Return the PID recorded in the pidfile, or None if absent/garbage.

    The pidfile is ``"<pid>"`` or ``"<pid> <port>"`` (the bound port, when
    not the default). Only the leading PID token is parsed here; the port is
    read separately by :func:`read_port`.
    """
    pf = pidfile_path(cfg)
    if not pf.exists():
        return None
    try:
        text = pf.read_text().strip()
    except OSError:
        return None
    if not text:
        return None
    first = text.split()[0]
    if not first.isdigit():
        return None
    return int(first)


def read_port(cfg: Config) -> int:
    """Return the port recorded in the pidfile, or ``DNS_PORT`` if absent.

    Lets ``status`` report the port the running server actually bound rather
    than assuming the default.
    """
    pf = pidfile_path(cfg)
    if not pf.exists():
        return DNS_PORT
    try:
        tokens = pf.read_text().split()
    except OSError:
        return DNS_PORT
    if len(tokens) >= 2 and tokens[1].isdigit():
        return int(tokens[1])
    return DNS_PORT


def pid_alive(pid: int) -> bool:
    """True if a process with ``pid`` exists and is signalable by us."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user
    return True


def _is_sinkhole_proc(pid: int) -> bool:
    """True if ``pid`` looks like our detached ``winbox sinkhole _serve``.

    The pidfile records a bare PID, which Linux recycles freely — a crashed
    sinkhole's PID can be reassigned to an unrelated process, and signalling it
    on ``stop`` would kill a bystander. Confirm identity via the process's own
    command line before we ever signal it. If ``/proc`` can't be read we return
    False (fail safe: refuse to signal an unverifiable PID rather than risk
    hitting the wrong process)."""
    if pid <= 0:
        return False
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        return False
    return "sinkhole" in cmd and "_serve" in cmd


def is_running(cfg: Config) -> int | None:
    """Return the live sinkhole PID, or None. Cleans up a stale pidfile."""
    pid = read_pidfile(cfg)
    if pid is None:
        return None
    # Alive AND actually our sinkhole — a recycled PID owned by an unrelated
    # process must read as "not running" (and clean up the stale pidfile), not
    # as a live sinkhole.
    if pid_alive(pid) and _is_sinkhole_proc(pid):
        return pid
    # Stale pidfile from a crashed process (or a recycled PID) — clean it up.
    try:
        pidfile_path(cfg).unlink()
    except OSError:
        pass
    return None


def wait_ready(server_log: Path, proc, *, timeout: float = 4.0) -> bool:
    """Block until the detached server is serving, dead, or ``timeout``.

    Returns True once :data:`READY_MARKER` appears in ``server_log`` (the
    server logged a successful bind). Returns False if the process exits
    first (bind failed — the traceback is in ``server_log``) or the timeout
    elapses. ``proc`` is the ``subprocess.Popen`` handle.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if READY_MARKER in server_log.read_text(errors="replace"):
                return True
        except OSError:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.1)
    return False


def write_pidfile(cfg: Config, pid: int, port: int | None = None) -> None:
    pf = pidfile_path(cfg)
    pf.parent.mkdir(parents=True, exist_ok=True)
    pf.write_text(f"{pid}\n" if port is None else f"{pid} {port}\n")


def stop(cfg: Config, *, timeout: float = 5.0) -> bool:
    """Stop the detached sinkhole via its pidfile. Returns True if a live
    process was signalled. Always removes the pidfile afterwards."""
    pid = read_pidfile(cfg)
    pf = pidfile_path(cfg)
    if pid is None:
        return False
    # Only signal a PID we can confirm is actually our sinkhole — a recycled PID
    # (crashed sinkhole, OS reassigned the number) must not get SIGTERM/SIGKILL.
    if not pid_alive(pid) or not _is_sinkhole_proc(pid):
        try:
            pf.unlink()
        except OSError:
            pass
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid = None
    except PermissionError:
        # Can't signal it (root-owned, we're not root). Leave the pidfile so
        # status still reflects reality; caller surfaces the error.
        raise

    deadline = time.time() + timeout
    while pid is not None and time.time() < deadline:
        if not pid_alive(pid):
            break
        time.sleep(0.1)
    else:
        if pid is not None and pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    try:
        pf.unlink()
    except OSError:
        pass
    return True


def try_bind(bind_ip: str, port: int = DNS_PORT) -> str:
    """Probe whether we can bind udp/``port`` on ``bind_ip``.

    Returns one of:
      * ``"ok"``      -- the bind succeeded (we can serve here)
      * ``"in_use"``  -- something already holds the address (EADDRINUSE)
      * ``"denied"``  -- we lack privilege for it (EACCES/EPERM, e.g. a
                         port < 1024 as a non-root user with no
                         CAP_NET_BIND_SERVICE / lowered port floor)
      * ``"error:<detail>"`` -- any other bind failure, verbatim

    The probe socket is closed immediately; the momentary gap is harmless.
    This lets ``start`` give an accurate, actionable error instead of
    pre-judging on euid — if the OS permits an unprivileged :53 bind, the
    sinkhole just works.

    The probe deliberately does **not** set ``SO_REUSEADDR``: libvirt's own
    dnsmasq holds the bridge :53 with it, and a probe that also sets it would
    co-bind and return "ok" — so ``start`` would launch the sinkhole over
    dnsmasq, the kernel would keep delivering guest DNS to dnsmasq, and the
    capture would silently record nothing. Without it the probe hits
    EADDRINUSE and correctly reports "in_use".
    """
    import errno

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((bind_ip, port))
    except PermissionError:
        return "denied"
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return "in_use"
        if e.errno in (errno.EACCES, errno.EPERM):
            return "denied"
        return f"error:{e}"
    finally:
        s.close()
    return "ok"


def port_in_use(bind_ip: str, port: int = DNS_PORT) -> bool:
    """True if something already holds udp/``port`` on ``bind_ip``.

    Thin wrapper over :func:`try_bind` kept for callers that only care about
    the EADDRINUSE case.
    """
    return try_bind(bind_ip, port) == "in_use"


def line_count(path: Path) -> int:
    """Count lines in the query log (0 if it doesn't exist)."""
    if not path.exists():
        return 0
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


# ─── INETSim config generation ──────────────────────────────────────────────────


def inetsim_installed() -> str | None:
    """Path to the INETSim binary if installed, else None."""
    import shutil

    found = shutil.which("inetsim")
    if found:
        return found
    for candidate in ("/usr/bin/inetsim", "/usr/sbin/inetsim"):
        if Path(candidate).exists():
            return candidate
    return None


def build_inetsim_conf(cfg: Config, *, bind_ip: str | None = None,
                       sink_ip: str | None = None) -> str:
    """Render an INETSim config bound to the bridge IP.

    DNS is left OFF on purpose — our own sinkhole owns udp/53. The fake
    service ports (http/https/ftp/smtp/...) are enabled and pointed at the
    bridge so a sample that connects after resolving its C2 to the sink IP
    gets a canned response captured by INETSim.
    """
    bind = bind_ip or cfg.host_ip
    sink = sink_ip or cfg.host_ip
    data_dir = inetsim_data_dir(cfg)
    lines = [
        "# winbox sinkhole — generated INETSim config",
        "# DNS is intentionally disabled: winbox's built-in sinkhole owns udp/53.",
        "# Point the guest's DNS at the bridge with: winbox dns set " + bind,
        "",
        f"service_bind_address   {bind}",
        f"dns_default_ip         {sink}",
        f"data_dir               {data_dir}",
        "",
        "# --- enabled fake services (start_service) ---",
        "start_service http",
        "start_service https",
        "start_service ftp",
        "start_service smtp",
        "start_service pop3",
        "start_service irc",
        "",
        "# DNS handled by winbox sinkhole — do NOT start INETSim's dns:",
        "# start_service dns",
        "",
        f"http_bind_port   80",
        f"https_bind_port  443",
    ]
    return "\n".join(lines) + "\n"


def write_inetsim_conf(cfg: Config, *, bind_ip: str | None = None,
                       sink_ip: str | None = None) -> Path:
    """Write the generated INETSim config + data dir, return the conf path."""
    conf = build_inetsim_conf(cfg, bind_ip=bind_ip, sink_ip=sink_ip)
    path = inetsim_conf_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    inetsim_data_dir(cfg).mkdir(parents=True, exist_ok=True)
    path.write_text(conf)
    return path
