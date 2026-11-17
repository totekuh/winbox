"""Daemon fork lifecycle — fork_daemon and its private helpers."""

from __future__ import annotations

import fcntl
import json
import os
import signal
import socket
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg import SymbolStore
from winbox.kdbg.debugger.rsp import RspClient, RspError
from winbox.kdbg.staging import UserModuleManifest
from winbox.kdbg.debugger.daemon._types import (
    DaemonError,
    TargetInfo,
    _DAEMON_STARTUP_TIMEOUT,
    _STARTUP_STATUS_MAX_BYTES,
    lock_path,
    log_path,
    session_path,
    sock_path,
)
from winbox.kdbg.debugger.daemon._helpers import _validate_register_layout
from winbox.kdbg.debugger.daemon._validation import (
    _apply_breakpoint_intents,
    _validate_module_bases,
    _validated_breakpoint_intents,
)


def _detach_to_log(log_file: Path) -> None:
    """Standard double-fork-style detach but we keep stderr/stdout
    redirected to a log file rather than /dev/null so daemon errors are
    visible during development."""
    os.setsid()
    f = open(log_file, "ab", buffering=0)
    os.dup2(f.fileno(), 1)
    os.dup2(f.fileno(), 2)
    try:
        with open(os.devnull, "rb") as dn:
            os.dup2(dn.fileno(), 0)
    except OSError:
        pass


def _acquire_lock_or_die(lock_file: Path) -> int:
    """Try LOCK_EX_NB; return fd. Raise DaemonError on failure."""
    fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise DaemonError("another kdbg session holds the lock")
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    os.fsync(fd)
    return fd


def _write_session_file(path: Path, info: dict[str, Any]) -> None:
    path.write_text(json.dumps(info, indent=2), encoding="utf-8")


def _bind_unix_socket(sock_file: Path) -> socket.socket:
    """Create a fresh listen socket. Removes any stale .sock left from
    a crashed previous daemon."""
    if sock_file.exists():
        sock_file.unlink()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock_file))
    sock_file.chmod(0o600)
    s.listen(8)
    return s


def fork_daemon(
    cfg: Config,
    target_pid: int,
    *,
    gdbstub_port: int = 1234,
    module_manifest: UserModuleManifest | None = None,
    breakpoint_intents: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> int:
    """Fork off a session daemon. Parent returns the daemon pid; child
    never returns from this function (it enters serve_forever)."""
    if module_manifest is not None and module_manifest.pid != target_pid:
        raise DaemonError(
            f"module manifest pid {module_manifest.pid} does not match "
            f"target pid {target_pid}"
        )
    validated_intents = _validated_breakpoint_intents(breakpoint_intents)

    from winbox.kdbg.cet import CetSafetyError, require_safe
    try:
        require_safe(cfg)
    except CetSafetyError as exc:
        raise DaemonError(str(exc)) from exc

    from winbox.kdbg.debugger.child_lifecycle import (
        ChildStartupError,
        supervise_startup,
    )

    pipe_r, pipe_w = os.pipe()
    pid = os.fork()
    if pid > 0:
        os.close(pipe_w)
        try:
            line = supervise_startup(
                pid,
                pipe_r,
                timeout=_DAEMON_STARTUP_TIMEOUT,
                max_bytes=_STARTUP_STATUS_MAX_BYTES,
                label="kdbg daemon",
            )
        except ChildStartupError as exc:
            raise DaemonError(str(exc)) from exc
        if line == b"OK":
            return pid
        text = line.decode("utf-8", errors="replace")
        if text.startswith("ERR:"):
            raise DaemonError(text[4:].strip())
        raise DaemonError(f"unexpected daemon status: {text!r}")

    # Child — won't return
    os.close(pipe_r)
    class _StartupCancelled(DaemonError):
        pass

    def _cancel_startup(_signum, _frame):
        raise _StartupCancelled("daemon startup cancelled by parent")

    signal.signal(signal.SIGTERM, _cancel_startup)
    signal.signal(signal.SIGINT, _cancel_startup)
    rsp: RspClient | None = None
    pipe_signaled = False
    try:
        _detach_to_log(log_path(cfg))
        lock_fd = _acquire_lock_or_die(lock_path(cfg))

        _MAX_ATTACH_ATTEMPTS = 3
        for _attempt in range(1, _MAX_ATTACH_ATTEMPTS + 1):
            rsp = RspClient.connect("127.0.0.1", gdbstub_port, timeout=5.0)
            try:
                rsp.handshake()
                initial_sr = rsp.query_halt_reason()
                break
            except RspError as _rsp_err:
                if "empty stop reply" not in str(_rsp_err):
                    raise
                with suppress(OSError):
                    rsp._sock.close()
                rsp = None
                if _attempt >= _MAX_ATTACH_ATTEMPTS:
                    raise DaemonError(
                        f"gdbstub returned empty stop reply on "
                        f"{_MAX_ATTACH_ATTEMPTS} consecutive attempts. "
                        f"Recovery: kdbg_stop, kdbg_start, then retry."
                    ) from _rsp_err
                from winbox.kdbg.hmp import hmp
                with suppress(Exception):
                    hmp(cfg.vm_name, "gdbserver none")
                time.sleep(0.5)
                hmp(
                    cfg.vm_name,
                    f"gdbserver tcp:127.0.0.1:{gdbstub_port}",
                )
                time.sleep(0.3)

        store = SymbolStore(cfg.symbols_dir)
        from winbox.kdbg.debugger.reader import use_local_rsp
        from winbox.kdbg.symbols import ensure_nt_base_current
        from winbox.kdbg.walk import find_process
        with use_local_rsp(cfg.vm_name, rsp, initial_sr, pagewalk=cfg.kdbg_pagewalk):
            ensure_nt_base_current(cfg, store)
            target_rec = find_process(cfg.vm_name, store, pid=target_pid)
        if target_rec is None:
            rsp.cont()
            time.sleep(0.1)
            rsp._sock.close()
            ga_warning = ""
            try:
                from winbox.vm.lifecycle import agent_channel_connected
                if not agent_channel_connected(cfg.vm_name):
                    ga_warning = (
                        " (warning: guest-agent channel is down; "
                        "it may need a few seconds to reconnect)"
                    )
            except Exception:
                pass
            msg = f"ERR: pid {target_pid} not found{ga_warning}\n"
            os.write(pipe_w, msg.encode())
            os.close(pipe_w)
            pipe_signaled = True
            os._exit(1)
        target = TargetInfo(
            pid=target_rec.pid,
            dtb=target_rec.directory_table_base,
            name=target_rec.name,
            user_dtb=target_rec.user_directory_table_base,
            eprocess=target_rec.eprocess,
            create_time=target_rec.create_time,
        )

        with use_local_rsp(cfg.vm_name, rsp, initial_sr, pagewalk=cfg.kdbg_pagewalk):
            _validate_module_bases(cfg, rsp, target, store)

        listen_sock = _bind_unix_socket(sock_path(cfg))
        session_record = {
            "target_pid": target.pid,
            "target_dtb": f"0x{target.dtb:x}",
            "target_name": target.name,
            "target_eprocess": f"0x{target.eprocess:x}",
            "target_create_time": (
                f"0x{target.create_time:x}" if target.create_time else None
            ),
            "daemon_pid": os.getpid(),
            "gdbstub_port": gdbstub_port,
            "attach_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "auto_stage": (
                module_manifest.summary() if module_manifest is not None else None
            ),
        }
        _write_session_file(session_path(cfg), session_record)

        from winbox.kdbg.debugger.daemon._session import DaemonSession
        session = DaemonSession(
            cfg=cfg, rsp=rsp, target=target, store=store,
            module_manifest=module_manifest,
        )
        session._capture_stop(initial_sr)
        _validate_register_layout(session.stop.raw_regs)
        if validated_intents is not None:
            session.breakpoint_intents = _apply_breakpoint_intents(
                session, validated_intents,
            )
            session_record["breakpoint_intents"] = session.breakpoint_intents
            _write_session_file(session_path(cfg), session_record)
        _install_signal_handlers(session)

        os.write(pipe_w, b"OK\n")
        os.close(pipe_w)
        pipe_signaled = True

        sys.stderr.write(f"[kdbg-daemon pid={os.getpid()}] attached to "
                         f"{target.name}({target.pid}) dtb=0x{target.dtb:x}\n")
        sys.stderr.flush()

        try:
            session.serve(listen_sock)
        finally:
            session.shutdown()
            with suppress(OSError):
                sock_path(cfg).unlink()
            with suppress(OSError):
                session_path(cfg).unlink()
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
            with suppress(OSError):
                lock_path(cfg).unlink()
        os._exit(0)
    except DaemonError as e:
        if rsp is not None and not pipe_signaled:
            with suppress(Exception):
                rsp.cont()
        if not pipe_signaled:
            with suppress(OSError):
                os.write(pipe_w, f"ERR: {e}\n".encode())
                os.close(pipe_w)
        os._exit(1)
    except Exception as e:  # noqa: BLE001 — surface anything that broke setup
        if rsp is not None and not pipe_signaled:
            with suppress(Exception):
                rsp.cont()
        if not pipe_signaled:
            with suppress(OSError):
                os.write(pipe_w, f"ERR: {type(e).__name__}: {e}\n".encode())
                os.close(pipe_w)
        os._exit(1)


def _install_signal_handlers(session) -> None:
    def on_term(signum, frame):  # noqa: ARG001
        session._serving = False
        session._shutdown_requested = True

    def on_usr1(signum, frame):  # noqa: ARG001
        session._interrupt_pending = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    signal.signal(signal.SIGUSR1, on_usr1)


def force_stop_daemon(
    cfg: Config,
    *,
    timeout: float = 5.0,
    term_grace: float = 2.0,
    kill_grace: float = 2.0,
) -> bool:
    """Guarantee the interactive session daemon is gone, cleanly if possible.

    Graceful-first: preempt any in-flight ``cont`` (lightweight ``interrupt``
    op + SIGUSR1), then a clean ``detach`` (restores CR3, resumes the guest,
    exits). If the daemon does not exit, escalate SIGTERM -> SIGKILL, verifying
    death via the flock probe (never ``waitpid`` — the daemon is setsid-detached
    and not our child).

    Returns ``True`` when a daemon existed and is now confirmed dead, ``False``
    when none was alive. Raises ``DaemonError`` if a daemon survives SIGKILL.
    The production clean-detach path is untouched; SIGKILL only fires when the
    graceful detach already failed to make the daemon exit.
    """
    from winbox.kdbg.debugger.child_lifecycle import kill_pid_until_dead
    from winbox.kdbg.debugger.client import ClientError, DaemonClient
    from winbox.kdbg.debugger.continue_job import cancel_continue

    client = DaemonClient(cfg)
    if not client.session_alive():
        with suppress(OSError):
            sock_path(cfg).unlink()
        with suppress(OSError):
            session_path(cfg).unlink()
        return False

    pid: int | None = None
    info = client.session_info()
    if info is not None:
        with suppress(ValueError, TypeError, KeyError):
            pid = int(info["daemon_pid"])

    # Preempt a busy cont so the graceful detach is serviceable.
    with suppress(Exception):
        cancel_continue(cfg)
    if pid is not None and pid > 0:
        with suppress(ProcessLookupError, OSError):
            os.kill(pid, signal.SIGUSR1)

    # Graceful detach: clean CR3 restore + resume + shutdown.
    with suppress(ClientError, OSError):
        client.call("detach", sock_timeout=timeout)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and client.session_alive():
        time.sleep(0.02)

    if client.session_alive():
        if not kill_pid_until_dead(
            pid,
            lambda: client.session_alive(),
            term_grace=term_grace,
            kill_grace=kill_grace,
        ):
            raise DaemonError(
                f"kdbg daemon pid={pid} survived SIGKILL; gdbstub may be stuck"
            )

    with suppress(OSError):
        sock_path(cfg).unlink()
    with suppress(OSError):
        session_path(cfg).unlink()
    return True
