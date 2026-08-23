#!/usr/bin/env python3
"""Persistent, serialized PyGhidra worker.

This file is deliberately executable by a *different* Python environment from
winbox's.  A pipx PyGhidra interpreter can run it by absolute path without
installing winbox into the JVM environment.  Keep imports before ``_start`` to
the standard library only.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import signal
import socket
import sys
import time
import traceback
import re
from pathlib import Path


MAX_REQUEST = 64 * 1024
MAX_CODE = 256 * 1024
MAX_CONTEXT_LINES = 20
MAX_OPEN_PROGRAMS = 1
MAX_LINE_BATCH = 100
MAX_MAPPED_INSTRUCTION_ASSOCIATIONS = 512
WORKER_API = "4"
ANALYSIS_PROFILE = "winbox-default-v1"


class WorkerError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


class OpenProgram:
    def __init__(self, context, api, decompiler):
        self.context = context
        self.api = api
        self.program = api.getCurrentProgram()
        self.decompiler = decompiler
        self.decompile_cache: collections.OrderedDict[int, object] = (
            collections.OrderedDict()
        )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.decompiler.dispose()
        with contextlib.suppress(Exception):
            self.context.__exit__(None, None, None)


class Worker:
    def __init__(self, cache: Path, projects: Path, ghidra_install_dir: str | None):
        self.cache = cache
        self.projects = projects
        self.ghidra_install_dir = ghidra_install_dir
        self.started = False
        self.pyghidra = None
        self.ghidra_version = None
        self.programs: collections.OrderedDict[str, OpenProgram] = (
            collections.OrderedDict()
        )
        self.shutdown = False

    def start_ghidra(self) -> None:
        if self.started:
            return
        try:
            import pyghidra
        except ImportError as exc:
            raise WorkerError(
                "this worker interpreter does not contain pyghidra"
            ) from exc
        try:
            if not pyghidra.started():
                if self.ghidra_install_dir:
                    pyghidra.start(install_dir=self.ghidra_install_dir)
                else:
                    pyghidra.start()
            from ghidra.framework import Application
            self.ghidra_version = str(Application.getApplicationVersion())
        except Exception as exc:
            hint = (
                " (set GHIDRA_INSTALL_DIR to the Ghidra installation)"
                if not self.ghidra_install_dir else ""
            )
            raise WorkerError(f"could not start Ghidra: {exc}{hint}") from exc
        self.pyghidra = pyghidra
        self.started = True

    def handle(self, op: str, args: dict) -> dict:
        if op == "status":
            return {
                "worker_api": WORKER_API,
                "analysis_profile": ANALYSIS_PROFILE,
                "jvm_started": self.started,
                "ghidra_version": self.ghidra_version,
                "worker_pid": os.getpid(),
                "open_programs": len(self.programs),
                "cached_programs": _count_projects(self.projects),
            }
        if op == "shutdown":
            self.shutdown = True
            return {"shutting_down": True}
        if op != "decompile":
            raise WorkerError(f"unknown operation: {op!r}")
        return self.decompile(args)

    def decompile(self, args: dict) -> dict:
        binary = Path(str(args.get("binary", ""))).expanduser().resolve()
        expected_sha = str(args.get("sha256", "")).lower()
        if not binary.is_file():
            raise WorkerError(f"binary does not exist: {binary}")
        if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
            raise WorkerError("sha256 must be 64 lowercase hexadecimal characters")
        actual_sha = _sha256(binary)
        if actual_sha != expected_sha:
            raise WorkerError(
                f"binary changed before analysis: expected {expected_sha}, got {actual_sha}"
            )
        try:
            rva = int(args.get("rva"))
        except (TypeError, ValueError) as exc:
            raise WorkerError("rva must be an integer") from exc
        if rva < 0 or rva >= (1 << 32):
            raise WorkerError(f"rva outside supported PE range: {rva}")
        before = max(0, min(int(args.get("before", 3)), MAX_CONTEXT_LINES))
        after = max(0, min(int(args.get("after", 5)), MAX_CONTEXT_LINES))
        full = bool(args.get("full", False))
        timeout = max(5, min(int(args.get("decompile_timeout", 60)), 300))
        line_start, line_end = _requested_lines(args)
        assembly_mode = str(args.get("assembly", "nearby")).strip().lower()
        if assembly_mode not in {"nearby", "mapped"}:
            raise WorkerError("assembly must be 'nearby' or 'mapped'")

        opened, cache_hit = self._open(binary, expected_sha)
        program = opened.program
        image_base = int(program.getImageBase().getOffset())
        target_value = image_base + rva
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            target_value
        )
        memory = program.getMemory()
        if not memory.contains(address):
            raise WorkerError(
                f"RVA 0x{rva:x} maps to {address}, outside Ghidra memory blocks"
            )
        manager = program.getFunctionManager()
        function = manager.getFunctionContaining(address)
        function_source = "analysis"
        if function is None:
            function, function_source = _recover_function(
                opened.api, program, address, rva, args.get("symbol_hint")
            )
        if function is None or not function.getBody().contains(address):
            instruction = program.getListing().getInstructionContaining(address)
            suffix = " (instruction exists but no containing function)" if instruction else ""
            raise WorkerError(f"no analyzed function contains RVA 0x{rva:x}{suffix}")

        entry = int(function.getEntryPoint().getOffset())
        result = opened.decompile_cache.pop(entry, None)
        decompile_cache_hit = result is not None
        if result is None:
            from ghidra.util.task import ConsoleTaskMonitor
            result = opened.decompiler.decompileFunction(
                function, timeout, ConsoleTaskMonitor()
            )
        if result is None or not result.decompileCompleted():
            message = result.getErrorMessage() if result is not None else "no result"
            raise WorkerError(
                f"Ghidra could not decompile {function.getName()}: {message}"
            )
        opened.decompile_cache[entry] = result
        while len(opened.decompile_cache) > 32:
            opened.decompile_cache.popitem(last=False)
        decompiled = result.getDecompiledFunction()
        code = decompiled.getC() if decompiled is not None else None
        if code is None:
            raise WorkerError(f"Ghidra returned no C for {function.getName()}")
        full_code = code
        returned_code, code_stats = _bounded_code_payload(full_code, full=full)

        mapping = _map_source(
            result.getCCodeMarkup(), address, full_code, before, after,
            line_start=line_start, line_end=line_end,
        )
        if assembly_mode == "mapped":
            mapping["assembly_truncated"] = _attach_mapped_assembly(
                program, function, mapping
            )
        instructions, instruction_location = _nearby_instructions(
            program, function, address
        )
        response = {
            "cache_hit": cache_hit,
            "decompile_cache_hit": decompile_cache_hit,
            "ghidra_version": self.ghidra_version,
            "analysis_profile": ANALYSIS_PROFILE,
            "ghidra_image_base": f"0x{image_base:x}",
            "ghidra_address": f"0x{target_value:x}",
            "function": {
                "name": str(function.getName()),
                "entry": f"0x{entry:x}",
                "rva": f"0x{entry - image_base:x}",
                "offset": f"0x{target_value - entry:x}",
                "signature": str(function.getSignature()),
                "is_thunk": bool(function.isThunk()),
                "source": function_source,
                "contains_requested_address": True,
            },
            "mapping": mapping,
            "assembly_mode": assembly_mode,
            "instructions": instructions,
            "instruction_location": instruction_location,
            "analysis": {
                "binary_sha256": expected_sha,
                "project_cached": True,
                **code_stats,
            },
        }
        if full:
            response["code"] = returned_code
        return response

    def _open(self, binary: Path, digest: str) -> tuple[OpenProgram, bool]:
        self.start_ghidra()
        if digest in self.programs:
            value = self.programs.pop(digest)
            self.programs[digest] = value
            return value, True

        binaries = self.cache / "binaries"
        binaries.mkdir(parents=True, exist_ok=True)
        self.projects.mkdir(parents=True, exist_ok=True)
        cached_binary = binaries / f"{digest}{binary.suffix.lower()}"
        if not cached_binary.exists() or _sha256(cached_binary) != digest:
            temp = cached_binary.with_suffix(cached_binary.suffix + ".part")
            shutil.copyfile(binary, temp)
            if _sha256(temp) != digest:
                with contextlib.suppress(OSError):
                    temp.unlink()
                raise WorkerError("binary changed while copying into analysis cache")
            os.replace(temp, cached_binary)

        safe_version = "".join(
            c if c.isalnum() else "_" for c in str(self.ghidra_version)
        )
        # Full digest, not a display-length prefix: binaries are attacker-
        # controlled and a project collision would silently reuse analysis of
        # the wrong content even though the immutable copy itself was exact.
        project_name = f"p_{safe_version}_{digest}"
        program_name = f"binary_{digest}{cached_binary.suffix}"
        project_exists = (self.projects / f"{project_name}.gpr").exists()
        context = self.pyghidra.open_program(
            str(cached_binary),
            project_location=str(self.projects),
            project_name=project_name,
            program_name=program_name,
            nested_project_location=False,
            analyze=True,
        )
        try:
            api = context.__enter__()
            from ghidra.app.decompiler import DecompInterface
            decompiler = DecompInterface()
            if not decompiler.openProgram(api.getCurrentProgram()):
                raise WorkerError("Ghidra decompiler rejected the imported program")
            opened = OpenProgram(context, api, decompiler)
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise
        self.programs[digest] = opened
        while len(self.programs) > MAX_OPEN_PROGRAMS:
            _, evicted = self.programs.popitem(last=False)
            evicted.close()
        return opened, project_exists

    def close(self) -> None:
        for opened in self.programs.values():
            opened.close()
        self.programs.clear()


def _walk_tokens(node):
    try:
        count = int(node.numChildren())
    except Exception:
        count = 0
    if count:
        for index in range(count):
            yield from _walk_tokens(node.Child(index))
    else:
        yield node


def _recover_function(api, program, address, rva: int, hint):
    """Create one missed function only from a close, verified PDB public RVA."""
    if not isinstance(hint, dict):
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

    # A public name is untrusted input from a PDB. Keep the useful readable
    # portion but force it into a legal, bounded Ghidra symbol.
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

    # Ghidra occasionally created a tiny/truncated function at the public
    # entry, leaving later instructions unowned. Recover at the exact queried
    # instruction only after the close PDB hint established which routine this
    # gap belongs to. Label it as a split so consumers never mistake the
    # synthetic entry for the real PDB entry.
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


def _map_source(
    markup,
    address,
    code: str,
    before: int,
    after: int,
    *,
    line_start: int | None = None,
    line_end: int | None = None,
) -> dict:
    target = int(address.getOffset())
    addressed: list[tuple[int, int, int]] = []
    for token in _walk_tokens(markup):
        try:
            minimum = token.getMinAddress()
            maximum = token.getMaxAddress()
            parent = token.getLineParent()
            if minimum is None or maximum is None or parent is None:
                continue
            lo = int(minimum.getOffset())
            hi = int(maximum.getOffset())
            line = int(parent.getLineNumber())
        except Exception:
            continue
        addressed.append((lo, hi, line))

    by_line: dict[int, set[tuple[int, int]]] = {}
    for lo, hi, line in addressed:
        by_line.setdefault(line, set()).add((lo, hi))

    exact_lines = sorted(
        line
        for line, ranges in by_line.items()
        if any(lo <= target <= hi for lo, hi in ranges)
    )
    candidate_lines: list[int]
    direction: str | None
    distance: int | None
    if exact_lines:
        selected = exact_lines[0]
        candidate_lines = exact_lines
        direction = "overlap"
        distance = 0
        if len(exact_lines) > 1:
            kind = "ambiguous"
        elif any(
            lo == target == hi for lo, hi in by_line.get(selected, set())
        ):
            kind = "exact"
        else:
            kind = "range"
        confidence = "exact"
    elif addressed:
        def gap(item: tuple[int, int, int]) -> int:
            lo, hi, _ = item
            if target < lo:
                return lo - target
            if target > hi:
                return target - hi
            return 0

        distance = min(gap(item) for item in addressed)
        nearest = [item for item in addressed if gap(item) == distance]
        candidate_lines = sorted({line for _, _, line in nearest})
        selected = candidate_lines[0]
        directions = {
            "forward" if target < lo else "backward" if target > hi else "overlap"
            for lo, hi, _ in nearest
        }
        direction = next(iter(directions)) if len(directions) == 1 else "mixed"
        kind = (
            "ambiguous"
            if len(candidate_lines) > 1
            else f"nearest-{direction}"
        )
        confidence = "nearest"
    else:
        selected = 1
        candidate_lines = []
        direction = None
        distance = None
        kind = "unmapped"
        confidence = "function-only"

    lines = code.splitlines()
    selected = max(1, min(selected, max(1, len(lines))))
    if line_start is not None and line_end is not None:
        if line_start > len(lines):
            raise WorkerError(
                f"requested pseudocode line {line_start} exceeds function length "
                f"({len(lines)} lines)"
            )
        start = line_start
        end = min(line_end, len(lines))
        selection = {
            "mode": "lines",
            "requested": {"start": line_start, "end": line_end},
            "start": start,
            "end": end,
            "truncated": end != line_end,
        }
    else:
        start = max(1, selected - before)
        end = min(len(lines), selected + after)
        selection = {
            "mode": "context",
            "start": start,
            "end": end,
            "truncated": False,
        }
    selection.update({
        "total_lines": len(lines),
        "has_more": end < len(lines),
        "next_start": end + 1 if end < len(lines) else None,
    })
    excerpt = []
    for number in range(start, end + 1):
        item = {"line": number, "text": lines[number - 1]}
        ranges = sorted(by_line.get(number, set()))
        if ranges:
            item["address_ranges"] = [
                {"start": f"0x{lo:x}", "end": f"0x{hi:x}"}
                for lo, hi in ranges
            ]
        if kind != "unmapped" and number in candidate_lines:
            item["relation"] = kind
        excerpt.append(item)

    selected_ranges = sorted(by_line.get(selected, set()))
    return {
        "confidence": confidence,
        "kind": kind,
        "line": None if kind == "unmapped" else selected,
        "candidate_lines": candidate_lines,
        "distance_bytes": distance,
        "direction": direction,
        "selection": selection,
        # Retain the old flat field in diagnostic output for clients that only
        # understand confidence/line/addresses. New clients should use the
        # explicit ranges and mapping kind above.
        "addresses": sorted(
            {f"0x{x:x}" for lo, hi in selected_ranges for x in (lo, hi)}
        ),
        "excerpt": excerpt,
    }


def _requested_lines(args: dict) -> tuple[int | None, int | None]:
    start_raw = args.get("line_start")
    end_raw = args.get("line_end")
    if start_raw is None and end_raw is None:
        return None, None
    if start_raw is None or end_raw is None:
        raise WorkerError("line_start and line_end must be supplied together")
    try:
        start = int(start_raw)
        end = int(end_raw)
    except (TypeError, ValueError) as exc:
        raise WorkerError("line_start and line_end must be integers") from exc
    if start < 1 or end < start:
        raise WorkerError("line range must be positive and ascending")
    if end - start + 1 > MAX_LINE_BATCH:
        raise WorkerError(f"line range may contain at most {MAX_LINE_BATCH} lines")
    return start, end


def _bounded_code_payload(code: str, *, full: bool) -> tuple[str, dict]:
    """Bound only the optional full-code payload, never mapping input."""
    encoded = code.encode("utf-8")
    returned = code
    truncated = len(encoded) > MAX_CODE
    if truncated:
        returned = encoded[:MAX_CODE].decode("utf-8", errors="ignore")
    return returned, {
        "code_truncated": truncated,
        "code_bytes": len(encoded),
        "code_lines": len(code.splitlines()),
        "returned_code_bytes": len(returned.encode("utf-8")) if full else 0,
        "returned_code_lines": len(returned.splitlines()) if full else 0,
    }


def _attach_mapped_assembly(program, function, mapping: dict) -> bool:
    """Attach bounded instruction lists to every address-bearing source line."""
    listing = program.getListing()
    instructions = []
    for instruction in listing.getInstructions(function.getBody(), True):
        start = int(instruction.getAddress().getOffset())
        end = start + int(instruction.getLength()) - 1
        instructions.append((start, end, instruction))

    associations = 0
    truncated = False
    first_truncated_line = None
    last_truncated_line = None
    for source_line in mapping.get("excerpt") or []:
        ranges = []
        for address_range in source_line.get("address_ranges") or []:
            try:
                ranges.append((
                    int(str(address_range["start"]), 0),
                    int(str(address_range["end"]), 0),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        if not ranges:
            continue
        mapped = []
        complete = True
        seen: set[int] = set()
        for start, end, instruction in instructions:
            if not any(start <= high and end >= low for low, high in ranges):
                continue
            if start in seen:
                continue
            if associations >= MAX_MAPPED_INSTRUCTION_ASSOCIATIONS:
                truncated = True
                complete = False
                if first_truncated_line is None:
                    first_truncated_line = source_line.get("line")
                last_truncated_line = source_line.get("line")
                break
            seen.add(start)
            mapped.append(_instruction_payload(instruction))
            associations += 1
        if mapped:
            source_line["assembly"] = mapped
        source_line["assembly_complete"] = complete
    if truncated:
        mapping["assembly_truncation"] = {
            "first_line": first_truncated_line,
            "last_line": last_truncated_line,
            "association_limit": MAX_MAPPED_INSTRUCTION_ASSOCIATIONS,
        }
    return truncated


def _nearby_instructions(program, function, address) -> tuple[list[dict], dict]:
    listing = program.getListing()
    target = int(address.getOffset())
    before = collections.deque(maxlen=2)
    after: list = []
    current = None
    for instruction in listing.getInstructions(function.getBody(), True):
        start = int(instruction.getAddress().getOffset())
        end = start + int(instruction.getLength()) - 1
        if start <= target <= end:
            current = instruction
            continue
        if end < target:
            before.append(instruction)
        elif start > target and len(after) < 2:
            after.append(instruction)
        elif start > target and len(after) >= 2:
            break
    selected = list(before) + ([current] if current is not None else []) + after
    output = []
    for instruction in selected:
        item = _instruction_payload(instruction)
        item["current"] = instruction is current
        output.append(item)
    location = {
        "requested_address": f"0x{target:x}",
        "decoded": current is not None,
        "kind": "instruction" if current is not None else "undecoded-gap",
        "previous_address": (
            f"0x{int(before[-1].getAddress().getOffset()):x}" if before else None
        ),
        "next_address": (
            f"0x{int(after[0].getAddress().getOffset()):x}" if after else None
        ),
    }
    return output, location


def _instruction_payload(instruction) -> dict:
    raw = bytes((int(value) & 0xFF) for value in instruction.getBytes())
    address = int(instruction.getAddress().getOffset())
    payload = {
        "address": f"0x{address:x}",
        "bytes": raw.hex(),
        "text": str(instruction),
    }
    try:
        flows = sorted({int(flow.getOffset()) for flow in instruction.getFlows()})
    except Exception:
        flows = []
    if flows:
        payload["flow_targets"] = [f"0x{target:x}" for target in flows]
    return payload


def _count_projects(path: Path) -> int:
    try:
        return sum(1 for _ in path.glob("*.gpr"))
    except OSError:
        return 0


def _read_request(conn: socket.socket) -> dict:
    data = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            raise WorkerError("connection closed before request newline")
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            data = data[:newline]
            break
        if len(data) > MAX_REQUEST:
            raise WorkerError(f"request exceeds {MAX_REQUEST} bytes")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError(f"invalid request JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("op"), str):
        raise WorkerError("request must contain a string op")
    args = value.get("args") or {}
    if not isinstance(args, dict):
        raise WorkerError("request args must be an object")
    return {"op": value["op"], "args": args}


def _serve(args) -> int:
    os.umask(0o077)
    # Containers deliberately use a tmpfs HOME with a read-only root. Ghidra's
    # LaunchSupport persists JDK/user settings there on first JVM startup.
    Path.home().mkdir(parents=True, exist_ok=True, mode=0o700)
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    args.projects.mkdir(parents=True, exist_ok=True)
    os.chmod(args.socket.parent, 0o700)
    os.chmod(args.projects, 0o700)
    lock_fd = os.open(args.lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock_fd)
        return 0
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    worker = Worker(args.cache, args.projects, args.ghidra_install_dir)
    try:
        with contextlib.suppress(FileNotFoundError):
            args.socket.unlink()
        listener.bind(str(args.socket))
        os.chmod(args.socket, 0o600)
        listener.listen(16)
        listener.settimeout(0.5)
        args.session.write_text(json.dumps({
            "pid": os.getpid(),
            "backend": args.backend,
            "worker_api": WORKER_API,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "socket": str(args.socket),
        }, indent=2) + "\n", encoding="utf-8")

        def stop(_signum, _frame):
            worker.shutdown = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        while not worker.shutdown:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if worker.shutdown:
                    break
                raise
            with conn:
                try:
                    request = _read_request(conn)
                    result = worker.handle(request["op"], request["args"])
                    reply = {"ok": True, "result": result}
                except Exception as exc:
                    traceback.print_exc(file=sys.stderr)
                    reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                encoded = json.dumps(reply, separators=(",", ":")).encode("utf-8") + b"\n"
                with contextlib.suppress(OSError):
                    conn.sendall(encoded)
    finally:
        worker.close()
        listener.close()
        with contextlib.suppress(FileNotFoundError):
            args.socket.unlink()
        with contextlib.suppress(FileNotFoundError):
            args.session.unlink()
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--projects", type=Path, required=True)
    parser.add_argument("--ghidra-install-dir")
    parser.add_argument("--backend", choices=("docker", "host"), default="host")
    return _serve(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
