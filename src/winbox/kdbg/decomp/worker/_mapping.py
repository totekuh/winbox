"""Ghidra decompiled-source-to-address mapping and instruction extraction."""

from __future__ import annotations

import collections

from winbox.kdbg.decomp.worker._common import (
    MAX_CODE,
    MAX_CONTEXT_LINES,
    MAX_LINE_BATCH,
    MAX_MAPPED_INSTRUCTION_ASSOCIATIONS,
    WorkerError,
)


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
