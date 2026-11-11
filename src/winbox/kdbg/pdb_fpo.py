"""PDB old-FPO and modern frame-data parsing from ``llvm-pdbutil dump --fpo``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from winbox.kdbg.pdb import PdbError, _run_dump

_FPO_MAX_RECORDS = 1_000_000
_FPO_MAX_PROGRAM = 4096
_FPO_ROW_RE = re.compile(r"^\s*([0-9A-Fa-f]{8})\s*\|")


@dataclass(frozen=True)
class FpoRecord:
    """One old-FPO or modern frame-data record, normalized for JSON."""

    rva: int
    code_size: int
    locals_size: int
    params_size: int
    prolog_size: int
    saved_regs_size: int
    source: str
    recipe: str
    use_bp: bool = False
    has_seh: bool = False
    stack_size: int = 0
    has_cpp_eh: bool = False
    function_start: bool = True
    frame_type: str = "FPO"
    program: str = ""
    alignment: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "rva": self.rva,
            "code_size": self.code_size,
            "locals_size": self.locals_size,
            "params_size": self.params_size,
            "prolog_size": self.prolog_size,
            "saved_regs_size": self.saved_regs_size,
            "source": self.source,
            "recipe": self.recipe,
            "use_bp": self.use_bp,
            "has_seh": self.has_seh,
            "stack_size": self.stack_size,
            "has_cpp_eh": self.has_cpp_eh,
            "function_start": self.function_start,
            "frame_type": self.frame_type,
            "program": self.program,
            "alignment": self.alignment,
        }


def _fpo_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise ValueError(f"invalid boolean {value!r}")
    return normalized == "true"


def _frame_recipe(program: str) -> tuple[str, int]:
    """Classify the finite frame-program shapes LLVM emits for MS PDBs."""
    normalized = " ".join(program.split())
    if ".raSearchStart" in normalized:
        return "ra-search-start", 0
    if ".raSearch" in normalized:
        match = re.search(r"\b(\d+)\s+@\s+=", normalized)
        if "@" not in normalized:
            return "ra-search", 0
        if match is None:
            return "unsupported", 0
        alignment = int(match.group(1))
        if alignment > 4096 or alignment < 2 or alignment & (alignment - 1):
            return "unsupported", 0
        return "ra-search", alignment
    if "$T1 $ebx =" in normalized and "$eip $T1 4 + ^ =" in normalized:
        return "ebx-frame", 0
    if "$T0 $ebp =" in normalized and "$eip $T0 4 + ^ =" in normalized:
        return "ebp-frame", 0
    return "unsupported", 0


def parse_fpo(text: str) -> list[FpoRecord]:
    """Parse ``llvm-pdbutil dump --fpo`` old and new frame tables."""
    section: str | None = None
    records: list[FpoRecord] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if "Old FPO Data" in line:
            section = "old"
            continue
        if "New FPO Data" in line:
            section = "new"
            continue
        if section is None or not _FPO_ROW_RE.match(line):
            continue
        if len(records) >= _FPO_MAX_RECORDS:
            raise PdbError(f"FPO record count exceeds {_FPO_MAX_RECORDS}")
        fields = [part.strip() for part in line.split("|")]
        try:
            if section == "old":
                if len(fields) != 9:
                    raise ValueError(f"expected 9 columns, got {len(fields)}")
                rva, code, locals_, params, prolog, saved = (
                    int(fields[0], 16), *(int(value, 10) for value in fields[1:6])
                )
                use_bp = _fpo_bool(fields[6])
                frame_type = fields[8]
                if frame_type.upper() in {"TRAP", "TSS"}:
                    recipe = "unsupported"
                else:
                    recipe = "ebp-frame" if use_bp else "fpo-stack"
                records.append(FpoRecord(
                    rva=rva, code_size=code,
                    locals_size=locals_ * 4, params_size=params * 4,
                    prolog_size=prolog, saved_regs_size=saved * 4,
                    source="pdb-old-fpo",
                    recipe=recipe,
                    use_bp=use_bp, has_seh=_fpo_bool(fields[7]),
                    frame_type=frame_type,
                ))
            else:
                if len(fields) != 11:
                    raise ValueError(f"expected 11 columns, got {len(fields)}")
                program = fields[10]
                if len(program) > _FPO_MAX_PROGRAM:
                    raise ValueError("frame program exceeds 4096 characters")
                recipe, alignment = _frame_recipe(program)
                records.append(FpoRecord(
                    rva=int(fields[0], 16), code_size=int(fields[1], 10),
                    locals_size=int(fields[2], 10),
                    params_size=int(fields[3], 10),
                    stack_size=int(fields[4], 10),
                    prolog_size=int(fields[5], 10),
                    saved_regs_size=int(fields[6], 10),
                    source="pdb-frame-data", recipe=recipe,
                    has_seh=_fpo_bool(fields[7]),
                    has_cpp_eh=_fpo_bool(fields[8]),
                    function_start=_fpo_bool(fields[9]),
                    program=program, alignment=alignment,
                ))
        except ValueError as exc:
            raise PdbError(f"malformed {section} FPO row: {line[:160]} ({exc})") from exc
    records.sort(key=lambda item: (item.rva, item.source != "pdb-frame-data"))
    return records


def load_fpo(pdb_path: Path) -> list[FpoRecord]:
    return parse_fpo(_run_dump(pdb_path, "--fpo"))
