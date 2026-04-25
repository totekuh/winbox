"""Pure formatters for kdbg sym/struct output.

The CLI (``cli/kdbg.py``) and the MCP tool layer (``mcp.py``) both want
to render symbol lookups and struct layouts. The two used to inline the
same logic with slightly different output formats. Extract the rendering
into ``list[str]`` builders so both frontends call one place — Rich /
Click on the CLI side, ``\\n``.join() on the MCP side.

These functions raise :class:`SymbolStoreError` from the underlying
``SymbolStore`` calls; callers decide how to surface that.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from winbox.kdbg.store import SymbolStore


def format_sym(
    store: "SymbolStore",
    name: str,
    *,
    search: bool = False,
    limit: int = 16,
    rva: bool = False,
) -> list[str]:
    """Resolve a symbol (or substring) to one or more lines.

    Returns a list of pre-formatted strings; an empty list means "no
    matches" (caller picks whether that's an error or a no-op).

    * ``search=False`` (default) -- exact lookup, returns one line.
    * ``search=True``            -- substring search, returns up to ``limit``.
    * ``rva=True``               -- print RVA instead of absolute VA.
    """
    module, sym = store.parse_symbol(name)
    if search:
        hits = store.search(sym, module=module, limit=limit)
        if not hits:
            return []
        if rva:
            return [f"{module}!{n} 0x{r:x}" for n, r in hits]
        base = store.load(module).get("base") or 0
        return [f"{module}!{n} 0x{base + r:x}" for n, r in hits]

    value = store.rva(name) if rva else store.resolve(name)
    return [f"{name} 0x{value:x}"]


def format_struct(
    store: "SymbolStore",
    type_name: str,
    field: str | None = None,
    *,
    module: str = "nt",
) -> list[str]:
    """Render a struct layout or a single field offset.

    With ``field=None`` returns ``[<header>, '+0xoff  name  type', ...]``
    sorted by offset. With ``field`` set, returns a single line for that
    field only.
    """
    info = store.struct(type_name, field=field, module=module)
    if field is not None:
        return [
            f"{module}!{type_name}.{field} off=0x{info['off']:x} "
            f"type={info.get('type', '')}"
        ]

    size = info.get("size", 0)
    lines = [f"{module}!{type_name} size=0x{size:x} ({size})"]
    for fname, fdata in sorted(
        info.get("fields", {}).items(), key=lambda kv: kv[1]["off"],
    ):
        lines.append(
            f"  +0x{fdata['off']:04x}  {fname}  {fdata.get('type', '')}"
        )
    return lines
