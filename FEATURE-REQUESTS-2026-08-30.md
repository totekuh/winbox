# winbox feature requests — from mpengine unpacker audit 2026-08-30

Status: completed by roadmap item 111 and included in Winbox v1.6.4.

## 1. `kdbg_bp` — accept `module+offset` syntax

**Problem:** Every BP requires manual VA computation: `base + RVA`. mpengine base changes on reload (ASLR), so the math repeats every session. Did it ~15 times in one session.

**Current workflow:**
```
kdbg_user_lm → find mpengine base (0x7ff8ed940000)
mental math: 0x7ff8ed940000 + 0xb52c40 = 0x7ff8ee492c40
kdbg_bp target=0x7ff8ee492c40
```

**Requested:**
```
kdbg_bp target=mpengine+0xb52c40
```

The tool already has module context from the attached session's user_lm manifest. Resolve `module+hex_offset` to VA internally.

**Edge cases:** module name should be case-insensitive, match against the staged module list. Error if module not found or session not attached.

---

## 2. `kdbg_decomp` — symbol/string search mode

**Problem:** Finding a function by its RTTI class name or by a string it references requires a multi-step manual process on the host:
1. `strings binary | grep pattern` to find the string RVA
2. Python script to parse RTTI Type Descriptor → COL → vtable chain
3. Python script to search for LEA instructions referencing the vtable
4. Finally decomp at the found RVA

This took 5-10 minutes per function and ~60% of the session's RE time.

**Requested:** A search parameter on `kdbg_decomp`:
```
kdbg_decomp module=mpengine search="HandleUnpacker"
kdbg_decomp module=mpengine search="AspackUnpacker"
kdbg_decomp module=mpengine search="FopScanner"
```

Behavior:
- Search the module's string table / .rdata for the query
- If it matches an RTTI type descriptor name (`.?AV<name>@@`): resolve the RTTI → COL → vtable chain, return the vtable address and first N vfunc RVAs
- If it matches a function's mangled name: resolve to the function RVA via .pdata unwind entries
- If it matches a plain string: find xrefs (LEA/MOV instructions) in .text that reference it, return the containing function RVAs
- Return results as a list of `{rva, context}` pairs, not full decomps — the caller picks which to decomp

This is essentially "find function by name" for binaries without PDB symbols (like mpengine). The RTTI data is rich enough to resolve most class methods.

**Scope:** Read-only, operates on the cached binary (no VM stop needed). Could be a separate tool (`kdbg_search` or `kdbg_find_symbol`) if adding it to decomp is awkward.

---

## Nice-to-have (lower priority)

### 3. `kdbg_bp` — show module+offset in `kdbg_bps` output

Currently `kdbg_bps` shows raw VAs:
```json
{"id":0, "va":"0x7ff8ee492c40", "target_pretty":"0x7ff8ee492c40"}
```

With module resolution:
```json
{"id":0, "va":"0x7ff8ee492c40", "target_pretty":"mpengine.dll+0xb52c40"}
```

Makes BP lists readable without manual reverse-computation.

### 4. `kdbg_decomp` — caller/callee xrefs

After decomping a function, common next question is "who calls this?" or "what does this call?". Today this required a Python script scanning for `E8` CALL instructions with matching RIP-relative offsets.

A `callers=true` or `callees=true` flag on decomp would return the list of direct call xrefs. Operates on the Ghidra project (which already has the call graph).

### 5. `kdbg_cont` — action-on-hit for breakpoints

For noisy BPs (like the parent function that fired on every PE section), having to poll/cancel/re-continue is slow. A BP action like `actions=["log_regs", "continue"]` would auto-log registers and resume without stopping, similar to WinDbg conditional breakpoints. (I see kdbg_bp already has `actions` and `condition` — if these work for this use case, document an example.)
