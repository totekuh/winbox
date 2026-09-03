# winbox feature requests — round 2 (from same session)

Status: completed by roadmap items 111–112 and included in Winbox v1.6.4.

## Fixed: kdbg_search couldn't find staged modules

`kdbg_search module=mpengine query=ResolveE8E9` returns "no exact cached PE matches module 'mpengine'" despite:
- mpengine.dll being staged during attach (symbol_state=failed but binary copied)
- mpengine.dll existing in decomp cache at `~/.winbox/decomp/cache/verified-binaries/d99dea0b...dll`
- A warm Ghidra project existing for this exact sha256

Tried both `module=mpengine` and `module=mpengine.dll`. Neither worked.

The search tool likely looks for the binary in the staging area (session-specific) rather than the decomp cache (persistent). Either:
- Make kdbg_search check the decomp cache in addition to the staging area
- Or accept a `sha256=` parameter to target a specific cached binary directly

This is the highest priority fix — kdbg_search was the #2 feature request and it doesn't work yet.

---

## Completed: durable module+offset breakpoint intents for detached sessions

Currently `kdbg_bp target=mpengine+0xb52c40` requires an attached session (to resolve module base from the manifest). Would be useful to pre-set breakpoints before attaching, using the LAST KNOWN base from a previous session. Store the module manifest persistently so BP setup doesn't require a full attach cycle.

Lower priority — current workflow (attach → set BP → cont) works, just slower than it could be.
