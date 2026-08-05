# winbox — known issues and roadmap

Everything currently known to be wrong, ranked. Each entry says what breaks,
how it was found, and what fixing it involves. Items are removed when fixed,
not ticked — `git log` is the record of what was done.

Ordering is risk × tractability, not severity alone: an unreproducible crash
outranks a typo on severity but cannot be worked on, and there is no value in
a roadmap whose top item nobody can start.

---

## Now

Items 1-3 (typed guest-agent exceptions, Defender write verification,
self-healing symbol bases) are **done** — see `git log`. What follows is what
is left.

## Next

### 4. Neither breakpoint mechanism works on both images

On Win11, `--mode soft` fails with `RspError: read timed out`; `hw` works. On
Server 2022 the reverse was observed — `hw` timed out on the 4-slot DR0..3
budget and `soft` worked. The e2e test accepts either mechanism, so this is
covered but not solved.

Almost certainly HVCI on the Win11 side: it is on by default and protects
kernel code pages from the `0xCC` patch a software breakpoint writes. Two
concrete pieces: `--mode auto` should fall back on a **timeout**, not only on
slot exhaustion; and the soft path should detect HVCI and say so rather than
reporting "read timed out". Wants investigation before implementation, which
is why it is not in the top three.

### 5. `tests/test_e2e_live.py:426` passes even in the bug it covers

`assert "closed" in tool("pipe_close")(sid)` is satisfied by every outcome
including the broker-leak case the stability round just fixed. Should assert
the specific outcome. Same shape as the weakened `"cmd."` assertion caught
during that round — worth a sweep for others rather than fixing this one alone.

### 6. The in-guest broker script is barely covered

The rewritten `_BROKER_SCRIPT` (`mcp.py`) is verified by `ast.parse` and
substring greps. It is a non-trivial program running inside the guest with no
real execution coverage. Could be exercised on the host with a fake pipe.

---

## Watching

### 8. The guest agent drops shortly after a reboot

Sharpened from "the guest wedges sometimes". It has now been seen three
times, always the same shape: a command runs fine, and the *next* one — a
few seconds later, after a reboot earlier in the sequence — gets
`Guest agent is not responding: QEMU guest agent is not connected`. Twice it
was `autologin status` immediately following the AppLocker test's reboot.

It is intermittent: the same test passes on most runs, and Server 2022 has
gone 85/85 with it. The one hard wedge earlier in this work (black console,
agent gone for good) was probably the same thing at its extreme, and its most
likely contributor — the `kdbg status` probe pausing the guest for minutes —
has since been fixed.

Now easy to recognise: since guest-agent errors are typed, this arrives as
`GuestAgentUnreachable` rather than a generic failure, so it is obvious at a
glance that the transport dropped rather than a command failing.

**Do not "fix" it with a blanket retry.** Retrying a command that may already
have run in the guest is exactly what roadmap item 1 existed to prevent. If
this is worth attacking, the safe version is a bounded retry on
`GuestAgentUnreachable` for *read-only* operations only, where re-running
costs nothing — and it needs to be a deliberate decision, not a reflex.

**If it recurs:** note what ran immediately before, and whether a reboot
happened within the previous minute.

---

## Environment notes

* `/tmp` is a 16 GB tmpfs. Tests that write ISO-sized files fill it —
  `tests/test_iso.py` shrinks the profile floor to 4 KB for this reason.
* Use the pipx venv interpreter for tests; the system python has an old `mcp`
  and fabricates 164 errors:
  `/home/witchtape/.local/share/pipx/venvs/winbox/bin/python -m pytest`
