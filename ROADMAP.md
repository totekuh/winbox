# winbox — known issues and roadmap

Everything currently known to be wrong, ranked. Each entry says what breaks,
how it was found, and what fixing it involves. Items are removed when fixed,
not ticked — `git log` is the record of what was done.

Ordering is risk × tractability, not severity alone: an unreproducible crash
outranks a typo on severity but cannot be worked on, and there is no value in
a roadmap whose top item nobody can start.

---

## Open

Nothing is currently queued above item 8. Items 1-7 are done — `git log` is
the record.

One finding from the breakpoint work is worth keeping, because it shapes any
future kdbg change: **neither breakpoint mechanism installs on both images.**
Windows 11 runs HVCI by default, which exists precisely to stop the `0xCC`
patch a software breakpoint writes into a kernel code page, so `--mode soft`
cannot work there. Server 2022 has instead been seen exhausting the four
per-vCPU DR0..3 slots, which is the hardware path's ceiling. `--mode auto`
tries hardware first and falls back, so it works on both, and the failure
messages now name the wall you actually hit instead of guessing at one.

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
