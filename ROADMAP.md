# winbox — known issues and roadmap

Everything currently known to be wrong, ranked. Each entry says what breaks,
how it was found, and what fixing it involves. Items are removed when fixed,
not ticked — `git log` is the record of what was done.

Ordering is risk × tractability, not severity alone: an unreproducible crash
outranks a typo on severity but cannot be worked on, and there is no value in
a roadmap whose top item nobody can start.

---

## Now — the next three

### 1. Guest-agent errors are discriminated by string matching

**Files:** `src/winbox/vm/guest.py:265,439`, `src/winbox/exec/executor.py:38`

Two call sites make control-flow decisions on the *text* of a
`GuestAgentError`, because the exception is flat and carries no structure.

`_errors_on_unknown_pid()` returns `True` on **any** `GuestAgentError` — a
virtio hiccup or a transient virsh failure reads identically to "the agent has
no record of this PID". At `guest.py:439` a `True` makes `resolve` return
`None`, discarding a result that the preceding read has **already freed from
the agent**. That result is then unrecoverable: the poll continues against a
PID with no entry.

`executor.py:38` decides whether a command already launched with
`"timed out" in msg`. libvirt renders `VIR_ERR_OPERATION_TIMEOUT` as
"operation timed out", so a genuinely retryable pre-launch failure can be
classified as "already ran" and the retry loop silently disabled.

**Why first:** this is the same failure mode as the PID-reuse contamination —
a wrong result returned confidently — in the same transport, and it can lose a
command's output outright. Both call sites want the same fix, so they are one
piece of work rather than two.

**Approach:** give `guest.py` typed exceptions —
`GuestExecTimeout(GuestAgentError)` for a command that exceeded its own
deadline, and something like `GuestAgentUnreachable` for transport failures,
raised where `_raw_command` fails. Then `_errors_on_unknown_pid` distinguishes
"agent answered, no such PID" from "agent did not answer" (and on the latter
must not discard anything), and `executor.py` catches the timeout type instead
of grepping. Also worth making `GuestAgentError` subclass `RuntimeError` to
match the convention in `lifecycle.py:23-32`. Unit-testable end to end; no VM
needed.

### 2. Defender service writes are issued without checking they landed

**File:** `src/winbox/defender.py` — `enable()` step 1.5

The loop writes `Services\<svc>\Start` for the four Defender services with
`reg.exe` and discards every exit code. We now know from live testing that
**those keys are ACL-protected and the writes fail** — Access is denied, even
with Defender stopped and Tamper Protection off.

The MCP frontend was fixed during the stability round by reading the values
back afterwards, but that fix lives in `mcp.py`. The CLI path and any future
caller still issue writes that are known to fail and treat them as done.

**Why second:** small, certain, and it is code that lies about a thing we have
already proven false. It also removes the duplicated `_DEFENDER_DEFAULT_START`
table (see item 6) as a side effect, since verification belongs next to the
values.

**Approach:** have `enable()` collect the failing services and surface them —
either a returned structure or a field on the state it already returns for the
reboot case. Callers then report honestly instead of implying success. Keep the
offline path as the actual remedy; this is about not claiming the in-guest
write worked.

### 3. The symbol store outlives the boot that produced it

**Files:** `src/winbox/kdbg/store.py`, `src/winbox/kdbg/symbols.py`

ASLR re-randomizes the nt and user-module load bases on every boot, but
`~/.winbox/symbols/` persists across reboots *and* across full rebuilds. After
any reboot the walkers refuse to run — `PageWalkError: PDPTE not present`, or
`stale module bases for X … ASLR moved them`.

The errors are accurate and name the remedy, and `kdbg base` /
`kdbg user-symbols` do fix it. But nothing invalidates the cache
automatically, so every reboot silently breaks kdbg until the user knows the
incantation. `tests/test_e2e_live.py` has to refresh explicitly before every
attach, which is the tell.

**Why third:** the most user-facing friction left, and the fix has a precedent
already in the codebase.

**Approach:** `load_nt` already keys its entries on the nt build id. Do the
same for user-module bases, keyed on something that changes per boot (the
guest's boot id, or the nt base itself, which is re-randomized each boot).
A stale entry then misses rather than matching wrongly, and the loader
refreshes instead of erroring. Needs a live VM to verify.

---

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

### 6. `_DEFENDER_DEFAULT_START` is duplicated

`mcp.py` and `defender.py` each hardcode the shipped start types (2/0/3/3),
in the module whose job is verifying the other one wrote them. Folds into
item 2.

### 7. The in-guest broker script is barely covered

The rewritten `_BROKER_SCRIPT` (`mcp.py`) is verified by `ast.parse` and
substring greps. It is a non-trivial program running inside the guest with no
real execution coverage. Could be exercised on the host with a fake pipe.

---

## Watching

### 8. The guest can wedge under sustained reboot churn

One e2e run left Windows unresponsive — black console, agent gone — after a
long sequence of reboots and network reconfiguration. A hard `virsh destroy` +
`start` recovered it with no disk damage.

Not reproducible in isolation, and the likeliest contributor (the `kdbg status`
probe pausing the guest for minutes at a time) has since been fixed, so this
may already be gone. It is listed here rather than in the work queue because
there is nothing actionable until it recurs: the e2e suite now fails fast with
a clear diagnosis instead of cascading, which is the instrumentation that would
catch it next time.

**If it recurs:** capture `virsh qemu-monitor-command --hmp 'info status'` and
a console screenshot before recovering, and note what ran immediately before.

---

## Environment notes

* `/tmp` is a 16 GB tmpfs. Tests that write ISO-sized files fill it —
  `tests/test_iso.py` shrinks the profile floor to 4 KB for this reason.
* Use the pipx venv interpreter for tests; the system python has an old `mcp`
  and fabricates 164 errors:
  `/home/witchtape/.local/share/pipx/venvs/winbox/bin/python -m pytest`
