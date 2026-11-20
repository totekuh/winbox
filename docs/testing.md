# Testing

```bash
pytest                                  # unit + coverage tests, no VM required
pytest -m integration                   # live end-to-end suite, drives the real VM
```

A bare `pytest` deselects everything marked `integration`, so it never touches a
VM you are using.

The live suite spans several integration test files:

- `tests/test_e2e_live.py` — primary end-to-end: CLI commands, MCP tools, kdbg debugger lifecycle
- `tests/test_kdbg_negative_integration.py` — session lifecycle error paths (no-session, double-attach, busy-during-cont, detach edges)
- `tests/test_kdbg_args_integration.py` — argument validation (bad PIDs, invalid limits/addresses)
- `tests/test_kdbg_stepping_integration.py` — real-binary debugging (step-over, step-out, interrupt during cont, disasm validation, kdbg_ps/lm/struct)
- `tests/test_kdbg_coverage_integration.py` — remaining tool gaps (read_va, search, session/status assertions, capture+diff, CET, CLI round-trips)
- `tests/test_kdbg_e2e_extras_integration.py` — breakpoint intents (CRUD + fire on cont), pipe/share negatives, resume recovery, sinkhole DNS resolution

`tests/bootstrap.py` automates VM provisioning for CI: creates the VM, disables
CET, reboots, resolves symbols, and snapshots as `integration-ready`.

Tests pass on **all four** profiles (`server2022`, `server2025`, `win11`, `win10`) — where they
genuinely differ (Tamper Protection, Server Core's smaller service set, the
Python payload) they assert the profile-appropriate behavior instead of skipping.

`tests/e2e_manifest.py` records how each command and tool is covered — live, or
excluded with a stated reason — and `tests/test_e2e_coverage.py` checks that
manifest against the real click tree and MCP registry. Adding a command or tool
fails the build until you say how it gets exercised, which is what keeps "we
test everything" a claim you can verify rather than one that quietly rots.

To validate a change across all images:

```bash
winbox setup --os server2022 -y && pytest -m integration
winbox setup --os server2025 -y && pytest -m integration
winbox setup --os win11 -y      && pytest -m integration
winbox setup --os win10 --iso /path/to/win10.iso -y && pytest -m integration
```
