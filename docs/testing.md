# Testing

```bash
pytest                                  # unit + coverage tests, no VM required
pytest -m integration                   # live end-to-end suite, drives the real VM
```

A bare `pytest` deselects everything marked `integration`, so it never touches a
VM you are using.

The live suite (`tests/test_e2e_live.py`) exercises every CLI command and every
MCP tool against whichever image `~/.winbox/config` points at, and is written to
pass on **all four** profiles (`server2022`, `server2025`, `win11`, `win10`) — where they
genuinely differ (Tamper Protection, Server Core's smaller service set, the
Python payload) it asserts the profile-appropriate behavior instead of skipping.

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
