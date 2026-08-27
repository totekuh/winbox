"""Coverage manifest for the live end-to-end suite.

Every CLI command and every MCP tool must appear here exactly once, with a
status saying how it is covered. ``tests/test_e2e_coverage.py`` enforces that
against the real click tree and the real MCP registry, so adding a command or
tool fails the build until someone decides how it gets exercised.

The point is that "we test everything" stays a checkable claim rather than an
aspiration that quietly rots. Anything genuinely untestable in CI is
``EXCLUDED`` with a reason you can read and argue with — not silently absent.

Statuses
--------
``LIVE``      Exercised against a running VM by ``tests/test_e2e_live.py``.
``GROUP``     A click group node, not an invocable command. Its ``--help`` is
              still checked by the CLI walk test.
``EXCLUDED``  Deliberately not run live. The note says why.
"""

from __future__ import annotations

LIVE = "LIVE"
GROUP = "GROUP"
EXCLUDED = "EXCLUDED"


# ─── CLI commands ───────────────────────────────────────────────────────────

CLI_COVERAGE: dict[str, tuple[str, str]] = {
    # Groups — no behavior of their own beyond dispatch.
    "applocker": (GROUP, ""),
    "autologin": (GROUP, ""),
    "av": (GROUP, ""),
    "binfmt": (GROUP, ""),
    "capture": (GROUP, ""),
    "detonate": (GROUP, ""),
    "dns": (GROUP, ""),
    "domain": (GROUP, ""),
    "hosts": (GROUP, ""),
    "iso": (GROUP, ""),
    "kdbg ghidra": (GROUP, ""),
    "jobs": (GROUP, ""),
    "kdbg": (GROUP, ""),
    "net": (GROUP, ""),
    "sinkhole": (GROUP, ""),
    "tools": (GROUP, ""),

    # Lifecycle
    "status": (LIVE, ""),
    "up": (LIVE, ""),
    "down": (LIVE, ""),
    "suspend": (LIVE, ""),
    "snapshot": (LIVE, "create + list"),
    "restore": (LIVE, ""),
    "provision": (LIVE, "re-runs provision.ps1 in the guest"),
    "setup": (EXCLUDED, "rebuilds the VM from scratch; driven by the rebuild "
                        "procedure, not the smoke suite"),
    "destroy": (EXCLUDED, "deletes the VM and its storage; see setup"),
    "vnc": (EXCLUDED, "launches virt-manager, a GUI application"),

    # Execute
    "exec": (LIVE, ""),
    "shell": (EXCLUDED, "interactive ConPTY session; needs a TTY"),
    "ssh": (EXCLUDED, "interactive SSH session; needs a TTY"),
    "eventlogs": (LIVE, ""),
    "eventlogs clear": (LIVE, ""),
    "jobs list": (LIVE, ""),
    "jobs output": (LIVE, ""),
    "jobs kill": (LIVE, ""),
    "msi": (LIVE, "argument validation only — installing a package mutates "
                  "the guest in ways the suite cannot undo"),

    # Files
    "tools list": (LIVE, ""),
    "tools add": (LIVE, ""),
    "tools remove": (LIVE, ""),
    "upload": (LIVE, ""),
    "iso status": (LIVE, ""),
    "iso download": (EXCLUDED, "multi-GB download from Microsoft's CDN"),

    # Network
    "net status": (LIVE, ""),
    "net isolate": (LIVE, "including the re-isolate idempotency case"),
    "net connect": (LIVE, ""),
    "net unplug": (LIVE, ""),
    "dns view": (LIVE, ""),
    "dns set": (LIVE, ""),
    "dns sync": (LIVE, ""),
    "hosts view": (LIVE, ""),
    "hosts add": (LIVE, ""),
    "hosts set": (LIVE, ""),
    "hosts delete": (LIVE, "including the nothing-to-remove case"),
    "domain join": (EXCLUDED, "needs a reachable Active Directory domain "
                              "controller and credentials"),
    "domain leave": (EXCLUDED, "needs a domain-joined guest; see domain join"),

    # Target
    "applocker status": (LIVE, ""),
    "applocker enable": (LIVE, ""),
    "applocker disable": (LIVE, ""),
    "autologin status": (LIVE, ""),
    "autologin enable": (LIVE, ""),
    "autologin disable": (LIVE, ""),
    "av status": (LIVE, ""),
    "av enable": (LIVE, ""),
    "av disable": (LIVE, "reboots the guest"),
    "hvci": (GROUP, ""),
    "hvci status": (LIVE, ""),
    "hvci disable": (LIVE, "reboots the guest"),
    "hvci enable": (LIVE, "reboots the guest"),

    # Malware Analysis
    "capture start": (LIVE, "via dumpcap, which Kali's Wireshark package "
                            "grants cap_net_raw to for the wireshark group "
                            "— no root needed. Falls back to tcpdump "
                            "(needs root) when dumpcap isn't installed"),
    "capture stop": (LIVE, ""),
    "capture status": (LIVE, ""),
    "sinkhole start": (LIVE, "on an unprivileged high port; the default :53 "
                             "bind needs root or a lowered "
                             "ip_unprivileged_port_start, same idea as "
                             "capture start needing dumpcap's capability"),
    "sinkhole stop": (LIVE, ""),
    "sinkhole status": (LIVE, ""),
    "sinkhole log": (LIVE, ""),
    "sinkhole inetsim": (LIVE, ""),
    "sinkhole _serve": (EXCLUDED, "internal foreground entrypoint `start` "
                                  "re-execs into as a detached process; it "
                                  "blocks serving DNS until SIGTERM, so "
                                  "invoking it directly would hang the "
                                  "suite"),
    "detonate check": (LIVE, "read-only preflight; run under an explicit "
                             "net isolate so the hard gate passes"),

    # Integrations
    "binfmt status": (LIVE, ""),
    "binfmt enable": (EXCLUDED, "writes to /proc/sys/fs/binfmt_misc as root; "
                                "a host-level change the suite must not make"),
    "binfmt disable": (EXCLUDED, "see binfmt enable"),
    "mcp": (EXCLUDED, "starts a blocking stdio server; the tools it serves are "
                      "covered directly in test_e2e_live.py"),
    "office": (EXCLUDED, "needs a licensed Microsoft Office installer image"),

    # kdbg
    "kdbg cet-status": (LIVE, "read-only debugger safety preflight"),
    "kdbg prepare": (LIVE, "confirmation-refusal path only; does not change policy"),
    "kdbg restore-cet": (LIVE, "confirmation-refusal path only; does not change policy"),
    "kdbg start": (LIVE, ""),
    "kdbg stop": (LIVE, ""),
    "kdbg status": (LIVE, ""),
    "kdbg context": (
        EXCLUDED,
        "same daemon operation is exercised live through kdbg_context; CLI JSON is unit-tested",
    ),
    "kdbg symbols": (LIVE, "downloads and parses the nt PDB"),
    "kdbg sym": (LIVE, ""),
    "kdbg struct": (LIVE, ""),
    "kdbg ps": (LIVE, ""),
    "kdbg threads": (LIVE, "validated ETHREAD ownership and scheduler metadata"),
    "kdbg lm": (LIVE, ""),
    "kdbg base": (LIVE, ""),
    "kdbg session": (LIVE, ""),
    "kdbg target-status": (LIVE, "bounded captured-process identity probe"),
    "kdbg attach": (LIVE, ""),
    "kdbg detach": (LIVE, "asserts the guest is not left paused"),
    "kdbg resume": (LIVE, ""),
    "kdbg user-lm": (LIVE, ""),
    "kdbg user-symbols": (LIVE, ""),
    "kdbg read-va": (LIVE, ""),
    "kdbg regs": (LIVE, "requires an attached session"),
    "kdbg decomp": (LIVE, "exact cached ntdll mapped from a live target VA"),
    "kdbg decomp-status": (LIVE, "read-only Docker/API/cache status"),
    "kdbg ghidra install": (EXCLUDED, "one-time 570 MB network image build; covered by the dedicated real Docker integration"),
    "kdbg ghidra run": (LIVE, "start and API-check the private container"),
    "kdbg ghidra status": (LIVE, "read-only image/container/API status"),
    "kdbg ghidra cache": (LIVE, "read-only content-cache inventory"),
    "kdbg ghidra prune": (EXCLUDED, "destructive apply requires explicit policy; unit-tested dry-run and deletion"),
    "kdbg ghidra repair": (EXCLUDED, "resets one exact Ghidra project cache; unit and real Docker integration tested"),
    "kdbg ghidra prepare": (LIVE, "offline exact-artifact analysis while the VM runs"),
    "kdbg ghidra prepare-status": (LIVE, "durable background preparation status"),
    "kdbg ghidra cancel": (EXCLUDED, "requires an active analysis/job; request and token cancellation are unit, real-process, Docker, and manual-live tested"),
    "kdbg ghidra stop": (LIVE, "stop container while preserving caches"),
    "kdbg mem": (LIVE, ""),
    "kdbg stack": (LIVE, ""),
    "kdbg bt": (LIVE, ""),
    "kdbg bps": (LIVE, ""),
    "kdbg bp": (LIVE, ""),
    "kdbg bp-trace": (EXCLUDED, "action trace querying is covered by CLI unit "
                                      "and real daemon-socket integration tests"),
    "kdbg rm": (LIVE, ""),
    "kdbg user-bp": (LIVE, "argument validation only"),
    "kdbg cont": (EXCLUDED, "blocks until a breakpoint fires or its budget "
                            "expires; leaves the guest halted on timeout"),
    "kdbg cont-start": (EXCLUDED, "continues the guest asynchronously; durable "
                                  "worker lifecycle is socket-integrated"),
    "kdbg cont-poll": (EXCLUDED, "paired with cont-start; socket-integrated"),
    "kdbg cont-cancel": (EXCLUDED, "paired with cont-start; socket-integrated"),
    "kdbg step": (EXCLUDED, "single-steps a halted guest; see kdbg cont"),
    "kdbg interrupt": (EXCLUDED, "halts the guest CPU; see kdbg cont"),
}


# ─── MCP tools ──────────────────────────────────────────────────────────────

MCP_COVERAGE: dict[str, tuple[str, str]] = {
    "exec": (LIVE, "including credentialed local-user execution"),
    "python": (LIVE, ""),
    "powershell": (LIVE, ""),
    "job_result": (LIVE, "retrieves a background exec/python/powershell job"),
    "ps": (LIVE, ""),
    "ioctl": (LIVE, "error path — a real device IOCTL depends on a driver "
                    "that is not part of a stock image"),
    "reg_query": (LIVE, ""),
    "reg_set": (LIVE, ""),
    "reg_delete": (LIVE, ""),
    "eventlogs": (LIVE, ""),
    "eventlogs_clear": (LIVE, ""),
    "upload": (LIVE, ""),
    "file_copy": (LIVE, ""),
    "mem_read": (LIVE, ""),
    "service_start": (LIVE, ""),
    "service_stop": (LIVE, ""),
    "av_status": (LIVE, ""),
    "av_enable": (LIVE, ""),
    "av_disable": (EXCLUDED, "reboots the guest mid-suite; the CLI path "
                             "`av disable` covers the same shared code"),
    "hvci_status": (LIVE, ""),
    "hvci_disable": (EXCLUDED, "reboots the guest mid-suite; the CLI path "
                               "`hvci disable` covers the same shared code"),
    "hvci_enable": (EXCLUDED, "reboots the guest mid-suite; the CLI path "
                              "`hvci enable` covers the same shared code"),
    "net_isolate": (LIVE, ""),
    "net_connect": (LIVE, ""),
    "net_unplug": (LIVE, ""),

    # Named-pipe broker
    "pipe_list": (LIVE, ""),
    "pipe_info": (LIVE, ""),
    "pipe_connect": (LIVE, ""),
    "pipe_open": (LIVE, ""),
    "pipe_send": (LIVE, ""),
    "pipe_recv": (LIVE, ""),
    "pipe_close": (LIVE, "including the double-close case"),

    # kdbg
    "kdbg_cet_status": (LIVE, "read-only debugger safety preflight"),
    "kdbg_prepare": (LIVE, "confirmation-refusal path only; does not change policy"),
    "kdbg_restore_cet": (LIVE, "confirmation-refusal path only; does not change policy"),
    "kdbg_start": (LIVE, ""),
    "kdbg_stop": (LIVE, ""),
    "kdbg_status": (LIVE, ""),
    "kdbg_session": (LIVE, ""),
    "kdbg_target_status": (LIVE, "bounded captured-process identity probe"),
    "kdbg_symbols_load": (LIVE, ""),
    "kdbg_sym": (LIVE, ""),
    "kdbg_struct": (LIVE, ""),
    "kdbg_ps": (LIVE, ""),
    "kdbg_threads": (LIVE, "validated ETHREAD ownership and scheduler metadata"),
    "kdbg_lm": (LIVE, ""),
    "kdbg_base_refresh": (LIVE, ""),
    "kdbg_attach": (LIVE, ""),
    "kdbg_detach": (LIVE, "asserts the guest is not left paused"),
    "kdbg_resume": (LIVE, ""),
    "kdbg_user_lm": (LIVE, ""),
    "kdbg_user_symbols_load": (LIVE, ""),
    "kdbg_read_va": (LIVE, ""),
    "kdbg_regs": (LIVE, ""),
    "kdbg_mem": (LIVE, ""),
    "kdbg_stack": (LIVE, ""),
    "kdbg_bt": (LIVE, ""),
    "kdbg_context": (LIVE, "one-call epoch-pinned stop triage"),
    "kdbg_bps": (LIVE, ""),
    "kdbg_bp": (LIVE, ""),
    "kdbg_bp_trace": (
        EXCLUDED,
        "requires attached daemon with action bp; socket-integrated and live-verified",
    ),
    "kdbg_rm": (LIVE, ""),
    "kdbg_disasm": (LIVE, ""),
    "kdbg_decomp": (LIVE, "exact cached ntdll mapped from a live target VA"),
    "kdbg_decomp_status": (LIVE, "read-only Docker/API/cache status"),
    "kdbg_decomp_cache": (LIVE, "read-only content-cache inventory"),
    "kdbg_decomp_cache_prune": (EXCLUDED, "destructive apply requires explicit policy; unit-tested dry-run and deletion"),
    "kdbg_decomp_cache_repair": (EXCLUDED, "resets one exact Ghidra project cache; unit and real Docker integration tested"),
    "kdbg_decomp_prepare": (LIVE, "offline exact-artifact analysis while the VM runs"),
    "kdbg_decomp_prepare_status": (LIVE, "durable background preparation status"),
    "kdbg_decomp_cancel": (EXCLUDED, "requires an active analysis/job; request and token cancellation are unit, real-process, Docker, and manual-live tested"),
    "kdbg_ghidra_install": (EXCLUDED, "one-time 570 MB network image build; covered by the dedicated real Docker integration"),
    "kdbg_ghidra_run": (LIVE, "start and API-check the private container"),
    "kdbg_ghidra_stop": (LIVE, "stop container while preserving caches"),
    "kdbg_write_mem": (EXCLUDED, "writes into live kernel memory; a wrong "
                                 "address or a misparsed read-back would "
                                 "destabilize the guest mid-suite for no "
                                 "coverage the RSP-level tests do not give"),
    "kdbg_cont": (EXCLUDED, "blocks until a breakpoint fires or its budget "
                            "expires; leaves the guest halted on timeout"),
    "kdbg_cont_start": (LIVE, "start a durable continue against the live VM"),
    "kdbg_cont_poll": (LIVE, "poll the durable live continue token"),
    "kdbg_cont_cancel": (LIVE, "interrupt and cancel the live continue"),
    "kdbg_step": (EXCLUDED, "single-steps a halted guest; see kdbg_cont"),
    "kdbg_interrupt": (EXCLUDED, "halts the guest CPU; see kdbg_cont"),
}


def statuses(coverage: dict[str, tuple[str, str]], status: str) -> set[str]:
    return {name for name, (st, _) in coverage.items() if st == status}


# ─── Unit coverage backing each live exclusion ──────────────────────────────
# Excluding something from the live suite is only acceptable if it is tested
# some other way. Each EXCLUDED entry above names the unit test file that
# covers it here, and test_e2e_coverage.py enforces that the mapping is
# complete and that the files exist — so "excluded" can never quietly become
# "untested".

CLI_EXCLUSION_UNIT_TESTS: dict[str, str] = {
    "sinkhole _serve": "tests/test_sinkhole.py",
    "setup": "tests/test_installer.py",
    "destroy": "tests/test_destroy.py",
    "vnc": "tests/test_status.py",
    "shell": "tests/test_shell.py",
    "ssh": "tests/test_shell.py",
    "iso download": "tests/test_iso.py",
    "domain join": "tests/test_network.py",
    "domain leave": "tests/test_network.py",
    "binfmt enable": "tests/test_binfmt.py",
    "binfmt disable": "tests/test_binfmt.py",
    "mcp": "tests/test_mcp.py",
    "office": "tests/test_office.py",
    "kdbg cont": "tests/test_kdbg_daemon.py",
    "kdbg cont-start": "tests/test_kdbg_continue_job.py",
    "kdbg cont-poll": "tests/test_kdbg_continue_job.py",
    "kdbg cont-cancel": "tests/test_kdbg_continue_job.py",
    "kdbg step": "tests/test_kdbg_daemon.py",
    "kdbg interrupt": "tests/test_kdbg_daemon.py",
    "kdbg context": "tests/test_kdbg_daemon.py",
    "kdbg bp-trace": "tests/test_kdbg.py",
    "kdbg ghidra install": "tests/test_kdbg_decomp_docker.py",
    "kdbg ghidra prune": "tests/test_kdbg_decomp_hardening.py",
    "kdbg ghidra repair": "tests/test_kdbg_decomp_hardening.py",
    "kdbg ghidra cancel": "tests/test_kdbg_decomp_prepare.py",
}

MCP_EXCLUSION_UNIT_TESTS: dict[str, str] = {
    "av_disable": "tests/test_mcp.py",
    "hvci_disable": "tests/test_hvci.py",
    "hvci_enable": "tests/test_hvci.py",
    "kdbg_write_mem": "tests/test_kdbg_rsp.py",
    "kdbg_cont": "tests/test_mcp.py",
    "kdbg_step": "tests/test_mcp.py",
    "kdbg_interrupt": "tests/test_mcp.py",
    "kdbg_bp_trace": "tests/test_kdbg_trace.py",
    "kdbg_ghidra_install": "tests/test_kdbg_decomp_docker.py",
    "kdbg_decomp_cache_prune": "tests/test_kdbg_decomp_hardening.py",
    "kdbg_decomp_cache_repair": "tests/test_kdbg_decomp_hardening.py",
    "kdbg_decomp_cancel": "tests/test_kdbg_decomp_prepare.py",
}
