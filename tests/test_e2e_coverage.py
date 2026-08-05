"""Enforces that the e2e manifest actually describes the whole surface.

These run without a VM. They are the reason "everything is covered" is a
checkable statement: add a CLI command or an MCP tool and the build fails
until the manifest says how it gets exercised — live, or excluded with a
reason someone can read and disagree with.
"""

from __future__ import annotations

import asyncio

import click
import pytest

from tests.e2e_manifest import (
    CLI_COVERAGE,
    EXCLUDED,
    GROUP,
    LIVE,
    MCP_COVERAGE,
)
from winbox.cli import cli as cli_root
from winbox.mcp import mcp


def _cli_tree() -> dict[str, click.Command]:
    """Every command path in the click tree, keyed by its space-joined path."""
    found: dict[str, click.Command] = {}

    def walk(cmd: click.Command, path: list[str]) -> None:
        if path:
            found[" ".join(path)] = cmd
        if isinstance(cmd, click.Group):
            for name in sorted(cmd.commands):
                walk(cmd.commands[name], path + [name])

    walk(cli_root, [])
    return found


def _mcp_tool_names() -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


CLI_TREE = _cli_tree()
MCP_TOOLS = _mcp_tool_names()


class TestCliManifestCompleteness:
    def test_every_cli_command_is_in_the_manifest(self):
        missing = sorted(set(CLI_TREE) - set(CLI_COVERAGE))
        assert missing == [], (
            "CLI commands with no e2e coverage decision: "
            + ", ".join(missing)
            + " — add them to CLI_COVERAGE in tests/e2e_manifest.py"
        )

    def test_manifest_has_no_commands_that_no_longer_exist(self):
        stale = sorted(set(CLI_COVERAGE) - set(CLI_TREE))
        assert stale == [], (
            "CLI_COVERAGE lists commands that are gone: " + ", ".join(stale)
        )

    @pytest.mark.parametrize("name", sorted(CLI_COVERAGE))
    def test_status_is_valid(self, name):
        status, _ = CLI_COVERAGE[name]
        assert status in (LIVE, GROUP, EXCLUDED)

    def test_group_status_is_used_for_groups_and_only_groups(self):
        """A GROUP entry must really be a pure dispatch node, and vice versa —
        otherwise a real command hides behind a status that means
        'nothing to run here'.

        A group with ``invoke_without_command=True`` (``eventlogs``) does real
        work when called bare, so it counts as a command, not a group.
        """
        def is_pure_group(cmd: click.Command | None) -> bool:
            return (
                isinstance(cmd, click.Group)
                and not getattr(cmd, "invoke_without_command", False)
            )

        wrong_group = sorted(
            name for name, (st, _) in CLI_COVERAGE.items()
            if st == GROUP and not is_pure_group(CLI_TREE.get(name))
        )
        assert wrong_group == [], (
            "marked GROUP but is an invocable command: " + ", ".join(wrong_group)
        )

        ungrouped = sorted(
            name for name, cmd in CLI_TREE.items()
            if is_pure_group(cmd) and CLI_COVERAGE[name][0] != GROUP
        )
        assert ungrouped == [], (
            "click groups not marked GROUP: " + ", ".join(ungrouped)
        )

    def test_every_exclusion_states_a_reason(self):
        silent = sorted(
            name for name, (st, note) in CLI_COVERAGE.items()
            if st == EXCLUDED and not note.strip()
        )
        assert silent == [], (
            "excluded without a reason: " + ", ".join(silent)
        )


class TestMcpManifestCompleteness:
    def test_every_mcp_tool_is_in_the_manifest(self):
        missing = sorted(MCP_TOOLS - set(MCP_COVERAGE))
        assert missing == [], (
            "MCP tools with no e2e coverage decision: "
            + ", ".join(missing)
            + " — add them to MCP_COVERAGE in tests/e2e_manifest.py"
        )

    def test_manifest_has_no_tools_that_no_longer_exist(self):
        stale = sorted(set(MCP_COVERAGE) - MCP_TOOLS)
        assert stale == [], (
            "MCP_COVERAGE lists tools that are gone: " + ", ".join(stale)
        )

    @pytest.mark.parametrize("name", sorted(MCP_COVERAGE))
    def test_status_is_valid(self, name):
        status, _ = MCP_COVERAGE[name]
        # GROUP is a click concept; MCP tools are all invocable.
        assert status in (LIVE, EXCLUDED)

    def test_every_exclusion_states_a_reason(self):
        silent = sorted(
            name for name, (st, note) in MCP_COVERAGE.items()
            if st == EXCLUDED and not note.strip()
        )
        assert silent == [], "excluded without a reason: " + ", ".join(silent)


class TestCoverageIsMostlyLive:
    """A guard against the manifest degrading into a list of excuses."""

    def test_most_cli_commands_are_exercised_live(self):
        invocable = {
            n for n, (st, _) in CLI_COVERAGE.items() if st != GROUP
        }
        live = {n for n in invocable if CLI_COVERAGE[n][0] == LIVE}
        assert len(live) / len(invocable) >= 0.70, (
            f"only {len(live)}/{len(invocable)} CLI commands are covered live"
        )

    def test_most_mcp_tools_are_exercised_live(self):
        live = {n for n, (st, _) in MCP_COVERAGE.items() if st == LIVE}
        assert len(live) / len(MCP_COVERAGE) >= 0.85, (
            f"only {len(live)}/{len(MCP_COVERAGE)} MCP tools are covered live"
        )


class TestEveryCommandHasHelp:
    """`--help` must work for every node — it is the only discovery surface,
    and a broken import or a bad decorator shows up here first."""

    @pytest.mark.parametrize("path", sorted(CLI_TREE))
    def test_help_renders(self, path):
        from click.testing import CliRunner

        result = CliRunner().invoke(cli_root, path.split() + ["--help"])
        assert result.exit_code == 0, result.output
        assert "Usage:" in result.output


class TestExclusionsAreStillTested:
    """Excluding something from the live suite is only acceptable if it is
    tested another way. Without this, "EXCLUDED" would be a place for
    coverage to quietly disappear."""

    def _repo_root(self):
        import pathlib

        return pathlib.Path(__file__).resolve().parents[1]

    def test_every_cli_exclusion_names_a_unit_test(self):
        from tests.e2e_manifest import CLI_EXCLUSION_UNIT_TESTS

        excluded = {n for n, (st, _) in CLI_COVERAGE.items() if st == EXCLUDED}
        missing = sorted(excluded - set(CLI_EXCLUSION_UNIT_TESTS))
        assert missing == [], (
            "excluded from the live suite with no unit test named: "
            + ", ".join(missing)
        )

    def test_every_mcp_exclusion_names_a_unit_test(self):
        from tests.e2e_manifest import MCP_EXCLUSION_UNIT_TESTS

        excluded = {n for n, (st, _) in MCP_COVERAGE.items() if st == EXCLUDED}
        missing = sorted(excluded - set(MCP_EXCLUSION_UNIT_TESTS))
        assert missing == [], (
            "excluded from the live suite with no unit test named: "
            + ", ".join(missing)
        )

    def test_named_unit_tests_exist(self):
        from tests.e2e_manifest import (
            CLI_EXCLUSION_UNIT_TESTS,
            MCP_EXCLUSION_UNIT_TESTS,
        )

        root = self._repo_root()
        named = set(CLI_EXCLUSION_UNIT_TESTS.values()) | set(
            MCP_EXCLUSION_UNIT_TESTS.values()
        )
        absent = sorted(p for p in named if not (root / p).is_file())
        assert absent == [], "named unit test files do not exist: " + ", ".join(absent)

    def test_named_unit_tests_are_not_empty(self):
        from tests.e2e_manifest import (
            CLI_EXCLUSION_UNIT_TESTS,
            MCP_EXCLUSION_UNIT_TESTS,
        )

        root = self._repo_root()
        named = set(CLI_EXCLUSION_UNIT_TESTS.values()) | set(
            MCP_EXCLUSION_UNIT_TESTS.values()
        )
        for rel in sorted(named):
            body = (root / rel).read_text()
            assert "def test_" in body, f"{rel} contains no tests"

    def test_no_stale_entries(self):
        from tests.e2e_manifest import (
            CLI_EXCLUSION_UNIT_TESTS,
            MCP_EXCLUSION_UNIT_TESTS,
        )

        cli_excluded = {n for n, (st, _) in CLI_COVERAGE.items() if st == EXCLUDED}
        mcp_excluded = {n for n, (st, _) in MCP_COVERAGE.items() if st == EXCLUDED}
        assert sorted(set(CLI_EXCLUSION_UNIT_TESTS) - cli_excluded) == []
        assert sorted(set(MCP_EXCLUSION_UNIT_TESTS) - mcp_excluded) == []


def test_coverage_summary(capsys):
    """Prints the coverage split. Not an assertion — a readable receipt for
    anyone asking "what is actually covered?"."""
    cli_live = sum(1 for st, _ in CLI_COVERAGE.values() if st == LIVE)
    cli_group = sum(1 for st, _ in CLI_COVERAGE.values() if st == GROUP)
    cli_excl = sum(1 for st, _ in CLI_COVERAGE.values() if st == EXCLUDED)
    mcp_live = sum(1 for st, _ in MCP_COVERAGE.values() if st == LIVE)
    mcp_excl = sum(1 for st, _ in MCP_COVERAGE.values() if st == EXCLUDED)
    with capsys.disabled():
        print(
            f"\n  CLI: {cli_live} live, {cli_excl} excluded (unit-tested), "
            f"{cli_group} dispatch groups — {len(CLI_COVERAGE)} total"
            f"\n  MCP: {mcp_live} live, {mcp_excl} excluded (unit-tested)"
            f" — {len(MCP_COVERAGE)} total"
        )


class TestLiveClaimsAreReal:
    """A LIVE entry that nothing actually invokes is worse than an honest
    exclusion — it reads as covered while testing nothing. Checked textually
    against the live suite, which is enough to catch a stale claim."""

    def _live_suite(self) -> str:
        import pathlib

        return (
            pathlib.Path(__file__).resolve().parent / "test_e2e_live.py"
        ).read_text()

    def test_every_live_mcp_tool_is_invoked(self):
        body = self._live_suite()
        uninvoked = sorted(
            name for name, (st, _) in MCP_COVERAGE.items()
            if st == LIVE and f'"{name}"' not in body
        )
        assert uninvoked == [], (
            "marked LIVE but never invoked in test_e2e_live.py: "
            + ", ".join(uninvoked)
        )

    def test_every_live_cli_command_is_invoked(self):
        body = self._live_suite()
        uninvoked = []
        for name, (st, _) in CLI_COVERAGE.items():
            if st != LIVE:
                continue
            call = "run(" + ", ".join(f'"{part}"' for part in name.split())
            if call not in body:
                uninvoked.append(name)
        assert sorted(uninvoked) == [], (
            "marked LIVE but never invoked as run(...) in test_e2e_live.py: "
            + ", ".join(sorted(uninvoked))
        )
