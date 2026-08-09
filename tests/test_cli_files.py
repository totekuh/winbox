"""Tests for the `winbox tools` and `winbox iso` CLI groups.

``iso status`` in particular is profile-driven: it must look for the ISO the
*active* profile needs. Reporting the Server ISO as present during a Win11
build sends the user to `winbox iso download`, which would then fetch — or
claim to already have — the wrong image.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config


def _unwrapped(output: str) -> str:
    """Rich hard-wraps long paths; join the lines before matching on them."""
    return output.replace("\n", "")


@pytest.fixture
def files_env(tmp_path, monkeypatch):
    """A real Config on a tmp dir, injected into the CLI context."""
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    cfg.iso_dir.mkdir(parents=True)
    cfg.tools_dir.mkdir(parents=True)
    cfg.loot_dir.mkdir(parents=True)
    monkeypatch.setattr(Config, "load", classmethod(lambda cls: cfg))
    return cfg


class TestIsoStatus:
    def test_reports_a_present_iso_with_its_size(self, files_env):
        iso = files_env.iso_dir / files_env.profile.iso_filename
        iso.write_bytes(b"\x00" * 2048)

        result = CliRunner().invoke(cli, ["iso", "status"])

        assert result.exit_code == 0
        assert "ISO found" in result.output
        assert files_env.profile.iso_filename in _unwrapped(result.output)

    def test_reports_a_missing_iso_with_the_next_step(self, files_env):
        result = CliRunner().invoke(cli, ["iso", "status"])

        assert result.exit_code == 0
        assert "not downloaded" in result.output
        assert "winbox iso download" in result.output

    @pytest.mark.parametrize("os_key", ["server2022", "win11"])
    def test_looks_for_the_active_profiles_iso(self, files_env, os_key):
        files_env.vm_os = os_key
        (files_env.iso_dir / files_env.profile.iso_filename).write_bytes(b"x")

        result = CliRunner().invoke(cli, ["iso", "status"])

        assert "ISO found" in result.output
        assert files_env.profile.iso_filename in _unwrapped(result.output)

    def test_the_other_profiles_iso_does_not_count(self, files_env):
        """A cached Server ISO must not make a Win11 build look ready."""
        from winbox.osprofile import OS_PROFILES

        files_env.vm_os = "win11"
        (files_env.iso_dir / OS_PROFILES["server2022"].iso_filename).write_bytes(b"x")

        result = CliRunner().invoke(cli, ["iso", "status"])

        assert "not downloaded" in result.output


class TestIsoDownload:
    def test_passes_force_through(self, files_env):
        with patch("winbox.cli.files.download_iso") as dl:
            CliRunner().invoke(cli, ["iso", "download", "--force"])
        assert dl.call_args.kwargs["force"] is True

    def test_defaults_to_not_forcing(self, files_env):
        with patch("winbox.cli.files.download_iso") as dl:
            CliRunner().invoke(cli, ["iso", "download"])
        assert dl.call_args.kwargs["force"] is False


class TestToolsCommands:
    def test_add_copies_files_into_the_shared_dir(self, files_env, tmp_path):
        payload = tmp_path / "payload.exe"
        payload.write_bytes(b"MZ")

        result = CliRunner().invoke(cli, ["tools", "add", str(payload)])

        assert result.exit_code == 0
        assert (files_env.tools_dir / "payload.exe").read_bytes() == b"MZ"

    def test_add_rejects_a_missing_file(self, files_env):
        result = CliRunner().invoke(cli, ["tools", "add", "/nope/missing.exe"])
        assert result.exit_code != 0

    def test_add_requires_at_least_one_file(self, files_env):
        assert CliRunner().invoke(cli, ["tools", "add"]).exit_code != 0

    def test_add_accepts_several_files(self, files_env, tmp_path):
        for name in ("a.txt", "b.txt"):
            (tmp_path / name).write_text(name)

        CliRunner().invoke(
            cli, ["tools", "add", str(tmp_path / "a.txt"), str(tmp_path / "b.txt")]
        )

        assert (files_env.tools_dir / "a.txt").exists()
        assert (files_env.tools_dir / "b.txt").exists()

    def test_list_shows_an_added_tool(self, files_env):
        (files_env.tools_dir / "shown.exe").write_bytes(b"MZ")

        result = CliRunner().invoke(cli, ["tools", "list"])

        assert result.exit_code == 0
        assert "shown.exe" in result.output

    def test_remove_deletes_the_tool(self, files_env):
        target = files_env.tools_dir / "gone.exe"
        target.write_bytes(b"MZ")

        result = CliRunner().invoke(cli, ["tools", "remove", "gone.exe"])

        assert result.exit_code == 0
        assert not target.exists()

    def test_remove_requires_a_name(self, files_env):
        assert CliRunner().invoke(cli, ["tools", "remove"]).exit_code != 0
