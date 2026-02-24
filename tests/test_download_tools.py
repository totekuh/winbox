"""Tests for download_tools — checksum verification, caching, re-download."""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbox.config import Config
from winbox.setup.installer import _sha256, download_tools


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    c.tools_dir.mkdir(parents=True)
    c.loot_dir.mkdir(parents=True)
    return c


def _make_tools_txt(tmp_path, lines):
    """Write a fake tools.txt and patch _data_file to return it."""
    txt = tmp_path / "tools.txt"
    txt.write_text("\n".join(lines) + "\n")
    return txt


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestSha256:
    def test_computes_correct_hash(self, tmp_path):
        f = tmp_path / "test.bin"
        content = b"hello world"
        f.write_bytes(content)
        assert _sha256(f) == hashlib.sha256(content).hexdigest()

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert _sha256(f) == hashlib.sha256(b"").hexdigest()

    def test_large_file(self, tmp_path):
        f = tmp_path / "large.bin"
        # Larger than the 64K chunk size
        content = b"\xab" * 200_000
        f.write_bytes(content)
        assert _sha256(f) == hashlib.sha256(content).hexdigest()


class TestDownloadToolsParsing:
    """Test tools.txt parsing (comments, blanks, format)."""

    def test_skips_comments_and_blanks(self, cfg, tmp_path):
        content = b"tooldata"
        h = _hash(content)
        txt = _make_tools_txt(tmp_path, [
            "# comment",
            "",
            "  # indented comment",
            f"https://example.com/Tool.exe {h}",
        ])
        # Pre-place the file so no download is needed
        (cfg.tools_dir / "Tool.exe").write_bytes(content)

        with patch("winbox.setup.installer._data_file", return_value=txt):
            download_tools(cfg)

        # Should not crash, file should still be there
        assert (cfg.tools_dir / "Tool.exe").exists()

    def test_empty_tools_txt(self, cfg, tmp_path):
        txt = _make_tools_txt(tmp_path, ["# nothing here", ""])
        with patch("winbox.setup.installer._data_file", return_value=txt):
            download_tools(cfg)  # should not crash

    def test_ignores_lines_without_hash(self, cfg, tmp_path):
        txt = _make_tools_txt(tmp_path, [
            "https://example.com/NoHash.exe",
        ])
        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run") as mock_run,
        ):
            download_tools(cfg)
            mock_run.assert_not_called()


class TestDownloadToolsCaching:
    """Test that cached files with correct checksums are skipped."""

    def test_skips_cached_file_with_matching_hash(self, cfg, tmp_path):
        content = b"MZ\x90\x00cached_tool"
        h = _hash(content)
        txt = _make_tools_txt(tmp_path, [f"https://example.com/Cached.exe {h}"])
        (cfg.tools_dir / "Cached.exe").write_bytes(content)

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run") as mock_run,
        ):
            download_tools(cfg)
            mock_run.assert_not_called()

    def test_multiple_cached_tools_all_skipped(self, cfg, tmp_path):
        data_a = b"tool_a_data"
        data_b = b"tool_b_data"
        txt = _make_tools_txt(tmp_path, [
            f"https://example.com/A.exe {_hash(data_a)}",
            f"https://example.com/B.exe {_hash(data_b)}",
        ])
        (cfg.tools_dir / "A.exe").write_bytes(data_a)
        (cfg.tools_dir / "B.exe").write_bytes(data_b)

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run") as mock_run,
        ):
            download_tools(cfg)
            mock_run.assert_not_called()


class TestDownloadToolsRedownload:
    """Test re-download on checksum mismatch."""

    def test_redownloads_on_checksum_mismatch(self, cfg, tmp_path):
        correct_data = b"correct_binary"
        correct_hash = _hash(correct_data)
        txt = _make_tools_txt(tmp_path, [f"https://example.com/Tool.exe {correct_hash}"])
        # Place a file with wrong content
        (cfg.tools_dir / "Tool.exe").write_bytes(b"corrupted")

        def fake_wget(cmd, *, check=True):
            # Simulate wget writing the correct file
            (cfg.tools_dir / "Tool.exe").write_bytes(correct_data)

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run", side_effect=fake_wget),
        ):
            download_tools(cfg)

        assert (cfg.tools_dir / "Tool.exe").read_bytes() == correct_data

    def test_deletes_file_if_download_has_wrong_hash(self, cfg, tmp_path):
        expected_hash = _hash(b"expected_content")
        txt = _make_tools_txt(tmp_path, [f"https://example.com/Bad.exe {expected_hash}"])

        def fake_wget(cmd, *, check=True):
            # wget writes a file but with wrong content
            (cfg.tools_dir / "Bad.exe").write_bytes(b"still_wrong")

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run", side_effect=fake_wget),
        ):
            download_tools(cfg)

        # File should be deleted after post-download hash mismatch
        assert not (cfg.tools_dir / "Bad.exe").exists()


class TestDownloadToolsFreshDownload:
    """Test downloading tools that don't exist yet."""

    def test_downloads_missing_file(self, cfg, tmp_path):
        content = b"fresh_tool_binary"
        h = _hash(content)
        txt = _make_tools_txt(tmp_path, [f"https://example.com/Fresh.exe {h}"])

        def fake_wget(cmd, *, check=True):
            (cfg.tools_dir / "Fresh.exe").write_bytes(content)

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run", side_effect=fake_wget),
        ):
            download_tools(cfg)

        assert (cfg.tools_dir / "Fresh.exe").exists()
        assert (cfg.tools_dir / "Fresh.exe").read_bytes() == content

    def test_wget_failure_does_not_crash(self, cfg, tmp_path):
        import subprocess as sp
        txt = _make_tools_txt(tmp_path, [
            f"https://example.com/Fail.exe {'a' * 64}",
        ])

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run", side_effect=sp.CalledProcessError(1, "wget")),
        ):
            download_tools(cfg)  # should not raise

    def test_zip_extracted_and_removed(self, cfg, tmp_path):
        import zipfile

        # Build a real zip in memory
        zip_path = tmp_path / "archive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("inner.exe", b"inner_binary")
        zip_data = zip_path.read_bytes()
        h = _hash(zip_data)

        txt = _make_tools_txt(tmp_path, [f"https://example.com/archive.zip {h}"])

        def fake_wget(cmd, *, check=True):
            (cfg.tools_dir / "archive.zip").write_bytes(zip_data)

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run", side_effect=fake_wget),
        ):
            download_tools(cfg)

        # Zip should be extracted and then deleted
        assert not (cfg.tools_dir / "archive.zip").exists()
        assert (cfg.tools_dir / "inner.exe").exists()
        assert (cfg.tools_dir / "inner.exe").read_bytes() == b"inner_binary"


class TestDownloadToolsMixed:
    """Test mixed scenarios: some cached, some need download."""

    def test_only_downloads_missing_and_mismatched(self, cfg, tmp_path):
        cached_data = b"cached_ok"
        mismatch_correct = b"correct_version"
        fresh_data = b"new_tool"

        txt = _make_tools_txt(tmp_path, [
            f"https://example.com/Cached.exe {_hash(cached_data)}",
            f"https://example.com/Mismatch.exe {_hash(mismatch_correct)}",
            f"https://example.com/Fresh.exe {_hash(fresh_data)}",
        ])

        (cfg.tools_dir / "Cached.exe").write_bytes(cached_data)
        (cfg.tools_dir / "Mismatch.exe").write_bytes(b"old_version")

        wget_calls = []

        def fake_wget(cmd, *, check=True):
            url = cmd[-1]
            wget_calls.append(url)
            filename = url.rsplit("/", 1)[-1]
            if filename == "Mismatch.exe":
                (cfg.tools_dir / filename).write_bytes(mismatch_correct)
            elif filename == "Fresh.exe":
                (cfg.tools_dir / filename).write_bytes(fresh_data)

        with (
            patch("winbox.setup.installer._data_file", return_value=txt),
            patch("subprocess.run", side_effect=fake_wget),
        ):
            download_tools(cfg)

        # wget should have been called for mismatch and fresh, not cached
        assert len(wget_calls) == 2
        assert any("Mismatch.exe" in u for u in wget_calls)
        assert any("Fresh.exe" in u for u in wget_calls)
        assert not any("Cached.exe" in u for u in wget_calls)

        # All three should be present with correct data
        assert (cfg.tools_dir / "Cached.exe").read_bytes() == cached_data
        assert (cfg.tools_dir / "Mismatch.exe").read_bytes() == mismatch_correct
        assert (cfg.tools_dir / "Fresh.exe").read_bytes() == fresh_data
