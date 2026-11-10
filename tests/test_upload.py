"""Tests for winbox upload command."""

from winbox.cli import cli
from winbox.cli.upload import _ps_quote
from winbox.vm.guest import ExecResult


def _make_src(cfg, name="payload.exe", size=2048):
    src = cfg.winbox_dir / name
    src.write_bytes(b"MZ" + b"\x00" * (size - 2))
    return src


class TestUploadStageOnly:
    def test_src_only_stages_to_shared_dir(self, runner, mock_env, cfg):
        """Bare upload drops the file at Z:\\<basename> on the share."""
        src = _make_src(cfg)

        result = runner.invoke(cli, ["upload", str(src)])
        assert result.exit_code == 0
        assert "Uploaded" in result.output
        assert "payload.exe" in result.output

        staged = cfg.shared_dir / "payload.exe"
        assert staged.exists()
        assert staged.stat().st_size == 2048
        # No VM-side copy needed when dst is omitted.
        mock_env.exec_powershell.assert_not_called()

    def test_src_only_reports_size(self, runner, mock_env, cfg):
        src = _make_src(cfg, size=4096)
        result = runner.invoke(cli, ["upload", str(src)])
        assert result.exit_code == 0
        assert "4096 bytes" in result.output


class TestUploadWithDst:
    def test_success(self, runner, mock_env, cfg):
        """With dst, the file is staged on Z:\\ then copied inside the VM."""
        src = _make_src(cfg)
        mock_env.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["upload", str(src), "C:\\Users\\Public\\payload.exe"])
        assert result.exit_code == 0
        assert "payload.exe -> C:\\Users\\Public\\payload.exe" in result.output

        # Staged copy still there on the share (matches MCP upload behavior).
        assert (cfg.shared_dir / "payload.exe").exists()

        # PowerShell script was invoked with the right paths.
        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Z:\\payload.exe" in script
        assert "C:\\Users\\Public\\payload.exe" in script
        assert "Copy-Item" in script
        # Parent-dir creation is part of the script.
        assert "New-Item -ItemType Directory" in script

    def test_vm_copy_failure_exits_nonzero(self, runner, mock_env, cfg):
        src = _make_src(cfg)
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access to the path is denied."
        )

        result = runner.invoke(cli, ["upload", str(src), "C:\\Windows\\System32\\x.dll"])
        assert result.exit_code != 0
        assert "Staged at Z:\\payload.exe" in result.output
        assert "failed" in result.output
        # Staged copy still there for inspection/retry.
        assert (cfg.shared_dir / "payload.exe").exists()


class TestUploadValidation:
    def test_missing_source_is_rejected_by_click(self, runner, mock_env):
        """Click's exists=True blocks the call before the command runs."""
        result = runner.invoke(cli, ["upload", "/tmp/does-not-exist-winbox-test"])
        assert result.exit_code != 0
        mock_env.exec_powershell.assert_not_called()

    def test_directory_without_recursive_flag_is_rejected(self, runner, mock_env, cfg):
        """Directories require -r flag."""
        subdir = cfg.winbox_dir / "some-dir"
        subdir.mkdir()
        result = runner.invoke(cli, ["upload", str(subdir)])
        assert result.exit_code != 0
        assert "recursive" in result.output.lower() or "recursive" in str(result.exception).lower()
        mock_env.exec_powershell.assert_not_called()

    def test_recursive_flag_on_file_is_rejected(self, runner, mock_env, cfg):
        """-r on a file is an error."""
        src = _make_src(cfg)
        result = runner.invoke(cli, ["upload", "-r", str(src)])
        assert result.exit_code != 0
        mock_env.exec_powershell.assert_not_called()


class TestUploadRecursive:
    def _make_tree(self, cfg):
        """Create a small directory tree for testing."""
        tree = cfg.winbox_dir / "mydir"
        tree.mkdir()
        (tree / "a.txt").write_text("hello")
        sub = tree / "sub"
        sub.mkdir()
        (sub / "b.exe").write_bytes(b"MZ" + b"\x00" * 100)
        return tree

    def test_recursive_stage_only(self, runner, mock_env, cfg):
        """Recursive upload without dst stages the tree on the share."""
        tree = self._make_tree(cfg)
        result = runner.invoke(cli, ["upload", "-r", str(tree)])
        assert result.exit_code == 0
        assert "mydir/" in result.output

        staged = cfg.shared_dir / "mydir"
        assert staged.is_dir()
        assert (staged / "a.txt").exists()
        assert (staged / "sub" / "b.exe").exists()
        mock_env.exec_powershell.assert_not_called()

    def test_recursive_with_dst(self, runner, mock_env, cfg):
        """Recursive upload with dst copies the tree inside the VM."""
        tree = self._make_tree(cfg)
        mock_env.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = runner.invoke(cli, ["upload", "-r", str(tree), "C:\\templates"])
        assert result.exit_code == 0
        assert "mydir/" in result.output
        assert "C:\\templates" in result.output

        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Copy-Item" in script
        assert "-Recurse" in script
        assert "Z:\\mydir" in script

    def test_recursive_vm_copy_failure(self, runner, mock_env, cfg):
        tree = self._make_tree(cfg)
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )
        result = runner.invoke(cli, ["upload", "-r", str(tree), "C:\\nope"])
        assert result.exit_code != 0
        assert "failed" in result.output


class TestPowerShellQuoting:
    def test_ps_quote_escapes_single_quotes(self):
        """_ps_quote doubles single quotes for PowerShell single-quoted literals."""
        assert _ps_quote("foo") == "foo"
        assert _ps_quote("O'Brien") == "O''Brien"
        assert _ps_quote("a'b'c") == "a''b''c"

    def test_dst_with_single_quote_is_safely_quoted(self, runner, mock_env, cfg):
        """A destination with a literal ' doesn't break the PowerShell script."""
        src = _make_src(cfg)
        mock_env.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        runner.invoke(cli, ["upload", str(src), "C:\\temp\\it's-fine\\x.exe"])
        script = mock_env.exec_powershell.call_args[0][0]
        # Doubled single-quote is how PowerShell escapes inside '...' literals.
        assert "it''s-fine" in script
