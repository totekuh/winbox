"""Tests for winbox destroy — VM deletion and job ledger cleanup."""

from winbox.cli import cli


class TestDestroyClearsJobsFile:
    """destroy must wipe jobs.json so stale RUNNING entries don't leak
    across VM recreations. (Found by background review agent.)"""

    def test_destroys_and_unlinks_jobs_file(self, runner, mock_env, cfg):
        cfg.jobs_file.write_text('[{"id": 1, "status": "running"}]')
        assert cfg.jobs_file.exists()

        result = runner.invoke(cli, ["destroy", "-y"])
        assert result.exit_code == 0
        assert not cfg.jobs_file.exists()
        mock_env._vm.destroy.assert_called_once()

    def test_destroy_with_no_jobs_file_is_fine(self, runner, mock_env, cfg):
        """Missing jobs.json must not cause a crash."""
        assert not cfg.jobs_file.exists()

        result = runner.invoke(cli, ["destroy", "-y"])
        assert result.exit_code == 0
        mock_env._vm.destroy.assert_called_once()

    def test_destroy_aborted_keeps_jobs_file(self, runner, mock_env, cfg):
        """If the user aborts at the confirmation prompt, jobs.json stays."""
        cfg.jobs_file.write_text('[{"id": 1}]')

        result = runner.invoke(cli, ["destroy"], input="n\n")
        assert result.exit_code == 0
        assert cfg.jobs_file.exists()
        mock_env._vm.destroy.assert_not_called()

    def test_destroy_nonexistent_vm_preserves_jobs_file(self, runner, mock_env, cfg):
        """No VM → nothing to destroy, jobs file untouched."""
        mock_env._vm.exists.return_value = False
        cfg.jobs_file.write_text('[{"id": 1}]')

        result = runner.invoke(cli, ["destroy", "-y"])
        assert result.exit_code == 0
        assert cfg.jobs_file.exists()  # only wiped when destroy actually ran
        mock_env._vm.destroy.assert_not_called()
