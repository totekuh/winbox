"""Test that `winbox setup` holds an exclusive lock so two concurrent
runs can't race on disk.qcow2. (Found by background review agent.)"""

import fcntl

from winbox.cli import cli


class TestSetupLock:
    def test_second_setup_bails_when_lock_held(self, runner, mock_env, cfg):
        """If another winbox setup is already holding the lock, the
        second one exits immediately with a clean error."""
        # Simulate another setup: grab LOCK_EX on the lock path first.
        lock_path = cfg.winbox_dir / ".setup.lock"
        with open(lock_path, "w") as first:
            fcntl.flock(first, fcntl.LOCK_EX)
            result = runner.invoke(cli, ["setup", "-y"])

        assert result.exit_code == 1
        assert "Another" in result.output and "setup" in result.output.lower()
        # Click wraps output on narrow terminals and can insert newlines inside
        # the lock-file path (e.g. split between '.' and 'setup.lock'). Strip
        # all whitespace to match the path regardless of wrap.
        unwrapped = "".join(result.output.split())
        assert ".setup.lock" in unwrapped
        # Must not have progressed into the actual setup pipeline.
        mock_env._vm.destroy.assert_not_called()

    def test_lock_file_is_created_in_winbox_dir(self, runner, mock_env, cfg):
        """Sanity: the lock path sits under cfg.winbox_dir."""
        lock_path = cfg.winbox_dir / ".setup.lock"
        # Pre-hold the lock so setup bails quickly without running the pipeline.
        with open(lock_path, "w") as first:
            fcntl.flock(first, fcntl.LOCK_EX)
            runner.invoke(cli, ["setup", "-y"])
        assert lock_path.exists()
