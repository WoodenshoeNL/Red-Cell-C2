"""
tests/test_deploy.py — Unit tests for lib/deploy.py.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Make lib/ importable when running from the automatic-test directory or repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.deploy import DeployError, TargetConfig, _quote_posix, _quote_powershell, _scp_args, _ssh_args, preflight_ssh


def _make_target(**kwargs) -> TargetConfig:
    defaults = dict(
        host="192.168.1.10",
        port=22,
        user="testuser",
        work_dir="/tmp/rc-test",
        key="~/.ssh/id_ed25519",
    )
    defaults.update(kwargs)
    return TargetConfig(**defaults)


class TestTargetConfigValidation(unittest.TestCase):
    def test_valid_config(self) -> None:
        t = _make_target()
        self.assertEqual(t.host, "192.168.1.10")
        self.assertEqual(t.key, "~/.ssh/id_ed25519")

    def test_empty_key_raises(self) -> None:
        """key="" must raise ValueError with a clear message."""
        with self.assertRaises(ValueError) as ctx:
            _make_target(key="")
        self.assertIn("'key' is required", str(ctx.exception))

    def test_none_key_raises(self) -> None:
        """Passing None for key must raise ValueError or TypeError."""
        with self.assertRaises((ValueError, TypeError)):
            TargetConfig(
                host="192.168.1.10",
                port=22,
                user="testuser",
                work_dir="/tmp/rc-test",
                key=None,  # type: ignore[arg-type]
            )

    def test_windows_target_with_key(self) -> None:
        t = _make_target(
            host="10.0.0.5",
            user="Administrator",
            work_dir="C:\\Temp\\rc-test",
        )
        self.assertEqual(t.work_dir, "C:\\Temp\\rc-test")


class TestSshArgs(unittest.TestCase):
    def setUp(self) -> None:
        self.target = _make_target(key="/home/user/.ssh/test_key")

    def test_first_arg_is_ssh(self) -> None:
        self.assertEqual(_ssh_args(self.target)[0], "ssh")

    def test_port_flag(self) -> None:
        args = _ssh_args(self.target)
        idx = args.index("-p")
        self.assertEqual(args[idx + 1], "22")

    def test_key_flag(self) -> None:
        args = _ssh_args(self.target)
        idx = args.index("-i")
        self.assertEqual(args[idx + 1], "/home/user/.ssh/test_key")

    def test_destination_last(self) -> None:
        args = _ssh_args(self.target)
        self.assertEqual(args[-1], f"{self.target.user}@{self.target.host}")

    def test_batchmode_yes(self) -> None:
        """BatchMode=yes must always be present to prevent interactive prompts."""
        args = _ssh_args(self.target)
        self.assertIn("BatchMode=yes", args)

    def test_no_password_in_args(self) -> None:
        """ssh args must never contain a plaintext password."""
        joined = " ".join(_ssh_args(self.target))
        self.assertNotIn("Password", joined)
        self.assertNotIn("sshpass", joined)

    def test_custom_port(self) -> None:
        t = _make_target(port=2222)
        args = _ssh_args(t)
        idx = args.index("-p")
        self.assertEqual(args[idx + 1], "2222")


class TestScpArgs(unittest.TestCase):
    def setUp(self) -> None:
        self.target = _make_target(key="/home/user/.ssh/test_key")

    def test_first_arg_is_scp(self) -> None:
        self.assertEqual(_scp_args(self.target)[0], "scp")

    def test_port_flag(self) -> None:
        # scp uses uppercase -P
        args = _scp_args(self.target)
        idx = args.index("-P")
        self.assertEqual(args[idx + 1], "22")

    def test_key_flag(self) -> None:
        args = _scp_args(self.target)
        idx = args.index("-i")
        self.assertEqual(args[idx + 1], "/home/user/.ssh/test_key")

    def test_batchmode_yes(self) -> None:
        args = _scp_args(self.target)
        self.assertIn("BatchMode=yes", args)

    def test_no_trailing_destination(self) -> None:
        """scp args must NOT include user@host — callers append src/dest."""
        args = _scp_args(self.target)
        joined = " ".join(args)
        self.assertNotIn(f"{self.target.user}@{self.target.host}", joined)


class TestQuotePosix(unittest.TestCase):
    """Tests for _quote_posix — POSIX sh quoting used in background execution."""

    def test_simple_path_unchanged(self) -> None:
        result = _quote_posix("/tmp/agent.bin")
        # shlex.quote wraps safe paths in single quotes or leaves them as-is
        self.assertIn("/tmp/agent.bin", result)

    def test_path_with_spaces_is_quoted(self) -> None:
        result = _quote_posix("/home/user/my dir/agent.bin")
        # The result must be a single token that the shell treats as one argument
        self.assertTrue(
            result.startswith("'") or result.startswith('"'),
            f"Expected quoted path, got: {result!r}",
        )
        self.assertIn("my dir", result)

    def test_path_with_special_chars(self) -> None:
        """Paths with $, &, ;, | etc. must be quoted so the shell does not interpret them."""
        path = "/tmp/evil$path&agent.bin"
        result = _quote_posix(path)
        # After unquoting, the original path must be recoverable
        import shlex
        self.assertEqual(shlex.split(result)[0], path)

    def test_plain_path_reconstructs(self) -> None:
        import shlex
        path = "/opt/rc-test/agent-abc123.bin"
        self.assertEqual(shlex.split(_quote_posix(path))[0], path)

    def test_path_with_spaces_reconstructs(self) -> None:
        import shlex
        path = "/home/test user/work dir/agent.bin"
        self.assertEqual(shlex.split(_quote_posix(path))[0], path)


class TestQuotePowerShell(unittest.TestCase):
    """Tests for _quote_powershell — PowerShell single-quote escaping."""

    def test_simple_path_is_single_quoted(self) -> None:
        result = _quote_powershell("C:\\Temp\\agent.exe")
        self.assertEqual(result, "'C:\\Temp\\agent.exe'")

    def test_path_with_spaces(self) -> None:
        result = _quote_powershell("C:\\Program Files\\agent.exe")
        self.assertEqual(result, "'C:\\Program Files\\agent.exe'")

    def test_embedded_single_quote_is_doubled(self) -> None:
        """A single quote inside the path must be escaped as '' for PowerShell."""
        result = _quote_powershell("C:\\it's here\\agent.exe")
        self.assertEqual(result, "'C:\\it''s here\\agent.exe'")

    def test_multiple_embedded_single_quotes(self) -> None:
        result = _quote_powershell("C:\\a'b'c\\agent.exe")
        self.assertEqual(result, "'C:\\a''b''c\\agent.exe'")

    def test_plain_path_roundtrip_token(self) -> None:
        """Quoted path must begin and end with a single quote."""
        path = "C:\\Temp\\rc-test\\agent-abc123.exe"
        result = _quote_powershell(path)
        self.assertTrue(result.startswith("'") and result.endswith("'"))

    def test_empty_path(self) -> None:
        self.assertEqual(_quote_powershell(""), "''")


class TestPreflightSsh(unittest.TestCase):
    """Tests for preflight_ssh connectivity check."""

    def setUp(self) -> None:
        self.target = _make_target(host="10.0.0.1", key="/home/user/.ssh/test_key")

    def _make_completed(self, returncode: int, stderr: str = "") -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout="", stderr=stderr
        )

    def test_success_does_not_raise(self) -> None:
        """preflight_ssh must not raise when ssh returns exit code 0."""
        with patch("subprocess.run", return_value=self._make_completed(0)):
            preflight_ssh(self.target)  # must not raise

    def test_failure_raises_deploy_error(self) -> None:
        """preflight_ssh must raise DeployError when ssh returns a non-zero exit code."""
        with patch("subprocess.run", return_value=self._make_completed(255, "Connection refused")):
            with self.assertRaises(DeployError) as ctx:
                preflight_ssh(self.target)
            self.assertIn("10.0.0.1", str(ctx.exception))
            self.assertIn("not reachable via SSH", str(ctx.exception))
            self.assertIn("targets.toml", str(ctx.exception))

    def test_error_message_contains_host(self) -> None:
        """DeployError message must identify the unreachable host."""
        target = _make_target(host="192.168.99.5", key="/tmp/key")
        with patch("subprocess.run", return_value=self._make_completed(1)):
            with self.assertRaises(DeployError) as ctx:
                preflight_ssh(target)
            self.assertIn("192.168.99.5", str(ctx.exception))

    def test_uses_connect_timeout_5(self) -> None:
        """preflight_ssh must use ConnectTimeout=5, not the longer default."""
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]  # first positional arg is the command list
        self.assertIn("ConnectTimeout=5", call_args)

    def test_uses_batch_mode(self) -> None:
        """preflight_ssh must always use BatchMode=yes."""
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]
        self.assertIn("BatchMode=yes", call_args)

    def test_runs_true_command(self) -> None:
        """preflight_ssh must run 'true' on the remote host — no side-effects."""
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args[-1], "true")

    def test_custom_port(self) -> None:
        """preflight_ssh must pass the target's SSH port."""
        target = _make_target(port=2222, key="/tmp/key")
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(target)
        call_args = mock_run.call_args[0][0]
        idx = call_args.index("-p")
        self.assertEqual(call_args[idx + 1], "2222")

    def test_timeout_error_bubbles_up(self) -> None:
        """A subprocess.TimeoutExpired must propagate (not be swallowed)."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                preflight_ssh(self.target)


if __name__ == "__main__":
    unittest.main()
