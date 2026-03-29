"""
tests/test_deploy.py — Unit tests for lib/deploy.py.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import sys
import unittest
from pathlib import Path

# Make lib/ importable when running from the automatic-test directory or repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.deploy import TargetConfig, _ssh_args, _scp_args


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


if __name__ == "__main__":
    unittest.main()
