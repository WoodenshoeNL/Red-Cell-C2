"""
Unit tests for lib.deploy.named_pipe_exists and lib.wait.wait_for_named_pipe.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.deploy import TargetConfig, named_pipe_exists
from lib.wait import ScenarioFailed, wait_for_named_pipe

_fd, _SAMPLE_KEY_PATH = tempfile.mkstemp(prefix="named-pipe-test-key-")
os.close(_fd)


def _sample_target() -> TargetConfig:
    return TargetConfig(
        host="win.example",
        port=22,
        user="tester",
        work_dir="C:\\work",
        key=_SAMPLE_KEY_PATH,
    )


class TestNamedPipeExists(unittest.TestCase):
    def test_true_when_powershell_prints_true(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "True\r\n"
        with patch("lib.deploy.subprocess.run", return_value=mock_result) as run:
            assert named_pipe_exists(_sample_target(), "my-pipe") is True
        run.assert_called_once()
        args, kwargs = run.call_args
        remote = args[0][-1]
        self.assertIn("Test-Path -LiteralPath", remote)
        self.assertIn("\\\\.\\pipe\\my-pipe", remote)

    def test_false_on_nonzero_exit(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with patch("lib.deploy.subprocess.run", return_value=mock_result):
            assert named_pipe_exists(_sample_target(), "x") is False

    def test_false_when_stdout_not_true(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "False"
        with patch("lib.deploy.subprocess.run", return_value=mock_result):
            assert named_pipe_exists(_sample_target(), "x") is False


class TestWaitForNamedPipe(unittest.TestCase):
    def test_raises_scenario_failed_when_pipe_never_appears(self) -> None:
        target = _sample_target()
        with patch("lib.wait.named_pipe_exists", return_value=False):
            with self.assertRaises(ScenarioFailed) as ctx:
                wait_for_named_pipe(target, "missing-pipe", timeout=0.4, interval=0.1)
        msg = str(ctx.exception)
        self.assertIn("missing-pipe", msg)
        self.assertIn(target.host, msg)
        self.assertIn("did not appear", msg)

    def test_returns_when_pipe_appears(self) -> None:
        target = _sample_target()
        calls = {"n": 0}

        def _side_effect(*_a, **_k):
            calls["n"] += 1
            return calls["n"] >= 2

        with patch("lib.wait.named_pipe_exists", side_effect=_side_effect):
            wait_for_named_pipe(target, "ok-pipe", timeout=2.0, interval=0.05)


if __name__ == "__main__":
    unittest.main()
