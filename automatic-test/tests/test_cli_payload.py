"""
Unit tests for payload_build / payload_build_and_fetch via the CLI wrapper.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import (
    PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
    CliConfig,
    CliError,
    agent_output,
    operator_set_role,
    payload_build,
    payload_build_and_fetch,
    payload_build_wait,
)


_CFG = CliConfig(server="https://127.0.0.1:40056", token="test-token", timeout=3)


class TestPayloadBuild(unittest.TestCase):
    def test_wait_false_returns_cli_submission_response(self) -> None:
        submitted = {"job_id": "job-1"}
        with patch("lib.cli._run", return_value=submitted) as mock_run:
            result = payload_build(_CFG, listener="test-listener", agent="phantom")
        self.assertEqual(result, submitted)
        mock_run.assert_called_once_with(
            _CFG,
            "payload",
            "build",
            "--listener",
            "test-listener",
            "--arch",
            "x64",
            "--format",
            "exe",
            "--agent",
            "phantom",
        )

    def test_wait_true_passes_wait_flag_to_cli(self) -> None:
        completed = {"id": "payload-2", "size_bytes": 77}
        with patch("lib.cli._run", return_value=completed) as mock_run:
            result = payload_build(_CFG, listener="listener-1", fmt="bin", agent="phantom", wait=True)
        self.assertEqual(result["id"], "payload-2")
        self.assertEqual(result["size_bytes"], 77)
        # wait=True switches to a longer-timeout config to survive compilation.
        mock_run.assert_called_once_with(
            _CFG.with_timeout(300),
            "payload",
            "build",
            "--listener",
            "listener-1",
            "--arch",
            "x64",
            "--format",
            "bin",
            "--agent",
            "phantom",
            "--wait",
        )

    def test_wait_false_does_not_pass_wait_flag(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "job-3"}) as mock_run:
            payload_build(_CFG, listener="listener-1", agent="demon")
        args = mock_run.call_args[0]
        self.assertNotIn("--wait", args)
        self.assertNotIn("--detach", args)

    def test_detach_passes_detach_flag(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "job-detach"}) as mock_run:
            r = payload_build(
                _CFG, listener="listener-1", agent="demon", detach=True
            )
        self.assertEqual(r["job_id"], "job-detach")
        args = mock_run.call_args[0]
        self.assertIn("--detach", args)
        self.assertNotIn("--wait", args)

    def test_wait_ignored_when_detach(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "j"}) as mock_run:
            payload_build(
                _CFG, listener="listener-1", wait=True, detach=True
            )
        args = mock_run.call_args[0]
        self.assertIn("--detach", args)
        self.assertNotIn("--wait", args)

    def test_sleep_secs_passed_to_cli(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "job-4"}) as mock_run:
            payload_build(_CFG, listener="listener-1", sleep_secs=60)
        args = mock_run.call_args[0]
        self.assertIn("--sleep", args)
        idx = args.index("--sleep")
        self.assertEqual(args[idx + 1], "60")


class TestPayloadBuildWait(unittest.TestCase):
    def test_invokes_build_wait(self) -> None:
        with patch("lib.cli._run", return_value={"payload_id": "p-1", "size_bytes": 3}) as mock_run:
            r = payload_build_wait(_CFG, "job-abc")
        self.assertEqual(r["payload_id"], "p-1")
        mock_run.assert_called_once_with(
            _CFG.with_timeout(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS),
            "payload",
            "build-wait",
            "job-abc",
            "--wait-timeout",
            str(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS),
        )


class TestOperatorSetRole(unittest.TestCase):
    def test_invokes_cli(self) -> None:
        with patch("lib.cli._run", return_value={"username": "a", "role": "admin"}) as mock_run:
            result = operator_set_role(_CFG, "alice", "admin")
        self.assertEqual(result["username"], "a")
        mock_run.assert_called_once_with(_CFG, "operator", "set-role", "alice", "admin")


class TestAgentOutput(unittest.TestCase):
    def test_without_since(self) -> None:
        with patch("lib.cli._run", return_value=[]) as mock_run:
            agent_output(_CFG, "dead0001")
        mock_run.assert_called_once_with(_CFG, "agent", "output", "dead0001")

    def test_with_since(self) -> None:
        with patch("lib.cli._run", return_value=[]) as mock_run:
            agent_output(_CFG, "dead0001", since=42)
        mock_run.assert_called_once_with(
            _CFG,
            "agent",
            "output",
            "dead0001",
            "--since",
            "42",
        )


class TestPayloadBuildAndFetch(unittest.TestCase):
    def test_downloads_payload_to_mkstemp_path_and_returns_bytes(self) -> None:
        with patch(
            "lib.cli.payload_build",
            return_value={"id": "payload-9", "size_bytes": 4},
        ) as mock_build, \
             patch("lib.cli.payload_download") as mock_download, \
             patch("tempfile.mkstemp", return_value=(17, "/tmp/payload.exe")) as mock_mkstemp, \
             patch("os.close") as mock_close, \
             patch("builtins.open", mock_open(read_data=b"ABCD")) as mock_file, \
             patch("os.unlink") as mock_unlink:
            result = payload_build_and_fetch(_CFG, listener="listener-1", fmt="exe", agent="demon")
        self.assertEqual(result, b"ABCD")
        mock_build.assert_called_once_with(
            _CFG,
            listener="listener-1",
            arch="x64",
            fmt="exe",
            agent="demon",
            sleep_secs=None,
            wait=True,
            detach=False,
        )
        mock_mkstemp.assert_called_once_with(suffix=".exe")
        mock_close.assert_called_once_with(17)
        mock_download.assert_called_once_with(_CFG, "payload-9", "/tmp/payload.exe")
        mock_file.assert_called_once_with("/tmp/payload.exe", "rb")
        mock_unlink.assert_called_once_with("/tmp/payload.exe")


if __name__ == "__main__":
    unittest.main()
