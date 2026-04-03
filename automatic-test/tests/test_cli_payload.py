"""
Unit tests for payload_build / payload_build_and_fetch job polling and agent checks.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError, payload_build, payload_build_and_fetch


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

    def test_wait_true_polls_job_and_validates_agent(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "job-2"}) as mock_run, \
             patch(
                 "lib.cli._poll_payload_job",
                 return_value={"id": "payload-2", "size_bytes": 77, "agent_type": "Phantom"},
             ) as mock_poll:
            result = payload_build(_CFG, listener="listener-1", fmt="bin", agent="phantom", wait=True)
        self.assertEqual(result["id"], "payload-2")
        mock_run.assert_called_once()
        mock_poll.assert_called_once_with(_CFG, "job-2", "phantom")

    def test_wait_true_requires_job_id(self) -> None:
        with patch("lib.cli._run", return_value={"ok": True}):
            with self.assertRaises(CliError) as ctx:
                payload_build(_CFG, listener="listener-1", wait=True)
        self.assertEqual(ctx.exception.code, "JOB_ID_MISSING")


class TestPayloadBuildAndFetch(unittest.TestCase):
    def test_downloads_payload_to_mkstemp_path_and_returns_bytes(self) -> None:
        with patch(
            "lib.cli.payload_build",
            return_value={"id": "payload-9", "size_bytes": 4, "agent_type": "Demon"},
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
        )
        mock_mkstemp.assert_called_once_with(suffix=".exe")
        mock_close.assert_called_once_with(17)
        mock_download.assert_called_once_with(_CFG, "payload-9", "/tmp/payload.exe")
        mock_file.assert_called_once_with("/tmp/payload.exe", "rb")
        mock_unlink.assert_called_once_with("/tmp/payload.exe")


class TestPollPayloadJob(unittest.TestCase):
    def test_done_status_with_matching_agent_type_returns_payload(self) -> None:
        status = {
            "job_id": "job-7",
            "status": "done",
            "agent_type": "Phantom",
            "payload_id": "payload-7",
            "size_bytes": 9001,
        }
        with patch("lib.cli._api_get", return_value=status) as mock_get:
            result = payload_build(_CFG, listener="listener-1", agent="phantom", wait=True)
        self.assertEqual(result["id"], "payload-7")
        self.assertEqual(result["agent_type"], "Phantom")
        mock_get.assert_called_once_with(_CFG, "/payloads/jobs/job-7")

    def test_mismatched_agent_type_raises(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "job-8"}), \
             patch(
                 "lib.cli._api_get",
                 return_value={
                     "job_id": "job-8",
                     "status": "done",
                     "agent_type": "Demon",
                     "payload_id": "payload-8",
                     "size_bytes": 1,
                 },
             ):
            with self.assertRaises(CliError) as ctx:
                payload_build(_CFG, listener="listener-1", agent="phantom", wait=True)
        self.assertEqual(ctx.exception.code, "UNEXPECTED_AGENT_TYPE")
        self.assertIn("expected 'Phantom'", ctx.exception.message)

    def test_error_status_raises_build_failed(self) -> None:
        with patch("lib.cli._run", return_value={"job_id": "job-9"}), \
             patch(
                 "lib.cli._api_get",
                 return_value={
                     "job_id": "job-9",
                     "status": "error",
                     "agent_type": "Archon",
                     "error": "toolchain missing",
                 },
             ):
            with self.assertRaises(CliError) as ctx:
                payload_build(_CFG, listener="listener-1", agent="archon", wait=True)
        self.assertEqual(ctx.exception.code, "PAYLOAD_BUILD_FAILED")
        self.assertEqual(ctx.exception.message, "toolchain missing")


if __name__ == "__main__":
    unittest.main()
