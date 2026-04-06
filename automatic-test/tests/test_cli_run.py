"""
Unit tests for lib.cli._run — stderr structured-error parsing and subprocess timeout.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError, _run, agent_exec


def _make_result(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


_CFG = CliConfig(server="https://127.0.0.1:40056", token="tok")


class TestRunStderrStructuredError(unittest.TestCase):
    """_run must parse stderr JSON error envelope on non-zero exit."""

    def _patch_run(self, result: SimpleNamespace):
        return patch("subprocess.run", return_value=result)

    def test_stderr_json_error_code_surfaced(self) -> None:
        envelope = {"ok": False, "error": "AUTH_FAILED", "message": "invalid API key"}
        result = _make_result(stderr=json.dumps(envelope), returncode=3)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "AUTH_FAILED")
        self.assertEqual(exc.message, "invalid API key")
        self.assertEqual(exc.exit_code, 3)

    def test_stderr_json_not_found_error(self) -> None:
        envelope = {"ok": False, "error": "NOT_FOUND", "message": "listener not found"}
        result = _make_result(stderr=json.dumps(envelope), returncode=1)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "listener", "show", "missing")
        exc = ctx.exception
        self.assertEqual(exc.code, "NOT_FOUND")
        self.assertEqual(exc.message, "listener not found")

    def test_stderr_json_timeout_error(self) -> None:
        envelope = {"ok": False, "error": "TIMEOUT", "message": "server did not respond"}
        result = _make_result(stderr=json.dumps(envelope), returncode=2)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "TIMEOUT")

    def test_stderr_plain_text_fallback(self) -> None:
        """Non-JSON stderr still surfaces as the message with UNKNOWN code."""
        result = _make_result(stderr="connection refused", returncode=1)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "UNKNOWN")
        self.assertEqual(exc.message, "connection refused")

    def test_stdout_error_takes_precedence_over_stderr(self) -> None:
        """Structured stdout error takes precedence over a stderr envelope."""
        stdout_payload = json.dumps({"ok": False, "error": "STDOUT_ERR", "message": "stdout msg"})
        stderr_payload = json.dumps({"ok": False, "error": "STDERR_ERR", "message": "stderr msg"})
        result = _make_result(stdout=stdout_payload, stderr=stderr_payload, returncode=1)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "STDOUT_ERR")
        self.assertEqual(exc.message, "stdout msg")

    def test_empty_stderr_falls_back_to_no_message(self) -> None:
        result = _make_result(returncode=1)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "UNKNOWN")
        self.assertEqual(exc.message, "no message")

    def test_stderr_json_without_message_key_uses_raw(self) -> None:
        """If stderr JSON lacks 'message', fall back to raw stderr string."""
        envelope = json.dumps({"ok": False, "error": "SERVER_ERROR"})
        result = _make_result(stderr=envelope, returncode=5)
        with self._patch_run(result):
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "SERVER_ERROR")
        # no message key in JSON → falls back to raw stderr text
        self.assertEqual(exc.message, envelope)

    def test_success_path_unaffected(self) -> None:
        result = _make_result(
            stdout=json.dumps({"ok": True, "data": {"status": "running"}}),
            returncode=0,
        )
        with self._patch_run(result):
            data = _run(_CFG, "status")
        self.assertEqual(data, {"status": "running"})


class TestRunSubprocessTimeout(unittest.TestCase):
    """_run must raise CliError(SUBPROCESS_TIMEOUT) when the subprocess hangs."""

    def _patch_run_timeout(self):
        return patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="red-cell-cli", timeout=40))

    def test_timeout_raises_cli_error(self) -> None:
        with self._patch_run_timeout():
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        exc = ctx.exception
        self.assertEqual(exc.code, "SUBPROCESS_TIMEOUT")
        self.assertIn("did not exit within", exc.message)

    def test_timeout_message_includes_timeout_value(self) -> None:
        cfg = CliConfig(server="https://127.0.0.1:40056", token="tok", timeout=30)
        # subprocess_timeout = min(30 + 10, 120) = 40
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="red-cell-cli", timeout=40)):
            with self.assertRaises(CliError) as ctx:
                _run(cfg, "status")
        self.assertIn("40s", ctx.exception.message)

    def test_subprocess_timeout_derived_from_cfg_timeout_plus_buffer(self) -> None:
        """subprocess.run must be called with timeout = min(cfg.timeout + 10, max_subprocess_secs)."""
        cfg = CliConfig(server="https://127.0.0.1:40056", token="tok", timeout=25, max_subprocess_secs=120)
        result = _make_result(
            stdout=json.dumps({"ok": True, "data": {}}),
            returncode=0,
        )
        with patch("subprocess.run", return_value=result) as mock_run:
            _run(cfg, "status")
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 35)  # 25 + 10

    def test_subprocess_timeout_capped_by_max_subprocess_secs(self) -> None:
        """subprocess_timeout must not exceed max_subprocess_secs."""
        cfg = CliConfig(server="https://127.0.0.1:40056", token="tok", timeout=200, max_subprocess_secs=60)
        result = _make_result(
            stdout=json.dumps({"ok": True, "data": {}}),
            returncode=0,
        )
        with patch("subprocess.run", return_value=result) as mock_run:
            _run(cfg, "status")
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 60)  # capped at max_subprocess_secs

    def test_timeout_exit_code_is_minus_one(self) -> None:
        with self._patch_run_timeout():
            with self.assertRaises(CliError) as ctx:
                _run(_CFG, "status")
        self.assertEqual(ctx.exception.exit_code, -1)


class TestAgentExecArgv(unittest.TestCase):
    """agent_exec must pass --wait-timeout (polling budget), not --timeout."""

    def test_wait_timeout_flag_and_value(self) -> None:
        cfg = CliConfig(server="https://127.0.0.1:40056", token="tok")
        result = _make_result(
            stdout=json.dumps({"ok": True, "data": {"output": "ok"}}),
            returncode=0,
        )
        with patch("subprocess.run", return_value=result) as mock_run:
            agent_exec(cfg, "agent-id-1", "echo hi", wait=True, timeout=42)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(
            cmd[-8:],
            [
                "agent",
                "exec",
                "agent-id-1",
                "--cmd",
                "echo hi",
                "--wait",
                "--wait-timeout",
                "42",
            ],
        )

    def test_omits_wait_timeout_when_timeout_none(self) -> None:
        cfg = CliConfig(server="https://127.0.0.1:40056", token="tok")
        result = _make_result(
            stdout=json.dumps({"ok": True, "data": {}}),
            returncode=0,
        )
        with patch("subprocess.run", return_value=result) as mock_run:
            agent_exec(cfg, "x", "id", wait=True, timeout=None)
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("--wait-timeout", cmd)


if __name__ == "__main__":
    unittest.main()
