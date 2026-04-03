"""
Unit tests for lib.cli._run — stderr structured-error parsing.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError, _run


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


if __name__ == "__main__":
    unittest.main()
