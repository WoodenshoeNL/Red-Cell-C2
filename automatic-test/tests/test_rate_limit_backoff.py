"""
Unit tests for inter-scenario rate-limit backoff in test.py.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError

# Import the helpers under test from test.py.  The module is not a package,
# so we load it by file path.
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "test_harness", str(Path(__file__).parent.parent / "test.py")
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["test_harness"] = _mod
_spec.loader.exec_module(_mod)

_parse_retry_after = _mod._parse_retry_after
_wait_out_rate_limit = _mod._wait_out_rate_limit
_RATE_LIMIT_EXIT_CODE = _mod._RATE_LIMIT_EXIT_CODE
_RATE_LIMIT_DEFAULT_WAIT_SECS = _mod._RATE_LIMIT_DEFAULT_WAIT_SECS
_RATE_LIMIT_MAX_WAITS = _mod._RATE_LIMIT_MAX_WAITS


_CFG = CliConfig(server="https://127.0.0.1:40056", token="tok")


class TestParseRetryAfter(unittest.TestCase):

    def test_parses_some_value(self) -> None:
        exc = CliError("RATE_LIMITED", "rate limited by server (retry after Some(30)s)", 6)
        self.assertEqual(_parse_retry_after(exc), 30)

    def test_parses_large_value(self) -> None:
        exc = CliError("RATE_LIMITED", "rate limited by server (retry after Some(120)s)", 6)
        self.assertEqual(_parse_retry_after(exc), 120)

    def test_none_falls_back_to_default(self) -> None:
        exc = CliError("RATE_LIMITED", "rate limited by server (retry after None)", 6)
        self.assertEqual(_parse_retry_after(exc), _RATE_LIMIT_DEFAULT_WAIT_SECS)

    def test_missing_pattern_falls_back_to_default(self) -> None:
        exc = CliError("RATE_LIMITED", "some other message", 6)
        self.assertEqual(_parse_retry_after(exc), _RATE_LIMIT_DEFAULT_WAIT_SECS)


class TestWaitOutRateLimit(unittest.TestCase):

    @patch("time.sleep")
    def test_no_sleep_when_not_rate_limited(self, mock_sleep: MagicMock) -> None:
        with patch.object(_mod, "cli_status", return_value={"ok": True}):
            _wait_out_rate_limit(_CFG)
        mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_sleeps_and_retries_on_rate_limit(self, mock_sleep: MagicMock) -> None:
        rate_err = CliError("RATE_LIMITED", "rate limited by server (retry after Some(10)s)", 6)
        call_count = 0

        def status_side_effect(cfg):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise rate_err
            return {"ok": True}

        with patch.object(_mod, "cli_status", side_effect=status_side_effect):
            _wait_out_rate_limit(_CFG)
        mock_sleep.assert_called_once_with(10)

    @patch("time.sleep")
    def test_exhausts_max_waits(self, mock_sleep: MagicMock) -> None:
        rate_err = CliError("RATE_LIMITED", "rate limited by server (retry after Some(5)s)", 6)

        with patch.object(_mod, "cli_status", side_effect=rate_err):
            _wait_out_rate_limit(_CFG)
        self.assertEqual(mock_sleep.call_count, _RATE_LIMIT_MAX_WAITS)

    @patch("time.sleep")
    def test_non_rate_limit_error_passes_through(self, mock_sleep: MagicMock) -> None:
        other_err = CliError("AUTH_FAILED", "bad token", 3)

        with patch.object(_mod, "cli_status", side_effect=other_err):
            _wait_out_rate_limit(_CFG)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
