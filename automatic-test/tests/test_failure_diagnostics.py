"""
Unit tests for lib.failure_diagnostics.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError
from lib.failure_diagnostics import (
    build_failure_diagnostic_report,
    capture_server_logs,
    tail_text_file,
    write_scenario_failure_file,
)


class TestTailTextFile(unittest.TestCase):
    def test_empty_file(self) -> None:
        p = Path(self._tmp()) / "e.txt"
        p.write_text("", encoding="utf-8")
        self.assertEqual(tail_text_file(p, 5), "")

    def test_respects_max_lines(self) -> None:
        p = Path(self._tmp()) / "lines.txt"
        p.write_text("a\nb\nc\nd\n", encoding="utf-8")
        out = tail_text_file(p, 2)
        self.assertEqual(out, "c\nd\n")

    def test_missing_file_message(self) -> None:
        p = Path("/nonexistent/path/that/does/not/exist.txt")
        out = tail_text_file(p, 3)
        self.assertIn("could not read log file", out)

    def _tmp(self) -> str:
        import tempfile

        return tempfile.mkdtemp()


class TestCaptureServerLogs(unittest.TestCase):
    def test_log_file_takes_precedence_over_url(self) -> None:
        import tempfile

        d = tempfile.mkdtemp()
        lf = Path(d) / "srv.log"
        lf.write_text("line1\nline2\n", encoding="utf-8")
        ctx = SimpleNamespace(
            cli=CliConfig(server="https://127.0.0.1:1", token="t"),
            env={
                "teamserver": {
                    "log_file": str(lf),
                    "log_tail_url": "https://example.invalid/should-not-fetch",
                }
            },
        )
        out = capture_server_logs(ctx, lines=10)
        self.assertIn("line2", out)
        self.assertNotIn("should-not-fetch", out)

    def test_guidance_when_unconfigured(self) -> None:
        ctx = SimpleNamespace(
            cli=CliConfig(server="https://127.0.0.1:1", token="t"),
            env={},
        )
        out = capture_server_logs(ctx)
        self.assertIn("log_file", out)


class TestBuildFailureDiagnosticReport(unittest.TestCase):
    def test_includes_sections_and_exception(self) -> None:
        ctx = SimpleNamespace(
            cli=CliConfig(server="https://127.0.0.1:1", token="t"),
            env={},
        )
        snap = ([{"id": "a1"}], [{"name": "L1"}], [{"ts": "t", "action": "x"}])

        with patch(
            "lib.failure_diagnostics.agent_list",
            return_value=snap[0],
        ), patch(
            "lib.failure_diagnostics.listener_list",
            return_value=snap[1],
        ), patch(
            "lib.failure_diagnostics.log_list",
            return_value=snap[2],
        ):
            text = build_failure_diagnostic_report(
                ctx,
                "99",
                "Test scenario",
                ValueError("boom"),
            )

        self.assertIn("=== EXCEPTION ===", text)
        self.assertIn("ValueError: boom", text)
        self.assertIn("=== TEAMSERVER LOG TAIL ===", text)
        self.assertIn("=== ACTIVE AGENTS ===", text)
        self.assertIn('"id": "a1"', text)
        self.assertIn("=== ACTIVE LISTENERS ===", text)
        self.assertIn("=== RECENT AUDIT LOG (last 20) ===", text)

    def test_cli_errors_in_snapshot(self) -> None:
        ctx = SimpleNamespace(
            cli=CliConfig(server="https://127.0.0.1:1", token="t"),
            env={},
        )
        err = CliError("AUTH_FAILED", "nope", 3)
        with patch(
            "lib.failure_diagnostics.agent_list",
            side_effect=err,
        ), patch(
            "lib.failure_diagnostics.listener_list",
            return_value=[],
        ), patch(
            "lib.failure_diagnostics.log_list",
            return_value=[],
        ):
            text = build_failure_diagnostic_report(
                ctx,
                "01",
                "t",
                RuntimeError("x"),
            )
        self.assertIn("agent list failed", text)
        self.assertIn("AUTH_FAILED", text)


class TestWriteScenarioFailureFile(unittest.TestCase):
    def test_creates_nested_path(self) -> None:
        import tempfile

        root = Path(tempfile.mkdtemp())
        text = "hello\n"
        p = write_scenario_failure_file(root, "04", text)
        self.assertTrue(p.is_file())
        self.assertEqual(p.read_text(encoding="utf-8"), text)
        self.assertIn("test-results", p.parts)
        self.assertRegex(p.name, r"scenario_04_failure\.txt")


if __name__ == "__main__":
    unittest.main()
