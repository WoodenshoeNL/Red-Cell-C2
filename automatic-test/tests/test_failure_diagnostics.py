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
    _listener_request_summary,
    build_failure_diagnostic_report,
    capture_server_logs,
    create_run_dir,
    tail_text_file,
    write_scenario_failure_file,
)


def _cli() -> CliConfig:
    return CliConfig(server="https://127.0.0.1:1", token="t")


def _patch_snapshot(
    agents=None,
    listeners=None,
    log_entries=None,
    listener_detail=None,
    log_side_effect=None,
):
    """Return a combined context manager that patches all CLI calls used by diagnostics.

    *log_side_effect* — if set, replaces the ``log_list`` mock's ``side_effect``
    so callers can vary the return value per invocation.
    """
    import contextlib

    def _log_list_default(*_a, **_kw):
        return log_entries if log_entries is not None else []

    @contextlib.contextmanager
    def _ctx():
        with patch(
            "lib.failure_diagnostics.agent_list",
            return_value=agents or [],
        ), patch(
            "lib.failure_diagnostics.listener_list",
            return_value=listeners or [],
        ), patch(
            "lib.failure_diagnostics.log_list",
            side_effect=log_side_effect or _log_list_default,
        ), patch(
            "lib.failure_diagnostics.listener_show",
            return_value=listener_detail or {},
        ):
            yield

    return _ctx()


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
            cli=_cli(),
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
        ctx = SimpleNamespace(cli=_cli(), env={})
        out = capture_server_logs(ctx)
        self.assertIn("log_file", out)


class TestListenerRequestSummary(unittest.TestCase):
    def test_zero_registrations_and_no_listeners(self) -> None:
        with patch(
            "lib.failure_diagnostics.log_list", return_value=[],
        ), patch(
            "lib.failure_diagnostics.listener_show", return_value={},
        ):
            text = _listener_request_summary(_cli(), [])
        self.assertIn("Agent registrations (total): 0", text)

    def test_reports_registration_count_and_latest(self) -> None:
        registrations = [
            {"ts": "2026-04-24T12:00:00Z", "action": "agent.registered", "agent_id": "DEADBEEF"},
            {"ts": "2026-04-24T11:50:00Z", "action": "agent.registered", "agent_id": "CAFEBABE"},
        ]

        def log_side_effect(*_a, action=None, **_kw):
            if action == "agent.registered":
                return registrations
            return []

        with patch(
            "lib.failure_diagnostics.log_list", side_effect=log_side_effect,
        ), patch(
            "lib.failure_diagnostics.listener_show", return_value={},
        ):
            text = _listener_request_summary(_cli(), [{"name": "http1", "status": "Running"}])
        self.assertIn("Agent registrations (total): 2", text)
        self.assertIn("DEADBEEF", text)
        self.assertIn("2026-04-24T12:00:00Z", text)

    def test_reports_listener_last_error(self) -> None:
        with patch(
            "lib.failure_diagnostics.log_list", return_value=[],
        ), patch(
            "lib.failure_diagnostics.listener_show",
            return_value={"last_error": "bind: address already in use"},
        ):
            text = _listener_request_summary(
                _cli(), [{"name": "http1", "status": "Error"}],
            )
        self.assertIn("address already in use", text)

    def test_reports_no_last_error(self) -> None:
        with patch(
            "lib.failure_diagnostics.log_list", return_value=[],
        ), patch(
            "lib.failure_diagnostics.listener_show",
            return_value={"last_error": None},
        ):
            text = _listener_request_summary(
                _cli(), [{"name": "http1", "status": "Running"}],
            )
        self.assertIn("last_error: (none)", text)

    def test_listener_show_failure_is_graceful(self) -> None:
        with patch(
            "lib.failure_diagnostics.log_list", return_value=[],
        ), patch(
            "lib.failure_diagnostics.listener_show",
            side_effect=CliError("NOT_FOUND", "no such listener", 1),
        ):
            text = _listener_request_summary(
                _cli(), [{"name": "gone", "status": "?"}],
            )
        self.assertIn("query failed", text)

    def test_reregistrations_included_when_present(self) -> None:
        def log_side_effect(*_a, action=None, **_kw):
            if action == "agent.reregistered":
                return [{"ts": "t1"}, {"ts": "t2"}, {"ts": "t3"}]
            return []

        with patch(
            "lib.failure_diagnostics.log_list", side_effect=log_side_effect,
        ), patch(
            "lib.failure_diagnostics.listener_show", return_value={},
        ):
            text = _listener_request_summary(_cli(), [])
        self.assertIn("Agent re-registrations (total): 3", text)

    def test_audit_query_failure_is_graceful(self) -> None:
        with patch(
            "lib.failure_diagnostics.log_list",
            side_effect=CliError("TIMEOUT", "timed out", 1),
        ), patch(
            "lib.failure_diagnostics.listener_show", return_value={},
        ):
            text = _listener_request_summary(_cli(), [])
        self.assertIn("query failed", text)


class TestBuildFailureDiagnosticReport(unittest.TestCase):
    def test_includes_sections_and_exception(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})

        with _patch_snapshot(
            agents=[{"id": "a1"}],
            listeners=[{"name": "L1"}],
            log_entries=[{"ts": "t", "action": "x"}],
        ):
            text = build_failure_diagnostic_report(
                ctx, "99", "Test scenario", ValueError("boom"),
            )

        self.assertIn("=== EXCEPTION ===", text)
        self.assertIn("ValueError: boom", text)
        self.assertIn("=== TEAMSERVER LOG TAIL ===", text)
        self.assertIn("=== ACTIVE AGENTS ===", text)
        self.assertIn('"id": "a1"', text)
        self.assertIn("=== ACTIVE LISTENERS ===", text)
        self.assertIn("=== LISTENER REQUEST DIAGNOSTICS ===", text)
        self.assertIn("=== RECENT AUDIT LOG (last 20) ===", text)

    def test_cli_errors_in_snapshot(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})
        err = CliError("AUTH_FAILED", "nope", 3)
        with patch(
            "lib.failure_diagnostics.agent_list", side_effect=err,
        ), patch(
            "lib.failure_diagnostics.listener_list", return_value=[],
        ), patch(
            "lib.failure_diagnostics.log_list", return_value=[],
        ), patch(
            "lib.failure_diagnostics.listener_show", return_value={},
        ):
            text = build_failure_diagnostic_report(
                ctx, "01", "t", RuntimeError("x"),
            )
        self.assertIn("agent list failed", text)
        self.assertIn("AUTH_FAILED", text)

    def test_request_diagnostics_in_report(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})

        def log_side_effect(*_a, action=None, **_kw):
            if action == "agent.registered":
                return [{"ts": "2026-04-24T12:00:00Z", "agent_id": "BEEF0001"}]
            return []

        with _patch_snapshot(
            listeners=[{"name": "http1", "status": "Running"}],
            listener_detail={"last_error": None},
            log_side_effect=log_side_effect,
        ):
            text = build_failure_diagnostic_report(
                ctx, "05", "Demon checkin", RuntimeError("timeout"),
            )

        self.assertIn("=== LISTENER REQUEST DIAGNOSTICS ===", text)
        self.assertIn("Agent registrations (total): 1", text)
        self.assertIn("Listener 'http1' (status=Running):", text)


class TestCreateRunDir(unittest.TestCase):
    def test_creates_run_dir_with_expected_structure(self) -> None:
        import tempfile

        root = Path(tempfile.mkdtemp())
        run_dir = create_run_dir(root)
        self.assertTrue(run_dir.is_dir())
        self.assertIn("test-results", run_dir.parts)
        self.assertRegex(run_dir.name, r"^run_\d{6}_[0-9a-f]{8}$")

    def test_latest_symlink_points_to_run_dir(self) -> None:
        import tempfile

        root = Path(tempfile.mkdtemp())
        run_dir = create_run_dir(root)
        latest = root / "test-results" / "latest"
        self.assertTrue(latest.is_symlink())
        self.assertEqual(latest.resolve(), run_dir.resolve())

    def test_second_run_updates_latest(self) -> None:
        import tempfile
        import time

        root = Path(tempfile.mkdtemp())
        run1 = create_run_dir(root)
        time.sleep(0.01)
        run2 = create_run_dir(root)
        self.assertNotEqual(run1, run2)
        latest = root / "test-results" / "latest"
        self.assertEqual(latest.resolve(), run2.resolve())


class TestWriteScenarioFailureFile(unittest.TestCase):
    def test_creates_file_in_run_dir(self) -> None:
        import tempfile

        run_dir = Path(tempfile.mkdtemp()) / "test-results" / "2026-04-25" / "run_120000_abcd1234"
        text = "hello\n"
        p = write_scenario_failure_file(run_dir, "04", text)
        self.assertTrue(p.is_file())
        self.assertEqual(p.read_text(encoding="utf-8"), text)
        self.assertRegex(p.name, r"scenario_04_failure\.txt")
        self.assertEqual(p.parent, run_dir)


if __name__ == "__main__":
    unittest.main()
