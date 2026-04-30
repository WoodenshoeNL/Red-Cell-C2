"""
Unit tests for lib.failure_diagnostics.
"""

from __future__ import annotations

import json
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError
from lib.failure_diagnostics import (
    _build_agent_state,
    _build_teamserver_state,
    _build_timeline,
    _collect_packet_ring_bytes,
    _fetch_log_tail_cli,
    _listener_request_summary,
    build_failure_diagnostic_report,
    capture_server_logs,
    create_run_dir,
    tail_text_file,
    write_scenario_diag_bundle,
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
    server_tail_entries=None,
):
    """Return a combined context manager that patches all CLI calls used by diagnostics.

    *log_side_effect* — if set, replaces the ``log_list`` mock's ``side_effect``
    so callers can vary the return value per invocation.
    *server_tail_entries* — entries returned by ``log_server_tail`` (defaults to empty).
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
        ), patch(
            "lib.failure_diagnostics.log_server_tail",
            return_value=server_tail_entries or [],
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
    def test_log_file_takes_precedence_over_cli(self) -> None:
        import tempfile

        d = tempfile.mkdtemp()
        lf = Path(d) / "srv.log"
        lf.write_text("line1\nline2\n", encoding="utf-8")
        ctx = SimpleNamespace(
            cli=_cli(),
            env={"teamserver": {"log_file": str(lf)}},
        )
        with patch("lib.failure_diagnostics.log_server_tail") as mock_tail:
            out = capture_server_logs(ctx, lines=10)
            mock_tail.assert_not_called()
        self.assertIn("line2", out)

    def test_falls_back_to_cli_when_no_log_file(self) -> None:
        entries = [
            {"timestamp": "12:00:01", "text": "listener started"},
            {"timestamp": "12:00:02", "text": "ready"},
        ]
        ctx = SimpleNamespace(cli=_cli(), env={})
        with patch("lib.failure_diagnostics.log_server_tail", return_value=entries):
            out = capture_server_logs(ctx, lines=100)
        self.assertIn("12:00:01", out)
        self.assertIn("listener started", out)
        self.assertIn("ready", out)

    def test_cli_error_is_reported_gracefully(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})
        with patch(
            "lib.failure_diagnostics.log_server_tail",
            side_effect=CliError("NOT_FOUND", "endpoint not found", 1),
        ):
            out = capture_server_logs(ctx)
        self.assertIn("log server-tail failed", out)
        self.assertIn("NOT_FOUND", out)

    def test_empty_entries_returns_message(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})
        with patch("lib.failure_diagnostics.log_server_tail", return_value=[]):
            out = capture_server_logs(ctx)
        self.assertIn("no log entries", out)


class TestFetchLogTailCli(unittest.TestCase):
    def test_formats_entries_as_text(self) -> None:
        entries = [
            {"timestamp": "09:30:00", "text": "hello world"},
            {"timestamp": "09:30:01", "text": "goodbye"},
        ]
        with patch("lib.failure_diagnostics.log_server_tail", return_value=entries):
            out = _fetch_log_tail_cli(_cli(), 100)
        self.assertEqual(out, "09:30:00  hello world\n09:30:01  goodbye\n")

    def test_handles_missing_fields(self) -> None:
        entries = [{"text": "no timestamp"}, {"timestamp": "10:00:00"}]
        with patch("lib.failure_diagnostics.log_server_tail", return_value=entries):
            out = _fetch_log_tail_cli(_cli(), 100)
        self.assertIn("?  no timestamp", out)
        self.assertIn("10:00:00  ", out)


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
        ), patch(
            "lib.failure_diagnostics.log_server_tail", return_value=[],
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

    def test_includes_scenario_pass_and_harness_tails_when_given(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})

        with _patch_snapshot(
            agents=[{"id": "a1"}],
            listeners=[{"name": "L1"}],
            log_entries=[],
        ):
            text = build_failure_diagnostic_report(
                ctx,
                "08",
                "Screenshot matrix",
                RuntimeError("loot wait"),
                scenario_active_pass="specter",
                scenario_stdout_tail="  [specter][wait] screenshot loot\n",
                scenario_stderr_tail="side note\n",
            )

        self.assertIn("=== SCENARIO CONTEXT ===", text)
        self.assertIn("Active agent pass: specter", text)
        self.assertIn("=== SCENARIO STDOUT TAIL (harness) ===", text)
        self.assertIn("[specter][wait] screenshot loot", text)
        self.assertIn("=== SCENARIO STDERR TAIL (harness) ===", text)
        self.assertIn("side note", text)
        self.assertIn("=== EXCEPTION ===", text)
        self.assertLess(text.index("=== SCENARIO CONTEXT ==="), text.index("=== EXCEPTION ==="))

    def test_harness_stdout_tail_respects_max_chars(self) -> None:
        ctx = SimpleNamespace(cli=_cli(), env={})
        blob = "a" * 50

        with _patch_snapshot(agents=[], listeners=[], log_entries=[]):
            text = build_failure_diagnostic_report(
                ctx,
                "01",
                "t",
                ValueError("x"),
                scenario_stdout_tail=blob,
                harness_output_max_chars=10,
            )

        pos = text.find("=== SCENARIO STDOUT TAIL (harness) ===")
        self.assertGreaterEqual(pos, 0)
        tail_section = text[pos : pos + 200]
        self.assertIn("a" * 10, tail_section)
        self.assertNotIn("a" * 11, tail_section)


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


# ── New diagnostic bundle tests ───────────────────────────────────────────────

def _make_ctx(cli: CliConfig) -> SimpleNamespace:
    """Return a minimal DiagnosticContext for bundle tests."""
    return SimpleNamespace(cli=cli, env={})


def _patch_bundle_snapshot(
    agents=None,
    listeners=None,
    log_entries=None,
    listener_detail=None,
    server_tail_entries=None,
    agent_show_return=None,
    agent_show_side_effect=None,
):
    """Combined context manager that patches every CLI call used by the bundle functions."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with patch(
            "lib.failure_diagnostics.agent_list",
            return_value=agents or [],
        ), patch(
            "lib.failure_diagnostics.agent_show",
            side_effect=agent_show_side_effect or (lambda *_a, **_kw: agent_show_return or {}),
        ), patch(
            "lib.failure_diagnostics.listener_list",
            return_value=listeners or [],
        ), patch(
            "lib.failure_diagnostics.log_list",
            return_value=log_entries if log_entries is not None else [],
        ), patch(
            "lib.failure_diagnostics.listener_show",
            return_value=listener_detail or {},
        ), patch(
            "lib.failure_diagnostics.log_server_tail",
            return_value=server_tail_entries or [],
        ):
            yield

    return _ctx()


class TestBuildAgentState(unittest.TestCase):
    def test_returns_agents_and_note(self) -> None:
        agents = [{"id": "DEADBEEF", "status": "active"}]
        with _patch_bundle_snapshot(agents=agents, log_entries=[]):
            result = _build_agent_state(_cli())
        self.assertIn("agents", result)
        self.assertEqual(len(result["agents"]), 1)
        self.assertIn("note", result)
        self.assertIn("last_seen_seq", result["note"])

    def test_agent_show_error_is_embedded(self) -> None:
        agents = [{"id": "DEADBEEF"}]
        with _patch_bundle_snapshot(
            agents=agents,
            agent_show_side_effect=lambda *_a, **_kw: (_ for _ in ()).throw(
                CliError("NOT_FOUND", "no such agent", 1)
            ),
        ):
            result = _build_agent_state(_cli())
        record = result["agents"][0]
        self.assertIn("detail_error", record)
        self.assertIn("NOT_FOUND", record["detail_error"])

    def test_agent_list_error_returns_error_key(self) -> None:
        with patch(
            "lib.failure_diagnostics.agent_list",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ):
            result = _build_agent_state(_cli())
        self.assertIn("error", result)
        self.assertEqual(result["agents"], [])

    def test_missing_id_field_embedded(self) -> None:
        agents = [{"hostname": "box1"}]  # no id field
        with _patch_bundle_snapshot(agents=agents):
            result = _build_agent_state(_cli())
        self.assertIn("error", result["agents"][0])


class TestBuildTeamserverState(unittest.TestCase):
    def test_contains_all_keys(self) -> None:
        with _patch_bundle_snapshot(
            agents=[{"id": "A1"}],
            listeners=[{"name": "L1", "status": "Running"}],
            log_entries=[{"ts": "t1", "action": "agent.registered"}],
            server_tail_entries=[{"timestamp": "09:00:00", "text": "started"}],
        ):
            result = _build_teamserver_state(_cli())
        self.assertIn("agents", result)
        self.assertIn("listeners", result)
        self.assertIn("audit_log_tail", result)
        self.assertIn("server_log_tail", result)
        self.assertIn("captured_at", result)

    def test_listener_detail_fetched(self) -> None:
        with _patch_bundle_snapshot(
            listeners=[{"name": "http1", "status": "Running"}],
            listener_detail={"last_error": "bind failed"},
        ):
            result = _build_teamserver_state(_cli())
        lsnr = result["listeners"][0]
        self.assertIn("detail", lsnr)
        self.assertEqual(lsnr["detail"]["last_error"], "bind failed")

    def test_server_log_formatted(self) -> None:
        with _patch_bundle_snapshot(
            server_tail_entries=[
                {"timestamp": "2026-04-30T10:00:00Z", "text": "hello"},
            ],
        ):
            result = _build_teamserver_state(_cli())
        self.assertIn("2026-04-30T10:00:00Z", result["server_log_tail"])
        self.assertIn("hello", result["server_log_tail"])


class TestBuildTimeline(unittest.TestCase):
    def test_audit_entries_appear(self) -> None:
        audit = [
            {"ts": "2026-04-30T10:00:00Z", "action": "agent.registered", "agent_id": "BEEF"},
        ]
        timeline = _build_timeline(audit, "", None, None)
        self.assertIn("[AUDIT]", timeline)
        self.assertIn("agent.registered", timeline)
        self.assertIn("BEEF", timeline)

    def test_server_log_appears(self) -> None:
        timeline = _build_timeline([], "2026-04-30T10:00:01Z  hello server\n", None, None)
        self.assertIn("[SERVER]", timeline)
        self.assertIn("hello server", timeline)

    def test_harness_stdout_appended(self) -> None:
        timeline = _build_timeline([], "", "harness output line", None)
        self.assertIn("HARNESS STDOUT", timeline)
        self.assertIn("harness output line", timeline)

    def test_harness_stderr_appended(self) -> None:
        timeline = _build_timeline([], "", None, "error output")
        self.assertIn("HARNESS STDERR", timeline)
        self.assertIn("error output", timeline)

    def test_chronological_sort(self) -> None:
        audit = [
            {"ts": "2026-04-30T10:00:02Z", "action": "b"},
            {"ts": "2026-04-30T10:00:01Z", "action": "a"},
        ]
        timeline = _build_timeline(audit, "", None, None)
        pos_a = timeline.find("action=a")
        pos_b = timeline.find("action=b")
        self.assertLess(pos_a, pos_b, "Earlier timestamp must appear first")

    def test_empty_inputs(self) -> None:
        timeline = _build_timeline([], "", None, None)
        self.assertIn("TIMELINE", timeline)


class TestWriteScenarioDiagBundle(unittest.TestCase):
    def _make_run_dir(self) -> Path:
        import tempfile
        return Path(tempfile.mkdtemp()) / "test-results" / "2026-04-30" / "run_100000_abcd1234"

    def test_creates_diag_dir_with_four_artifacts(self) -> None:
        run_dir = self._make_run_dir()
        ctx = _make_ctx(_cli())
        with _patch_bundle_snapshot(
            agents=[{"id": "DEADBEEF"}],
            listeners=[{"name": "L1"}],
            log_entries=[],
        ):
            diag_dir = write_scenario_diag_bundle(run_dir, "04", ctx)

        self.assertTrue(diag_dir.is_dir())
        self.assertRegex(diag_dir.name, r"^scenario_04_diag$")
        for artifact in ("agent_state.json", "teamserver_state.json", "timeline.txt", "last_packets.bin"):
            p = diag_dir / artifact
            self.assertTrue(p.exists(), f"{artifact} must exist")

    def test_agent_state_json_is_valid(self) -> None:
        run_dir = self._make_run_dir()
        ctx = _make_ctx(_cli())
        with _patch_bundle_snapshot(agents=[{"id": "CAFE0001"}]):
            diag_dir = write_scenario_diag_bundle(run_dir, "07", ctx)
        data = json.loads((diag_dir / "agent_state.json").read_text())
        self.assertIn("agents", data)

    def test_teamserver_state_json_is_valid(self) -> None:
        run_dir = self._make_run_dir()
        ctx = _make_ctx(_cli())
        with _patch_bundle_snapshot():
            diag_dir = write_scenario_diag_bundle(run_dir, "07", ctx)
        data = json.loads((diag_dir / "teamserver_state.json").read_text())
        self.assertIn("agents", data)
        self.assertIn("listeners", data)

    def test_timeline_includes_harness_streams(self) -> None:
        run_dir = self._make_run_dir()
        ctx = _make_ctx(_cli())
        with _patch_bundle_snapshot():
            diag_dir = write_scenario_diag_bundle(
                run_dir, "04", ctx,
                harness_stdout="stdout line\n",
                harness_stderr="stderr line\n",
            )
        timeline = (diag_dir / "timeline.txt").read_text()
        self.assertIn("stdout line", timeline)
        self.assertIn("stderr line", timeline)

    def test_last_packets_bin_is_empty(self) -> None:
        run_dir = self._make_run_dir()
        ctx = _make_ctx(_cli())
        with _patch_bundle_snapshot():
            diag_dir = write_scenario_diag_bundle(run_dir, "04", ctx)
        self.assertEqual((diag_dir / "last_packets.bin").read_bytes(), b"")

    def test_existing_failure_file_unchanged(self) -> None:
        """Diag bundle must not overwrite the scenario_NN_failure.txt."""
        import tempfile
        run_dir = Path(tempfile.mkdtemp()) / "run"
        run_dir.mkdir(parents=True)
        failure_file = run_dir / "scenario_04_failure.txt"
        failure_file.write_text("original failure text\n")
        ctx = _make_ctx(_cli())
        with _patch_bundle_snapshot():
            write_scenario_diag_bundle(run_dir, "04", ctx)
        self.assertEqual(failure_file.read_text(), "original failure text\n")

    def test_cli_errors_do_not_raise(self) -> None:
        """All CLI errors must be absorbed — the bundle must still be created."""
        run_dir = self._make_run_dir()
        ctx = _make_ctx(_cli())
        with patch(
            "lib.failure_diagnostics.agent_list",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ), patch(
            "lib.failure_diagnostics.listener_list",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ), patch(
            "lib.failure_diagnostics.log_list",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ), patch(
            "lib.failure_diagnostics.listener_show",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ), patch(
            "lib.failure_diagnostics.log_server_tail",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ), patch(
            "lib.failure_diagnostics.agent_show",
            side_effect=CliError("UNAUTH", "forbidden", 3),
        ):
            diag_dir = write_scenario_diag_bundle(run_dir, "05", ctx)
        for artifact in ("agent_state.json", "teamserver_state.json", "timeline.txt", "last_packets.bin"):
            self.assertTrue((diag_dir / artifact).exists())


class TestCollectPacketRingBytes(unittest.TestCase):
    """Unit tests for _collect_packet_ring_bytes."""

    def test_empty_agent_list_returns_empty_bytes(self) -> None:
        result = _collect_packet_ring_bytes(_cli(), [])
        self.assertEqual(result, b"")

    def test_cli_error_agent_silently_skipped(self) -> None:
        agents = [{"id": "DEADBEEF"}]
        with patch(
            "lib.failure_diagnostics.agent_packet_ring",
            side_effect=CliError("NOT_FOUND", "no ring", 1),
        ):
            result = _collect_packet_ring_bytes(_cli(), agents)
        self.assertEqual(result, b"")

    def test_agent_with_frames_encodes_correct_structure(self) -> None:
        agent_id = "CAFE0001"
        frame_hex = "deadbeef"
        raw_bytes = bytes.fromhex(frame_hex)
        agents = [{"id": agent_id}]
        ring = {"frames": [{"direction": "rx", "bytes_hex": frame_hex}]}

        with patch("lib.failure_diagnostics.agent_packet_ring", return_value=ring):
            result = _collect_packet_ring_bytes(_cli(), agents)

        agent_id_encoded = agent_id.encode("utf-8")
        expected = (
            struct.pack(">I", len(agent_id_encoded))
            + agent_id_encoded
            + struct.pack(">I", 1)          # frame_count
            + struct.pack(">B", 0x00)       # direction: rx
            + struct.pack(">I", len(raw_bytes))
            + raw_bytes
        )
        self.assertEqual(result, expected)

    def test_direction_bytes_encoding(self) -> None:
        agents = [{"id": "A1"}]
        frames = [
            {"direction": "rx", "bytes_hex": "aa"},
            {"direction": "tx", "bytes_hex": "bb"},
            {"direction": "???", "bytes_hex": "cc"},
        ]
        ring = {"frames": frames}

        with patch("lib.failure_diagnostics.agent_packet_ring", return_value=ring):
            result = _collect_packet_ring_bytes(_cli(), agents)

        agent_id_encoded = b"A1"
        # Skip header (4 + 2 + 4 bytes) then read direction bytes
        offset = 4 + len(agent_id_encoded) + 4  # agent_id_len + agent_id + frame_count
        directions = []
        for _ in range(3):
            direction_byte = struct.unpack_from(">B", result, offset)[0]
            directions.append(direction_byte)
            frame_len = struct.unpack_from(">I", result, offset + 1)[0]
            offset += 1 + 4 + frame_len

        self.assertEqual(directions[0], 0x00)   # rx
        self.assertEqual(directions[1], 0x01)   # tx
        self.assertEqual(directions[2], 0xFF)   # unknown

    def test_agent_with_empty_frames_list_is_skipped(self) -> None:
        agents = [{"id": "EMPTY01"}]
        ring = {"frames": []}

        with patch("lib.failure_diagnostics.agent_packet_ring", return_value=ring):
            result = _collect_packet_ring_bytes(_cli(), agents)

        self.assertEqual(result, b"")

    def test_invalid_bytes_hex_produces_zero_length_frame(self) -> None:
        agent_id = "BADHEX01"
        agents = [{"id": agent_id}]
        ring = {"frames": [{"direction": "rx", "bytes_hex": "ZZ"}]}

        with patch("lib.failure_diagnostics.agent_packet_ring", return_value=ring):
            # Must not raise even though "ZZ" is not valid hex.
            result = _collect_packet_ring_bytes(_cli(), agents)

        agent_id_encoded = agent_id.encode("utf-8")
        # Header: agent_id_len + agent_id + frame_count
        header_size = 4 + len(agent_id_encoded) + 4
        # Frame: direction (1) + frame_len (4) + raw (0)
        expected_total = header_size + 1 + 4
        self.assertEqual(len(result), expected_total)

        frame_count = struct.unpack_from(">I", result, 4 + len(agent_id_encoded))[0]
        self.assertEqual(frame_count, 1)

        frame_len = struct.unpack_from(">I", result, header_size + 1)[0]
        self.assertEqual(frame_len, 0)

    def test_mixed_agents_only_encodes_agents_with_frames(self) -> None:
        agents = [{"id": "NOFRAMES"}, {"id": "HASFRAMES"}]
        no_frames_ring = {"frames": []}
        has_frames_ring = {"frames": [{"direction": "tx", "bytes_hex": "ff"}]}

        def _ring(_cli_arg, agent_id: str):
            if agent_id == "NOFRAMES":
                return no_frames_ring
            return has_frames_ring

        with patch("lib.failure_diagnostics.agent_packet_ring", side_effect=_ring):
            result = _collect_packet_ring_bytes(_cli(), agents)

        # Only HASFRAMES should appear — check the agent_id encoded in the blob
        agent_id_len = struct.unpack_from(">I", result, 0)[0]
        agent_id_in_blob = result[4 : 4 + agent_id_len].decode("utf-8")
        self.assertEqual(agent_id_in_blob, "HASFRAMES")
        # Verify no second agent follows
        frame_count = struct.unpack_from(">I", result, 4 + agent_id_len)[0]
        frame_len = struct.unpack_from(">I", result, 4 + agent_id_len + 4 + 1)[0]
        expected_total = 4 + agent_id_len + 4 + 1 + 4 + frame_len
        self.assertEqual(len(result), expected_total)


if __name__ == "__main__":
    unittest.main()
