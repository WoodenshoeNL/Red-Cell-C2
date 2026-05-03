"""
Unit tests for lib.archon_triage.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig


class TestFormatArchonCheckinTimeoutDiagnostics(unittest.TestCase):
    def test_includes_harness_utc_and_probes(self) -> None:
        from lib.archon_triage import format_archon_checkin_timeout_diagnostics

        ctx = MagicMock()
        ctx.env = {"server": {"callback_host": "10.0.0.5"}}
        ctx.cli = CliConfig(
            server="https://10.0.0.5:40056",
            token="t",
            timeout=30,
            max_subprocess_secs=60,
        )
        target = MagicMock()
        exc = TimeoutError("Timed out after 60s waiting for agent checkin")

        with patch("lib.deploy.run_remote", return_value="2026-04-26T12:00:00+00:00") as m:
            text = format_archon_checkin_timeout_diagnostics(ctx, target, 19082, exc)

        self.assertIn("Archon check-in timeout", text)
        self.assertIn("Harness UTC now", text)
        self.assertIn("10.0.0.5", text)
        self.assertIn("19082", text)
        self.assertIn("Windows target UTC", text)
        self.assertIn("Test-NetConnection", text)
        self.assertIn("live processes from target.work_dir", text)
        self.assertIn("APPCRASH", text)
        self.assertIn("MpPreference ExclusionIpAddress", text)
        # UTC (1) + TNC (1) + netstat (1) + Defender AV (1) + NP events (1)
        # + process probe (1) + APPCRASH (1) + MpPreference (1).
        self.assertGreaterEqual(m.call_count, 8)

    def test_skips_tnc_when_no_host(self) -> None:
        from lib.archon_triage import format_archon_checkin_timeout_diagnostics

        ctx = MagicMock()
        ctx.env = {}
        ctx.cli = None
        target = MagicMock()
        exc = TimeoutError("boom")

        with patch("lib.deploy.run_remote", return_value="ok") as m:
            text = format_archon_checkin_timeout_diagnostics(ctx, target, 1, exc)

        self.assertIn("Could not determine", text)
        # TNC is skipped when no probe host, but UTC + netstat + Defender are still called.
        self.assertNotIn("Test-NetConnection", text)
        self.assertIn("live processes from target.work_dir", text)
        # UTC (1) + netstat (1) + Defender AV events (1) + Network Protection events (1)
        # + process probe (1) + Firewall block events (1).
        # APPCRASH, MpPreference, and active firewall rules are probe_host-gated →
        # skipped when probe_host is None (ctx.env={}, ctx.cli=None).
        self.assertEqual(m.call_count, 6)


class TestTryWindowsWorkdirProcesses(unittest.TestCase):
    def _call(self, work_dir: str) -> str:
        from lib.archon_triage import _try_windows_workdir_processes

        target = MagicMock()
        target.work_dir = work_dir
        captured: list[str] = []

        def _fake_run(t: object, cmd: str, timeout: int = 30) -> str:
            captured.append(cmd)
            return "1234|agent.exe|(owner unavailable)|" + work_dir + "\\agent.exe"

        _try_windows_workdir_processes(target, _fake_run)
        self.assertEqual(len(captured), 1)
        return captured[0]

    def test_standard_path_uses_single_backslashes(self) -> None:
        """Backslashes in work_dir must not be doubled in the generated PowerShell command."""
        cmd = self._call("C:\\Temp\\rc-test")
        # $wd must be assigned with literal single backslashes inside a PS single-quoted string.
        self.assertIn("$wd = 'C:\\Temp\\rc-test'", cmd)
        # Double backslashes in $wd assignment indicate the double-escaping bug.
        self.assertNotIn("C:\\\\Temp", cmd)

    def test_like_pattern_uses_single_backslash_separator(self) -> None:
        """The -like wildcard separator must be a single backslash, not double."""
        cmd = self._call("C:\\Work")
        self.assertIn("'\\*'", cmd)
        self.assertNotIn("'\\\\*'", cmd)

    def test_single_quote_in_path_is_escaped(self) -> None:
        """Single quotes in work_dir must be doubled for the PS single-quoted string."""
        cmd = self._call("C:\\Temp\\it's here")
        self.assertIn("it''s here", cmd)


class TestLogArchonEcdhPrelude(unittest.TestCase):
    def test_warns_when_callback_host_missing(self) -> None:
        from lib.archon_triage import log_archon_ecdh_prelude

        ctx = MagicMock()
        ctx.env = {}
        ctx.cli = CliConfig(
            server="https://192.168.1.1:40056",
            token="t",
            timeout=30,
            max_subprocess_secs=60,
        )
        out: list[str] = []

        def _print(*args: object, **kwargs: object) -> None:
            out.append(" ".join(str(a) for a in args))

        with patch("builtins.print", side_effect=_print):
            log_archon_ecdh_prelude(ctx, "ln", 19082)

        joined = "\n".join(out)
        self.assertIn("WARNING", joined)
        self.assertIn("callback_host", joined)
        self.assertIn("192.168.1.1", joined)
