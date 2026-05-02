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
        self.assertGreaterEqual(m.call_count, 3)

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
        # Exactly: UTC probe (1) + netstat (1) + Defender events (1) + process probe (1) = 4 calls.
        self.assertEqual(m.call_count, 4)


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
