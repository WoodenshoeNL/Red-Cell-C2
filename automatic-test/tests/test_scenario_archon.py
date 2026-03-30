"""
tests/test_scenario_archon.py — Unit tests for scenario 17 (Archon Windows checkin).

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Make automatic-test/ importable from repo root or from the test directory.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped

# Import the scenario module directly.
_SCENARIO_PATH = Path(__file__).parent.parent / "scenarios" / "17_agent_archon_archon_windows_checkin.py"
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("scenario_archon", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _make_ctx(windows=True, dry_run=False, env=None):
    """Build a minimal RunContext-like object for testing."""
    ctx = MagicMock()
    ctx.dry_run = dry_run
    ctx.env = env or {}
    if windows:
        ctx.windows = MagicMock()
        ctx.windows.work_dir = "C:\\Temp\\rc-test"
    else:
        ctx.windows = None
    ctx.cli = MagicMock()
    return ctx


class TestRunSkipsWhenNoWindows(unittest.TestCase):
    def test_no_windows_raises_scenario_skipped(self) -> None:
        ctx = _make_ctx(windows=False)
        with self.assertRaises(ScenarioSkipped) as cm:
            _mod.run(ctx)
        self.assertIn("ctx.windows is None", str(cm.exception))


class TestRunSkipsWhenPayloadBuildFails(unittest.TestCase):
    """Scenario must skip (not fail) when the teamserver rejects agent='archon'."""

    def test_cli_error_on_payload_build_raises_scenario_skipped(self) -> None:
        from lib.cli import CliError

        ctx = _make_ctx()

        with patch("lib.cli.agent_list", return_value=[]), \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.cli.payload_build", side_effect=CliError("UNKNOWN_AGENT", "unknown agent type: archon", 1)):
            with self.assertRaises(ScenarioSkipped) as cm:
                _mod.run(ctx)
        self.assertIn("Archon payload build failed", str(cm.exception))


class TestRunArchonExtensions(unittest.TestCase):
    def test_no_extensions_does_not_raise(self) -> None:
        """Empty extension list must complete silently."""
        _mod._run_archon_extensions(MagicMock(), "agent-123", [])

    def test_extension_command_called_and_asserted(self) -> None:
        from lib.cli import agent_exec as _orig_exec

        cli = MagicMock()
        agent_id = "agent-abc"
        extensions = [{"cmd": "whoami /priv", "match": "SeDebug"}]

        fake_result = {"output": "Privilege Information:\nSeDebugPrivilege  Enabled"}

        with patch("lib.cli.agent_exec", return_value=fake_result):
            # Should not raise.
            _mod._run_archon_extensions(cli, agent_id, extensions)

    def test_extension_command_missing_match_raises(self) -> None:
        cli = MagicMock()
        extensions = [{"cmd": "whoami /priv", "match": "SeDebug"}]

        fake_result = {"output": "no privileges here"}

        with patch("lib.cli.agent_exec", return_value=fake_result):
            with self.assertRaises(AssertionError) as cm:
                _mod._run_archon_extensions(cli, "agent-abc", extensions)
        self.assertIn("SeDebug", str(cm.exception))

    def test_extension_empty_output_raises(self) -> None:
        cli = MagicMock()
        extensions = [{"cmd": "whoami", "match": ""}]

        with patch("lib.cli.agent_exec", return_value={"output": ""}):
            with self.assertRaises(AssertionError):
                _mod._run_archon_extensions(cli, "agent-abc", extensions)


if __name__ == "__main__":
    unittest.main()
