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
from lib.cli import CliConfig
from lib.config import timeouts_for_unit_tests

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
    ctx.timeouts = timeouts_for_unit_tests()
    if windows:
        ctx.windows = MagicMock()
        ctx.windows.work_dir = "C:\\Temp\\rc-test"
    else:
        ctx.windows = None
    ctx.cli = CliConfig(
        server="https://127.0.0.1:40056",
        token="test-token",
        timeout=30,
        max_subprocess_secs=120,
    )
    return ctx


class TestRunSkipsWhenNoWindows(unittest.TestCase):
    def test_no_windows_raises_scenario_skipped(self) -> None:
        ctx = _make_ctx(windows=False)
        with self.assertRaises(ScenarioSkipped) as cm:
            _mod.run(ctx)
        self.assertIn("ctx.windows is None", str(cm.exception))


class TestRunArchonAvailabilityGate(unittest.TestCase):
    def test_missing_archon_in_available_agents_raises_scenario_skipped(self) -> None:
        ctx = _make_ctx(env={"agents": {"available": ["demon"]}})
        with self.assertRaises(ScenarioSkipped) as cm:
            _mod.run(ctx)
        self.assertIn("'archon' not listed", str(cm.exception))

    def test_build_failure_is_not_converted_to_skip(self) -> None:
        from lib.cli import CliError

        ctx = _make_ctx(env={"agents": {"available": ["demon", "archon"]}})

        with patch("lib.deploy.preflight_ssh"), \
             patch("lib.cli.agent_list", return_value=[]), \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.deploy_agent.payload_build_and_fetch", side_effect=CliError("UNKNOWN_AGENT", "unknown agent type: archon", 1)):
            with self.assertRaises(CliError) as cm:
                _mod.run(ctx)
        self.assertEqual(cm.exception.code, "UNKNOWN_AGENT")


class TestRunArchonExtensions(unittest.TestCase):
    def test_no_extensions_does_not_raise(self) -> None:
        """Empty extension list must complete silently."""
        _mod._run_archon_extensions(MagicMock(), "agent-123", [], 30)

    def test_extension_command_called_and_asserted(self) -> None:
        from lib.cli import agent_exec as _orig_exec

        cli = MagicMock()
        agent_id = "agent-abc"
        extensions = [{"cmd": "whoami /priv", "match": "SeDebug"}]

        fake_result = {"output": "Privilege Information:\nSeDebugPrivilege  Enabled"}

        with patch("lib.cli.agent_exec", return_value=fake_result):
            # Should not raise.
            _mod._run_archon_extensions(cli, agent_id, extensions, 30)

    def test_extension_command_missing_match_raises(self) -> None:
        cli = MagicMock()
        extensions = [{"cmd": "whoami /priv", "match": "SeDebug"}]

        fake_result = {"output": "no privileges here"}

        with patch("lib.cli.agent_exec", return_value=fake_result):
            with self.assertRaises(AssertionError) as cm:
                _mod._run_archon_extensions(cli, "agent-abc", extensions, 30)
        self.assertIn("SeDebug", str(cm.exception))

    def test_extension_empty_output_raises(self) -> None:
        cli = MagicMock()
        extensions = [{"cmd": "whoami", "match": ""}]

        with patch("lib.cli.agent_exec", return_value={"output": ""}):
            with self.assertRaises(AssertionError):
                _mod._run_archon_extensions(cli, "agent-abc", extensions, 30)


class TestArchonExtensionsTOMLShape(unittest.TestCase):
    """Verify that the [archon.extensions] single-dict TOML shape is normalised correctly.

    With ``tomllib``, ``[archon.extensions]`` produces a dict while
    ``[[archon.extensions]]`` produces a list of dicts.  The scenario must
    handle both so that the first configured extension does not crash at
    runtime.
    """

    def _make_toml_env(self, toml_text: str) -> dict:
        """Parse *toml_text* and return the resulting dict."""
        import tomllib
        return tomllib.loads(toml_text)

    def test_single_table_dict_is_normalised_to_list(self) -> None:
        """``[archon.extensions]`` (dict) must be wrapped into a list."""
        toml_text = "[archon.extensions]\ncmd = \"whoami\"\nmatch = \"DOMAIN\"\n"
        env = self._make_toml_env(toml_text)
        ext_raw = env.get("archon", {}).get("extensions", [])
        # tomllib gives us a dict for [archon.extensions]
        self.assertIsInstance(ext_raw, dict)
        # Apply the same normalisation used in run()
        normalised = [ext_raw] if isinstance(ext_raw, dict) else list(ext_raw)
        self.assertEqual(len(normalised), 1)
        self.assertEqual(normalised[0]["cmd"], "whoami")
        self.assertEqual(normalised[0]["match"], "DOMAIN")

    def test_array_of_tables_list_is_unchanged(self) -> None:
        """``[[archon.extensions]]`` (list of dicts) must pass through unchanged."""
        toml_text = (
            "[[archon.extensions]]\ncmd = \"whoami\"\nmatch = \"DOMAIN\"\n"
            "[[archon.extensions]]\ncmd = \"ipconfig\"\nmatch = \"IPv4\"\n"
        )
        env = self._make_toml_env(toml_text)
        ext_raw = env.get("archon", {}).get("extensions", [])
        # tomllib gives us a list for [[archon.extensions]]
        self.assertIsInstance(ext_raw, list)
        normalised = [ext_raw] if isinstance(ext_raw, dict) else list(ext_raw)
        self.assertEqual(len(normalised), 2)
        self.assertEqual(normalised[0]["cmd"], "whoami")
        self.assertEqual(normalised[1]["cmd"], "ipconfig")

    def test_single_table_env_runs_extension_without_error(self) -> None:
        """Full round-trip: dict from [archon.extensions] reaches _run_archon_extensions."""
        toml_text = "[archon.extensions]\ncmd = \"whoami\"\nmatch = \"CONTOSO\"\n"
        env = self._make_toml_env(toml_text)
        ext_raw = env.get("archon", {}).get("extensions", [])
        normalised = [ext_raw] if isinstance(ext_raw, dict) else list(ext_raw)

        fake_result = {"output": "CONTOSO\\Administrator"}
        with patch("lib.cli.agent_exec", return_value=fake_result):
            # Must not raise AttributeError ('str' has no attribute 'get')
            _mod._run_archon_extensions(MagicMock(), "agent-abc", normalised, 30)


if __name__ == "__main__":
    unittest.main()
