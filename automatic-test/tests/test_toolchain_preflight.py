"""Unit tests for toolchain pre-flight helpers in test.py."""

from __future__ import annotations

import shutil
import sys
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure the automatic-test root is on the path so test.py is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))

from test import _payload_scenario_ids, check_toolchain


class TestPayloadScenarioIds(unittest.TestCase):
    """_payload_scenario_ids scans scenario files for payload_build_and_fetch."""

    def _make_scenarios(self, tmp_path: Path, files: dict[str, str]) -> None:
        for name, content in files.items():
            (tmp_path / name).write_text(content, encoding="utf-8")

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.mkdtemp()
        self.scenarios_dir = Path(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def test_empty_directory_returns_empty_set(self):
        result = _payload_scenario_ids(self.scenarios_dir)
        self.assertEqual(result, frozenset())

    def test_scenario_with_payload_build_and_fetch_is_included(self):
        (self.scenarios_dir / "04_something.py").write_text(
            "from lib.cli import payload_build_and_fetch\n", encoding="utf-8"
        )
        result = _payload_scenario_ids(self.scenarios_dir)
        self.assertIn("04", result)

    def test_scenario_without_payload_build_is_excluded(self):
        (self.scenarios_dir / "01_no_payload.py").write_text(
            "# no payload here\ndef run(ctx): pass\n", encoding="utf-8"
        )
        result = _payload_scenario_ids(self.scenarios_dir)
        self.assertNotIn("01", result)

    def test_non_scenario_files_are_ignored(self):
        # helpers and __init__ must not be included
        (self.scenarios_dir / "helpers.py").write_text(
            "payload_build_and_fetch = None\n", encoding="utf-8"
        )
        (self.scenarios_dir / "__init__.py").write_text("", encoding="utf-8")
        result = _payload_scenario_ids(self.scenarios_dir)
        self.assertEqual(result, frozenset())

    def test_multiple_scenarios_detected(self):
        for sid, has_payload in [("03", True), ("04", True), ("01", False)]:
            content = "payload_build_and_fetch()\n" if has_payload else "pass\n"
            (self.scenarios_dir / f"{sid}_test.py").write_text(content, encoding="utf-8")
        result = _payload_scenario_ids(self.scenarios_dir)
        self.assertEqual(result, frozenset({"03", "04"}))

    def test_result_is_frozenset(self):
        result = _payload_scenario_ids(self.scenarios_dir)
        self.assertIsInstance(result, frozenset)


class TestCheckToolchain(unittest.TestCase):
    """check_toolchain only runs when a payload-building scenario is selected."""

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.mkdtemp()
        self.scenarios_dir = Path(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def _write_payload_scenario(self, sid: str) -> None:
        (self.scenarios_dir / f"{sid}_payload.py").write_text(
            "from lib.cli import payload_build_and_fetch\n", encoding="utf-8"
        )

    def _write_non_payload_scenario(self, sid: str) -> None:
        (self.scenarios_dir / f"{sid}_simple.py").write_text(
            "def run(ctx): pass\n", encoding="utf-8"
        )

    def test_returns_true_when_no_payload_scenarios_selected(self):
        self._write_non_payload_scenario("01")
        # No toolchain checks should run; returns True immediately.
        result = check_toolchain({"01"}, scenarios_dir=self.scenarios_dir)
        self.assertTrue(result)

    def test_returns_true_when_selected_ids_dont_overlap_payload_scenarios(self):
        self._write_payload_scenario("04")
        self._write_non_payload_scenario("01")
        # Only "01" is selected — toolchain check must be skipped.
        result = check_toolchain({"01"}, scenarios_dir=self.scenarios_dir)
        self.assertTrue(result)

    def test_checks_toolchain_when_payload_scenario_selected(self):
        self._write_payload_scenario("04")
        # Patch shutil.which to simulate both tools missing.
        with patch("shutil.which", return_value=None):
            result = check_toolchain({"04"}, scenarios_dir=self.scenarios_dir)
        self.assertFalse(result)

    def test_returns_true_when_all_tools_present(self):
        self._write_payload_scenario("03")
        # Simulate all tools present and working.
        with patch("shutil.which", return_value="/usr/bin/tool"), \
             patch("subprocess.run"):
            result = check_toolchain({"03"}, scenarios_dir=self.scenarios_dir)
        self.assertTrue(result)

    def test_non_03_payload_scenario_triggers_check(self):
        """Scenarios beyond 03 that call payload_build_and_fetch must trigger the check."""
        for sid in ("04", "05", "17"):
            self._write_payload_scenario(sid)
        with patch("shutil.which", return_value=None):
            for sid in ("04", "05", "17"):
                result = check_toolchain({sid}, scenarios_dir=self.scenarios_dir)
                self.assertFalse(result, f"scenario {sid} should have triggered toolchain check")

    def test_empty_selected_ids_returns_true(self):
        result = check_toolchain(set(), scenarios_dir=self.scenarios_dir)
        self.assertTrue(result)

    def test_defaults_to_real_scenarios_dir(self):
        """check_toolchain with no scenarios_dir kwarg must not raise."""
        # The real scenarios dir has many payload scenarios; just verify it
        # returns without error when toolchain tools are present.
        with patch("shutil.which", return_value="/usr/bin/tool"), \
             patch("subprocess.run"):
            result = check_toolchain({"03"})
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
