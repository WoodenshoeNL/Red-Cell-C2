"""Unit tests for SSH target pre-flight helpers in test.py."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

# Ensure the automatic-test root is on the path so test.py is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))

from test import _ssh_deploy_scenario_ids, check_ssh_targets

_fd, _TEST_KEY_PATH = tempfile.mkstemp(prefix="ssh-preflight-test-key-")
os.close(_fd)


def _make_target(**kwargs):
    """Return a minimal TargetConfig-like object for testing."""
    from lib.deploy import TargetConfig
    defaults = dict(
        host="10.0.0.1",
        port=22,
        user="testuser",
        work_dir="/tmp/rc-test",
        key=_TEST_KEY_PATH,
    )
    defaults.update(kwargs)
    return TargetConfig(**defaults)


class TestSshDeployScenarioIds(unittest.TestCase):
    """_ssh_deploy_scenario_ids scans scenario files for lib.deploy imports."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.scenarios_dir = Path(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def test_empty_directory_returns_empty_set(self):
        result = _ssh_deploy_scenario_ids(self.scenarios_dir)
        self.assertEqual(result, frozenset())

    def test_scenario_with_deploy_import_is_included(self):
        (self.scenarios_dir / "04_linux.py").write_text(
            "from lib.deploy import run_remote, upload\n", encoding="utf-8"
        )
        result = _ssh_deploy_scenario_ids(self.scenarios_dir)
        self.assertIn("04", result)

    def test_scenario_without_deploy_import_is_excluded(self):
        (self.scenarios_dir / "01_auth.py").write_text(
            "# no deploy here\ndef run(ctx): pass\n", encoding="utf-8"
        )
        result = _ssh_deploy_scenario_ids(self.scenarios_dir)
        self.assertNotIn("01", result)

    def test_non_scenario_files_are_ignored(self):
        (self.scenarios_dir / "helpers.py").write_text(
            "from lib.deploy import run_remote\n", encoding="utf-8"
        )
        (self.scenarios_dir / "__init__.py").write_text("", encoding="utf-8")
        result = _ssh_deploy_scenario_ids(self.scenarios_dir)
        self.assertEqual(result, frozenset())

    def test_multiple_deploy_scenarios_detected(self):
        for sid, has_deploy in [("04", True), ("05", True), ("01", False)]:
            content = "from lib.deploy import run_remote\n" if has_deploy else "pass\n"
            (self.scenarios_dir / f"{sid}_test.py").write_text(content, encoding="utf-8")
        result = _ssh_deploy_scenario_ids(self.scenarios_dir)
        self.assertEqual(result, frozenset({"04", "05"}))

    def test_result_is_frozenset(self):
        result = _ssh_deploy_scenario_ids(self.scenarios_dir)
        self.assertIsInstance(result, frozenset)

    def test_defaults_to_real_scenarios_dir(self):
        """_ssh_deploy_scenario_ids with no arg must include real deploy scenarios."""
        result = _ssh_deploy_scenario_ids(Path(__file__).parent.parent / "scenarios")
        # The known deploy scenarios must all be present.
        for expected in ("04", "05", "06", "07", "08", "09", "10", "15", "16", "17", "19"):
            self.assertIn(expected, result, f"scenario {expected} should be in deploy set")


class TestCheckSshTargets(unittest.TestCase):
    """check_ssh_targets runs pre-flight and prints status without aborting."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.scenarios_dir = Path(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def _write_deploy_scenario(self, sid: str) -> None:
        (self.scenarios_dir / f"{sid}_deploy.py").write_text(
            "from lib.deploy import run_remote\n", encoding="utf-8"
        )

    def _write_non_deploy_scenario(self, sid: str) -> None:
        (self.scenarios_dir / f"{sid}_simple.py").write_text(
            "def run(ctx): pass\n", encoding="utf-8"
        )

    def test_no_output_when_no_deploy_scenarios_selected(self):
        """check_ssh_targets must be silent when no deploy scenarios are selected."""
        self._write_non_deploy_scenario("01")
        target = _make_target()
        buf = StringIO()
        with patch("sys.stdout", buf):
            check_ssh_targets([("linux", target)], {"01"}, scenarios_dir=self.scenarios_dir)
        self.assertEqual(buf.getvalue(), "")

    def test_skips_none_targets(self):
        """None targets must be reported as 'not configured', not cause errors."""
        self._write_deploy_scenario("04")
        buf = StringIO()
        with patch("sys.stdout", buf):
            check_ssh_targets([("linux", None)], {"04"}, scenarios_dir=self.scenarios_dir)
        self.assertIn("not configured", buf.getvalue())

    def test_reachable_target_prints_checkmark(self):
        """A reachable target must print a ✓ line."""
        self._write_deploy_scenario("04")
        target = _make_target(host="10.0.0.2")
        from lib.deploy import DeployError
        with patch("lib.deploy.preflight_ssh"):
            buf = StringIO()
            with patch("sys.stdout", buf):
                check_ssh_targets([("linux", target)], {"04"}, scenarios_dir=self.scenarios_dir)
        self.assertIn("✓", buf.getvalue())
        self.assertIn("10.0.0.2", buf.getvalue())

    def test_unreachable_target_prints_cross_but_does_not_raise(self):
        """An unreachable target must print ✗ but NOT abort (no exception raised)."""
        self._write_deploy_scenario("04")
        target = _make_target(host="10.0.0.99")
        from lib.deploy import DeployError
        with patch("lib.deploy.preflight_ssh", side_effect=DeployError("not reachable")):
            buf = StringIO()
            with patch("sys.stdout", buf):
                # Must not raise
                check_ssh_targets([("linux", target)], {"04"}, scenarios_dir=self.scenarios_dir)
        self.assertIn("✗", buf.getvalue())
        self.assertIn("10.0.0.99", buf.getvalue())

    def test_empty_targets_list_does_not_raise(self):
        """An empty targets list must not raise even when deploy scenarios are selected."""
        self._write_deploy_scenario("04")
        check_ssh_targets([], {"04"}, scenarios_dir=self.scenarios_dir)

    def test_multiple_targets_all_checked(self):
        """All non-None targets must be checked when deploy scenarios are selected."""
        self._write_deploy_scenario("04")
        targets = [
            ("linux", _make_target(host="10.0.0.1")),
            ("windows", _make_target(host="10.0.0.2")),
        ]
        call_hosts = []
        from lib.deploy import DeployError

        def _mock_preflight(target):
            call_hosts.append(target.host)

        with patch("lib.deploy.preflight_ssh", side_effect=_mock_preflight):
            with patch("sys.stdout", StringIO()):
                check_ssh_targets(targets, {"04"}, scenarios_dir=self.scenarios_dir)

        self.assertIn("10.0.0.1", call_hosts)
        self.assertIn("10.0.0.2", call_hosts)


if __name__ == "__main__":
    unittest.main()
