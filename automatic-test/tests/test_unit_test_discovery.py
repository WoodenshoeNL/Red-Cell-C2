"""Unit tests for automatic-test.test unit test discovery."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import test as autotest_main


class TestRunUnitTestsDiscovery(unittest.TestCase):
    def test_discovers_autotest_and_repo_root_suites(self) -> None:
        loader = unittest.TestLoader()
        autotest_suite = unittest.TestSuite()
        repo_suite = unittest.TestSuite()

        with patch.object(
            unittest,
            "TestLoader",
            autospec=True,
            return_value=loader,
        ) as mock_loader_cls, patch.object(
            loader,
            "discover",
            autospec=True,
            return_value=autotest_suite,
        ) as mock_discover, patch(
            "test._load_repo_root_test_suite",
            autospec=True,
            return_value=repo_suite,
        ) as mock_repo_suite, patch(
            "unittest.TextTestRunner.run",
            autospec=True,
            return_value=unittest.TestResult(),
        ) as mock_run:
            ok = autotest_main.run_unit_tests()

        self.assertTrue(ok)
        mock_loader_cls.assert_called_once_with()
        mock_discover.assert_called_once_with(
            start_dir=str(autotest_main.TESTS_DIR),
            pattern="test_*.py",
        )
        mock_repo_suite.assert_called_once_with(loader)

        discovered_suite = mock_run.call_args.args[1]
        self.assertEqual(discovered_suite.countTestCases(), 0)


class TestLoadRepoRootTestSuite(unittest.TestCase):
    def test_loads_root_test_modules_from_paths(self) -> None:
        loader = unittest.TestLoader()

        suite = autotest_main._load_repo_root_test_suite(loader)

        self.assertGreater(suite.countTestCases(), 0)


if __name__ == "__main__":
    unittest.main()
