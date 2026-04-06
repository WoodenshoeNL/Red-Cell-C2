"""
tests/test_scenario_08_screenshot.py — Unit tests for scenario 08 X11 preflight.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped
from lib.deploy import DeployError

_SCENARIO_PATH = Path(__file__).parent.parent / "scenarios" / "08_screenshot_screenshot_capture.py"
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location("scenario_08_screenshot", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class TestPreflightLinuxX11Display(unittest.TestCase):
    def test_xdpyinfo_succeeds(self):
        target = object()
        with patch("lib.deploy.run_remote", return_value="dimensions:"):
            _mod._preflight_linux_x11_display(target, ":99")

    def test_xdpyinfo_failure_raises_scenario_skipped(self):
        target = object()
        with patch(
            "lib.deploy.run_remote",
            side_effect=DeployError("xdpyinfo: unable to open display"),
        ):
            with self.assertRaises(ScenarioSkipped) as cm:
                _mod._preflight_linux_x11_display(target, ":99")
        msg = str(cm.exception)
        self.assertIn("DISPLAY :99", msg)
        self.assertIn("Xvfb :99", msg)


if __name__ == "__main__":
    unittest.main()
