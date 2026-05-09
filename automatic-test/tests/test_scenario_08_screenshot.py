"""
tests/test_scenario_08_screenshot.py — Unit tests for scenario 08 X11 preflight.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestWindowsDegradedFallsThrough(unittest.TestCase):
    """When windows_degraded=True, sc08 must skip the Windows block and fall through to Linux."""

    def _make_ctx(self, *, windows=True, linux=False, windows_degraded=True, env=None):
        ctx = MagicMock()
        ctx.windows_degraded = windows_degraded
        ctx.dry_run = False
        ctx.payload_parallel = True
        ctx.env = env or {}
        ctx.timeouts = MagicMock()
        ctx.linux = MagicMock() if linux else None
        ctx.windows = MagicMock() if windows else None
        return ctx

    def test_windows_degraded_no_linux_raises_scenario_skipped(self) -> None:
        """WFP-degraded Windows + no Linux → ScenarioSkipped (no suitable target)."""
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=True)
        with self.assertRaises(ScenarioSkipped):
            _mod.run(ctx)

    def test_windows_degraded_linux_no_display_raises_scenario_skipped(self) -> None:
        """WFP-degraded Windows + Linux without DISPLAY → ScenarioSkipped."""
        ctx = self._make_ctx(windows=True, linux=True, windows_degraded=True, env={})
        ctx.linux.display = None
        with self.assertRaises(ScenarioSkipped) as cm:
            _mod.run(ctx)
        self.assertIn("DISPLAY", str(cm.exception))

    def test_windows_not_degraded_uses_windows_branch(self) -> None:
        """windows_degraded=False must enter the Windows branch (preflight_ssh called)."""
        from lib.cli import CliError
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=False,
                             env={"agents": {"available": ["archon"]}})
        with patch("lib.deploy.preflight_ssh") as mock_ssh, \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.payload.build_parallel", side_effect=CliError("BUILD_FAILED", "build failed", 1)):
            with self.assertRaises(CliError):
                _mod.run(ctx)
        mock_ssh.assert_called_once()


if __name__ == "__main__":
    unittest.main()
