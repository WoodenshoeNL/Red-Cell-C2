from __future__ import annotations

import importlib.util as _ilu
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped

_SCENARIO_PATH = (
    Path(__file__).parent.parent / "scenarios" / "14_stress_concurrent_agents.py"
)
_spec = _ilu.spec_from_file_location("scenario_14_stress_concurrent_agents", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class TestWindowsDegradedSkipsDemonPass(unittest.TestCase):
    """windows_degraded=True must skip the Demon pass without touching Windows SSH."""

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
        """windows_degraded=True + no Linux → ScenarioSkipped (no passes can run)."""
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=True)
        with patch("lib.deploy.preflight_ssh") as mock_preflight:
            with self.assertRaises(ScenarioSkipped):
                _mod.run(ctx)
            mock_preflight.assert_not_called()

    def test_windows_degraded_linux_phantom_still_runs(self) -> None:
        """windows_degraded=True + Linux with phantom → Demon skipped, Phantom path reached."""
        from lib.cli import CliError
        ctx = self._make_ctx(
            windows=True, linux=True, windows_degraded=True,
            env={"agents": {"available": ["phantom"]}},
        )
        with patch("lib.deploy.preflight_ssh") as mock_preflight, \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.payload.build_parallel",
                   side_effect=CliError("BUILD_FAILED", "build failed", 1)):
            with self.assertRaises(CliError):
                _mod.run(ctx)
            # preflight_ssh must NOT be called — windows_degraded guard fires first
            mock_preflight.assert_not_called()

    def test_windows_degraded_false_does_not_skip_early(self) -> None:
        """windows_degraded=False must not trigger the early Windows skip."""
        from lib.cli import CliError
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=False,
                             env={"agents": {"available": ["demon"]}})
        with patch("lib.deploy.preflight_ssh"), \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.payload.build_parallel",
                   side_effect=CliError("BUILD_FAILED", "build failed", 1)):
            with self.assertRaises(CliError):
                _mod.run(ctx)


if __name__ == "__main__":
    unittest.main()
