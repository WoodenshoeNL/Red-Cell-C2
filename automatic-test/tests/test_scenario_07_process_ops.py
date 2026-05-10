from __future__ import annotations

import importlib.util as _ilu
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped

_SCENARIO_PATH = (
    Path(__file__).parent.parent / "scenarios" / "07_process_ops_process_operations.py"
)
_spec = _ilu.spec_from_file_location("scenario_07_process_ops_process_operations", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class TestLinuxSpawnSleepCommand(unittest.TestCase):
    def test_detaches_background_process_from_ssh_session(self) -> None:
        cmd = _mod._linux_spawn_sleep_command()
        self.assertIn("nohup sleep 9999", cmd)
        self.assertIn(">/dev/null 2>&1 < /dev/null", cmd)
        self.assertTrue(cmd.endswith("echo $!'"))


class TestWindowsDegradedSkipsWindowsPasses(unittest.TestCase):
    """windows_degraded=True must skip all Windows passes, preserving Linux coverage."""

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
        """No Linux target + WFP-degraded Windows → ScenarioSkipped (no passes ran)."""
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=True)
        with patch("lib.deploy.preflight_ssh"):
            with self.assertRaises(ScenarioSkipped):
                _mod.run(ctx)

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
             patch("lib.payload.build_parallel", side_effect=CliError("BUILD_FAILED", "build failed", 1)):
            with self.assertRaises(CliError):
                _mod.run(ctx)


class TestWindowsSshUnreachableFallback(unittest.TestCase):
    """When Windows preflight_ssh raises ScenarioSkipped, sc07 must fall through to Linux."""

    def _make_ctx(self, *, windows=True, linux=False, env=None):
        ctx = MagicMock()
        ctx.windows_degraded = False
        ctx.dry_run = False
        ctx.payload_parallel = True
        ctx.env = env or {}
        ctx.timeouts = MagicMock()
        ctx.linux = MagicMock() if linux else None
        ctx.windows = MagicMock() if windows else None
        return ctx

    def test_windows_ssh_unreachable_no_linux_raises_scenario_skipped(self) -> None:
        """Windows SSH unreachable + no Linux → ScenarioSkipped (no cells to run)."""
        ctx = self._make_ctx(windows=True, linux=False)

        def _preflight(target):
            if target is ctx.windows:
                raise ScenarioSkipped("target 192.168.213.160 was unreachable at startup")

        with patch("lib.deploy.preflight_ssh", side_effect=_preflight):
            with self.assertRaises(ScenarioSkipped):
                _mod.run(ctx)

    def test_windows_ssh_unreachable_falls_through_to_linux_phantom(self) -> None:
        """Windows SSH unreachable + Linux with phantom → falls through to payload build."""
        from lib.cli import CliError
        ctx = self._make_ctx(
            windows=True, linux=True,
            env={"agents": {"available": ["phantom"]}},
        )

        def _preflight(target):
            if target is ctx.windows:
                raise ScenarioSkipped("target 192.168.213.160 was unreachable at startup")
            # Linux succeeds

        # CliError from build_parallel proves run() reached the Linux payload step
        # rather than aborting with ScenarioSkipped at the Windows preflight.
        with patch("lib.deploy.preflight_ssh", side_effect=_preflight), \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.payload.build_parallel", side_effect=CliError("BUILD_FAILED", "build failed", 1)):
            with self.assertRaises(CliError):
                _mod.run(ctx)


if __name__ == "__main__":
    unittest.main()
