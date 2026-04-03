"""
Unit tests for scenario 19 availability and build-failure behavior.
"""

from __future__ import annotations

import importlib.util as _ilu
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped
from lib.cli import CliError

_SCENARIO_PATH = Path(__file__).parent.parent / "scenarios" / "19_cross_agent_interop.py"
_spec = _ilu.spec_from_file_location("scenario_19_cross_agent_interop", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _make_ctx(env: dict | None = None) -> MagicMock:
    ctx = MagicMock()
    ctx.cli = MagicMock()
    ctx.env = env or {}
    ctx.dry_run = False
    ctx.linux = MagicMock()
    ctx.linux.work_dir = "/tmp/red-cell-linux"
    ctx.windows = MagicMock()
    ctx.windows.work_dir = "C:\\Temp\\red-cell"
    return ctx


class TestScenario19Gates(unittest.TestCase):
    def test_missing_phantom_in_available_agents_skips(self) -> None:
        ctx = _make_ctx(env={"agents": {"available": ["demon"]}})
        with self.assertRaises(ScenarioSkipped) as cm:
            _mod.run(ctx)
        self.assertIn("'phantom' not listed", str(cm.exception))

    def test_linux_build_failure_propagates(self) -> None:
        with patch("lib.cli.payload_build_and_fetch", side_effect=CliError("BUILD_FAILED", "boom", 1)):
            with self.assertRaises(CliError) as cm:
                _mod._build_and_deploy_linux(MagicMock(), MagicMock(work_dir="/tmp"), "listener-1", "uid")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")


if __name__ == "__main__":
    unittest.main()
