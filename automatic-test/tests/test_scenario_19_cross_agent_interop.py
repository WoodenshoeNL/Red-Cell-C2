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
from lib.config import timeouts_for_unit_tests

_SCENARIO_PATH = Path(__file__).parent.parent / "scenarios" / "19_cross_agent_interop.py"
_spec = _ilu.spec_from_file_location("scenario_19_cross_agent_interop", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _make_ctx(env: dict | None = None) -> MagicMock:
    ctx = MagicMock()
    ctx.cli = MagicMock()
    ctx.env = env or {}
    ctx.timeouts = timeouts_for_unit_tests()
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

    def test_deploy_linux_rejects_empty_payload(self) -> None:
        ctx = _make_ctx()
        target = MagicMock(work_dir="/tmp")
        with self.assertRaises(AssertionError) as cm:
            _mod._deploy_linux(ctx, target, "listener-1", "uid", b"")
        self.assertIn("empty", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
