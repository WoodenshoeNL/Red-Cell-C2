from __future__ import annotations

import importlib.util as _ilu
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

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


if __name__ == "__main__":
    unittest.main()
