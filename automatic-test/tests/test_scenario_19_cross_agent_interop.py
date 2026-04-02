"""
tests/test_scenario_19_cross_agent_interop.py — Unit tests for scenario 19.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import importlib.util as _ilu
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Make automatic-test/ importable from repo root or from the test directory.
sys.path.insert(0, str(Path(__file__).parent.parent))

_SCENARIO_PATH = (
    Path(__file__).parent.parent / "scenarios" / "19_cross_agent_interop.py"
)
_spec = _ilu.spec_from_file_location("scenario_19_cross_agent_interop", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class TestWaitForAgentsDisconnected(unittest.TestCase):
    def test_wait_helper_uses_status_field_from_cli_contract(self) -> None:
        cli = MagicMock()
        agent_ids = ["WIN123", "LIN456"]
        snapshots = iter(
            [
                [
                    {"id": "WIN123", "status": "alive"},
                    {"id": "LIN456", "status": "alive"},
                ],
                [
                    {"id": "WIN123", "status": "dead"},
                    {"id": "LIN456", "status": "alive"},
                ],
                [
                    {"id": "WIN123", "status": "dead"},
                    {"id": "LIN456", "status": "dead"},
                ],
            ]
        )

        def fake_poll(fn, predicate, timeout=60, interval=2.0, description="condition"):
            self.assertEqual(description, "agents disconnected")
            self.assertEqual(timeout, 15)

            for _ in range(3):
                result = fn()
                if predicate(result):
                    return result

            self.fail("poll did not observe both agents as disconnected")

        with patch("lib.cli.agent_list", side_effect=lambda _: next(snapshots)) as agent_list, \
             patch("lib.wait.poll", side_effect=fake_poll) as poll:
            _mod._wait_for_agents_disconnected(cli, agent_ids, timeout=15)

        self.assertEqual(agent_list.call_count, 3)
        poll.assert_called_once()


if __name__ == "__main__":
    unittest.main()
