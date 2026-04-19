"""
Unit tests for scenario 13 wrong-endian registration handling.
"""

from __future__ import annotations

import importlib.util as _ilu
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

_SCENARIO_PATH = Path(__file__).parent.parent / "scenarios" / "13_protocol_compliance.py"
_spec = _ilu.spec_from_file_location("scenario_13_protocol_compliance", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class TestWrongEndianCheck(unittest.TestCase):
    def test_wrong_endian_registration_accepted(self) -> None:
        """Server accepts garbled-endian packet (transport is valid) — function succeeds."""
        with patch.object(_mod, "_post_raw", return_value=(200, b"ack")):
            agent_id = _mod._run_wrong_endian_check("http://127.0.0.1:19090/")
        self.assertIsInstance(agent_id, int)
        self.assertNotEqual(agent_id, 0)

    def test_wrong_endian_registration_rejected_is_failure(self) -> None:
        """Server rejects the packet (404) — function raises AssertionError."""
        with patch.object(_mod, "_post_raw", return_value=(404, b"")):
            with self.assertRaises(AssertionError) as ctx:
                _mod._run_wrong_endian_check("http://127.0.0.1:19090/")
        self.assertIn("BE-encoded DEMON_INIT accepted", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
