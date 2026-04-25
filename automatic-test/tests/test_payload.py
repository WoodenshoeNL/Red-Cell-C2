"""
Unit tests for lib.payload.build_parallel and MatrixCell.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig
from lib.payload import MatrixCell, _normalize_cell, build_parallel

_CFG = CliConfig(server="https://127.0.0.1:40056", token="test-token", timeout=3)


class TestNormalizeCell(unittest.TestCase):
    def test_matrix_cell_unchanged(self) -> None:
        m = MatrixCell(arch="x86", fmt="dll")
        self.assertIs(_normalize_cell(m), m)

    def test_two_tuple(self) -> None:
        m = _normalize_cell(("x64", "bin"))
        self.assertEqual(m.arch, "x64")
        self.assertEqual(m.fmt, "bin")
        self.assertEqual(m.agent, "demon")

    def test_list_same_as_tuple(self) -> None:
        m = _normalize_cell(["x86", "exe"])
        self.assertEqual(m.arch, "x86")
        self.assertEqual(m.fmt, "exe")


class TestBuildParallel(unittest.TestCase):
    def test_empty_returns_empty(self) -> None:
        self.assertEqual(build_parallel(_CFG, "L", []), [])

    def test_serial_path_uses_build_and_fetch(self) -> None:
        cells = [MatrixCell(arch="x64", fmt="exe"), MatrixCell(arch="x64", fmt="bin")]
        with patch("lib.cli.payload_build_and_fetch", side_effect=[b"AA", b"BB"]) as m_fetch:
            out = build_parallel(_CFG, "http1", cells, parallel=False)
        self.assertEqual(out, [b"AA", b"BB"])
        self.assertEqual(m_fetch.call_count, 2)
        c1, c2 = m_fetch.call_args_list
        self.assertEqual(c1[1]["arch"], "x64")
        self.assertEqual(c1[1]["fmt"], "exe")
        self.assertEqual(c2[1]["fmt"], "bin")

    def test_parallel_path_preserves_order(self) -> None:
        with patch("lib.payload._one_cell_bytes", side_effect=[b"one", b"two"]) as m_one:
            out = build_parallel(
                _CFG,
                "L",
                [MatrixCell(), MatrixCell(arch="x86", fmt="bin")],
                parallel=True,
            )
        self.assertEqual(out, [b"one", b"two"])
        self.assertEqual(m_one.call_count, 2)


if __name__ == "__main__":
    unittest.main()
