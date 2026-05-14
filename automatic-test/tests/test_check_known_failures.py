"""Unit tests for check_known_failures.py."""

from __future__ import annotations

import subprocess
import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add the parent directory so we can import the script directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import check_known_failures as ckf


_OPEN_OUTPUT = "◐ red-cell-c2-aaaaa · some bug title   [● P2 · OPEN]\nsome details"
_IN_PROGRESS_OUTPUT = "◐ red-cell-c2-bbbbb · another title   [● P1 · IN_PROGRESS]\nsome details"
_CLOSED_OUTPUT = "✓ red-cell-c2-ccccc · closed title   [● P3 · CLOSED]\nsome details"
_UNKNOWN_OUTPUT = "red-cell-c2-ddddd · weird output no status badge"


class TestCheckBead(unittest.TestCase):
    def _make_result(self, returncode: int, stdout: str) -> MagicMock:
        r = MagicMock()
        r.returncode = returncode
        r.stdout = stdout
        return r

    def test_open_bead(self) -> None:
        with patch("subprocess.run", return_value=self._make_result(0, _OPEN_OUTPUT)):
            status, title = ckf._check_bead("red-cell-c2-aaaaa")
        self.assertEqual(status, "OPEN")
        self.assertEqual(title, "some bug title")

    def test_in_progress_bead(self) -> None:
        with patch("subprocess.run", return_value=self._make_result(0, _IN_PROGRESS_OUTPUT)):
            status, title = ckf._check_bead("red-cell-c2-bbbbb")
        self.assertEqual(status, "IN_PROGRESS")

    def test_closed_bead(self) -> None:
        with patch("subprocess.run", return_value=self._make_result(0, _CLOSED_OUTPUT)):
            status, title = ckf._check_bead("red-cell-c2-ccccc")
        self.assertEqual(status, "CLOSED")
        self.assertEqual(title, "closed title")

    def test_not_found_nonzero_returncode(self) -> None:
        with patch("subprocess.run", return_value=self._make_result(1, "")):
            status, title = ckf._check_bead("red-cell-c2-ddddd")
        self.assertEqual(status, "NOT_FOUND")

    def test_unknown_via_timeout(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["br"], 15)):
            status, title = ckf._check_bead("red-cell-c2-eeeee")
        self.assertEqual(status, "UNKNOWN")
        self.assertIn("timed out", title)

    def test_unknown_via_unrecognized_output(self) -> None:
        with patch("subprocess.run", return_value=self._make_result(0, _UNKNOWN_OUTPUT)):
            status, title = ckf._check_bead("red-cell-c2-ddddd")
        self.assertEqual(status, "UNKNOWN")

    def test_br_not_on_path_exits_2(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(SystemExit) as cm:
                ckf._check_bead("red-cell-c2-aaaaa")
        self.assertEqual(cm.exception.code, 2)


_ACTIVE_MD = """\
## Active

| Bead | Scenario | Symptom |
|---|---|---|
| red-cell-c2-aaaaa | sc01 | something |
| red-cell-c2-bbbbb | sc02 | something else |

---
"""

_ACTIVE_CLOSED_MD = """\
## Active

| Bead | Scenario | Symptom |
|---|---|---|
| red-cell-c2-ccccc | sc01 | a closed one |

---
"""

_ACTIVE_NOT_FOUND_MD = """\
## Active

| Bead | Scenario | Symptom |
|---|---|---|
| red-cell-c2-xxxxx | sc01 | typo bead |

---
"""

_ACTIVE_MIXED_MD = """\
## Active

| Bead | Scenario | Symptom |
|---|---|---|
| red-cell-c2-aaaaa | sc01 | open one |
| red-cell-c2-ccccc | sc02 | closed one |
| red-cell-c2-eeeee | sc03 | unknown one |

---
"""

_EMPTY_ACTIVE_MD = """\
## Active

*(none)*

---
"""


class TestMain(unittest.TestCase):
    def _run_main(self, md_text: str, side_effects: list) -> tuple[int, str]:
        """Run main() with mocked KNOWN_FAILURES content and subprocess side-effects."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = md_text

        buf = StringIO()
        with patch.object(ckf, "KNOWN_FAILURES", mock_path), \
             patch("subprocess.run", side_effect=side_effects), \
             patch("sys.stdout", buf):
            rc = ckf.main()
        return rc, buf.getvalue()

    def _ok(self, returncode: int = 0, stdout: str = "") -> MagicMock:
        r = MagicMock()
        r.returncode = returncode
        r.stdout = stdout
        return r

    # ------------------------------------------------------------------ #
    # Exit-0 cases                                                          #
    # ------------------------------------------------------------------ #

    def test_all_open_exits_zero(self) -> None:
        effects = [
            self._ok(0, _OPEN_OUTPUT),
            self._ok(0, _IN_PROGRESS_OUTPUT),
        ]
        rc, out = self._run_main(_ACTIVE_MD, effects)
        self.assertEqual(rc, 0)
        self.assertNotIn("STALE", out)

    def test_empty_active_table_exits_zero(self) -> None:
        rc, out = self._run_main(_EMPTY_ACTIVE_MD, [])
        self.assertEqual(rc, 0)
        self.assertIn("empty", out)

    # ------------------------------------------------------------------ #
    # Exit-1 cases                                                          #
    # ------------------------------------------------------------------ #

    def test_closed_bead_exits_one(self) -> None:
        effects = [self._ok(0, _CLOSED_OUTPUT)]
        rc, out = self._run_main(_ACTIVE_CLOSED_MD, effects)
        self.assertEqual(rc, 1)
        self.assertIn("STALE", out)
        self.assertIn("CLOSED", out)
        self.assertIn("red-cell-c2-ccccc", out)

    def test_not_found_bead_exits_one(self) -> None:
        effects = [self._ok(1, "")]
        rc, out = self._run_main(_ACTIVE_NOT_FOUND_MD, effects)
        self.assertEqual(rc, 1)
        self.assertIn("NOT_FOUND", out)

    def test_unknown_timeout_exits_one(self) -> None:
        effects = [subprocess.TimeoutExpired(["br"], 15)]
        md = _ACTIVE_NOT_FOUND_MD.replace("red-cell-c2-xxxxx", "red-cell-c2-eeeee")
        rc, out = self._run_main(md, effects)
        self.assertEqual(rc, 1)
        self.assertIn("UNKNOWN", out)

    def test_unknown_unrecognized_output_exits_one(self) -> None:
        effects = [self._ok(0, _UNKNOWN_OUTPUT)]
        md = _ACTIVE_NOT_FOUND_MD.replace("red-cell-c2-xxxxx", "red-cell-c2-ddddd")
        rc, out = self._run_main(md, effects)
        self.assertEqual(rc, 1)
        self.assertIn("UNKNOWN", out)

    def test_missing_known_failures_returns_2(self) -> None:
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = False
        with patch.object(ckf, "KNOWN_FAILURES", mock_path), \
             patch("sys.stderr", StringIO()):
            rc = ckf.main()
        self.assertEqual(rc, 2)

    def test_mixed_stale_reports_all(self) -> None:
        effects = [
            self._ok(0, _OPEN_OUTPUT),        # red-cell-c2-aaaaa → OPEN
            self._ok(0, _CLOSED_OUTPUT),       # red-cell-c2-ccccc → CLOSED
            subprocess.TimeoutExpired(["br"], 15),  # red-cell-c2-eeeee → UNKNOWN
        ]
        rc, out = self._run_main(_ACTIVE_MIXED_MD, effects)
        self.assertEqual(rc, 1)
        self.assertIn("red-cell-c2-ccccc", out)
        self.assertIn("red-cell-c2-eeeee", out)
        self.assertNotIn("• red-cell-c2-aaaaa", out)


class TestParseActiveBeads(unittest.TestCase):
    def test_extracts_bead_ids(self) -> None:
        ids = ckf._parse_active_beads(_ACTIVE_MD)
        self.assertEqual(ids, ["red-cell-c2-aaaaa", "red-cell-c2-bbbbb"])

    def test_deduplicates(self) -> None:
        text = "## Active\nred-cell-c2-aaaaa red-cell-c2-aaaaa\n---\n"
        ids = ckf._parse_active_beads(text)
        self.assertEqual(ids, ["red-cell-c2-aaaaa"])

    def test_empty_section_returns_empty(self) -> None:
        ids = ckf._parse_active_beads(_EMPTY_ACTIVE_MD)
        self.assertEqual(ids, [])

    def test_no_active_section_returns_empty(self) -> None:
        ids = ckf._parse_active_beads("## Resolved\nsome stuff\n---\n")
        self.assertEqual(ids, [])


if __name__ == "__main__":
    unittest.main()
