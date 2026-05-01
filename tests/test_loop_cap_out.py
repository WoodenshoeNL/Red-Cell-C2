"""
Unit tests for the error_max_turns (cap-out) handling in loop.py.

Covers:
- extract_cap_out_checkpoint: checkpoint extraction from output/summary
- release_cap_out_bead: bead reset to open + checkpoint note written
- filter_cap_out_candidates: skip-list filtering with fallback for single-bead queues
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, call

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from loop import extract_cap_out_checkpoint, release_cap_out_bead, filter_cap_out_candidates


class _FakeLogger:
    def __init__(self):
        self.messages: list = []

    def log(self, msg: str) -> None:
        self.messages.append(msg)


class _FakeResult:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


# ── extract_cap_out_checkpoint ────────────────────────────────────────────────


class TestExtractCapOutCheckpoint(unittest.TestCase):
    def test_uses_summary_when_available(self):
        summary = ["Task: abc123", "Status: closed", "What changed:", "- fixed the bug"]
        result = extract_cap_out_checkpoint("lots of output here", summary)
        self.assertIn("Task: abc123", result)
        self.assertIn("fixed the bug", result)

    def test_summary_takes_precedence_over_output(self):
        summary = ["summary line"]
        result = extract_cap_out_checkpoint("output that should be ignored", summary)
        self.assertNotIn("output that should be ignored", result)
        self.assertIn("summary line", result)

    def test_falls_back_to_last_2048_chars_of_output(self):
        long_output = "A" * 3000 + "B" * 2048
        result = extract_cap_out_checkpoint(long_output, [])
        self.assertEqual(len(result), 2048)
        self.assertTrue(result.startswith("B"))

    def test_short_output_returned_as_is(self):
        result = extract_cap_out_checkpoint("short output", [])
        self.assertEqual(result, "short output")

    def test_empty_output_returns_empty_string(self):
        result = extract_cap_out_checkpoint("", [])
        self.assertEqual(result, "")

    def test_summary_capped_at_2048(self):
        summary = ["x" * 3000]
        result = extract_cap_out_checkpoint("", summary)
        self.assertLessEqual(len(result), 2048)

    def test_empty_summary_falls_back_to_output(self):
        result = extract_cap_out_checkpoint("fallback output", [])
        self.assertEqual(result, "fallback output")


# ── release_cap_out_bead ──────────────────────────────────────────────────────


class TestReleaseCapOutBead(unittest.TestCase):
    def _mock_br(self, calls):
        def side_effect(args):
            calls.append(list(args))
            return _FakeResult()
        return side_effect

    def test_calls_br_update_with_open_status(self):
        calls = []
        log = _FakeLogger()
        with patch("loop.br", side_effect=self._mock_br(calls)), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", "checkpoint text", "agent1", log)

        update_calls = [c for c in calls if c[0] == "update" and "abc-123" in c]
        self.assertTrue(update_calls, "should have called br update with task id")
        combined = " ".join(str(t) for c in update_calls for t in c)
        self.assertIn("--status=open", combined)

    def test_clears_owner_field(self):
        calls = []
        log = _FakeLogger()
        with patch("loop.br", side_effect=self._mock_br(calls)), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", "checkpoint text", "agent1", log)

        update_calls = [c for c in calls if c[0] == "update" and "abc-123" in c]
        self.assertTrue(update_calls)
        # --owner "" must be present (empty string clears the owner)
        self.assertTrue(
            any("--owner" in c for c in update_calls),
            f"--owner flag not found in br calls: {update_calls}",
        )
        for c in update_calls:
            if "--owner" in c:
                owner_idx = c.index("--owner")
                self.assertEqual(c[owner_idx + 1], "", f"owner should be cleared (empty string), got {c[owner_idx + 1]!r}")

    def test_writes_checkpoint_in_notes(self):
        calls = []
        log = _FakeLogger()
        with patch("loop.br", side_effect=self._mock_br(calls)), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", "my checkpoint text", "agent1", log)

        update_calls = [c for c in calls if c[0] == "update" and "abc-123" in c]
        self.assertTrue(any("--notes" in c for c in update_calls))
        for c in update_calls:
            if "--notes" in c:
                note_idx = c.index("--notes")
                note_val = c[note_idx + 1]
                self.assertIn("my checkpoint text", note_val)

    def test_note_length_capped_at_4000_chars(self):
        calls = []
        log = _FakeLogger()
        long_checkpoint = "x" * 5000
        with patch("loop.br", side_effect=self._mock_br(calls)), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", long_checkpoint, "agent1", log)

        for c in calls:
            if "--notes" in c:
                note_idx = c.index("--notes")
                note_val = c[note_idx + 1]
                self.assertLessEqual(len(note_val), 4000, "note must be ≤ 4000 chars")

    def test_empty_checkpoint_writes_fallback_message(self):
        calls = []
        log = _FakeLogger()
        with patch("loop.br", side_effect=self._mock_br(calls)), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", "", "agent1", log)

        for c in calls:
            if "--notes" in c:
                note_idx = c.index("--notes")
                note_val = c[note_idx + 1]
                self.assertIn("turn limit", note_val)

    def test_empty_checkpoint_writes_token_limit_fallback(self):
        calls = []
        log = _FakeLogger()
        with patch("loop.br", side_effect=self._mock_br(calls)), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", "", "agent1", log, cause="token_limit")

        for c in calls:
            if "--notes" in c:
                note_idx = c.index("--notes")
                note_val = c[note_idx + 1]
                self.assertIn("token limit", note_val)
                self.assertNotIn("turn limit", note_val)

    def test_calls_commit_beads_if_dirty(self):
        log = _FakeLogger()
        with patch("loop.br", return_value=_FakeResult()), \
             patch("loop.commit_beads_if_dirty", return_value=True) as mock_commit:
            release_cap_out_bead("abc-123", "cp", "agent1", log)
        mock_commit.assert_called_once()
        reason = mock_commit.call_args[0][0]
        self.assertIn("abc-123", reason)
        self.assertIn("cap-out", reason)

    def test_logs_reset_confirmation(self):
        log = _FakeLogger()
        with patch("loop.br", return_value=_FakeResult()), \
             patch("loop.commit_beads_if_dirty", return_value=True):
            release_cap_out_bead("abc-123", "cp", "agent1", log)
        self.assertTrue(
            any("abc-123" in m and "open" in m for m in log.messages),
            f"Expected a log message confirming reset to open, got: {log.messages}",
        )


# ── filter_cap_out_candidates ─────────────────────────────────────────────────


class TestFilterCapOutCandidates(unittest.TestCase):
    def test_returns_non_skipped_candidates(self):
        candidates = ["a", "b", "c"]
        skip = {"a"}
        result, consumed = filter_cap_out_candidates(candidates, skip)
        self.assertEqual(result, ["b", "c"])
        self.assertEqual(consumed, {"a"})

    def test_all_skipped_falls_back_to_full_list(self):
        """When all candidates are in the skip set (only 1 bead available), allow them."""
        candidates = ["a"]
        skip = {"a"}
        result, consumed = filter_cap_out_candidates(candidates, skip)
        self.assertEqual(result, ["a"], "should fall back to full list when all are skipped")
        self.assertEqual(consumed, {"a"})

    def test_multiple_skipped_falls_back_when_all_skipped(self):
        candidates = ["a", "b"]
        skip = {"a", "b"}
        result, consumed = filter_cap_out_candidates(candidates, skip)
        self.assertCountEqual(result, ["a", "b"])
        self.assertEqual(consumed, {"a", "b"})

    def test_no_overlap_with_skip_list(self):
        candidates = ["x", "y"]
        skip = {"z", "w"}
        result, consumed = filter_cap_out_candidates(candidates, skip)
        self.assertEqual(result, ["x", "y"])
        self.assertEqual(consumed, set())

    def test_empty_candidates_list(self):
        result, consumed = filter_cap_out_candidates([], {"a", "b"})
        self.assertEqual(result, [])
        self.assertEqual(consumed, set())

    def test_empty_skip_set(self):
        candidates = ["a", "b", "c"]
        result, consumed = filter_cap_out_candidates(candidates, set())
        self.assertEqual(result, ["a", "b", "c"])
        self.assertEqual(consumed, set())

    def test_preserves_candidate_order(self):
        candidates = ["c", "a", "b"]
        skip = {"a"}
        result, _ = filter_cap_out_candidates(candidates, skip)
        self.assertEqual(result, ["c", "b"])

    def test_consumed_entries_are_subset_of_skip(self):
        candidates = ["a", "c"]
        skip = {"a", "b"}
        _, consumed = filter_cap_out_candidates(candidates, skip)
        self.assertEqual(consumed, {"a"})  # "b" was in skip but not in candidates


if __name__ == "__main__":
    unittest.main()
