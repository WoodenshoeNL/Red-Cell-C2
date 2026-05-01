"""
Unit tests for extract_pre_claim_verdict in loop.py.

Covers:
- Single result block: PASS, REFINED, BLOCKED each parse correctly
- Multiple result blocks: rfind selects the last one (not the first)
- Missing end marker → UNKNOWN
- Missing start marker → UNKNOWN
- Unknown verdict string → UNKNOWN (not propagated as-is)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from loop import extract_pre_claim_verdict


def _make_block(verdict: str, reason: str) -> str:
    return (
        "=== PRE-CLAIM QA RESULT ===\n"
        f"Verdict: {verdict}\n"
        f"Reason: {reason}\n"
        "=== END PRE-CLAIM QA ==="
    )


class TestSingleBlock(unittest.TestCase):
    def test_pass(self):
        output = _make_block("PASS", "looks good")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(reason, "looks good")

    def test_refined(self):
        output = _make_block("REFINED", "minor tweak needed")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "REFINED")
        self.assertEqual(reason, "minor tweak needed")

    def test_blocked(self):
        output = _make_block("BLOCKED", "critical issue found")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "BLOCKED")
        self.assertEqual(reason, "critical issue found")

    def test_verdict_case_insensitive(self):
        output = _make_block("pass", "lowercase verdict")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(reason, "lowercase verdict")

    def test_reason_with_colons(self):
        output = _make_block("PASS", "reason: has colons: inside")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(reason, "reason: has colons: inside")


class TestMultipleBlocks(unittest.TestCase):
    def test_rfind_selects_last_block(self):
        # Simulate prompt example block (first) followed by real result block (last).
        prompt_example = _make_block("BLOCKED", "this is just an example")
        real_result = _make_block("PASS", "actual result")
        output = f"Some preamble\n{prompt_example}\nSome middle text\n{real_result}\nTrailing text"
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(reason, "actual result")

    def test_rfind_selects_last_of_three_blocks(self):
        block1 = _make_block("BLOCKED", "block one")
        block2 = _make_block("REFINED", "block two")
        block3 = _make_block("PASS", "block three")
        output = f"{block1}\n{block2}\n{block3}"
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(reason, "block three")


class TestMissingMarkers(unittest.TestCase):
    def test_missing_end_marker(self):
        output = "=== PRE-CLAIM QA RESULT ===\nVerdict: PASS\nReason: good\n"
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no structured result block", reason)

    def test_missing_start_marker(self):
        output = "Verdict: PASS\nReason: good\n=== END PRE-CLAIM QA ==="
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no structured result block", reason)

    def test_empty_output(self):
        verdict, reason = extract_pre_claim_verdict("")
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no structured result block", reason)

    def test_end_marker_before_start_marker(self):
        # end marker appears before start marker — end search from start=-1 wraps to 0,
        # which can find a spurious match; the function should return UNKNOWN.
        output = "=== END PRE-CLAIM QA ===\nsome text\n=== PRE-CLAIM QA RESULT ===\n"
        verdict, _ = extract_pre_claim_verdict(output)
        # start is the last occurrence of the start marker (valid), but end search
        # from that position finds nothing → UNKNOWN.
        self.assertEqual(verdict, "UNKNOWN")


class TestUnknownVerdict(unittest.TestCase):
    def test_garbage_verdict_becomes_unknown(self):
        output = _make_block("MAYBE", "not sure")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "UNKNOWN")
        # reason is still parsed even when verdict is unknown
        self.assertEqual(reason, "not sure")

    def test_empty_verdict_becomes_unknown(self):
        output = _make_block("", "no verdict line value")
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "UNKNOWN")

    def test_no_verdict_line_returns_unknown(self):
        output = (
            "=== PRE-CLAIM QA RESULT ===\n"
            "Reason: something\n"
            "=== END PRE-CLAIM QA ==="
        )
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertEqual(reason, "something")

    def test_no_reason_line_returns_empty_reason(self):
        output = (
            "=== PRE-CLAIM QA RESULT ===\n"
            "Verdict: PASS\n"
            "=== END PRE-CLAIM QA ==="
        )
        verdict, reason = extract_pre_claim_verdict(output)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(reason, "")


if __name__ == "__main__":
    unittest.main()
