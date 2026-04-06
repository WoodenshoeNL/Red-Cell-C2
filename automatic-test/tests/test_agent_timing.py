"""Unit tests for lib/agent_timing.py."""

from __future__ import annotations

import unittest

from lib.agent_timing import jitter_seconds, parse_last_seen, sleep_interval_seconds


class ParseLastSeenTests(unittest.TestCase):
    def test_parses_slash_format(self) -> None:
        dt = parse_last_seen("04/06/2026 14:30:00")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.day, 6)

    def test_parses_iso_t_format(self) -> None:
        dt = parse_last_seen("2026-04-06T14:30:00")
        self.assertEqual(dt.hour, 14)
        self.assertEqual(dt.minute, 30)


class SleepIntervalTests(unittest.TestCase):
    def test_sleep_interval_seconds(self) -> None:
        self.assertEqual(sleep_interval_seconds({"sleep_interval": 10}), 10)
        self.assertIsNone(sleep_interval_seconds({}))
        self.assertIsNone(sleep_interval_seconds({"sleep_interval": None}))

    def test_jitter_seconds(self) -> None:
        self.assertEqual(jitter_seconds({"jitter": 15}), 15)
        self.assertIsNone(jitter_seconds({}))


if __name__ == "__main__":
    unittest.main()
