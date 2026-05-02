"""
Unit tests for lib.wait.poll (exponential backoff and jitter).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.wait import TimeoutError, poll


class TestPoll(unittest.TestCase):
    def test_returns_immediately_when_predicate_true_first_call(self) -> None:
        sleeps: list[float] = []

        def sleep_rec(d: float) -> None:
            sleeps.append(d)

        with patch("lib.wait.time.sleep", side_effect=sleep_rec):
            r = poll(lambda: 42, lambda x: x == 42, timeout=30, interval=1.0)
        self.assertEqual(r, 42)
        self.assertEqual(sleeps, [])

    def test_constant_interval_when_backoff_one_and_no_jitter(self) -> None:
        n = 0

        def fn() -> int:
            nonlocal n
            n += 1
            return n

        sleeps: list[float] = []

        def sleep_rec(d: float) -> None:
            sleeps.append(d)

        with patch("lib.wait.time.sleep", side_effect=sleep_rec):
            r = poll(
                fn,
                lambda x: x >= 3,
                timeout=30,
                interval=0.5,
                backoff=1.0,
                jitter=0.0,
            )
        self.assertEqual(r, 3)
        self.assertEqual(sleeps, [0.5, 0.5])

    def test_exponential_backoff_increases_sleep(self) -> None:
        n = 0

        def fn() -> int:
            nonlocal n
            n += 1
            return n

        sleeps: list[float] = []

        def sleep_rec(d: float) -> None:
            sleeps.append(d)

        with patch("lib.wait.time.sleep", side_effect=sleep_rec):
            with patch("lib.wait.random.uniform", return_value=0.0):
                r = poll(
                    fn,
                    lambda x: x >= 4,
                    timeout=100,
                    interval=1.0,
                    backoff=2.0,
                    max_interval=10.0,
                    jitter=0.0,
                )
        self.assertEqual(r, 4)
        self.assertEqual(sleeps, [1.0, 2.0, 4.0])

    def test_raises_timeout_after_deadline(self) -> None:
        clock = [0.0]

        def mono() -> float:
            return clock[0]

        def sleep_adv(d: float) -> None:
            clock[0] += d

        with patch("lib.wait.time.monotonic", side_effect=mono):
            with patch("lib.wait.time.sleep", side_effect=sleep_adv):
                with self.assertRaises(TimeoutError):
                    poll(
                        lambda: 0,
                        lambda x: False,
                        timeout=5,
                        interval=1.0,
                        description="never",
                    )
        self.assertGreaterEqual(clock[0], 5.0)

    def test_jitter_adds_to_sleep(self) -> None:
        n = 0

        def fn() -> int:
            nonlocal n
            n += 1
            return n

        sleeps: list[float] = []

        def sleep_rec(d: float) -> None:
            sleeps.append(d)

        with patch("lib.wait.time.sleep", side_effect=sleep_rec):
            with patch("lib.wait.random.uniform", return_value=0.15):
                poll(
                    fn,
                    lambda x: x >= 2,
                    timeout=30,
                    interval=1.0,
                    backoff=1.0,
                    jitter=0.2,
                )
        self.assertEqual(sleeps, [1.15])


class TestPollPeriodicCallback(unittest.TestCase):
    def test_periodic_callback_runs_during_wait(self) -> None:
        n = 0

        def fn() -> int:
            nonlocal n
            n += 1
            return n

        saw: list[int] = []

        def tick() -> None:
            saw.append(n)

        clock = [0.0]

        def mono() -> float:
            return clock[0]

        def sleep_adv(d: float) -> None:
            clock[0] += d

        with patch("lib.wait.time.monotonic", side_effect=mono):
            with patch("lib.wait.time.sleep", side_effect=sleep_adv):
                r = poll(
                    fn,
                    lambda x: x >= 5,
                    timeout=60,
                    interval=1.0,
                    backoff=1.0,
                    jitter=0.0,
                    periodic_interval=2.0,
                    periodic_callback=tick,
                )
        self.assertEqual(r, 5)
        self.assertGreaterEqual(len(saw), 1)


if __name__ == "__main__":
    unittest.main()
