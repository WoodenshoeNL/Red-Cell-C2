"""
Tests for _clean_cargo_target_inplace — specifically the hard-limit override
that forces a clean even when _stable_cargo_target_in_use returns True.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from loop import _clean_cargo_target_inplace, TMP_CARGO_SIZE_LIMIT_GB, TMP_CARGO_HARD_LIMIT_GB


class _FakeLogger:
    def __init__(self):
        self.messages: list[str] = []

    def log(self, msg: str) -> None:
        self.messages.append(msg)


def _make_profile_dir(target: Path, profile: str = "debug") -> Path:
    """Create a realistic cargo profile directory with heavyweight subdirs."""
    p = target / profile
    for sub in ("deps", "build", "incremental", ".fingerprint"):
        (p / sub).mkdir(parents=True, exist_ok=True)
    return p


class TestCleanCargoTargetInplace(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.target = Path(self._tmp.name) / "red-cell-target-test"
        self.target.mkdir()
        _make_profile_dir(self.target)
        self.log = _FakeLogger()

    def tearDown(self):
        self._tmp.cleanup()

    def _deps_exist(self, profile: str = "debug") -> bool:
        return (self.target / profile / "deps").exists()

    # -- Below soft limit: nothing happens --

    def test_below_soft_limit_no_clean(self):
        with patch("loop._dir_size_gb", return_value=1.0), \
             patch("loop._stable_cargo_target_in_use", return_value=False):
            _clean_cargo_target_inplace(self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log)
        self.assertTrue(self._deps_exist(), "should not have cleaned below soft limit")
        self.assertEqual(self.log.messages, [])

    # -- Above soft limit, in-use, below hard limit: deferred --

    def test_above_soft_in_use_below_hard_defers(self):
        with patch("loop._dir_size_gb", return_value=TMP_CARGO_SIZE_LIMIT_GB + 1.0), \
             patch("loop._stable_cargo_target_in_use", return_value=True):
            _clean_cargo_target_inplace(self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log)
        self.assertTrue(self._deps_exist(), "should not have cleaned while in-use below hard limit")
        self.assertTrue(any("deferring" in m for m in self.log.messages), self.log.messages)

    # -- Above hard limit, in-use: forced clean --

    def test_above_hard_limit_in_use_forces_clean(self):
        with patch("loop._dir_size_gb", return_value=TMP_CARGO_HARD_LIMIT_GB + 1.0), \
             patch("loop._stable_cargo_target_in_use", return_value=True):
            _clean_cargo_target_inplace(self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log)
        self.assertFalse(self._deps_exist(), "deps should have been removed at hard limit")
        self.assertTrue(any("forcing" in m for m in self.log.messages), self.log.messages)

    # -- Above soft limit, not in-use: normal clean --

    def test_above_soft_not_in_use_cleans(self):
        with patch("loop._dir_size_gb", return_value=TMP_CARGO_SIZE_LIMIT_GB + 1.0), \
             patch("loop._stable_cargo_target_in_use", return_value=False):
            _clean_cargo_target_inplace(self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log)
        self.assertFalse(self._deps_exist(), "deps should have been removed")
        self.assertTrue(any("cleaning" in m for m in self.log.messages), self.log.messages)

    # -- Custom hard_limit_gb parameter --

    def test_custom_hard_limit_respected(self):
        """Caller can pass a custom hard_limit_gb (e.g. for testing or tuning)."""
        custom_hard = 8.0
        with patch("loop._dir_size_gb", return_value=custom_hard + 1.0), \
             patch("loop._stable_cargo_target_in_use", return_value=True):
            _clean_cargo_target_inplace(
                self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log,
                hard_limit_gb=custom_hard,
            )
        self.assertFalse(self._deps_exist(), "should clean at custom hard limit")

    # -- Exactly at hard limit: forced clean (>= boundary) --

    def test_exactly_at_hard_limit_forces_clean(self):
        with patch("loop._dir_size_gb", return_value=TMP_CARGO_HARD_LIMIT_GB), \
             patch("loop._stable_cargo_target_in_use", return_value=True):
            _clean_cargo_target_inplace(self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log)
        self.assertFalse(self._deps_exist(), "should force-clean at exactly hard limit")

    # -- Cross-compile layout (depth-2) cleaned under hard limit --

    def test_cross_compile_triple_cleaned_at_hard_limit(self):
        triple_dir = self.target / "x86_64-unknown-linux-musl"
        _make_profile_dir(triple_dir, "release")
        with patch("loop._dir_size_gb", return_value=TMP_CARGO_HARD_LIMIT_GB + 1.0), \
             patch("loop._stable_cargo_target_in_use", return_value=True):
            _clean_cargo_target_inplace(self.target, "test", TMP_CARGO_SIZE_LIMIT_GB, self.log)
        self.assertFalse(
            (triple_dir / "release" / "deps").exists(),
            "cross-compile deps should be cleaned at hard limit",
        )


if __name__ == "__main__":
    unittest.main()
