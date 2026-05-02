"""Tests for autotest cargo / sccache environment wiring in loop.py."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from loop import (  # noqa: E402
    AUTOTEST_SCCACHE_CACHE_SIZE_DEFAULT,
    _autotest_cargo_compile_env,
    autotest_sccache_prep,
)


class _FakeLogger:
    def __init__(self):
        self.messages: list[str] = []

    def log(self, msg: str) -> None:
        self.messages.append(msg)


class TestAutotestCargoCompileEnv(unittest.TestCase):
    def test_default_size_when_not_set(self):
        keys = ("SCCACHE_CACHE_SIZE", "RC_AUTOTEST_SCCACHE_CACHE_SIZE")
        saved = {k: os.environ.pop(k) for k in keys if k in os.environ}
        try:
            out = _autotest_cargo_compile_env({"HOME": "/tmp", "PATH": "/bin"})
            self.assertEqual(
                out.get("SCCACHE_CACHE_SIZE"),
                AUTOTEST_SCCACHE_CACHE_SIZE_DEFAULT,
            )
        finally:
            os.environ.update(saved)

    def test_respects_preset_sccache_cache_size(self):
        out = _autotest_cargo_compile_env({"SCCACHE_CACHE_SIZE": "2G"})
        self.assertEqual(out["SCCACHE_CACHE_SIZE"], "2G")

    def test_rc_override_when_sccache_size_unset(self):
        with patch.dict(
            os.environ,
            {"RC_AUTOTEST_SCCACHE_CACHE_SIZE": "3G"},
            clear=False,
        ):
            out = _autotest_cargo_compile_env({"PATH": "/bin"})
        self.assertEqual(out["SCCACHE_CACHE_SIZE"], "3G")


class TestAutotestSccachePrep(unittest.TestCase):
    def test_skipped_when_rc_flag_set(self):
        log = _FakeLogger()
        env = {"SCCACHE_CACHE_SIZE": "5G"}
        with patch.dict(os.environ, {"RC_AUTOTEST_SKIP_SCCACHE_PREP": "1"}):
            autotest_sccache_prep(log, env)
        self.assertTrue(any("skipped" in m for m in log.messages))


if __name__ == "__main__":
    unittest.main()
