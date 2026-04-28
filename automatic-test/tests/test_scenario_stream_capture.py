"""Unit tests for harness stdout/stderr capture during scenario runs."""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent


def _load_harness():
    name = "red_cell_automatic_test_harness"
    spec = importlib.util.spec_from_file_location(name, _PKG_ROOT / "test.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestScenarioStreamCapture(unittest.TestCase):
    def test_bounded_tail_utf8(self) -> None:
        harness = _load_harness()
        sink = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout = sink
            sys.stderr = sink
            with harness._ScenarioStreamCapture(max_chars=8) as cap:
                sys.stdout.write("abcdefghi")
            out, err = cap.tails()
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        self.assertEqual(out, "bcdefghi")
        self.assertEqual(err, "")
        self.assertEqual(sink.getvalue(), "abcdefghi")

    def test_stderr_captured_separately(self) -> None:
        harness = _load_harness()
        out_sink = io.StringIO()
        err_sink = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout = out_sink
            sys.stderr = err_sink
            with harness._ScenarioStreamCapture(max_chars=256) as cap:
                sys.stdout.write("out\n")
                sys.stderr.write("err\n")
            out, err = cap.tails()
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        self.assertEqual(out, "out\n")
        self.assertEqual(err, "err\n")
        self.assertEqual(out_sink.getvalue(), "out\n")
        self.assertEqual(err_sink.getvalue(), "err\n")
