from __future__ import annotations

import importlib.util as _ilu
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped

_SCENARIO_PATH = (
    Path(__file__).parent.parent / "scenarios" / "06_file_transfer_file_transfer.py"
)
_spec = _ilu.spec_from_file_location("scenario_06_file_transfer_file_transfer", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class TestWaitForLocalFile(unittest.TestCase):
    def test_waits_until_file_is_non_empty(self) -> None:
        fd, path = tempfile.mkstemp()
        os.close(fd)
        os.unlink(path)

        def _writer() -> None:
            time.sleep(0.1)
            with open(path, "wb") as fh:
                fh.write(b"x")

        t = threading.Thread(target=_writer)
        t.start()
        try:
            _mod._wait_for_local_file(path, timeout=2)
        finally:
            t.join()
            if os.path.exists(path):
                os.unlink(path)

    def test_remote_sha_linux_retries_until_file_exists(self) -> None:
        target = object()
        calls = {"count": 0}

        def _fake_run_remote(_target, _command, timeout):
            calls["count"] += 1
            if calls["count"] < 3:
                raise RuntimeError("not yet")
            return "abc123  /tmp/file"

        with patch("lib.deploy.run_remote", side_effect=_fake_run_remote):
            sha = _mod._wait_for_remote_sha_linux(target, "/tmp/file", timeout=2)

        self.assertEqual(sha, "abc123")
        self.assertEqual(calls["count"], 3)


class TestWindowsDegradedSkipsWindowsPasses(unittest.TestCase):
    """windows_degraded=True must skip all Windows passes, preserving Linux coverage."""

    def _make_ctx(self, *, windows=True, linux=False, windows_degraded=True, env=None):
        ctx = MagicMock()
        ctx.windows_degraded = windows_degraded
        ctx.dry_run = False
        ctx.payload_parallel = True
        ctx.env = env or {}
        ctx.timeouts = MagicMock()
        ctx.linux = MagicMock() if linux else None
        ctx.windows = MagicMock() if windows else None
        return ctx

    def test_windows_degraded_no_linux_raises_scenario_skipped(self) -> None:
        """No Linux target + WFP-degraded Windows → ScenarioSkipped (no passes ran)."""
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=True)
        with patch("lib.deploy.preflight_ssh"):
            with self.assertRaises(ScenarioSkipped):
                _mod.run(ctx)

    def test_windows_degraded_false_does_not_skip_early(self) -> None:
        """windows_degraded=False must not trigger the early Windows skip."""
        from lib.cli import CliError
        ctx = self._make_ctx(windows=True, linux=False, windows_degraded=False,
                             env={"agents": {"available": ["demon"]}})
        # With no Linux target and degraded=False, run() proceeds into Windows passes
        # and will fail when trying to build payloads — that's a CliError, not ScenarioSkipped.
        with patch("lib.deploy.preflight_ssh"), \
             patch("lib.cli.listener_create"), \
             patch("lib.cli.listener_start"), \
             patch("lib.cli.listener_stop"), \
             patch("lib.cli.listener_delete"), \
             patch("lib.payload.build_parallel", side_effect=CliError("BUILD_FAILED", "build failed", 1)):
            with self.assertRaises(CliError):
                _mod.run(ctx)


if __name__ == "__main__":
    unittest.main()
