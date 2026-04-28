from __future__ import annotations

import importlib.util as _ilu
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

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


if __name__ == "__main__":
    unittest.main()
