"""
Unit tests for lib.wait.wait_for_port.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.wait import ScenarioFailed, wait_for_port


def _bind_free_port() -> int:
    """Bind to an ephemeral port and return its number, then close."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestWaitForPort(unittest.TestCase):
    def test_succeeds_immediately_when_port_is_open(self) -> None:
        """wait_for_port returns as soon as the port accepts connections."""
        with socket.socket() as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            # Should not raise.
            wait_for_port("127.0.0.1", port, timeout=5.0)

    def test_raises_when_port_never_opens(self) -> None:
        """wait_for_port raises ScenarioFailed when the port stays closed."""
        port = _bind_free_port()
        with self.assertRaises(ScenarioFailed) as ctx:
            wait_for_port("127.0.0.1", port, timeout=0.5, interval=0.1)
        self.assertIn(str(port), str(ctx.exception))

    def test_succeeds_after_delayed_open(self) -> None:
        """wait_for_port retries and succeeds once the port becomes available."""
        port = _bind_free_port()
        ready = threading.Event()

        def _open_after_delay():
            time.sleep(0.3)
            with socket.socket() as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1", port))
                srv.listen(1)
                ready.set()
                conn, _ = srv.accept()
                conn.close()

        t = threading.Thread(target=_open_after_delay, daemon=True)
        t.start()
        wait_for_port("127.0.0.1", port, timeout=5.0, interval=0.1)
        ready.wait(timeout=2)
        t.join(timeout=2)

    def test_error_message_includes_host_and_port(self) -> None:
        """ScenarioFailed message identifies which host:port timed out."""
        port = _bind_free_port()
        with self.assertRaises(ScenarioFailed) as ctx:
            wait_for_port("127.0.0.1", port, timeout=0.2, interval=0.1)
        msg = str(ctx.exception)
        self.assertIn("127.0.0.1", msg)
        self.assertIn(str(port), msg)


if __name__ == "__main__":
    unittest.main()
