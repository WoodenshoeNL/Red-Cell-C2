"""
Unit tests for payload_build / payload_build_and_fetch agent-type guard.

Verifies that:
  - Demon builds are accepted and forwarded to the CLI subprocess.
  - Non-Demon builds raise AgentNotSupportedError immediately, without
    ever invoking the CLI binary.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import AgentNotSupportedError, CliConfig, payload_build, payload_build_and_fetch


_CFG = CliConfig(server="https://127.0.0.1:40056", token="test-token")

_DEMON_BUILD_RESPONSE = {"ok": True, "id": 42, "size_bytes": 1024}


class TestPayloadBuildAgentGuard(unittest.TestCase):
    def test_demon_agent_accepted(self) -> None:
        with patch("lib.cli._run", return_value=_DEMON_BUILD_RESPONSE) as mock_run:
            result = payload_build(_CFG, listener="test-listener", agent="demon")
        self.assertEqual(result["id"], 42)
        mock_run.assert_called_once()

    def test_default_agent_is_demon(self) -> None:
        with patch("lib.cli._run", return_value=_DEMON_BUILD_RESPONSE) as mock_run:
            result = payload_build(_CFG, listener="test-listener")
        self.assertEqual(result["id"], 42)
        mock_run.assert_called_once()

    def test_phantom_agent_raises_not_supported(self) -> None:
        with patch("lib.cli._run") as mock_run:
            with self.assertRaises(AgentNotSupportedError) as ctx:
                payload_build(_CFG, listener="test-listener", agent="phantom")
        mock_run.assert_not_called()
        self.assertIn("phantom", str(ctx.exception))
        self.assertIn("red-cell-c2-iyl94", str(ctx.exception))

    def test_specter_agent_raises_not_supported(self) -> None:
        with patch("lib.cli._run") as mock_run:
            with self.assertRaises(AgentNotSupportedError) as ctx:
                payload_build(_CFG, listener="test-listener", agent="specter")
        mock_run.assert_not_called()
        self.assertIn("specter", str(ctx.exception))

    def test_archon_agent_raises_not_supported(self) -> None:
        with patch("lib.cli._run") as mock_run:
            with self.assertRaises(AgentNotSupportedError) as ctx:
                payload_build(_CFG, listener="test-listener", agent="archon")
        mock_run.assert_not_called()
        self.assertIn("archon", str(ctx.exception))

    def test_agent_not_supported_error_stores_agent_name(self) -> None:
        exc = AgentNotSupportedError("phantom")
        self.assertEqual(exc.agent, "phantom")


class TestPayloadBuildAndFetchAgentGuard(unittest.TestCase):
    def test_non_demon_raises_before_subprocess(self) -> None:
        with patch("lib.cli._run") as mock_run:
            with self.assertRaises(AgentNotSupportedError):
                payload_build_and_fetch(_CFG, listener="test-listener", agent="phantom")
        mock_run.assert_not_called()

    def test_specter_raises_before_subprocess(self) -> None:
        with patch("lib.cli._run") as mock_run:
            with self.assertRaises(AgentNotSupportedError) as ctx:
                payload_build_and_fetch(_CFG, listener="test-listener", agent="specter")
        mock_run.assert_not_called()
        self.assertIn("specter", str(ctx.exception))

    def test_demon_does_not_raise_agent_not_supported(self) -> None:
        # Demon must not raise AgentNotSupportedError; _run will raise because
        # there is no real CLI binary — we only care that the guard is not the
        # cause of any exception.
        with patch("lib.cli._run", return_value={"ok": True, "id": 1, "size_bytes": 0}):
            with patch("lib.cli.payload_download"):
                try:
                    payload_build_and_fetch(_CFG, listener="test-listener", agent="demon")
                except AgentNotSupportedError:
                    self.fail("payload_build_and_fetch raised AgentNotSupportedError for demon")


if __name__ == "__main__":
    unittest.main()
