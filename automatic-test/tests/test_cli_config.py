"""
Unit tests for autotest CLI config resolution and auth helpers.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, login
from lib.config import ConfigError, make_cli_config


def _minimal_harness_env(*, command_output: int = 30) -> dict:
    """Valid env.toml-shaped dict for :func:`make_cli_config` (schema-complete)."""

    return {
        "server": {
            "url": "wss://127.0.0.1:40056",
            "rest_url": "https://127.0.0.1:40056",
        },
        "operator": {
            "username": "test-operator",
            "password": "changeme",
            "api_key": "test-api-key",
        },
        "timeouts": {
            "agent_checkin": 60,
            "command_output": command_output,
            "agent_disconnect": 30,
            "screenshot_loot": 30,
            "loot_entry": 30,
            "max_cli_subprocess_secs": 120,
        },
        "listeners": {
            "dns_port": 15353,
            "dns_domain": "c2.test.local",
            "linux_port": 19081,
            "windows_port": 19082,
            "payload_build_port": 19080,
            "protocol_probe_port": 19090,
            "interop_win_port": 19091,
            "interop_lin_port": 19092,
            "stress_port": 19093,
            "rbac_admin_port": 19098,
            "rbac_viewer_port": 19099,
            "smb_pipe": "redcell-c2",
        },
        "agents": {"available": ["demon"]},
    }


class TestMakeCliConfig(unittest.TestCase):
    def test_uses_rest_url_and_api_key(self) -> None:
        env = _minimal_harness_env(command_output=45)

        cfg = make_cli_config(env)

        self.assertEqual(cfg.server, "https://127.0.0.1:40056")
        self.assertEqual(cfg.token, "test-api-key")
        self.assertEqual(cfg.timeout, 45)

    def test_converts_websocket_url_when_rest_url_missing(self) -> None:
        env = _minimal_harness_env()
        env["server"] = {"url": "wss://teamserver.example:8443"}

        cfg = make_cli_config(env)

        self.assertEqual(cfg.server, "https://teamserver.example:8443")

    def test_requires_explicit_api_key(self) -> None:
        env = _minimal_harness_env()
        del env["operator"]["api_key"]

        with self.assertRaises(ConfigError) as cm:
            make_cli_config(env)
        self.assertIn("api_key", str(cm.exception))


class TestLogin(unittest.TestCase):
    def test_login_validates_api_key_via_status(self) -> None:
        cfg = CliConfig(server="https://127.0.0.1:40056", token="test-api-key")

        with patch("lib.cli.status", return_value={"status": "ok"}) as mock_status:
            token = login(cfg)

        self.assertEqual(token, "test-api-key")
        mock_status.assert_called_once_with(cfg)


if __name__ == "__main__":
    unittest.main()
