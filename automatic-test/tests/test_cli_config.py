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
from lib.config import make_cli_config


class TestMakeCliConfig(unittest.TestCase):
    def test_uses_rest_url_and_api_key(self) -> None:
        env = {
            "server": {
                "url": "wss://127.0.0.1:40056",
                "rest_url": "https://127.0.0.1:40056",
            },
            "operator": {
                "username": "test-operator",
                "password": "changeme",
                "api_key": "test-api-key",
            },
            "timeouts": {"command_output": 45},
        }

        cfg = make_cli_config(env)

        self.assertEqual(cfg.server, "https://127.0.0.1:40056")
        self.assertEqual(cfg.token, "test-api-key")
        self.assertEqual(cfg.timeout, 45)

    def test_converts_websocket_url_when_rest_url_missing(self) -> None:
        env = {
            "server": {"url": "wss://teamserver.example:8443"},
            "operator": {"api_key": "test-api-key"},
        }

        cfg = make_cli_config(env)

        self.assertEqual(cfg.server, "https://teamserver.example:8443")

    def test_requires_explicit_api_key(self) -> None:
        env = {
            "server": {
                "url": "wss://127.0.0.1:40056",
                "rest_url": "https://127.0.0.1:40056",
            },
            "operator": {
                "username": "test-operator",
                "password": "changeme",
            },
        }

        with self.assertRaisesRegex(KeyError, "operator.api_key"):
            make_cli_config(env)


class TestLogin(unittest.TestCase):
    def test_login_validates_api_key_via_status(self) -> None:
        cfg = CliConfig(server="https://127.0.0.1:40056", token="test-api-key")

        with patch("lib.cli.status", return_value={"status": "ok"}) as mock_status:
            token = login(cfg)

        self.assertEqual(token, "test-api-key")
        mock_status.assert_called_once_with(cfg)


if __name__ == "__main__":
    unittest.main()
