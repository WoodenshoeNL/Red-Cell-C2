"""
Unit tests for env.toml / targets.toml schema validation (lib.config).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.config import (
    ConfigError,
    load_env,
    load_targets,
    parse_env_config,
    parse_targets_config,
    timeouts_for_unit_tests,
    validate_env_dict,
    validate_targets_dict,
)


def _minimal_valid_env() -> dict:
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
            "command_output": 30,
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


def _minimal_valid_targets() -> dict:
    return {
        "linux": {
            "host": "10.0.0.1",
            "port": 22,
            "user": "u",
            "work_dir": "/tmp/rc",
            "key": "/home/u/.ssh/k",
        },
        "windows": {
            "host": "10.0.0.2",
            "port": 22,
            "user": "u",
            "work_dir": "C:\\Temp\\rc",
            "key": "/home/u/.ssh/k",
        },
    }


class TestValidateEnvDict(unittest.TestCase):
    def test_minimal_valid(self) -> None:
        validate_env_dict(_minimal_valid_env())

    def test_parse_returns_dataclass(self) -> None:
        cfg = parse_env_config(_minimal_valid_env())
        self.assertEqual(cfg.server.url, "wss://127.0.0.1:40056")
        self.assertEqual(cfg.agents.available, ["demon"])
        self.assertEqual(cfg.timeouts.listener_startup, 5.0)
        self.assertEqual(cfg.timeouts.poll_interval, 2.0)
        self.assertEqual(cfg.timeouts.ssh_connect, 10.0)

    def test_agent_checkin_secs_alias(self) -> None:
        raw = _minimal_valid_env()
        del raw["timeouts"]["agent_checkin"]
        del raw["timeouts"]["command_output"]
        raw["timeouts"]["agent_checkin_secs"] = 60
        raw["timeouts"]["command_output_secs"] = 30
        cfg = parse_env_config(raw)
        self.assertEqual(cfg.timeouts.agent_checkin, 60.0)
        self.assertEqual(cfg.timeouts.command_output, 30.0)

    def test_timeout_pair_conflict_errors(self) -> None:
        raw = _minimal_valid_env()
        raw["timeouts"]["agent_checkin_secs"] = 60
        raw["timeouts"]["agent_checkin"] = 99
        with self.assertRaises(ConfigError) as ctx:
            parse_env_config(raw)
        self.assertIn("agent_checkin_secs", str(ctx.exception))

    def test_timeouts_for_unit_tests(self) -> None:
        t = timeouts_for_unit_tests()
        self.assertEqual(t.poll_interval, 2.0)
        self.assertEqual(t.stress_concurrent_checkin, 30.0)

    def test_unknown_top_level_key(self) -> None:
        raw = _minimal_valid_env()
        raw["typo_section"] = {}
        with self.assertRaises(ConfigError) as ctx:
            validate_env_dict(raw)
        self.assertIn("typo_section", str(ctx.exception))

    def test_unknown_server_key(self) -> None:
        raw = _minimal_valid_env()
        raw["server"]["ur"] = "x"
        with self.assertRaises(ConfigError) as ctx:
            validate_env_dict(raw)
        self.assertIn("[server]", str(ctx.exception))
        self.assertIn("ur", str(ctx.exception))

    def test_missing_operator_api_key(self) -> None:
        raw = _minimal_valid_env()
        del raw["operator"]["api_key"]
        with self.assertRaises(ConfigError) as ctx:
            validate_env_dict(raw)
        self.assertIn("api_key", str(ctx.exception))

    def test_analyst_operator_empty_api_key_allowed(self) -> None:
        raw = _minimal_valid_env()
        raw["analyst_operator"] = {"username": "analyst", "api_key": ""}
        validate_env_dict(raw)
        cfg = parse_env_config(raw)
        assert cfg.analyst_operator is not None
        self.assertEqual(cfg.analyst_operator.api_key, "")

    def test_committed_env_toml_loads(self) -> None:
        path = Path(__file__).parent.parent / "config" / "env.toml"
        if not path.is_file():
            self.skipTest("config/env.toml not present")
        env = load_env(path)
        self.assertIn("server", env)
        self.assertIsInstance(env["agents"]["available"], list)


class TestValidateTargetsDict(unittest.TestCase):
    def test_minimal_valid(self) -> None:
        validate_targets_dict(_minimal_valid_targets())

    def test_unknown_stanza(self) -> None:
        raw = _minimal_valid_targets()
        raw["macos"] = {"host": "h"}
        with self.assertRaises(ConfigError) as ctx:
            validate_targets_dict(raw)
        self.assertIn("macos", str(ctx.exception))

    def test_linux_missing_key(self) -> None:
        raw = _minimal_valid_targets()
        del raw["linux"]["key"]
        with self.assertRaises(ConfigError) as ctx:
            validate_targets_dict(raw)
        self.assertIn("key", str(ctx.exception))

    def test_parse_returns_dataclass(self) -> None:
        cfg = parse_targets_config(_minimal_valid_targets())
        assert cfg.linux is not None
        self.assertEqual(cfg.linux.host, "10.0.0.1")

    def test_optional_windows2(self) -> None:
        raw = _minimal_valid_targets()
        raw["windows2"] = {
            "host": "10.0.0.3",
            "port": 22,
            "user": "u",
            "work_dir": "C:\\Temp\\rc",
            "key": "/k",
        }
        validate_targets_dict(raw)


class TestLoadTargetsFile(unittest.TestCase):
    def test_missing_file_returns_empty_dict(self) -> None:
        path = Path("/nonexistent/targets-9f3a.toml")
        self.assertEqual(load_targets(path), {})


class TestLoadEnvFile(unittest.TestCase):
    def test_load_env_validates(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False, mode="wb") as tmp:
            path = Path(tmp.name)
        try:
            toml_text = """
[server]
url = "wss://127.0.0.1:40056"
rest_url = "https://127.0.0.1:40056"

[operator]
username = "u"
password = "p"
api_key = "k"

[timeouts]
agent_checkin = 60
command_output = 30
agent_disconnect = 30
screenshot_loot = 30
loot_entry = 30
max_cli_subprocess_secs = 120

[listeners]
dns_port = 15353
dns_domain = "c2.test.local"
linux_port = 19081
windows_port = 19082
payload_build_port = 19080
protocol_probe_port = 19090
interop_win_port = 19091
interop_lin_port = 19092
stress_port = 19093
rbac_admin_port = 19098
rbac_viewer_port = 19099
smb_pipe = "redcell-c2"

[agents]
available = ["demon"]
"""
            path.write_text(toml_text, encoding="utf-8")
            loaded = load_env(path)
            self.assertEqual(loaded["operator"]["api_key"], "k")
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
