"""Unit tests for lib/listeners.py helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.listeners import (
    collect_env_listener_bind_ports,
    http_listener_kwargs,
    normalize_callback_host_for_listener,
    resolve_listener_row_status,
)


class TestNormalizeCallbackHost(unittest.TestCase):
    def test_ipv4_strips_suffix_port(self) -> None:
        self.assertEqual(normalize_callback_host_for_listener("192.168.1.5:19081"), "192.168.1.5")

    def test_hostname_strips_suffix_port(self) -> None:
        self.assertEqual(normalize_callback_host_for_listener("c2.example.com:443"), "c2.example.com")

    def test_preserves_host_without_port(self) -> None:
        self.assertEqual(normalize_callback_host_for_listener("10.0.0.2"), "10.0.0.2")

    def test_bracket_ipv6_strips_port(self) -> None:
        self.assertEqual(
            normalize_callback_host_for_listener("[2001:db8::1]:8443"),
            "[2001:db8::1]",
        )

    def test_bracket_ipv6_without_port(self) -> None:
        self.assertEqual(normalize_callback_host_for_listener("[2001:db8::1]"), "[2001:db8::1]")


class TestHttpListenerKwargs(unittest.TestCase):
    def test_normalizes_callback_host(self) -> None:
        env = {"server": {"callback_host": "10.0.0.1:19999"}}
        kw = http_listener_kwargs(19182, env)
        self.assertEqual(kw["port"], 19182)
        self.assertEqual(kw["hosts"], "10.0.0.1")

    def test_sets_legacy_mode_for_demon(self) -> None:
        env: dict = {"server": {}}
        kw = http_listener_kwargs(19081, env, agent_type="demon")
        self.assertEqual(kw["legacy_mode"], True)

    def test_no_legacy_for_archon_listener(self) -> None:
        env: dict = {"server": {}}
        kw = http_listener_kwargs(19082, env, agent_type="archon")
        self.assertNotIn("legacy_mode", kw)


class TestListenerRowStatus(unittest.TestCase):
    def test_flat_status(self) -> None:
        self.assertEqual(resolve_listener_row_status({"name": "a", "status": "Running"}), "running")

    def test_nested_state(self) -> None:
        self.assertEqual(
            resolve_listener_row_status(
                {"name": "a", "state": {"status": "Stopped", "last_error": None}}
            ),
            "stopped",
        )

    def test_flat_takes_precedence(self) -> None:
        self.assertEqual(
            resolve_listener_row_status(
                {"name": "a", "status": "Created", "state": {"status": "Running"}}
            ),
            "created",
        )

    def test_empty(self) -> None:
        self.assertEqual(resolve_listener_row_status({}), "")


class TestEnvListenerBindPorts(unittest.TestCase):
    def test_collects_ints_from_listeners(self) -> None:
        env = {
            "listeners": {
                "linux_port": 19181,
                "windows_port": 19182,
                "dns_port": 15354,
                "smb_pipe": "redcell",
            }
        }
        self.assertEqual(collect_env_listener_bind_ports(env), frozenset({19181, 19182, 15354}))

    def test_missing_stanza(self) -> None:
        self.assertEqual(collect_env_listener_bind_ports({}), frozenset())


if __name__ == "__main__":
    unittest.main()
