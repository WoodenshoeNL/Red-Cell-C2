"""Unit tests for lib/resilience.py and deploy_and_checkin expect_checkin mode."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig
from lib.config import timeouts_for_unit_tests
from lib.deploy_agent import deploy_and_checkin
from lib.resilience import (
    extract_http_callback_host,
    http_listener_inner_config,
    pick_inactive_working_hours,
)
from lib.wait import TimeoutError as WaitTimeoutError

# Capture before any test patches replace ``tempfile.mkstemp`` on the module.
_REAL_MKSTEMP = tempfile.mkstemp


def _mkstemp_bin(*args: object, **kwargs: object) -> tuple[int, str]:
    return _REAL_MKSTEMP(*args, **kwargs)


class TestResilienceHelpers(unittest.TestCase):
    def test_extract_http_callback_host_from_rest_url(self) -> None:
        env = {"server": {"rest_url": "https://192.168.1.5:40056"}}
        self.assertEqual(extract_http_callback_host(env), "192.168.1.5")

    def test_extract_http_callback_host_fallback(self) -> None:
        env = {"server": {"url": "wss://127.0.0.1:40056"}}
        self.assertEqual(extract_http_callback_host(env), "127.0.0.1")

    def test_http_listener_inner_config_includes_hosts_and_extras(self) -> None:
        env = {"server": {"rest_url": "https://10.0.0.1:8443"}}
        inner = http_listener_inner_config("ln", 19100, env, kill_date="1234567890", working_hours="02:00-03:00")
        self.assertEqual(inner["name"], "ln")
        self.assertEqual(inner["port_bind"], 19100)
        self.assertEqual(inner["hosts"], ["10.0.0.1:19100"])
        self.assertEqual(inner["kill_date"], "1234567890")
        self.assertEqual(inner["working_hours"], "02:00-03:00")

    def test_pick_inactive_working_hours(self) -> None:
        self.assertEqual(pick_inactive_working_hours(14), "02:00-03:00")
        self.assertEqual(pick_inactive_working_hours(2), "10:00-11:00")


class TestDeployExpectCheckin(unittest.TestCase):
    def test_expect_checkin_false_returns_none_on_timeout(self) -> None:
        cli = CliConfig(server="https://x", token="t")
        ctx = MagicMock()
        ctx.env = {"timeouts": {"agent_checkin": 60, "working_hours_probe": 12}}
        ctx.timeouts = timeouts_for_unit_tests()

        target = MagicMock()
        target.work_dir = "/tmp/rc-test"
        target.host = "h"

        with (
            patch("lib.deploy_agent.agent_list", return_value=[]),
            patch("lib.deploy_agent.payload_build_and_fetch", return_value=b"MZ"),
            patch("lib.deploy_agent.tempfile.mkstemp", side_effect=_mkstemp_bin),
            patch("lib.deploy_agent.os.unlink"),
            patch("lib.deploy_agent.ensure_work_dir"),
            patch("lib.deploy_agent.upload"),
            patch("lib.deploy_agent.run_remote"),
            patch("lib.deploy_agent.execute_background"),
            patch(
                "lib.deploy_agent.wait_for_agent",
                side_effect=WaitTimeoutError("timed out"),
            ),
        ):
            out = deploy_and_checkin(
                ctx,
                cli,
                target,
                "demon",
                "bin",
                "listener-1",
                expect_checkin=False,
                no_checkin_timeout=12,
            )
        self.assertIsNone(out)

    def test_expect_checkin_false_raises_if_agent_appears(self) -> None:
        cli = CliConfig(server="https://x", token="t")
        ctx = MagicMock()
        ctx.env = {"timeouts": {"agent_checkin": 60}}
        ctx.timeouts = timeouts_for_unit_tests()

        target = MagicMock()
        target.work_dir = "/tmp/rc-test"

        with (
            patch("lib.deploy_agent.agent_list", return_value=[]),
            patch("lib.deploy_agent.payload_build_and_fetch", return_value=b"MZ"),
            patch("lib.deploy_agent.tempfile.mkstemp", side_effect=_mkstemp_bin),
            patch("lib.deploy_agent.os.unlink"),
            patch("lib.deploy_agent.ensure_work_dir"),
            patch("lib.deploy_agent.upload"),
            patch("lib.deploy_agent.run_remote"),
            patch("lib.deploy_agent.execute_background"),
            patch("lib.deploy_agent.wait_for_agent", return_value={"id": "deadbeef"}),
        ):
            with self.assertRaises(AssertionError) as cm:
                deploy_and_checkin(
                    ctx,
                    cli,
                    target,
                    "demon",
                    "bin",
                    "listener-1",
                    expect_checkin=False,
                    no_checkin_timeout=5,
                )
        self.assertIn("unexpectedly", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
