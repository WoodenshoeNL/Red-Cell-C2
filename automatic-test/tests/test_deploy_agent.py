"""
tests/test_deploy_agent.py — Unit tests for lib/deploy_agent.py.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.deploy import TargetConfig
from lib.deploy_agent import deploy_and_checkin

_MODULE_KEY_PATH: str | None = None


def _module_key_path() -> str:
    global _MODULE_KEY_PATH
    if _MODULE_KEY_PATH is None:
        fd, path = tempfile.mkstemp(prefix="deploy-agent-test-key-")
        os.close(fd)
        _MODULE_KEY_PATH = path
    return _MODULE_KEY_PATH


def _make_linux_target(**kwargs) -> TargetConfig:
    defaults = dict(
        host="192.168.1.10",
        port=22,
        user="testuser",
        work_dir="/tmp/rc-test",
        key=_module_key_path(),
    )
    defaults.update(kwargs)
    return TargetConfig(**defaults)


def _make_fake_ctx():
    ctx = MagicMock()
    ctx.env = {}
    ctx.timeouts = None
    return ctx


def _infrastructure_patches(execute_background_mock):
    """Return patches needed to run deploy_and_checkin without live infrastructure."""
    return [
        patch("lib.deploy_agent.agent_list", return_value=[]),
        patch("lib.deploy_agent.maybe_flush_payload_cache_for_rust_agent"),
        patch("lib.deploy_agent.payload_build_and_fetch", return_value=b"fake_payload"),
        patch("lib.deploy_agent.ensure_work_dir"),
        patch("lib.deploy_agent.upload"),
        patch("lib.deploy_agent.run_remote"),
        patch("lib.deploy_agent.execute_background", execute_background_mock),
        patch(
            "lib.deploy_agent.wait_for_agent",
            return_value={"id": "test-agent-001"},
        ),
    ]


class TestDeployAndCheckinExecEnvForwarding(unittest.TestCase):
    """deploy_and_checkin must forward exec_env verbatim to execute_background."""

    def _run_deploy(self, exec_bg_mock, **deploy_kwargs):
        ctx = _make_fake_ctx()
        target = _make_linux_target()
        cli = MagicMock()
        patches = _infrastructure_patches(exec_bg_mock)
        for p in patches:
            p.start()
        try:
            return deploy_and_checkin(
                ctx=ctx,
                cli=cli,
                target=target,
                agent_type="phantom",
                fmt="exe",
                listener_name="test-listener",
                **deploy_kwargs,
            )
        finally:
            for p in patches:
                p.stop()

    def test_exec_env_forwarded_as_env_vars_kwarg(self) -> None:
        """exec_env dict must arrive at execute_background as env_vars=."""
        exec_bg = MagicMock()
        env = {"DISPLAY": ":99"}
        self._run_deploy(exec_bg, exec_env=env)
        exec_bg.assert_called_once()
        _, kwargs = exec_bg.call_args
        self.assertEqual(
            kwargs.get("env_vars"),
            env,
            "execute_background must receive env_vars equal to exec_env",
        )

    def test_exec_env_none_forwarded_when_not_provided(self) -> None:
        """When exec_env is omitted, execute_background receives env_vars=None."""
        exec_bg = MagicMock()
        self._run_deploy(exec_bg)
        exec_bg.assert_called_once()
        _, kwargs = exec_bg.call_args
        self.assertIsNone(
            kwargs.get("env_vars"),
            "execute_background must receive env_vars=None when exec_env is not provided",
        )

    def test_exec_env_with_multiple_vars_forwarded_intact(self) -> None:
        """A multi-key exec_env must be forwarded without modification."""
        exec_bg = MagicMock()
        env = {"DISPLAY": ":99", "HOME": "/home/testuser", "SECRET": "$token"}
        self._run_deploy(exec_bg, exec_env=env)
        exec_bg.assert_called_once()
        _, kwargs = exec_bg.call_args
        self.assertEqual(kwargs.get("env_vars"), env)
