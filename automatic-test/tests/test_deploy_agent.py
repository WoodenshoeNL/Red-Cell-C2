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
from lib.deploy_agent import ProbeAbortError, deploy_and_checkin

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


def _make_windows_target(**kwargs) -> TargetConfig:
    defaults = dict(
        host="192.168.1.50",
        port=22,
        user="rctest",
        work_dir="C:\\Temp\\rc-test",
        key=_module_key_path(),
        platform="windows",
    )
    defaults.update(kwargs)
    return TargetConfig(**defaults)


class TestProbeAbortError(unittest.TestCase):
    """deploy_and_checkin must raise ProbeAbortError when a probe pattern matches."""

    def _run_deploy_with_probe(
        self,
        probe_output: str,
        probe_abort_patterns: list[str] | None,
    ):
        """Run deploy_and_checkin on a Windows target with a mocked probe."""
        ctx = _make_fake_ctx()
        target = _make_windows_target()
        cli = MagicMock()
        exec_bg = MagicMock(return_value=None)
        patches = [
            patch("lib.deploy_agent.agent_list", return_value=[]),
            patch("lib.deploy_agent.maybe_flush_payload_cache_for_rust_agent"),
            patch("lib.deploy_agent.payload_build_and_fetch", return_value=b"fake_payload"),
            patch("lib.deploy_agent.ensure_work_dir"),
            patch("lib.deploy_agent.upload"),
            patch("lib.deploy_agent.defender_add_process_exclusion"),
            patch("lib.deploy_agent.windows_sync_payload_probe", return_value=probe_output),
            patch("lib.deploy_agent.execute_background", exec_bg),
            patch(
                "lib.deploy_agent.wait_for_agent",
                return_value={"id": "test-agent-001"},
            ),
        ]
        for p in patches:
            p.start()
        try:
            return deploy_and_checkin(
                ctx=ctx,
                cli=cli,
                target=target,
                agent_type="specter",
                fmt="exe",
                listener_name="test-listener",
                windows_prelaunch_probe=True,
                probe_abort_patterns=probe_abort_patterns,
            ), exec_bg
        finally:
            for p in patches:
                p.stop()

    def test_probe_abort_raises_when_pattern_matches(self) -> None:
        """ProbeAbortError must be raised if probe output contains a pattern."""
        probe_out = (
            "PROBE_TIMEOUT_MS\n"
            "PROBE_STDOUT:tcp connect error: ... (os error 10055)\n"
        )
        with self.assertRaises(ProbeAbortError):
            self._run_deploy_with_probe(probe_out, ["os error 10055"])

    def test_probe_abort_does_not_launch_background(self) -> None:
        """When ProbeAbortError fires, execute_background must NOT be called."""
        probe_out = "PROBE_TIMEOUT_MS\nPROBE_STDOUT:os error 10055\n"
        exec_bg_outer = MagicMock(return_value=None)
        # Patch execute_background at the module level so we can inspect it after raise.
        ctx = _make_fake_ctx()
        target = _make_windows_target()
        cli = MagicMock()
        patches = [
            patch("lib.deploy_agent.agent_list", return_value=[]),
            patch("lib.deploy_agent.maybe_flush_payload_cache_for_rust_agent"),
            patch("lib.deploy_agent.payload_build_and_fetch", return_value=b"fake_payload"),
            patch("lib.deploy_agent.ensure_work_dir"),
            patch("lib.deploy_agent.upload"),
            patch("lib.deploy_agent.defender_add_process_exclusion"),
            patch("lib.deploy_agent.windows_sync_payload_probe", return_value=probe_out),
            patch("lib.deploy_agent.execute_background", exec_bg_outer),
            patch("lib.deploy_agent.wait_for_agent", return_value={"id": "test-agent-001"}),
        ]
        for p in patches:
            p.start()
        try:
            with self.assertRaises(ProbeAbortError):
                deploy_and_checkin(
                    ctx=ctx, cli=cli, target=target,
                    agent_type="specter", fmt="exe", listener_name="test-listener",
                    windows_prelaunch_probe=True,
                    probe_abort_patterns=["os error 10055"],
                )
        finally:
            for p in patches:
                p.stop()
        exec_bg_outer.assert_not_called()

    def test_no_probe_abort_when_pattern_absent(self) -> None:
        """No ProbeAbortError when probe output does not match any pattern."""
        probe_out = "PROBE_TIMEOUT_MS\nPROBE_STDOUT:agent initialized\n"
        result, exec_bg = self._run_deploy_with_probe(probe_out, ["os error 10055"])
        self.assertEqual(result["id"], "test-agent-001")
        exec_bg.assert_called_once()

    def test_no_probe_abort_when_patterns_is_none(self) -> None:
        """When probe_abort_patterns is None, deploy always proceeds regardless of output."""
        probe_out = "PROBE_TIMEOUT_MS\nPROBE_STDOUT:os error 10055\n"
        result, exec_bg = self._run_deploy_with_probe(probe_out, None)
        self.assertEqual(result["id"], "test-agent-001")
        exec_bg.assert_called_once()

    def test_probe_abort_on_first_matching_pattern(self) -> None:
        """ProbeAbortError fires on the first pattern that matches."""
        probe_out = "PROBE_STDOUT:os error 10055 and WSAENOBUFS\n"
        with self.assertRaises(ProbeAbortError) as cm:
            self._run_deploy_with_probe(probe_out, ["os error 10055", "WSAENOBUFS"])
        self.assertIn("os error 10055", str(cm.exception))
