"""
Fail-fast behavior: if an agent type is listed in agents.available and its
payload build fails, the scenario must propagate the CliError instead of
swallowing it as a skip.

Covers scenarios 04, 05, 06, 07, 14, 15 (scenario 19 is covered by
test_scenario_19_cross_agent_interop.py).
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig, CliError


_SCENARIOS = Path(__file__).parent.parent / "scenarios"
_CFG = CliConfig(server="https://127.0.0.1:40056", token="test-token", timeout=3)


def _load(filename: str):
    """Load a scenario module by filename without registering it in sys.modules."""
    path = _SCENARIOS / filename
    stem = filename.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _linux_ctx():
    ctx = MagicMock()
    ctx.cli = _CFG
    ctx.env = {"agents": {"available": ["demon"]}, "listeners": {}, "timeouts": {}}
    ctx.linux = MagicMock()
    ctx.linux.work_dir = "/tmp/rc-test"
    ctx.linux.user = "testuser"
    ctx.windows = None
    ctx.dry_run = False
    return ctx


def _windows_ctx():
    ctx = MagicMock()
    ctx.cli = _CFG
    ctx.env = {"agents": {"available": ["demon"]}, "listeners": {}, "timeouts": {}}
    ctx.windows = MagicMock()
    ctx.windows.work_dir = "C:\\Temp\\rc-test"
    ctx.linux = None
    ctx.dry_run = False
    return ctx


# Shared patch set for _run_for_agent / _run_stress_for_agent: listener calls
# succeed, payload build raises CliError.
_BUILD_FAIL = CliError("BUILD_FAILED", "toolchain error", 1)
_LISTENER_PATCHES = [
    patch("lib.cli.listener_create", return_value={}),
    patch("lib.cli.listener_start", return_value={}),
    patch("lib.cli.payload_build_and_fetch", side_effect=_BUILD_FAIL),
]


def _apply_patches(patches):
    """Context manager that activates all patches and yields the CliError mock."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        stack = contextlib.ExitStack()
        for p in patches:
            stack.enter_context(p)
        with stack:
            yield

    return _ctx()


# ── Scenario 04: Linux agent (Demon + Phantom) ───────────────────────────────

class TestScenario04(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("04_agent_linux_linux_agent_checkin.py")

    def test_phantom_build_failure_propagates(self) -> None:
        ctx = _linux_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "phantom", "bin", "test-linux-phantom")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_phantom_skipped_when_not_in_available(self) -> None:
        """run() skips the phantom pass silently; no exception raised."""
        ctx = _linux_ctx()
        # phantom not in available_agents; mock _run_for_agent so demon pass
        # succeeds without network.
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run:
            self.mod.run(ctx)
        # _run_for_agent called exactly once — for the demon pass only.
        mock_run.assert_called_once()
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertIn("demon", agent_types)
        self.assertNotIn("phantom", agent_types)


# ── Scenario 05: Windows agent (Demon + Specter) ─────────────────────────────

class TestScenario05(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("05_agent_windows_windows_agent_checkin.py")

    def test_specter_build_failure_propagates(self) -> None:
        ctx = _windows_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "specter", "exe", "test-win-specter")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_specter_skipped_when_not_in_available(self) -> None:
        ctx = _windows_ctx()
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertIn("demon", agent_types)
        self.assertNotIn("specter", agent_types)


# ── Scenario 06: File transfer (Linux + Windows) ─────────────────────────────

class TestScenario06(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("06_file_transfer_file_transfer.py")

    def test_phantom_linux_build_failure_propagates(self) -> None:
        ctx = _linux_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "phantom", "bin", "test-ftransfer-phantom")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_specter_windows_build_failure_propagates(self) -> None:
        ctx = _windows_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent_windows(ctx, "specter", "exe", "test-ftransfer-specter")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_phantom_skipped_when_not_in_available_linux(self) -> None:
        ctx = _linux_ctx()
        ctx.windows = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run, \
             patch.object(self.mod, "_run_for_agent_windows"):
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("phantom", agent_types)

    def test_specter_skipped_when_not_in_available_windows(self) -> None:
        ctx = _windows_ctx()
        ctx.linux = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent"), \
             patch.object(self.mod, "_run_for_agent_windows") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("specter", agent_types)


# ── Scenario 07: Process operations (Linux + Windows) ────────────────────────

class TestScenario07(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("07_process_ops_process_operations.py")

    def test_phantom_linux_build_failure_propagates(self) -> None:
        ctx = _linux_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "phantom", "bin", "test-procops-phantom")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_specter_windows_build_failure_propagates(self) -> None:
        ctx = _windows_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent_windows(ctx, "specter", "exe", "test-procops-specter")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_phantom_skipped_when_not_in_available_linux(self) -> None:
        ctx = _linux_ctx()
        ctx.windows = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run, \
             patch.object(self.mod, "_run_for_agent_windows"):
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("phantom", agent_types)

    def test_specter_skipped_when_not_in_available_windows(self) -> None:
        ctx = _windows_ctx()
        ctx.linux = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent"), \
             patch.object(self.mod, "_run_for_agent_windows") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("specter", agent_types)


# ── Scenario 14: Stress concurrent agents ────────────────────────────────────

class TestScenario14(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("14_stress_concurrent_agents.py")

    def test_phantom_build_failure_propagates(self) -> None:
        ctx = _linux_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_stress_for_agent(
                    ctx, "phantom", "bin", "test-stress-phantom",
                    agent_count=1, run_seconds=5,
                )
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_phantom_skipped_when_not_in_available(self) -> None:
        ctx = _linux_ctx()
        with patch.object(self.mod, "_run_stress_for_agent") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertIn("demon", agent_types)
        self.assertNotIn("phantom", agent_types)


# ── Scenario 15: DNS agent checkin ───────────────────────────────────────────

class TestScenario15(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("15_agent_dns_dns_agent_checkin.py")

    def test_phantom_build_failure_propagates(self) -> None:
        ctx = _linux_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "phantom", "bin", "test-dns-phantom")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_phantom_skipped_when_not_in_available(self) -> None:
        ctx = _linux_ctx()
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertIn("demon", agent_types)
        self.assertNotIn("phantom", agent_types)


if __name__ == "__main__":
    unittest.main()
