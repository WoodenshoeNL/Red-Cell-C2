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
from lib.config import timeouts_for_unit_tests


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
    ctx.timeouts = timeouts_for_unit_tests()
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
    ctx.timeouts = timeouts_for_unit_tests()
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
    # patch both the module-level binding (used by lib.deploy_agent) and the
    # source symbol (used by scenarios that import lazily from lib.cli directly)
    patch("lib.deploy_agent.payload_build_and_fetch", side_effect=_BUILD_FAIL),
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


# ── Scenario 04: Linux agent (Phantom only — Demon is Windows-only) ──────────

class TestScenario04(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("04_agent_linux_linux_agent_checkin.py")

    def test_phantom_build_failure_propagates(self) -> None:
        ctx = _linux_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "phantom", "exe", "test-linux-phantom")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_skipped_when_phantom_not_in_available(self) -> None:
        """run() raises ScenarioSkipped when phantom is not listed in agents.available.

        Demon is Windows-only and cannot run on Linux, so the scenario has no
        work to do without Phantom.
        """
        from lib import ScenarioSkipped
        ctx = _linux_ctx()  # env has only "demon" in available
        with patch("lib.deploy.preflight_ssh"):
            with self.assertRaises(ScenarioSkipped):
                self.mod.run(ctx)

    def test_phantom_pass_when_in_available(self) -> None:
        """run() calls _run_for_agent with phantom+exe when phantom is available."""
        ctx = _linux_ctx()
        ctx.env["agents"]["available"] = ["demon", "phantom"]
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run:
            self.mod.run(ctx)
        mock_run.assert_called_once()
        call = mock_run.call_args_list[0]
        self.assertEqual(call.kwargs["agent_type"], "phantom")
        self.assertEqual(call.kwargs["fmt"], "exe")


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

    def test_archon_build_failure_propagates(self) -> None:
        ctx = _windows_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent(ctx, "archon", "exe", "test-win-archon")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_archon_skipped_when_not_in_available(self) -> None:
        ctx = _windows_ctx()  # env has only "demon" in available
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertIn("demon", agent_types)
        self.assertNotIn("archon", agent_types)


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

    def test_phantom_skipped_when_not_in_available_linux_only(self) -> None:
        """Linux-only + phantom absent → ScenarioSkipped (zero agent passes ran)."""
        from lib import ScenarioSkipped
        ctx = _linux_ctx()
        ctx.windows = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run, \
             patch.object(self.mod, "_run_for_agent_windows"):
            with self.assertRaises(ScenarioSkipped):
                self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("phantom", agent_types)

    def test_phantom_skipped_linux_windows_still_runs(self) -> None:
        """Linux + Windows + phantom absent → Windows passes run, no ScenarioSkipped."""
        ctx = _linux_ctx()
        ctx.windows = MagicMock()
        ctx.windows.work_dir = "C:\\Temp\\rc-test"
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_linux, \
             patch.object(self.mod, "_run_for_agent_windows") as mock_win:
            self.mod.run(ctx)
        linux_types = [c.kwargs["agent_type"] for c in mock_linux.call_args_list]
        self.assertNotIn("phantom", linux_types)
        # demon always runs on Windows regardless of available list
        win_types = [c.kwargs["agent_type"] for c in mock_win.call_args_list]
        self.assertIn("demon", win_types)

    def test_specter_skipped_when_not_in_available_windows(self) -> None:
        ctx = _windows_ctx()
        ctx.linux = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent"), \
             patch.object(self.mod, "_run_for_agent_windows") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("specter", agent_types)

    def test_archon_windows_build_failure_propagates(self) -> None:
        ctx = _windows_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent_windows(ctx, "archon", "exe", "test-ftransfer-archon")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_archon_skipped_when_not_in_available_windows(self) -> None:
        ctx = _windows_ctx()  # env has only "demon" in available
        ctx.linux = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent"), \
             patch.object(self.mod, "_run_for_agent_windows") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("archon", agent_types)


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

    def test_phantom_skipped_when_not_in_available_linux_only(self) -> None:
        """Linux-only + phantom absent → ScenarioSkipped (zero agent passes ran)."""
        from lib import ScenarioSkipped
        ctx = _linux_ctx()
        ctx.windows = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_run, \
             patch.object(self.mod, "_run_for_agent_windows"):
            with self.assertRaises(ScenarioSkipped):
                self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("phantom", agent_types)

    def test_phantom_skipped_linux_windows_still_runs(self) -> None:
        """Linux + Windows + phantom absent → Windows passes run, no ScenarioSkipped."""
        ctx = _linux_ctx()
        ctx.windows = MagicMock()
        ctx.windows.work_dir = "C:\\Temp\\rc-test"
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent") as mock_linux, \
             patch.object(self.mod, "_run_for_agent_windows") as mock_win:
            self.mod.run(ctx)
        linux_types = [c.kwargs["agent_type"] for c in mock_linux.call_args_list]
        self.assertNotIn("phantom", linux_types)
        win_types = [c.kwargs["agent_type"] for c in mock_win.call_args_list]
        self.assertIn("demon", win_types)

    def test_specter_skipped_when_not_in_available_windows(self) -> None:
        ctx = _windows_ctx()
        ctx.linux = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent"), \
             patch.object(self.mod, "_run_for_agent_windows") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("specter", agent_types)

    def test_archon_windows_build_failure_propagates(self) -> None:
        ctx = _windows_ctx()
        with _apply_patches(_LISTENER_PATCHES):
            with self.assertRaises(CliError) as cm:
                self.mod._run_for_agent_windows(ctx, "archon", "exe", "test-procops-archon")
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_archon_skipped_when_not_in_available_windows(self) -> None:
        ctx = _windows_ctx()  # env has only "demon" in available
        ctx.linux = None
        with patch("lib.deploy.preflight_ssh"), \
             patch.object(self.mod, "_run_for_agent"), \
             patch.object(self.mod, "_run_for_agent_windows") as mock_run:
            self.mod.run(ctx)
        agent_types = [c.kwargs["agent_type"] for c in mock_run.call_args_list]
        self.assertNotIn("archon", agent_types)


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
                    ctx, ctx.linux, "phantom", "bin", "test-stress-phantom",
                    agent_count=1, run_seconds=5,
                )
        self.assertEqual(cm.exception.code, "BUILD_FAILED")

    def test_phantom_skipped_when_not_in_available(self) -> None:
        # Demon needs windows target; phantom not in available → only demon runs.
        from unittest.mock import MagicMock
        ctx = _linux_ctx()
        ctx.windows = MagicMock()
        ctx.windows.work_dir = "C:\\Temp\\rc-test"
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

    def test_scenario_skipped_when_phantom_not_in_available(self) -> None:
        # Demon has no DNS transport — when phantom is absent too, the scenario skips.
        ctx = _linux_ctx()
        from lib import ScenarioSkipped
        with patch("lib.deploy.preflight_ssh"), \
             patch("lib.deploy.inject_hosts_entry"), \
             patch("lib.deploy.preflight_dns"), \
             patch.object(self.mod, "_run_for_agent"):
            with self.assertRaises(ScenarioSkipped):
                self.mod.run(ctx)

    def test_demon_never_run_for_dns(self) -> None:
        # Scenario 15 was rewritten in commit 61b8d7e4 to unconditionally skip:
        # no Rust agent currently implements primary-DNS transport, and Demon
        # has no TransportDns either, so there is nothing to test end-to-end.
        # The test now asserts the skip itself (which prevents Demon from ever
        # being invoked for DNS — the original property this test guarded).
        from lib import ScenarioSkipped
        ctx = _linux_ctx()
        ctx.env["agents"]["available"] = ["demon", "phantom"]
        with self.assertRaises(ScenarioSkipped):
            self.mod.run(ctx)


# ── Scenario 20: DoH DNS listener interop ────────────────────────────────────

class TestScenario20(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load("20_agent_doh_dns_listener_interop.py")

    def _ctx_with_server(self) -> MagicMock:
        ctx = _linux_ctx()
        ctx.env["listeners"] = {"dns_domain": "c2.test.local", "dns_port": 15353}
        ctx.env["server"] = {"url": "https://10.0.0.2:8443"}
        return ctx

    def _proto_mock(self) -> MagicMock:
        m = MagicMock()
        m.AES_KEY_LEN = 32
        m.AES_IV_LEN = 16
        # _aes_256_ctr_at_offset and _u32le must agree so the init-ACK assertion passes.
        # Scenario 20 was migrated to monotonic-CTR helpers in commit b1f739fc; the
        # mock was previously set up for the legacy _aes_256_ctr name.
        m._aes_256_ctr_at_offset.return_value = b"ACK"
        m._u32le.return_value = b"ACK"
        m._ctr_blocks_for_len.return_value = 0
        m._build_get_job_packet.return_value = b"\x00" * 32
        return m

    def test_inject_hosts_entry_called_with_correct_args(self) -> None:
        ctx = self._ctx_with_server()
        proto = self._proto_mock()

        with patch("lib.deploy.inject_hosts_entry") as mock_inject, \
             patch("lib.deploy.preflight_dns"), \
             patch("lib.cli.listener_create", return_value={}), \
             patch("lib.cli.listener_start", return_value={}), \
             patch("lib.cli.listener_stop", return_value={}), \
             patch("lib.cli.listener_delete", return_value={}), \
             patch("lib.cli.agent_kill", return_value={}), \
             patch.object(self.mod, "_load_protocol_probe_module", return_value=proto), \
             patch.object(self.mod, "_wait_for_dns_listener"), \
             patch.object(self.mod, "_chunk_packet", return_value=["chunk1", "chunk2"]), \
             patch.object(self.mod, "_random_session_hex", return_value="aabbccdd"), \
             patch.object(self.mod, "_upload_packet_via_doh_grammar"), \
             patch.object(self.mod, "_poll_ready_via_doh_grammar", return_value=1), \
             patch.object(
                 self.mod,
                 "_download_response_via_doh_grammar",
                 side_effect=[b"encrypted_ack", b""],
             ), \
             patch.object(self.mod, "_maybe_specter_doh_agent_pass"):
            self.mod.run(ctx)

        mock_inject.assert_called_once_with(ctx.linux, "c2.test.local", "10.0.0.2")

    def test_inject_hosts_entry_skipped_when_no_linux(self) -> None:
        ctx = self._ctx_with_server()
        ctx.linux = None
        proto = self._proto_mock()

        with patch("lib.deploy.inject_hosts_entry") as mock_inject, \
             patch("lib.deploy.preflight_dns"), \
             patch("lib.cli.listener_create", return_value={}), \
             patch("lib.cli.listener_start", return_value={}), \
             patch("lib.cli.listener_stop", return_value={}), \
             patch("lib.cli.listener_delete", return_value={}), \
             patch("lib.cli.agent_kill", return_value={}), \
             patch.object(self.mod, "_load_protocol_probe_module", return_value=proto), \
             patch.object(self.mod, "_wait_for_dns_listener"), \
             patch.object(self.mod, "_chunk_packet", return_value=["chunk1", "chunk2"]), \
             patch.object(self.mod, "_random_session_hex", return_value="aabbccdd"), \
             patch.object(self.mod, "_upload_packet_via_doh_grammar"), \
             patch.object(self.mod, "_poll_ready_via_doh_grammar", return_value=1), \
             patch.object(
                 self.mod,
                 "_download_response_via_doh_grammar",
                 side_effect=[b"encrypted_ack", b""],
             ), \
             patch.object(self.mod, "_maybe_specter_doh_agent_pass"):
            self.mod.run(ctx)

        mock_inject.assert_not_called()


if __name__ == "__main__":
    unittest.main()
