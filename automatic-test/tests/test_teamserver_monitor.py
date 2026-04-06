"""
tests/test_teamserver_monitor.py — Unit tests for lib/teamserver_monitor.py.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.teamserver_monitor import (
    ResourceSample,
    TeamserverMonitorSettings,
    TeamserverResourceMonitor,
    TeamserverSshConfig,
    assert_resource_limits,
    format_samples_for_output,
    is_loopback_host,
    load_teamserver_monitor_settings,
    parse_ps_cpu_rss_line,
    resolve_teamserver_host,
    sample_local_teamserver_cpu_rss,
    sample_remote_teamserver_cpu_rss,
)


class TestResolveTeamserverHost(unittest.TestCase):
    def test_explicit_host(self) -> None:
        env = {"teamserver": {"host": "10.0.0.5"}, "server": {"url": "wss://127.0.0.1:1"}}
        self.assertEqual(resolve_teamserver_host(env), "10.0.0.5")

    def test_from_server_url(self) -> None:
        env = {"server": {"url": "wss://c2.example.com:40056"}}
        self.assertEqual(resolve_teamserver_host(env), "c2.example.com")

    def test_default_when_no_hostname(self) -> None:
        env = {"server": {"url": ""}}
        self.assertEqual(resolve_teamserver_host(env), "127.0.0.1")


class TestIsLoopback(unittest.TestCase):
    def test_common_loopbacks(self) -> None:
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("::1"))

    def test_non_loopback(self) -> None:
        self.assertFalse(is_loopback_host("192.168.1.1"))
        self.assertFalse(is_loopback_host("c2.example.com"))


class TestParsePsLine(unittest.TestCase):
    def test_basic(self) -> None:
        cpu, rss = parse_ps_cpu_rss_line("  12.5  123456 \n")
        self.assertEqual(cpu, 12.5)
        self.assertEqual(rss, 123456)

    def test_empty(self) -> None:
        cpu, rss = parse_ps_cpu_rss_line("")
        self.assertIsNone(cpu)
        self.assertIsNone(rss)


class TestLoadSettings(unittest.TestCase):
    def test_defaults(self) -> None:
        env = {"server": {"url": "wss://127.0.0.1:1"}}
        s = load_teamserver_monitor_settings(env, default_cpu_limit_pct=80.0)
        self.assertIsInstance(s, TeamserverMonitorSettings)
        self.assertEqual(s.host, "127.0.0.1")
        self.assertEqual(s.cpu_limit_pct, 80.0)
        self.assertIsNone(s.rss_limit_mb)
        self.assertIsNone(s.ssh)

    def test_ssh_when_all_set(self) -> None:
        env = {
            "teamserver": {
                "host": "10.0.0.2",
                "ssh_user": "u",
                "ssh_key": "/k",
                "ssh_port": 2222,
                "rss_limit_mb": 4096,
            },
            "server": {"url": "wss://ignored:1"},
        }
        s = load_teamserver_monitor_settings(env)
        self.assertEqual(s.host, "10.0.0.2")
        self.assertEqual(s.rss_limit_mb, 4096.0)
        assert s.ssh is not None
        self.assertEqual(s.ssh.user, "u")
        self.assertEqual(s.ssh.key, "/k")
        self.assertEqual(s.ssh.port, 2222)
        self.assertEqual(s.ssh.host, "10.0.0.2")


class TestAssertResourceLimits(unittest.TestCase):
    def test_cpu_exceeds(self) -> None:
        s = TeamserverMonitorSettings(
            host="127.0.0.1", cpu_limit_pct=50.0, rss_limit_mb=None
        )
        errs = assert_resource_limits(s, max_cpu=90.0, max_rss_kb=100, had_samples=True)
        self.assertEqual(len(errs), 1)
        self.assertIn("CPU peaked", errs[0])

    def test_skips_when_no_samples(self) -> None:
        s = TeamserverMonitorSettings(
            host="127.0.0.1", cpu_limit_pct=50.0, rss_limit_mb=None
        )
        errs = assert_resource_limits(s, max_cpu=99.0, max_rss_kb=0, had_samples=False)
        self.assertEqual(errs, [])

    def test_rss_exceeds(self) -> None:
        s = TeamserverMonitorSettings(
            host="127.0.0.1", cpu_limit_pct=100.0, rss_limit_mb=1.0
        )
        # 3 MiB process vs 1 MiB limit
        errs = assert_resource_limits(
            s, max_cpu=1.0, max_rss_kb=3 * 1024, had_samples=True
        )
        self.assertEqual(len(errs), 1)
        self.assertIn("RSS peaked", errs[0])


class TestFormatSamples(unittest.TestCase):
    def test_formats(self) -> None:
        samples = [
            ResourceSample(1.0, 10.0, 1024, "stress_start"),
            ResourceSample(2.0, 20.0, 2048, ""),
        ]
        out = format_samples_for_output(samples)
        self.assertIn("stress_start", out)
        self.assertIn("rss_mb=1.0", out)


class TestTeamserverResourceMonitor(unittest.TestCase):
    def test_configure_remote_without_ssh_disables(self) -> None:
        s = TeamserverMonitorSettings(
            host="203.0.113.1", cpu_limit_pct=80.0, rss_limit_mb=None, ssh=None
        )
        m = TeamserverResourceMonitor(s)
        m.configure()
        self.assertEqual(m.mode, "disabled")
        self.assertIsNotNone(m.disable_reason)

    def test_configure_local(self) -> None:
        s = TeamserverMonitorSettings(
            host="127.0.0.1", cpu_limit_pct=80.0, rss_limit_mb=None, ssh=None
        )
        m = TeamserverResourceMonitor(s)
        m.configure()
        self.assertEqual(m.mode, "local")

    @patch("lib.teamserver_monitor.sample_local_teamserver_cpu_rss")
    def test_take_edge_sample_updates_max(self, mock_sample: MagicMock) -> None:
        mock_sample.return_value = (15.0, 1000)
        s = TeamserverMonitorSettings(
            host="127.0.0.1", cpu_limit_pct=80.0, rss_limit_mb=None, ssh=None
        )
        m = TeamserverResourceMonitor(s)
        m.configure()
        edge = m.take_edge_sample("x")
        self.assertIsNotNone(edge)
        assert edge is not None
        self.assertEqual(edge.cpu_pct, 15.0)
        self.assertEqual(m.max_cpu, 15.0)
        self.assertEqual(m.max_rss_kb, 1000)


class TestSampleLocalIntegration(unittest.TestCase):
    """Best-effort: succeeds whether or not red-cell is running."""

    def test_call_does_not_crash(self) -> None:
        sample_local_teamserver_cpu_rss()


class TestSampleRemote(unittest.TestCase):
    @patch("lib.teamserver_monitor.subprocess.run")
    def test_parses_ssh_ps_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="  3.25  2048 \n")
        cfg = TeamserverSshConfig(
            host="203.0.113.7", user="u", port=2222, key="/tmp/k"
        )
        cpu, rss = sample_remote_teamserver_cpu_rss(cfg)
        self.assertEqual(cpu, 3.25)
        self.assertEqual(rss, 2048)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertEqual(args[0], "ssh")
        self.assertIn("u@203.0.113.7", args)


if __name__ == "__main__":
    unittest.main()
