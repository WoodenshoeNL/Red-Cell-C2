"""
tests/test_deploy.py — Unit tests for lib/deploy.py.

Run with:  python3 -m unittest discover -s automatic-test/tests
"""

import base64
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# Make lib/ importable when running from the automatic-test directory or repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.deploy import (
    DeployError,
    TargetConfig,
    WFP_RESTART_THRESHOLD,
    cleanup_windows_harness_work_dir,
    clear_globally_unreachable_hosts,
    configure_deploy_timeouts,
    defender_add_exclusion,
    defender_add_process_exclusion,
    defender_disable_network_protection,
    defender_remove_process_exclusion,
    ensure_work_dir,
    execute_background,
    firewall_allow_program,
    firewall_remove_program,
    inject_hosts_entry,
    mark_host_unreachable,
    preflight_dns,
    preflight_ssh,
    run_remote,
    upload,
    wfp_preflight_cleanup,
    _is_transient_ssh_failure,
    _quote_posix,
    _quote_powershell,
    _scp_args,
    _ssh_args,
    _windows_wmi_create_script,
    _windows_schtask_script,
)

_MODULE_KEY_PATH: str | None = None


def _decoded_windows_launch_script(remote_ssh_cmd: str) -> str:
    """Decode ``powershell -EncodedCommand`` payload (UTF-16 LE) from the SSH remote command."""

    suffix = remote_ssh_cmd.split("-EncodedCommand", 1)[1].strip()
    return base64.b64decode(suffix).decode("utf-16-le")


def _module_key_path() -> str:
    """Real filesystem path used as an SSH key placeholder in unit tests."""

    global _MODULE_KEY_PATH
    if _MODULE_KEY_PATH is None:
        fd, path = tempfile.mkstemp(prefix="deploy-test-key-")
        os.close(fd)
        _MODULE_KEY_PATH = path
    return _MODULE_KEY_PATH


def _make_target(**kwargs) -> TargetConfig:
    defaults = dict(
        host="192.168.1.10",
        port=22,
        user="testuser",
        work_dir="/tmp/rc-test",
        key=_module_key_path(),
    )
    defaults.update(kwargs)
    return TargetConfig(**defaults)


class TestIsTransientSshFailure(unittest.TestCase):
    def test_connection_timed_out(self) -> None:
        self.assertTrue(
            _is_transient_ssh_failure(
                "ssh: connect to host x port 22: Connection timed out",
            )
        )

    def test_connection_refused(self) -> None:
        self.assertTrue(
            _is_transient_ssh_failure(
                "ssh: connect to host x port 22: Connection refused",
            )
        )

    def test_permission_denied_not_transient(self) -> None:
        self.assertFalse(
            _is_transient_ssh_failure("Permission denied (publickey,password)."),
        )

    def test_case_insensitive(self) -> None:
        self.assertTrue(_is_transient_ssh_failure("CONNECTION REFUSED"))


class TestTargetConfigValidation(unittest.TestCase):
    def test_valid_config(self) -> None:
        t = _make_target()
        self.assertEqual(t.host, "192.168.1.10")
        self.assertTrue(Path(t.key).is_file())

    def test_empty_key_raises(self) -> None:
        """key="" must raise ValueError with a clear message."""
        with self.assertRaises(ValueError) as ctx:
            _make_target(key="")
        self.assertIn("'key' is required", str(ctx.exception))

    def test_none_key_raises(self) -> None:
        """Passing None for key must raise ValueError or TypeError."""
        with self.assertRaises((ValueError, TypeError)):
            TargetConfig(
                host="192.168.1.10",
                port=22,
                user="testuser",
                work_dir="/tmp/rc-test",
                key=None,  # type: ignore[arg-type]
            )

    def test_windows_target_with_key(self) -> None:
        t = _make_target(
            host="10.0.0.5",
            user="Administrator",
            work_dir="C:\\Temp\\rc-test",
            platform="windows",
        )
        self.assertEqual(t.work_dir, "C:\\Temp\\rc-test")
        self.assertEqual(t.platform, "windows")

    def test_platform_defaults_to_linux(self) -> None:
        t = _make_target()
        self.assertEqual(t.platform, "linux")

    def test_platform_windows_explicit(self) -> None:
        t = _make_target(platform="windows")
        self.assertEqual(t.platform, "windows")

    def test_invalid_platform_raises(self) -> None:
        """Invalid platform values must raise ValueError with a clear message."""
        for bad in ("macos", "Windows", "Linux", "darwin", ""):
            with self.subTest(platform=bad):
                with self.assertRaises(ValueError) as ctx:
                    _make_target(platform=bad)
                self.assertIn("platform must be", str(ctx.exception))

    def test_non_c_drive_windows_target_uses_platform_field(self) -> None:
        """D:\\ work_dir must work as Windows when platform='windows' is set."""
        ok_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        t = _make_target(
            work_dir="D:\\Workdir\\rc-test",
            platform="windows",
        )
        with patch("subprocess.run", return_value=ok_result) as m:
            execute_background(t, "D:\\Workdir\\rc-test\\agent.exe")
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("-EncodedCommand", remote_cmd)

    def test_defender_add_exclusion_non_c_drive(self) -> None:
        """defender_add_exclusion must work for D:\\ paths when platform='windows'."""
        ok_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        t = _make_target(
            work_dir="D:\\Workdir\\rc-test",
            platform="windows",
        )
        with patch("subprocess.run", return_value=ok_result) as m:
            defender_add_exclusion(t, "D:\\Workdir\\rc-test")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("Add-MpPreference", script)
        self.assertIn("D:\\Workdir\\rc-test", script)

    def test_defender_add_exclusion_linux_platform_raises(self) -> None:
        """defender_add_exclusion must raise ValueError for platform='linux' targets."""
        t = _make_target(work_dir="/tmp/rc-test", platform="linux")
        with self.assertRaises(ValueError) as ctx:
            defender_add_exclusion(t, "/tmp/rc-test")
        self.assertIn("Windows", str(ctx.exception))


class TestSshArgs(unittest.TestCase):
    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(key=self.key_path)

    def test_first_arg_is_ssh(self) -> None:
        self.assertEqual(_ssh_args(self.target)[0], "ssh")

    def test_port_flag(self) -> None:
        args = _ssh_args(self.target)
        idx = args.index("-p")
        self.assertEqual(args[idx + 1], "22")

    def test_key_flag(self) -> None:
        args = _ssh_args(self.target)
        idx = args.index("-i")
        self.assertEqual(args[idx + 1], self.key_path)

    def test_destination_last(self) -> None:
        args = _ssh_args(self.target)
        self.assertEqual(args[-1], f"{self.target.user}@{self.target.host}")

    def test_batchmode_yes(self) -> None:
        """BatchMode=yes must always be present to prevent interactive prompts."""
        args = _ssh_args(self.target)
        self.assertIn("BatchMode=yes", args)

    def test_no_password_in_args(self) -> None:
        """ssh args must never contain a plaintext password."""
        joined = " ".join(_ssh_args(self.target))
        self.assertNotIn("Password", joined)
        self.assertNotIn("sshpass", joined)

    def test_custom_port(self) -> None:
        t = _make_target(port=2222)
        args = _ssh_args(t)
        idx = args.index("-p")
        self.assertEqual(args[idx + 1], "2222")


class TestScpArgs(unittest.TestCase):
    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(key=self.key_path)

    def test_first_arg_is_scp(self) -> None:
        self.assertEqual(_scp_args(self.target)[0], "scp")

    def test_port_flag(self) -> None:
        # scp uses uppercase -P
        args = _scp_args(self.target)
        idx = args.index("-P")
        self.assertEqual(args[idx + 1], "22")

    def test_key_flag(self) -> None:
        args = _scp_args(self.target)
        idx = args.index("-i")
        self.assertEqual(args[idx + 1], self.key_path)

    def test_batchmode_yes(self) -> None:
        args = _scp_args(self.target)
        self.assertIn("BatchMode=yes", args)

    def test_no_trailing_destination(self) -> None:
        """scp args must NOT include user@host — callers append src/dest."""
        args = _scp_args(self.target)
        joined = " ".join(args)
        self.assertNotIn(f"{self.target.user}@{self.target.host}", joined)


class TestQuotePosix(unittest.TestCase):
    """Tests for _quote_posix — POSIX sh quoting used in background execution."""

    def test_simple_path_unchanged(self) -> None:
        result = _quote_posix("/tmp/agent.bin")
        # shlex.quote wraps safe paths in single quotes or leaves them as-is
        self.assertIn("/tmp/agent.bin", result)

    def test_path_with_spaces_is_quoted(self) -> None:
        result = _quote_posix("/home/user/my dir/agent.bin")
        # The result must be a single token that the shell treats as one argument
        self.assertTrue(
            result.startswith("'") or result.startswith('"'),
            f"Expected quoted path, got: {result!r}",
        )
        self.assertIn("my dir", result)

    def test_path_with_special_chars(self) -> None:
        """Paths with $, &, ;, | etc. must be quoted so the shell does not interpret them."""
        path = "/tmp/evil$path&agent.bin"
        result = _quote_posix(path)
        # After unquoting, the original path must be recoverable
        import shlex
        self.assertEqual(shlex.split(result)[0], path)

    def test_plain_path_reconstructs(self) -> None:
        import shlex
        path = "/opt/rc-test/agent-abc123.bin"
        self.assertEqual(shlex.split(_quote_posix(path))[0], path)

    def test_path_with_spaces_reconstructs(self) -> None:
        import shlex
        path = "/home/test user/work dir/agent.bin"
        self.assertEqual(shlex.split(_quote_posix(path))[0], path)


class TestQuotePowerShell(unittest.TestCase):
    """Tests for _quote_powershell — PowerShell single-quote escaping."""

    def test_simple_path_is_single_quoted(self) -> None:
        result = _quote_powershell("C:\\Temp\\agent.exe")
        self.assertEqual(result, "'C:\\Temp\\agent.exe'")

    def test_path_with_spaces(self) -> None:
        result = _quote_powershell("C:\\Program Files\\agent.exe")
        self.assertEqual(result, "'C:\\Program Files\\agent.exe'")

    def test_embedded_single_quote_is_doubled(self) -> None:
        """A single quote inside the path must be escaped as '' for PowerShell."""
        result = _quote_powershell("C:\\it's here\\agent.exe")
        self.assertEqual(result, "'C:\\it''s here\\agent.exe'")

    def test_multiple_embedded_single_quotes(self) -> None:
        result = _quote_powershell("C:\\a'b'c\\agent.exe")
        self.assertEqual(result, "'C:\\a''b''c\\agent.exe'")

    def test_plain_path_roundtrip_token(self) -> None:
        """Quoted path must begin and end with a single quote."""
        path = "C:\\Temp\\rc-test\\agent-abc123.exe"
        result = _quote_powershell(path)
        self.assertTrue(result.startswith("'") and result.endswith("'"))

    def test_empty_path(self) -> None:
        self.assertEqual(_quote_powershell(""), "''")


class TestPreflightSsh(unittest.TestCase):
    """Tests for preflight_ssh connectivity check."""

    def setUp(self) -> None:
        # Clear globally-unreachable registry so tests that manipulate it cannot
        # interfere with these direct SSH-behaviour tests.
        clear_globally_unreachable_hosts()
        self.key_path = _module_key_path()
        self.target = _make_target(host="10.0.0.1", key=self.key_path)

    def tearDown(self) -> None:
        clear_globally_unreachable_hosts()

    def _make_completed(self, returncode: int, stderr: str = "") -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout="", stderr=stderr
        )

    def test_success_does_not_raise(self) -> None:
        """preflight_ssh must not raise when ssh returns exit code 0."""
        with patch("subprocess.run", return_value=self._make_completed(0)):
            preflight_ssh(self.target)  # must not raise

    def test_failure_raises_deploy_error(self) -> None:
        """preflight_ssh must raise DeployError on non-transient SSH failure (no retry)."""
        # Permission denied is not retried — unlike Connection refused / timed out.
        with patch("subprocess.run", return_value=self._make_completed(255, "Permission denied (publickey)")):
            with self.assertRaises(DeployError) as ctx:
                preflight_ssh(self.target)
            self.assertIn("10.0.0.1", str(ctx.exception))
            self.assertIn("not reachable via SSH", str(ctx.exception))
            self.assertIn("targets.toml", str(ctx.exception))

    def test_transient_connection_refused_exhausts_retries(self) -> None:
        """After 3 transient failures, DeployError includes attempt count and stderr."""
        bad = self._make_completed(255, "ssh: connect to host 10.0.0.1 port 22: Connection refused")
        with patch("subprocess.run", return_value=bad):
            with patch("lib.deploy.time.sleep"):
                with self.assertRaises(DeployError) as ctx:
                    preflight_ssh(self.target)
        msg = str(ctx.exception)
        self.assertIn("after 3 attempts", msg)
        self.assertIn("Connection refused", msg)

    def test_transient_retries_then_succeeds(self) -> None:
        """Transient failures are retried; success on the 3rd attempt returns without raising."""
        ok = self._make_completed(0)
        bad = self._make_completed(255, "Connection timed out")
        with patch("subprocess.run", side_effect=[bad, bad, ok]) as mock_run:
            with patch("lib.deploy.time.sleep"):
                preflight_ssh(self.target)
        self.assertEqual(mock_run.call_count, 3)

    def test_error_message_contains_host(self) -> None:
        """DeployError message must identify the unreachable host."""
        target = _make_target(host="192.168.99.5", key=self.key_path)
        with patch("subprocess.run", return_value=self._make_completed(1)):
            with self.assertRaises(DeployError) as ctx:
                preflight_ssh(target)
            self.assertIn("192.168.99.5", str(ctx.exception))

    def test_uses_configured_connect_timeout(self) -> None:
        """preflight_ssh uses ``ConnectTimeout`` from :func:`configure_deploy_timeouts` (default 10 s)."""
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]  # first positional arg is the command list
        self.assertIn("ConnectTimeout=10", call_args)

    def test_custom_ssh_connect_secs_propagates_to_connect_timeout(self) -> None:
        """configure_deploy_timeouts(ssh_connect_secs=5) must change ConnectTimeout in SSH commands.

        Verifies the env.toml ``ssh_connect_secs`` knob actually reaches the
        SSH ``-o ConnectTimeout=…`` flag so operators on fast networks can reduce
        the startup check_ssh_targets() cost.
        """
        self.addCleanup(
            configure_deploy_timeouts,
            ssh_connect_secs=10.0,
            scp_transfer_secs=60.0,
            default_remote_cmd_secs=30.0,
        )
        configure_deploy_timeouts(ssh_connect_secs=5.0, scp_transfer_secs=60.0, default_remote_cmd_secs=30.0)
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]
        self.assertIn("ConnectTimeout=5", call_args)
        self.assertNotIn("ConnectTimeout=10", call_args)

    def test_uses_batch_mode(self) -> None:
        """preflight_ssh must always use BatchMode=yes."""
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]
        self.assertIn("BatchMode=yes", call_args)

    def test_runs_noop_command(self) -> None:
        """preflight_ssh must run a no-op on the remote host — no side-effects.

        Uses ``exit 0`` rather than ``true`` so the probe works under Windows
        OpenSSH (whose default shell is ``cmd.exe`` and does not know ``true``).
        """
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(self.target)
        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args[-1], "exit 0")

    def test_custom_port(self) -> None:
        """preflight_ssh must pass the target's SSH port."""
        target = _make_target(port=2222, key=self.key_path)
        with patch("subprocess.run", return_value=self._make_completed(0)) as mock_run:
            preflight_ssh(target)
        call_args = mock_run.call_args[0][0]
        idx = call_args.index("-p")
        self.assertEqual(call_args[idx + 1], "2222")

    def test_timeout_error_bubbles_up(self) -> None:
        """A subprocess.TimeoutExpired must propagate (not be swallowed)."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                preflight_ssh(self.target)


class TestGloballyUnreachableHosts(unittest.TestCase):
    """Tests for mark_host_unreachable / clear_globally_unreachable_hosts / preflight_ssh short-circuit."""

    def setUp(self) -> None:
        # Always start each test with a clean registry.
        clear_globally_unreachable_hosts()
        self.key_path = _module_key_path()
        self.target = _make_target(host="192.168.213.160", key=self.key_path)

    def tearDown(self) -> None:
        clear_globally_unreachable_hosts()

    def test_preflight_ssh_skips_globally_unreachable_host(self) -> None:
        """preflight_ssh must raise ScenarioSkipped (no SSH call) when host is globally unreachable."""
        from lib import ScenarioSkipped
        mark_host_unreachable(self.target.host)
        with patch("subprocess.run") as mock_run:
            with self.assertRaises(ScenarioSkipped) as ctx:
                preflight_ssh(self.target)
        mock_run.assert_not_called()
        self.assertIn(self.target.host, str(ctx.exception))

    def test_preflight_ssh_attempts_ssh_when_host_not_registered(self) -> None:
        """preflight_ssh must still make an SSH call when the host is not in the unreachable set."""
        with patch("subprocess.run", return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )) as mock_run:
            preflight_ssh(self.target)
        mock_run.assert_called_once()

    def test_mark_host_unreachable_is_idempotent(self) -> None:
        """Calling mark_host_unreachable twice for the same host must not raise."""
        mark_host_unreachable(self.target.host)
        mark_host_unreachable(self.target.host)
        from lib import ScenarioSkipped
        with self.assertRaises(ScenarioSkipped):
            preflight_ssh(self.target)

    def test_clear_globally_unreachable_hosts_restores_ssh_attempts(self) -> None:
        """After clear, previously-marked hosts are no longer short-circuited."""
        mark_host_unreachable(self.target.host)
        clear_globally_unreachable_hosts()
        with patch("subprocess.run", return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )) as mock_run:
            preflight_ssh(self.target)
        mock_run.assert_called_once()

    def test_only_registered_host_is_short_circuited(self) -> None:
        """Short-circuit must apply only to the registered host, not other hosts."""
        from lib import ScenarioSkipped
        mark_host_unreachable("10.10.10.10")
        # self.target.host is 192.168.213.160 — not registered — must still attempt SSH
        with patch("subprocess.run", return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )) as mock_run:
            preflight_ssh(self.target)
        mock_run.assert_called_once()
        # The registered host must be short-circuited
        other_target = _make_target(host="10.10.10.10", key=self.key_path)
        mock_run.reset_mock()
        with self.assertRaises(ScenarioSkipped):
            preflight_ssh(other_target)
        mock_run.assert_not_called()


class TestPreflightDns(unittest.TestCase):
    """Tests for preflight_dns — remote probe must not embed domain in Python source."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(host="10.0.0.1", key=self.key_path)

    def _completed(self, stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=""
        )

    def test_success_when_resolution_matches(self) -> None:
        with patch("subprocess.run", return_value=self._completed("192.168.1.50\n")) as mock_run:
            preflight_dns(self.target, "c2.example.test", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        prefix = "python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "
        self.assertEqual(remote_cmd, prefix + shlex.quote("c2.example.test"))

    def test_domain_passed_via_argv_shell_escaped(self) -> None:
        """Domain with shell metacharacters must be argv[1], not interpolated into -c."""
        domain = "evil'$(rm -rf /)"
        expected_ip = "127.0.0.1"
        with patch("subprocess.run", return_value=self._completed(expected_ip + "\n")) as mock_run:
            preflight_dns(self.target, domain, expected_ip)
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("sys.argv[1]", remote_cmd)
        self.assertNotIn(domain, remote_cmd)
        prefix = "python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "
        self.assertEqual(remote_cmd, prefix + shlex.quote(domain))

    def test_mismatch_raises_scenario_skipped(self) -> None:
        from lib import ScenarioSkipped

        with patch("subprocess.run", return_value=self._completed("10.0.0.99\n")):
            with self.assertRaises(ScenarioSkipped) as ctx:
                preflight_dns(self.target, "dns.test", "192.168.1.1")
        self.assertIn("10.0.0.99", str(ctx.exception))
        self.assertIn("192.168.1.1", str(ctx.exception))

    def test_linux_error_mentions_etc_hosts(self) -> None:
        from lib import ScenarioSkipped

        with patch("subprocess.run", return_value=self._completed("", returncode=1)):
            with self.assertRaises(ScenarioSkipped) as ctx:
                preflight_dns(self.target, "dns.test", "192.168.1.1")
        self.assertIn("/etc/hosts", str(ctx.exception))


class TestPreflightDnsWindows(unittest.TestCase):
    """Tests for preflight_dns on Windows targets — uses PowerShell instead of Python."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(
            host="192.168.213.160", work_dir="C:\\rc-test", platform="windows", key=self.key_path,
        )

    def _completed(self, stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=""
        )

    def test_windows_uses_powershell_probe(self) -> None:
        with patch("subprocess.run", return_value=self._completed("192.168.1.50\n")) as mock_run:
            preflight_dns(self.target, "c2.example.test", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("powershell", remote_cmd)
        self.assertIn("GetHostAddresses", remote_cmd)
        self.assertNotIn("python", remote_cmd)

    def test_windows_probe_embeds_domain(self) -> None:
        with patch("subprocess.run", return_value=self._completed("10.0.0.1\n")) as mock_run:
            preflight_dns(self.target, "c2.test.local", "10.0.0.1")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("c2.test.local", remote_cmd)

    def test_windows_domain_single_quote_escaped(self) -> None:
        domain = "evil'domain.test"
        with patch("subprocess.run", return_value=self._completed("10.0.0.1\n")) as mock_run:
            preflight_dns(self.target, domain, "10.0.0.1")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("evil''domain.test", remote_cmd)

    def test_windows_mismatch_raises_scenario_skipped(self) -> None:
        from lib import ScenarioSkipped

        with patch("subprocess.run", return_value=self._completed("10.0.0.99\n")):
            with self.assertRaises(ScenarioSkipped) as ctx:
                preflight_dns(self.target, "dns.test", "192.168.1.1")
        self.assertIn("10.0.0.99", str(ctx.exception))

    def test_windows_error_mentions_windows_hosts_path(self) -> None:
        from lib import ScenarioSkipped

        with patch("subprocess.run", return_value=self._completed("", returncode=1)):
            with self.assertRaises(ScenarioSkipped) as ctx:
                preflight_dns(self.target, "dns.test", "192.168.1.1")
        msg = str(ctx.exception)
        self.assertIn(r"C:\Windows\System32\drivers\etc\hosts", msg)
        self.assertNotIn("/etc/hosts", msg)

    def test_windows_mismatch_mentions_windows_hosts_path(self) -> None:
        from lib import ScenarioSkipped

        with patch("subprocess.run", return_value=self._completed("10.0.0.99\n")):
            with self.assertRaises(ScenarioSkipped) as ctx:
                preflight_dns(self.target, "dns.test", "192.168.1.1")
        msg = str(ctx.exception)
        self.assertIn(r"C:\Windows\System32\drivers\etc\hosts", msg)


class TestDeployErrorPaths(unittest.TestCase):
    """Deployment error paths with mocked subprocess (no real SSH)."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(key=self.key_path)

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_ssh_missing_key(self) -> None:
        missing = f"/nonexistent/ssh_key_{os.getpid()}"
        with self.assertRaises(ValueError) as ctx:
            TargetConfig(
                host="h.example",
                port=22,
                user="u",
                work_dir="/tmp/w",
                key=missing,
            )
        self.assertIn("not found", str(ctx.exception))
        self.assertIn(missing, str(ctx.exception))

    def test_ssh_connection_refused(self) -> None:
        """Exit 255 with connection refused exhausts retries and raises DeployError."""
        bad = self._completed(
            255,
            "ssh: connect to host 10.0.0.1 port 22: Connection refused",
        )
        t = _make_target(host="10.0.0.1", key=self.key_path)
        with patch("subprocess.run", return_value=bad):
            with patch("lib.deploy.time.sleep"):
                with self.assertRaises(DeployError) as ctx:
                    run_remote(t, "echo hi")
        msg = str(ctx.exception)
        self.assertIn("after 3 attempts", msg)
        self.assertIn("Connection refused", msg)

    def test_scp_transfer_failure(self) -> None:
        bad = self._completed(1, "scp: /remote/path: Permission denied")
        with patch("subprocess.run", return_value=bad):
            with self.assertRaises(DeployError) as ctx:
                upload(self.target, "/tmp/local.bin", "/remote/path")
        msg = str(ctx.exception)
        self.assertIn("SCP upload failed", msg)
        self.assertIn("exit 1", msg)
        self.assertIn("/tmp/local.bin", msg)
        self.assertIn("Permission denied", msg)

    def test_ensure_work_dir_permission_denied(self) -> None:
        bad = self._completed(
            1,
            "mkdir: cannot create directory '/root/forbidden': Permission denied",
        )
        t = _make_target(work_dir="/root/forbidden", key=self.key_path)
        with patch("subprocess.run", return_value=bad):
            with self.assertRaises(DeployError) as ctx:
                ensure_work_dir(t)
        msg = str(ctx.exception)
        self.assertIn("Remote command failed", msg)
        self.assertIn("mkdir", msg)

    def test_ensure_work_dir_windows_c_drive(self) -> None:
        """Windows branch must issue a PowerShell New-Item command for C:\\ paths."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            ensure_work_dir(t)
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("New-Item", remote_cmd)
        self.assertIn("-ItemType Directory", remote_cmd)
        self.assertIn("C:\\Temp\\rc-test", remote_cmd)

    def test_ensure_work_dir_windows_d_drive(self) -> None:
        """Windows branch must issue a PowerShell New-Item command for D:\\ paths."""
        ok = self._completed(0)
        t = _make_target(work_dir="D:\\Workdir\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            ensure_work_dir(t)
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("New-Item", remote_cmd)
        self.assertIn("-ItemType Directory", remote_cmd)
        self.assertIn("D:\\Workdir\\rc-test", remote_cmd)

    def test_ensure_work_dir_windows_error_raises_deploy_error(self) -> None:
        """Non-zero PowerShell exit on Windows must raise DeployError."""
        bad = self._completed(
            1,
            "New-Item : Access to the path 'C:\\Temp\\rc-test' is denied.",
        )
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=bad):
            with self.assertRaises(DeployError) as ctx:
                ensure_work_dir(t)
        msg = str(ctx.exception)
        self.assertIn("Remote command failed", msg)

    def test_execute_background_returns_immediately(self) -> None:
        """Local subprocess.run must return quickly; remote command uses nohup … &."""
        ok = self._completed(0)
        t = _make_target(work_dir="/tmp/rc-bg", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            t0 = time.perf_counter()
            execute_background(t, "/bin/sleep 86400")
            elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0)
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("nohup", remote_cmd)
        self.assertIn("&", remote_cmd)

    def test_execute_background_linux_ignores_arguments(self) -> None:
        """On Linux, the arguments parameter must be silently ignored.

        The nohup command issued over SSH must contain only the executable path —
        the arguments string must not appear anywhere in the SSH command.
        """
        ok = self._completed(0)
        t = _make_target(work_dir="/tmp/rc-bg", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "/tmp/rc/agent", "--sleep 5 --port 8443")
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("nohup", remote_cmd)
        self.assertIn("/tmp/rc/agent", remote_cmd)
        self.assertNotIn("--sleep", remote_cmd)
        self.assertNotIn("--port", remote_cmd)
        self.assertNotIn("8443", remote_cmd)

    def test_execute_background_windows_uses_schtask(self) -> None:
        """Windows deploy must use Task Scheduler (S4U) to run as user, not SYSTEM."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Temp\\rc-test\\agent.exe")
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("-EncodedCommand", remote_cmd)
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("Register-ScheduledTask", script)
        self.assertIn("Start-ScheduledTask", script)
        self.assertIn("New-ScheduledTaskPrincipal", script)
        self.assertIn("S4U", script)
        self.assertIn("C:\\Temp\\rc-test\\agent.exe", script)
        self.assertNotIn("Invoke-WmiMethod", script)
        self.assertNotIn("Start-Process", script)

    def test_execute_background_windows_quotes_paths_with_spaces(self) -> None:
        """Paths with spaces must be single-quoted for PowerShell New-ScheduledTaskAction."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Program Files\\rc", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Program Files\\rc\\agent.exe")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("Register-ScheduledTask", script)
        self.assertIn("'C:\\Program Files\\rc\\agent.exe'", script)
        self.assertIn("-Execute $ep", script)

    def test_execute_background_windows_escapes_single_quotes(self) -> None:
        """Single quotes in the path must be doubled for PS single-quote string."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\it's here\\agent.exe")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("it''s here", script)

    def test_wmi_script_current_directory_not_empty(self) -> None:
        """CurrentDirectory must be the exe's parent dir, not an empty string.

        PureWindowsPath is required because pathlib.Path on Linux treats
        backslashes as literal characters, returning '.' as the parent.
        """
        script = _windows_wmi_create_script("C:\\Temp\\rc-test\\agent.exe")
        args = script.split("-ArgumentList ", 1)[1].split(";")[0]
        cmd_arg, cwd_arg = args.split(",", 1)
        cwd_arg = cwd_arg.strip()
        self.assertNotEqual(cwd_arg, "''", "CurrentDirectory must not be empty")
        self.assertIn("C:\\Temp\\rc-test", cwd_arg)
        self.assertNotIn("agent.exe", cwd_arg)

    def test_wmi_script_deep_path(self) -> None:
        """Deeply nested Windows paths extract the correct parent."""
        script = _windows_wmi_create_script(
            "C:\\Users\\admin\\AppData\\Local\\Temp\\work\\agent.exe"
        )
        args = script.split("-ArgumentList ", 1)[1].split(";")[0]
        _, cwd_arg = args.split(",", 1)
        cwd_arg = cwd_arg.strip()
        self.assertIn("C:\\Users\\admin\\AppData\\Local\\Temp\\work", cwd_arg)
        self.assertNotIn("agent.exe", cwd_arg)

    def test_wmi_script_root_path(self) -> None:
        """Exe at drive root should have drive root as CurrentDirectory."""
        script = _windows_wmi_create_script("C:\\agent.exe")
        args = script.split("-ArgumentList ", 1)[1].split(";")[0]
        _, cwd_arg = args.split(",", 1)
        cwd_arg = cwd_arg.strip()
        self.assertNotEqual(cwd_arg, "''")
        self.assertIn("C:\\", cwd_arg)


class TestExecuteBackgroundLinuxEnvVars(unittest.TestCase):
    """execute_background Linux env-var prefix tests (the env_vars= argument)."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_display_env_var_prepended_before_nohup(self) -> None:
        """DISPLAY=':99' must appear before nohup in the remote SSH command."""
        ok = self._completed(0)
        t = _make_target(key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "/tmp/rc/agent", env_vars={"DISPLAY": ":99"})
        remote_cmd = m.call_args[0][0][-1]
        # shlex.quote(':99') == ':99' — colon is in shlex's safe-char set, no quoting
        self.assertIn("DISPLAY=:99", remote_cmd)
        self.assertLess(
            remote_cmd.index("DISPLAY="),
            remote_cmd.index("nohup"),
            "env var prefix must come before nohup",
        )
        self.assertIn("/tmp/rc/agent", remote_cmd)
        self.assertIn("</dev/null >/dev/null 2>&1 &", remote_cmd)

    def test_env_var_value_with_spaces_is_single_quoted(self) -> None:
        """Values containing spaces must be wrapped in single quotes by shlex.quote."""
        ok = self._completed(0)
        t = _make_target(key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(
                t, "/tmp/rc/agent", env_vars={"MY_VAR": "value with spaces"}
            )
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("MY_VAR='value with spaces'", remote_cmd)
        self.assertIn("nohup", remote_cmd)

    def test_env_var_value_with_shell_metacharacters_is_quoted(self) -> None:
        """Values with $ ; ! must be single-quoted so the shell does not expand them."""
        ok = self._completed(0)
        t = _make_target(key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(
                t, "/tmp/rc/agent", env_vars={"SECRET": "$TOKEN;whoami"}
            )
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("SECRET='$TOKEN;whoami'", remote_cmd)
        # The bare unquoted form must not appear
        self.assertNotIn("SECRET=$TOKEN", remote_cmd)

    def test_multiple_env_vars_all_prepend_before_nohup(self) -> None:
        """All env var KEY=VALUE pairs must precede nohup, space-separated."""
        ok = self._completed(0)
        t = _make_target(key=self.key_path)
        env = {"DISPLAY": ":99", "HOME": "/home/user"}
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "/tmp/rc/agent", env_vars=env)
        remote_cmd = m.call_args[0][0][-1]
        nohup_pos = remote_cmd.index("nohup")
        self.assertLess(remote_cmd.index("DISPLAY="), nohup_pos)
        self.assertLess(remote_cmd.index("HOME="), nohup_pos)

    def test_empty_env_vars_dict_produces_bare_nohup(self) -> None:
        """An empty dict is falsy — must produce the same bare nohup command as None."""
        ok = self._completed(0)
        t = _make_target(key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "/tmp/rc/agent", env_vars={})
        remote_cmd = m.call_args[0][0][-1]
        self.assertTrue(
            remote_cmd.startswith("nohup"),
            f"Expected bare nohup (no env prefix) for empty dict, got: {remote_cmd!r}",
        )

    def test_none_env_vars_produces_bare_nohup(self) -> None:
        """env_vars=None (default) must produce a bare nohup command."""
        ok = self._completed(0)
        t = _make_target(key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "/tmp/rc/agent")
        remote_cmd = m.call_args[0][0][-1]
        self.assertTrue(
            remote_cmd.startswith("nohup"),
            f"Expected bare nohup command, got: {remote_cmd!r}",
        )

    def test_windows_target_ignores_env_vars(self) -> None:
        """On Windows, env_vars must be silently ignored — schtask path is taken."""
        ok = self._completed(0)
        t = _make_target(platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(
                t, "C:\\Temp\\agent.exe", env_vars={"DISPLAY": ":99"}
            )
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("-EncodedCommand", remote_cmd)
        # DISPLAY must not appear anywhere in the Windows command
        self.assertNotIn("DISPLAY", remote_cmd)


class TestWindowsSchedTaskScript(unittest.TestCase):
    """Unit tests for _windows_schtask_script."""

    def test_contains_register_scheduled_task(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\rc-test\\agent.exe")
        self.assertIn("Register-ScheduledTask", script)

    def test_contains_start_scheduled_task(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\rc-test\\agent.exe")
        self.assertIn("Start-ScheduledTask", script)

    def test_contains_s4u_logon_type(self) -> None:
        """Must use S4U (service for user) — runs as the named user without stored password."""
        script = _windows_schtask_script("C:\\Temp\\rc-test\\agent.exe")
        self.assertIn("S4U", script)

    def test_contains_working_directory(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\rc-test\\agent.exe")
        self.assertIn("-WorkingDirectory $wd", script)
        self.assertIn("Split-Path -Parent -LiteralPath $ep", script)

    def test_emits_schtask_state_marker(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("RCTEST_SCHTASK_STATE:", script)
        self.assertIn("Get-ScheduledTask", script)

    def test_emits_schtask_identity_and_result_markers(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("RCTEST_SCHTASK_NAME:", script)
        self.assertIn("RCTEST_SCHTASK_USER:", script)
        self.assertIn("RCTEST_SCHTASK_LOGON:", script)
        self.assertIn("RCTEST_SCHTASK_LASTTASKRESULT:", script)
        self.assertIn("RCTEST_SCHTASK_LASTRUNTIME:", script)

    def test_emits_schtask_process_probe(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("RCTEST_SCHTASK_PROCESS:", script)
        self.assertIn("Get-CimInstance Win32_Process", script)
        self.assertIn("Invoke-CimMethod", script)

    def test_contains_exe_path_single_quoted(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\rc-test\\agent.exe")
        self.assertIn("'C:\\Temp\\rc-test\\agent.exe'", script)

    def test_path_with_spaces_single_quoted(self) -> None:
        script = _windows_schtask_script("C:\\Program Files\\rc\\agent.exe")
        self.assertIn("'C:\\Program Files\\rc\\agent.exe'", script)

    def test_embedded_single_quote_is_doubled(self) -> None:
        script = _windows_schtask_script("C:\\it's here\\agent.exe")
        self.assertIn("it''s here", script)

    def test_unique_task_name_uses_guid(self) -> None:
        """Task name must be derived from a GUID to avoid collisions."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("NewGuid", script)

    def test_does_not_use_wmi(self) -> None:
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertNotIn("Invoke-WmiMethod", script)
        self.assertNotIn("Win32_Process.Create", script)

    def test_unregisters_task_after_start(self) -> None:
        """Task definition must be removed after launch to avoid accumulation."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("Unregister-ScheduledTask", script)
        start_idx = script.index("Start-ScheduledTask")
        unreg_idx = script.index("Unregister-ScheduledTask")
        self.assertLess(start_idx, unreg_idx, "Unregister must come after Start")

    def test_uses_windows_identity_for_user(self) -> None:
        """Must resolve current user via WindowsIdentity, not $env:USERNAME."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("WindowsIdentity", script)

    def test_unlimited_execution_time(self) -> None:
        """ExecutionTimeLimit must be zero so long-running agents are not killed."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertIn("ExecutionTimeLimit", script)
        self.assertIn("TimeSpan]::Zero", script)

    def test_no_arguments_omits_argument_clause(self) -> None:
        """When no arguments are supplied, -Argument must not appear in the script."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe")
        self.assertNotIn("-Argument", script)

    def test_arguments_included_via_argument_flag(self) -> None:
        """-Argument must be passed to New-ScheduledTaskAction when args are present."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe", "--sleep 5")
        self.assertIn("-Argument", script)
        self.assertIn("--sleep 5", script)

    def test_arguments_do_not_appear_in_execute(self) -> None:
        """-Execute must reference $exePath only, not embed arguments."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe", "--sleep 5")
        execute_idx = script.index("-Execute")
        argument_idx = script.index("-Argument")
        self.assertLess(execute_idx, argument_idx)
        self.assertIn("-Execute $ep", script)
        self.assertIn("'C:\\Temp\\agent.exe'", script)
        self.assertIn("-WorkingDirectory $wd", script)

    def test_arguments_with_spaces_single_quoted(self) -> None:
        """Argument values containing spaces must be single-quoted."""
        script = _windows_schtask_script("C:\\Temp\\agent.exe", "--config C:\\path with spaces\\cfg.toml")
        self.assertIn("-Argument", script)
        self.assertIn("--config C:\\path with spaces\\cfg.toml", script)


class TestExecuteBackgroundWindowsArguments(unittest.TestCase):
    """Tests that execute_background correctly passes arguments on Windows."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_no_arguments_no_argument_clause(self) -> None:
        """Plain exe path (no args) must not produce -Argument in the script."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Temp\\rc-test\\agent.exe")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertNotIn("-Argument", script)
        self.assertIn("C:\\Temp\\rc-test\\agent.exe", script)

    def test_arguments_parameter_produces_argument_clause(self) -> None:
        """Passing arguments= must produce -Argument in the scheduled task action."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Temp\\rc-test\\agent.exe", "--sleep 5 --port 8443")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("-Execute $ep", script)
        self.assertIn("-Argument", script)
        self.assertIn("--sleep 5 --port 8443", script)

    def test_arguments_with_spaces_in_exe_path(self) -> None:
        """Exe path with spaces plus arguments — both must appear correctly."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Program Files\\rc", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Program Files\\rc\\agent.exe", "--flag")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("-Execute $ep", script)
        self.assertIn("-Argument", script)
        self.assertIn("--flag", script)


class TestDefenderAddExclusion(unittest.TestCase):
    """Unit tests for defender_add_exclusion."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_target_runs_add_mppreference(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_add_exclusion(t, "C:\\Temp\\rc-test")
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("Add-MpPreference", script)
        self.assertIn("ExclusionPath", script)
        self.assertIn("C:\\Temp\\rc-test", script)

    def test_path_is_single_quoted(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_add_exclusion(t, "C:\\Temp\\rc-test")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("'C:\\Temp\\rc-test'", script)

    def test_uses_silent_continue_so_disabled_defender_does_not_fail(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_add_exclusion(t, "C:\\Temp\\rc-test")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("SilentlyContinue", script)

    def test_linux_target_raises_value_error(self) -> None:
        t = _make_target(work_dir="/tmp/rc-test", key=self.key_path)
        with self.assertRaises(ValueError) as ctx:
            defender_add_exclusion(t, "/tmp/rc-test")
        self.assertIn("Windows", str(ctx.exception))

    def test_path_with_spaces_quoted(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Program Files\\rc", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_add_exclusion(t, "C:\\Program Files\\rc")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("'C:\\Program Files\\rc'", script)


class TestDefenderProcessExclusion(unittest.TestCase):
    """defender_add_process_exclusion uses ExclusionProcess (basename only)."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_sends_exclusion_process(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_add_process_exclusion(t, "C:\\Temp\\rc-test\\agent-abcd1234.exe")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("ExclusionProcess", script)
        self.assertIn("'agent-abcd1234.exe'", script)

    def test_linux_raises(self) -> None:
        t = _make_target(work_dir="/tmp/x", key=self.key_path)
        with self.assertRaises(ValueError):
            defender_add_process_exclusion(t, "/tmp/x/a.exe")


class TestFirewallAllowProgram(unittest.TestCase):
    """firewall_allow_program adds outbound allow rule for a full exe path."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_new_net_firewall_rule(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            firewall_allow_program(t, "C:\\Temp\\rc-test\\agent-abcd1234.exe")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("New-NetFirewallRule", script)
        self.assertIn("-Direction Outbound", script)
        self.assertIn("agent-abcd1234.exe", script)
        self.assertIn("Remove-NetFirewallRule", script)

    def test_linux_raises(self) -> None:
        t = _make_target(work_dir="/tmp/x", key=self.key_path)
        with self.assertRaises(ValueError):
            firewall_allow_program(t, "/tmp/x/a.exe")


class TestDefenderRemoveProcessExclusion(unittest.TestCase):
    """defender_remove_process_exclusion uses Remove-MpPreference -ExclusionProcess (basename only)."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_sends_remove_exclusion_process(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_remove_process_exclusion(t, "C:\\Temp\\rc-test\\agent-abcd1234.exe")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("Remove-MpPreference", script)
        self.assertIn("ExclusionProcess", script)
        self.assertIn("'agent-abcd1234.exe'", script)
        self.assertNotIn("Add-MpPreference", script)

    def test_linux_raises(self) -> None:
        t = _make_target(work_dir="/tmp/x", key=self.key_path)
        with self.assertRaises(ValueError):
            defender_remove_process_exclusion(t, "/tmp/x/a.exe")

    def test_empty_basename_is_noop(self) -> None:
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run") as m:
            defender_remove_process_exclusion(t, "")
        m.assert_not_called()


class TestFirewallRemoveProgram(unittest.TestCase):
    """firewall_remove_program removes the RC-Harness-<digest> rule (Windows only)."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_removes_harness_rule(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            firewall_remove_program(t, "C:\\Temp\\rc-test\\agent-abcd1234.exe")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("Remove-NetFirewallRule", script)
        self.assertIn("RC-Harness-", script)
        self.assertNotIn("New-NetFirewallRule", script)

    def test_rule_name_matches_allow_program_digest(self) -> None:
        """firewall_remove_program uses the same digest as firewall_allow_program."""
        import hashlib
        path = "C:\\Temp\\rc-test\\agent-deadbeef.exe"
        digest = hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:12]
        expected_name = f"RC-Harness-{digest}"
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            firewall_remove_program(t, path)
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn(expected_name, script)

    def test_linux_raises(self) -> None:
        t = _make_target(work_dir="/tmp/x", key=self.key_path)
        with self.assertRaises(ValueError):
            firewall_remove_program(t, "/tmp/x/a.exe")


class TestDefenderDisableNetworkProtection(unittest.TestCase):
    """defender_disable_network_protection issues Set-MpPreference -EnableNetworkProtection Disabled."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_disables_network_protection(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_disable_network_protection(t)
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("Set-MpPreference", script)
        self.assertIn("EnableNetworkProtection", script)
        self.assertIn("Disabled", script)
        self.assertNotIn("ExclusionIpAddress", script)

    def test_linux_raises(self) -> None:
        t = _make_target(work_dir="/tmp/x", key=self.key_path)
        with self.assertRaises(ValueError):
            defender_disable_network_protection(t)


class TestInjectHostsEntry(unittest.TestCase):
    """Tests for inject_hosts_entry — idempotent /etc/hosts injection via SSH."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(host="10.0.0.1", key=self.key_path)

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_success_does_not_raise(self) -> None:
        """inject_hosts_entry must not raise when SSH exits 0 (entry injected or already present)."""
        with patch("subprocess.run", return_value=self._completed(0)):
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")

    def test_failure_raises_deploy_error(self) -> None:
        """Non-zero exit must raise DeployError with host and entry in the message."""
        with patch("subprocess.run", return_value=self._completed(1, "sudo: command not found")):
            with self.assertRaises(DeployError) as ctx:
                inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        msg = str(ctx.exception)
        self.assertIn("10.0.0.1", msg)
        self.assertIn("c2.test.local", msg)
        self.assertIn("192.168.1.50", msg)

    def test_command_contains_idempotent_grep_check(self) -> None:
        """SSH command must check /etc/hosts before appending (idempotency)."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("grep", remote_cmd)
        self.assertIn("/etc/hosts", remote_cmd)
        self.assertIn("tee -a /etc/hosts", remote_cmd)

    def test_command_contains_expected_entry(self) -> None:
        """SSH command must embed the ip and domain in the hosts entry."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "10.99.0.1")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("10.99.0.1", remote_cmd)
        self.assertIn("c2.test.local", remote_cmd)

    def test_domain_with_shell_metacharacters_is_quoted(self) -> None:
        """Domain with metacharacters must not result in a bare-word injection."""
        domain = "evil$(rm -rf /)"
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, domain, "127.0.0.1")
        remote_cmd = mock_run.call_args[0][0][-1]
        # shlex.quote wraps the entry in single quotes; the $(…) must never
        # appear as a bare (unquoted) token in the command string.
        self.assertIn(shlex.quote(f"127.0.0.1  {domain}"), remote_cmd)

    def test_uses_sudo_tee(self) -> None:
        """Entry must be appended via sudo so non-root SSH users can write /etc/hosts."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("sudo", remote_cmd)
        self.assertIn("tee", remote_cmd)

    def test_transient_failure_exhausts_retries_and_raises(self) -> None:
        """Transient SSH failures are retried; exhaustion must raise DeployError."""
        bad = self._completed(255, "ssh: connect to host 10.0.0.1 port 22: Connection refused")
        with patch("subprocess.run", return_value=bad):
            with patch("lib.deploy.time.sleep"):
                with self.assertRaises(DeployError):
                    inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")


class TestInjectHostsEntryWindows(unittest.TestCase):
    """Tests for inject_hosts_entry on Windows targets."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()
        self.target = _make_target(
            host="10.0.0.2",
            key=self.key_path,
            work_dir="C:\\Users\\testuser\\Desktop",
            platform="windows",
        )

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_success_does_not_raise(self) -> None:
        """inject_hosts_entry must not raise when SSH exits 0 on a Windows target."""
        with patch("subprocess.run", return_value=self._completed(0)):
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")

    def test_failure_raises_deploy_error(self) -> None:
        """Non-zero exit on Windows must raise DeployError with host and entry."""
        with patch("subprocess.run", return_value=self._completed(1, "Access denied")):
            with self.assertRaises(DeployError) as ctx:
                inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        msg = str(ctx.exception)
        self.assertIn("10.0.0.2", msg)
        self.assertIn("c2.test.local", msg)
        self.assertIn("drivers", msg)

    def test_command_uses_powershell(self) -> None:
        """Windows branch must use powershell, not grep/tee."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("powershell", remote_cmd)
        self.assertNotIn("grep", remote_cmd)
        self.assertNotIn("sudo", remote_cmd)

    def test_command_contains_idempotent_check(self) -> None:
        """Windows command must check hosts file before appending (Select-String)."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("Select-String", remote_cmd)
        self.assertIn("Add-Content", remote_cmd)

    def test_command_targets_windows_hosts_path(self) -> None:
        """Windows command must target the Windows hosts file path."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn(r"C:\Windows\System32\drivers\etc\hosts", remote_cmd)

    def test_command_contains_expected_entry(self) -> None:
        """Windows SSH command must embed the ip and domain in the hosts entry."""
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(self.target, "c2.test.local", "10.99.0.1")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("10.99.0.1", remote_cmd)
        self.assertIn("c2.test.local", remote_cmd)

    def test_linux_target_still_uses_grep_tee(self) -> None:
        """Linux target must still use the grep/tee path, not PowerShell."""
        linux_target = _make_target(host="10.0.0.3", key=self.key_path)
        with patch("subprocess.run", return_value=self._completed(0)) as mock_run:
            inject_hosts_entry(linux_target, "c2.test.local", "192.168.1.50")
        remote_cmd = mock_run.call_args[0][0][-1]
        self.assertIn("grep", remote_cmd)
        self.assertIn("sudo", remote_cmd)
        self.assertNotIn("powershell", remote_cmd)


class TestCleanupWindowsHarnessWorkDir(unittest.TestCase):
    """Unit tests for :func:`cleanup_windows_harness_work_dir`."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_linux_target_does_not_open_ssh(self, mock_ssh: object) -> None:
        t = _make_target(work_dir="/tmp/rc-test", key=self.key_path)
        cleanup_windows_harness_work_dir(t)
        mock_ssh.assert_not_called()

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_windows_uses_encoded_cleanup_script(self, mock_ssh: object) -> None:
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        cleanup_windows_harness_work_dir(t, timeout=100)
        mock_ssh.assert_called_once()
        cmd_list = mock_ssh.call_args[0][0]
        remote = cmd_list[-1]
        self.assertIn("-EncodedCommand", remote)
        decoded = _decoded_windows_launch_script(remote)
        self.assertIn("agent-*.exe", decoded)
        self.assertIn("stress-agent-*.exe", decoded)
        self.assertIn("Stop-Process", decoded)
        self.assertIn(r"C:\Temp\rc-test", decoded)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_locked_files_emits_single_summary_line(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="HARNESS_LOCKED_FILES:C:\\Temp\\rc-test\\a.exe\n",
            stderr="",
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        cleanup_windows_harness_work_dir(t, log_prefix="  [tag]")
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(
            any("locked harness files remain" in p for p in printed),
            printed,
        )

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry", side_effect=DeployError("ssh failed"))
    def test_deploy_error_prints_skipped_message(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        cleanup_windows_harness_work_dir(t, log_prefix="  [tag]")
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(any("cleanup skipped" in p for p in printed), printed)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_includes_defender_firewall_sweep(self, mock_ssh: object) -> None:
        """Cleanup script must revert RC-Harness-* firewall rules and agent-*.exe exclusions."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        cleanup_windows_harness_work_dir(t, timeout=100)
        cmd_list = mock_ssh.call_args[0][0]
        decoded = _decoded_windows_launch_script(cmd_list[-1])
        self.assertIn("Remove-NetFirewallRule", decoded)
        self.assertIn("RC-Harness-*", decoded)
        self.assertIn("Remove-MpPreference", decoded)
        self.assertIn("ExclusionProcess", decoded)
        self.assertIn("agent-", decoded)
        self.assertIn("stress-agent-", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_defender_sweep_precedes_work_dir_check(self, mock_ssh: object) -> None:
        """Defender/firewall cleanup must appear before the work-dir existence check."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        cleanup_windows_harness_work_dir(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        fw_pos = decoded.index("Remove-NetFirewallRule")
        wd_pos = decoded.index("Test-Path")
        self.assertLess(fw_pos, wd_pos)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_no_ip_exclusions_in_script(self, mock_ssh: object) -> None:
        """Script must not contain ExclusionIpAddress — NP is disabled globally, not per-run."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        cleanup_windows_harness_work_dir(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertNotIn("ExclusionIpAddress", decoded)


class TestWfpPreflightCleanup(unittest.TestCase):
    """Unit tests for :func:`wfp_preflight_cleanup`."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_linux_target_does_not_open_ssh(self, mock_ssh: object) -> None:
        """No SSH connection for Linux targets — function must be a no-op."""
        t = _make_target(work_dir="/tmp/rc-test", key=self.key_path)
        wfp_preflight_cleanup(t)
        mock_ssh.assert_not_called()

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_windows_uses_encoded_command(self, mock_ssh: object) -> None:
        """Windows target must send a PowerShell -EncodedCommand invocation."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        mock_ssh.assert_called_once()
        remote = mock_ssh.call_args[0][0][-1]
        self.assertIn("-EncodedCommand", remote)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_removes_rc_harness_rules(self, mock_ssh: object) -> None:
        """Script must remove RC-Harness-* firewall rules."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertIn("Remove-NetFirewallRule", decoded)
        self.assertIn("RC-Harness-*", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_removes_agent_rules(self, mock_ssh: object) -> None:
        """Script must also remove agent-* display-name rules (Windows-auto-created)."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertIn("agent-*", decoded)
        self.assertIn("Remove-NetFirewallRule", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_removes_exclusion_process(self, mock_ssh: object) -> None:
        """Script must remove agent-*.exe / stress-agent-*.exe process exclusions."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertIn("ExclusionProcess", decoded)
        self.assertIn("Remove-MpPreference", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_no_ip_exclusion_removal_in_script(self, mock_ssh: object) -> None:
        """Script must not remove ExclusionIpAddress — NP is disabled globally, not per-run."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertNotIn("ExclusionIpAddress", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_emits_wfp_before_and_after_markers(self, mock_ssh: object) -> None:
        """Script must emit WFP_BEFORE: and WFP_AFTER: markers for diagnostics."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertIn("WFP_BEFORE:", decoded)
        self.assertIn("WFP_AFTER:", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_measures_wfp_filter_count(self, mock_ssh: object) -> None:
        """Script must invoke netsh wfp show state and include wfp= in both diagnostic lines.

        This captures WFP filter objects owned by Defender and other WFP providers
        that are not visible via Get-NetFirewallRule — the primary non-paged-pool
        consumers that survive the firewall-rule sweep (os error 10055 root cause).
        """
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertIn('netsh wfp show state "file=$_wfp_tmp"', decoded)
        self.assertIn('netsh wfp show state "file=$_wfp_tmp2"', decoded)
        self.assertIn("_wfp_count", decoded)
        self.assertIn("',wfp=' + $_wfp_count", decoded)
        self.assertIn("',wfp=' + $_wfp_count_after", decoded)

    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_script_measures_time_wait_connections(self, mock_ssh: object) -> None:
        """Script must measure TCP TIME_WAIT count and include twait= in both diagnostic lines.

        TIME_WAIT connections persist for up to 4 minutes after close and consume
        non-paged pool even after firewall rules are swept.  Tracking twait= across
        runs reveals whether zombie connections are accumulating between scenarios.
        """
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, timeout=100)
        decoded = _decoded_windows_launch_script(mock_ssh.call_args[0][0][-1])
        self.assertIn("Get-NetTCPConnection -State TimeWait", decoded)
        self.assertIn("_twait", decoded)
        self.assertIn("',twait=' + $_twait", decoded)
        self.assertIn("',twait=' + $_twait_after", decoded)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_wfp_after_output_is_logged(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """WFP_BEFORE:/WFP_AFTER: lines in stdout must be printed with the log prefix."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="WFP_BEFORE:rc=3,agent=2,wfp=847,twait=12\nWFP_AFTER:rc=0,agent=0,wfp=831,twait=8\n",
            stderr="",
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, log_prefix="  [tag]", timeout=100)
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(any("[tag]" in p and "before" in p for p in printed), printed)
        self.assertTrue(any("[tag]" in p and "after" in p for p in printed), printed)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_wfp_after_remaining_rules_emits_warning(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """If WFP_AFTER shows remaining rules, a WARNING line must be printed."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="WFP_BEFORE:rc=3,agent=2,wfp=850,twait=5\nWFP_AFTER:rc=1,agent=0,wfp=851,twait=3\n",
            stderr="",
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, log_prefix="  [tag]", timeout=100)
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(any("WARNING" in p for p in printed), printed)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry", side_effect=Exception("connection refused"))
    def test_ssh_failure_prints_skipped_and_does_not_raise(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """SSH failures must be swallowed — function must never raise."""
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, log_prefix="  [tag]", timeout=100)
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(any("skipped" in p for p in printed), printed)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_nonzero_exit_prints_error_and_does_not_raise(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """A non-zero PowerShell exit code must be logged but must not raise."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="access denied"
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        wfp_preflight_cleanup(t, log_prefix="  [tag]", timeout=100)
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(any("remote sweep failed" in p for p in printed), printed)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_returns_parsed_wfp_after_on_success(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """Successful sweep must return dict with wfp_after and twait_after parsed from WFP_AFTER:."""
        mock_ssh.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="WFP_BEFORE:rc=3,agent=2,wfp=847,twait=12\nWFP_AFTER:rc=0,agent=0,wfp=831,twait=8\n",
            stderr="",
        )
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(t, log_prefix="  [tag]", timeout=100)
        self.assertIsNotNone(result, "should return dict, not None, on success")
        self.assertEqual(result["wfp_after"], 831)
        self.assertEqual(result["twait_after"], 8)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry", side_effect=Exception("refused"))
    def test_returns_none_on_ssh_failure(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """SSH failures must return None — callers can check for None rather than catching."""
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(t, log_prefix="  [tag]", timeout=100)
        self.assertIsNone(result)

    def test_returns_none_for_nonwindows_target(self) -> None:
        """Non-Windows targets must return None immediately without doing any network I/O."""
        t = _make_target(work_dir="/tmp/rc-test", platform="linux", key=self.key_path)
        result = wfp_preflight_cleanup(t)
        self.assertIsNone(result)

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_restart_nonzero_exit_reports_failure_not_success(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """Non-zero mpssvc restart exit must warn and return original parsed_after, not claim success.

        Regression: the original code used ``; exit 0`` in the restart script which masked
        PowerShell errors, and discarded the return value so a non-zero exit was never
        checked — causing a spurious "mpssvc restarted" success message and continuing
        the sweep against unchanged (exhausted) WFP state.
        """
        sweep_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=3,agent=2,wfp=900,twait=12\n"
                "WFP_AFTER:rc=0,agent=0,wfp=900,twait=8\n"
            ),
            stderr="",
        )
        restart_result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Access is denied."
        )
        mock_ssh.side_effect = [sweep_result, restart_result]
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(
            t, log_prefix="  [tag]", timeout=100, restart_threshold=WFP_RESTART_THRESHOLD
        )
        # Must return the original sweep's parsed_after — restart failed but sweep data is valid.
        self.assertIsNotNone(result, "should return original parsed_after, not None")
        self.assertEqual(result["wfp_after"], 900)
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        # Must NOT print the spurious success message.
        self.assertFalse(
            any("restarted" in p for p in printed),
            f"should not claim restart succeeded; got: {printed}",
        )
        # Must print a failure/warning message.
        self.assertTrue(
            any("restart failed" in p or "WARNING" in p for p in printed),
            f"should warn about restart failure; got: {printed}",
        )

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_restart_exception_reports_failure_not_success(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """Exception raised during mpssvc restart must print failure and return original parsed_after.

        Exercises the ``except Exception`` branch (~line 1098 of deploy.py) that fires when
        ``_run_ssh_cli_with_retry`` raises (e.g. DeployError after exhausted retries or
        subprocess.TimeoutExpired) rather than returning a CompletedProcess.  The sweep
        call succeeds with wfp_after above ``restart_threshold``, triggering the restart
        path; the restart call then raises.
        """
        sweep_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=3,agent=2,wfp=900,twait=12\n"
                "WFP_AFTER:rc=0,agent=0,wfp=900,twait=8\n"
            ),
            stderr="",
        )
        mock_ssh.side_effect = [sweep_result, Exception("connection timed out")]
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(
            t, log_prefix="  [tag]", timeout=100, restart_threshold=WFP_RESTART_THRESHOLD
        )
        # Must return the original sweep's parsed_after — restart raised but sweep data is valid.
        self.assertIsNotNone(result, "should return original parsed_after, not None")
        self.assertEqual(result["wfp_after"], 900)
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        # Must NOT print the spurious success message.
        self.assertFalse(
            any("restarted" in p for p in printed),
            f"should not claim restart succeeded; got: {printed}",
        )
        # Must print a failure message mentioning 'restart failed'.
        self.assertTrue(
            any("restart failed" in p for p in printed),
            f"should report restart failure; got: {printed}",
        )

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_wfp_critical_set_when_mpssvc_restart_refused_by_os(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """wfp_critical must be True when mpssvc restart itself exits non-zero.

        CouldNotStopService / non-zero exit means the OS refused the restart.
        The WFP count is still >= threshold — callers must skip Windows scenarios.
        Previously this path returned parsed_after without wfp_critical, causing
        Windows scenarios to run and time out with WSAENOBUFS / os error 10055.
        """
        first_sweep = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=0,agent=0,wfp=6398,twait=10\n"
                "WFP_AFTER:rc=0,agent=0,wfp=6398,twait=10\n"
            ),
            stderr="",
        )
        restart_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="CouldNotStopService"
        )
        mock_ssh.side_effect = [first_sweep, restart_fail]
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(
            t, log_prefix="  [tag]", timeout=100, restart_threshold=WFP_RESTART_THRESHOLD
        )
        self.assertIsNotNone(result, "should return dict, not None")
        self.assertEqual(result.get("wfp_after"), 6398)
        self.assertTrue(
            result.get("wfp_critical"),
            f"wfp_critical must be True when mpssvc restart is refused; got: {result}",
        )
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(
            any("CRITICAL" in p and "reboot required" in p for p in printed),
            f"must print CRITICAL reboot-required warning; got: {printed}",
        )

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_wfp_critical_set_when_post_restart_still_above_threshold(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """wfp_critical must be True when post-mpssvc-restart wfp_after is still >= threshold.

        Exercises the case where the WFP objects surviving mpssvc restart are OS-level
        platform/driver filters (not Defender callout objects) — only a full VM reboot
        can drain them.  The returned dict must have ``wfp_critical: True`` so callers can
        skip remaining Windows scenarios rather than deploying agents that will fail with
        WSAENOBUFS / os error 10055.
        """
        first_sweep = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=0,agent=0,wfp=6393,twait=4\n"
                "WFP_AFTER:rc=0,agent=0,wfp=6393,twait=4\n"
            ),
            stderr="",
        )
        restart_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        retry_sweep = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=0,agent=0,wfp=6393,twait=4\n"
                "WFP_AFTER:rc=0,agent=0,wfp=6393,twait=4\n"
            ),
            stderr="",
        )
        mock_ssh.side_effect = [first_sweep, restart_ok, retry_sweep]
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(
            t, log_prefix="  [tag]", timeout=100, restart_threshold=WFP_RESTART_THRESHOLD
        )
        self.assertIsNotNone(result, "should return dict, not None")
        self.assertEqual(result.get("wfp_after"), 6393)
        self.assertTrue(
            result.get("wfp_critical"),
            f"wfp_critical must be True when post-restart wfp >= threshold; got: {result}",
        )
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertTrue(
            any("CRITICAL" in p and "reboot required" in p for p in printed),
            f"must print CRITICAL reboot-required warning; got: {printed}",
        )

    @patch("builtins.print")
    @patch("lib.deploy._run_ssh_cli_with_retry")
    def test_wfp_critical_not_set_when_post_restart_below_threshold(
        self, mock_ssh: object, mock_print: object,
    ) -> None:
        """wfp_critical must NOT be set when mpssvc restart successfully reduces wfp_after.

        Verifies the happy path: restart clears the callout objects and the retry sweep
        shows wfp_after < threshold — no critical flag, no spurious warning.
        """
        first_sweep = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=0,agent=0,wfp=900,twait=4\n"
                "WFP_AFTER:rc=0,agent=0,wfp=900,twait=4\n"
            ),
            stderr="",
        )
        restart_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        retry_sweep = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "WFP_BEFORE:rc=0,agent=0,wfp=350,twait=2\n"
                "WFP_AFTER:rc=0,agent=0,wfp=350,twait=2\n"
            ),
            stderr="",
        )
        mock_ssh.side_effect = [first_sweep, restart_ok, retry_sweep]
        t = _make_target(work_dir=r"C:\Temp\rc-test", platform="windows", key=self.key_path)
        result = wfp_preflight_cleanup(
            t, log_prefix="  [tag]", timeout=100, restart_threshold=WFP_RESTART_THRESHOLD
        )
        self.assertIsNotNone(result, "should return dict, not None")
        self.assertEqual(result.get("wfp_after"), 350)
        self.assertFalse(
            result.get("wfp_critical"),
            f"wfp_critical must be absent/False when post-restart wfp < threshold; got: {result}",
        )
        printed = [str(c.args[0]) for c in mock_print.call_args_list if c.args]
        self.assertFalse(
            any("CRITICAL" in p for p in printed),
            f"must not print CRITICAL warning when restart succeeded; got: {printed}",
        )


if __name__ == "__main__":
    unittest.main()
