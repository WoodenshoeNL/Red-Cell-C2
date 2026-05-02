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
    cleanup_windows_harness_work_dir,
    defender_add_process_exclusion,
    defender_remove_process_exclusion,
    defender_network_protection_exclusion,
    defender_remove_network_protection_exclusion,
    firewall_allow_program,
    firewall_remove_program,
    _is_transient_ssh_failure,
    _quote_posix,
    _quote_powershell,
    _scp_args,
    _ssh_args,
    _windows_wmi_create_script,
    _windows_schtask_script,
    defender_add_exclusion,
    ensure_work_dir,
    execute_background,
    inject_hosts_entry,
    preflight_dns,
    preflight_ssh,
    run_remote,
    upload,
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
        self.key_path = _module_key_path()
        self.target = _make_target(host="10.0.0.1", key=self.key_path)

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


class TestDefenderRemoveNetworkProtectionExclusion(unittest.TestCase):
    """defender_remove_network_protection_exclusion uses Remove-MpPreference -ExclusionIpAddress."""

    def setUp(self) -> None:
        self.key_path = _module_key_path()

    def _completed(
        self, returncode: int, stderr: str = "", stdout: str = ""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_windows_removes_ip_exclusion(self) -> None:
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", platform="windows", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            defender_remove_network_protection_exclusion(t, "10.0.0.1")
        script = _decoded_windows_launch_script(m.call_args[0][0][-1])
        self.assertIn("Remove-MpPreference", script)
        self.assertIn("ExclusionIpAddress", script)
        self.assertIn("10.0.0.1", script)
        self.assertNotIn("Add-MpPreference", script)

    def test_linux_raises(self) -> None:
        t = _make_target(work_dir="/tmp/x", key=self.key_path)
        with self.assertRaises(ValueError):
            defender_remove_network_protection_exclusion(t, "10.0.0.1")


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


if __name__ == "__main__":
    unittest.main()
