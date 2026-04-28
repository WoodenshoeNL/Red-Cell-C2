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
    _is_transient_ssh_failure,
    _quote_posix,
    _quote_powershell,
    _scp_args,
    _ssh_args,
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
        )
        self.assertEqual(t.work_dir, "C:\\Temp\\rc-test")


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
            host="192.168.213.160", work_dir="C:\\rc-test", key=self.key_path,
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

    def test_execute_background_windows_uses_wmi(self) -> None:
        """Windows deploy must use WMI Win32_Process.Create to escape SSH job objects."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp\\rc-test", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Temp\\rc-test\\agent.exe")
        self.assertEqual(m.call_count, 1)
        remote_cmd = m.call_args[0][0][-1]
        self.assertIn("-EncodedCommand", remote_cmd)
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("Invoke-WmiMethod", script)
        self.assertIn("Win32_Process", script)
        self.assertIn("ReturnValue", script)
        self.assertIn("C:\\Temp\\rc-test\\agent.exe", script)
        self.assertIn("C:\\Temp\\rc-test", script)
        self.assertIn("-ArgumentList", script)
        self.assertIn(",", script)
        self.assertNotIn("Start-Process", script)

    def test_execute_background_windows_quotes_paths_with_spaces(self) -> None:
        """Paths with spaces must be double-quoted for CreateProcess."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Program Files\\rc", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\Program Files\\rc\\agent.exe")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("Invoke-WmiMethod", script)
        self.assertIn('"C:\\Program Files\\rc\\agent.exe"', script)
        self.assertIn("C:\\Program Files\\rc", script)

    def test_execute_background_windows_escapes_single_quotes(self) -> None:
        """Single quotes in the command must be doubled for PS single-quote string."""
        ok = self._completed(0)
        t = _make_target(work_dir="C:\\Temp", key=self.key_path)
        with patch("subprocess.run", return_value=ok) as m:
            execute_background(t, "C:\\it's here\\agent.exe")
        remote_cmd = m.call_args[0][0][-1]
        script = _decoded_windows_launch_script(remote_cmd)
        self.assertIn("it''s here", script)


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


if __name__ == "__main__":
    unittest.main()
