"""
lib/deploy.py — SSH/SCP deployment helpers for Linux and Windows targets.

Uses the system `ssh` and `scp` binaries so no extra Python dependencies
are needed. Both Linux and Windows targets are accessed via SSH
(OpenSSH for Windows — see docs/win11-ssh-setup.md).
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from lib import ScenarioSkipped

logger = logging.getLogger(__name__)

_SSH_MAX_ATTEMPTS = 3
_SSH_RETRY_BACKOFF_SEC = 2

# Set by :func:`configure_deploy_timeouts` from ``config/env.toml`` ``[timeouts]``.
_SSH_CONNECT_SECS = 10
_SCP_TRANSFER_SECS = 60
_DEFAULT_REMOTE_CMD_SECS = 30


def configure_deploy_timeouts(
    *,
    ssh_connect_secs: float,
    scp_transfer_secs: float,
    default_remote_cmd_secs: float,
) -> None:
    """Apply harness timeout values to SSH/SCP helpers (call once from ``test.py`` main)."""

    global _SSH_CONNECT_SECS, _SCP_TRANSFER_SECS, _DEFAULT_REMOTE_CMD_SECS
    _SSH_CONNECT_SECS = max(1, int(ssh_connect_secs))
    _SCP_TRANSFER_SECS = max(1, int(scp_transfer_secs))
    _DEFAULT_REMOTE_CMD_SECS = max(1, int(default_remote_cmd_secs))


class DeployError(Exception):
    pass


def _is_transient_ssh_failure(stderr: str, stdout: str = "") -> bool:
    """Return True if ssh/scp output indicates a retryable connection-level failure."""
    combined = f"{stderr}\n{stdout}".lower()
    return (
        "connection timed out" in combined
        or "connection refused" in combined
    )


def _run_ssh_cli_with_retry(
    cmd: list[str],
    host: str,
    *,
    timeout: int | None,
    tool: str = "ssh",
    raise_on_exhausted_transient: bool = True,
) -> subprocess.CompletedProcess:
    """Run ``ssh`` or ``scp`` with retries on transient connection failures.

    Retries at most ``_SSH_MAX_ATTEMPTS`` times with ``_SSH_RETRY_BACKOFF_SEC``
    seconds between attempts. Only ``Connection timed out`` and
    ``Connection refused`` in combined stderr/stdout trigger retries.

    Args:
        cmd: Full argv (including ``ssh`` or ``scp`` as ``cmd[0]``).
        host: Target hostname for logging and error messages.
        timeout: Subprocess timeout, or None for no limit.
        tool: ``\"ssh\"`` or ``\"scp\"`` — used in log lines and :class:`DeployError` text.
        raise_on_exhausted_transient: If False, return the last failed
            :class:`~subprocess.CompletedProcess` when all attempts exhaust on a
            transient error (used by :func:`named_pipe_exists`).

    Returns:
        The completed process (exit code 0 on success).

    Raises:
        DeployError: After all retries are exhausted on a transient failure
            (when ``raise_on_exhausted_transient`` is True), or
            :class:`subprocess.TimeoutExpired` from :func:`subprocess.run`
            (not retried).
    """
    last_result: subprocess.CompletedProcess | None = None
    for attempt in range(1, _SSH_MAX_ATTEMPTS + 1):
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        last_result = result
        if result.returncode == 0:
            return result
        combined = (result.stderr or "") + (result.stdout or "")
        transient = _is_transient_ssh_failure(result.stderr or "", result.stdout or "")
        if transient and attempt < _SSH_MAX_ATTEMPTS:
            log_label = "SSH" if tool == "ssh" else "SCP"
            logger.warning(
                "%s to %s failed (attempt %d/%d), retrying in %ds...",
                log_label,
                host,
                attempt,
                _SSH_MAX_ATTEMPTS,
                _SSH_RETRY_BACKOFF_SEC,
            )
            time.sleep(_SSH_RETRY_BACKOFF_SEC)
            continue
        if transient and attempt == _SSH_MAX_ATTEMPTS:
            if not raise_on_exhausted_transient:
                return result
            exhausted_label = "SSH" if tool == "ssh" else "SCP"
            raise DeployError(
                f"{exhausted_label} to {host} failed after {_SSH_MAX_ATTEMPTS} attempts: "
                f"{combined.strip()}"
            )
        return result
    assert last_result is not None
    return last_result


@dataclass
class TargetConfig:
    host: str
    port: int
    user: str
    work_dir: str
    key: str  # path to SSH private key — required, password auth is not supported
    display: str = ""  # X11 DISPLAY value for Linux targets with Xvfb (e.g. ":99")

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError(
                f"SSH target {self.user}@{self.host}: 'key' is required — "
                "password authentication is not supported (BatchMode=yes is always set). "
                "Generate a key with ssh-keygen and set key= in targets.toml."
            )
        key_path = Path(self.key).expanduser()
        if not key_path.is_file():
            raise ValueError(
                f"SSH target {self.user}@{self.host}: SSH private key file not found: {key_path}"
            )


def _ssh_args(target: TargetConfig) -> list[str]:
    return [
        "ssh",
        "-p", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_SECS}",
        "-i", target.key,
        f"{target.user}@{target.host}",
    ]


def _scp_args(target: TargetConfig) -> list[str]:
    return [
        "scp",
        "-P", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_SECS}",
        "-i", target.key,
    ]


def preflight_ssh(target: TargetConfig) -> None:
    """Check that the target host is reachable via SSH before deploying.

    Uses ``ConnectTimeout`` from :func:`configure_deploy_timeouts` so tuning is
    centralised with the rest of the harness.
    Call this at the start of any scenario that deploys a payload via SSH.

    Raises:
        DeployError: if the SSH connection cannot be established.
    """
    cmd = [
        "ssh",
        "-p", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_SECS}",
        "-i", target.key,
        f"{target.user}@{target.host}",
        "exit 0",
    ]
    result = _run_ssh_cli_with_retry(
        cmd, target.host, timeout=max(_SSH_CONNECT_SECS + 5, 10), tool="ssh"
    )
    if result.returncode != 0:
        raise DeployError(
            f"target {target.host} not reachable via SSH — "
            "check targets.toml and network"
        )


def preflight_dns(target: TargetConfig, domain: str, expected_ip: str) -> None:
    """Check that ``domain`` resolves to ``expected_ip`` on the target machine.

    On Linux targets, runs a ``python3`` one-liner via SSH.  On Windows targets
    (detected by ``work_dir`` containing backslashes), runs a PowerShell
    ``[System.Net.Dns]::GetHostAddresses()`` probe instead — Windows does not
    ship Python by default and the Microsoft Store stub causes misleading errors.

    DNS listener scenarios (15, 20) require the C2 domain to resolve to the
    teamserver IP on the target's resolver before the agent can check in.
    If the setup is missing the agent silently fails to connect and the scenario
    times out with no indication of the root cause.

    Args:
        target:      SSH target to probe DNS resolution from.
        domain:      C2 domain to resolve (e.g. ``"c2.test.local"``).
        expected_ip: Teamserver IP the domain must map to.

    Raises:
        ScenarioSkipped: if resolution fails or returns an unexpected address,
            with an actionable message describing the required hosts-file
            entry.
    """
    is_windows = target.work_dir.startswith("C:\\") or "\\" in target.work_dir
    if is_windows:
        escaped = domain.replace("'", "''")
        probe = (
            "powershell -NoProfile -Command \""
            f"([System.Net.Dns]::GetHostAddresses('{escaped}') "
            "| Where-Object { $_.AddressFamily -eq 'InterNetwork' } "
            "| Select-Object -First 1).IPAddressToString\""
        )
    else:
        probe = (
            "python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "
            + shlex.quote(domain)
        )
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [probe],
        target.host,
        timeout=15,
        tool="ssh",
    )
    hosts_hint = (
        r"C:\Windows\System32\drivers\etc\hosts"
        if is_windows
        else "/etc/hosts"
    )
    if result.returncode != 0:
        raise ScenarioSkipped(
            f"DNS for {domain!r} on {target.host} could not be resolved "
            f"(probe failed: {result.stderr.strip()}); "
            f"add entry to {hosts_hint}: '{expected_ip}  {domain}'"
        )
    actual_ip = result.stdout.strip()
    if actual_ip != expected_ip:
        raise ScenarioSkipped(
            f"DNS for {domain!r} on {target.host} resolves to {actual_ip!r} "
            f"not {expected_ip!r}; "
            f"add entry to {hosts_hint}: '{expected_ip}  {domain}'"
        )


def inject_hosts_entry(target: TargetConfig, domain: str, ip: str) -> None:
    """Ensure the hosts file on *target* maps *domain* to *ip*.

    Idempotent — a no-op if the exact ``"ip  domain"`` line is already
    present.

    On Linux targets, uses ``sudo tee -a`` so the SSH user does not need
    write permission on ``/etc/hosts``; the account must have passwordless
    sudo.

    On Windows targets (detected by ``work_dir`` containing backslashes),
    uses PowerShell to idempotently append to
    ``C:\\Windows\\System32\\drivers\\etc\\hosts``.  The SSH user must have
    Administrator privileges.

    DNS scenarios (15, 20) call this before :func:`preflight_dns` so the
    harness injects the required entry automatically rather than requiring
    manual host configuration on the test VM.

    Args:
        target: SSH target to modify (Linux or Windows).
        domain: Hostname to add (e.g. ``"c2.test.local"``).
        ip:     IP address to map it to (e.g. ``"192.168.213.157"``).

    Raises:
        DeployError: if the SSH command exits non-zero.
    """
    entry = f"{ip}  {domain}"
    is_windows = target.work_dir.startswith("C:\\") or "\\" in target.work_dir
    if is_windows:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        escaped_entry = entry.replace("'", "''")
        escaped_path = hosts_path.replace("'", "''")
        cmd = (
            "powershell -NoProfile -Command \""
            f"$h = '{escaped_path}'; "
            f"$e = '{escaped_entry}'; "
            "if (-not (Select-String -Path $h -SimpleMatch $e -Quiet)) "
            "{ Add-Content -Path $h -Value $e }\""
        )
    else:
        cmd = (
            f"grep -qF {shlex.quote(entry)} /etc/hosts || "
            f"echo {shlex.quote(entry)} | sudo tee -a /etc/hosts > /dev/null"
        )
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [cmd],
        target.host,
        timeout=15,
        tool="ssh",
    )
    hosts_file = hosts_path if is_windows else "/etc/hosts"
    if result.returncode != 0:
        raise DeployError(
            f"inject_hosts_entry: failed to add '{entry}' to {hosts_file} on "
            f"{target.host} — exit {result.returncode}: {result.stderr.strip()}"
        )
    logger.debug("inject_hosts_entry: '%s' ensured on %s", entry, target.host)


def named_pipe_exists(target: TargetConfig, pipe_name: str, ssh_timeout: int = 25) -> bool:
    """Return True if the named pipe exists on the Windows target (``Test-Path`` on ``\\\\.\\pipe\\``).

    Uses SSH + PowerShell (``Test-Path -LiteralPath``) so the probe runs on the
    same machine the agent will use. Used as a pre-flight after starting an SMB
    listener so bind failures surface before deploy/checkin timeouts.

    Args:
        target:       Windows SSH target.
        pipe_name:    Pipe name suffix (same as listener config, under ``\\\\.\\pipe\\``).
        ssh_timeout:  Per-attempt SSH subprocess timeout in seconds.

    Returns:
        True if PowerShell reports the path exists; False on SSH failure,
        non-zero exit, or stdout other than ``True``.
    """
    safe = pipe_name.replace("'", "''")
    pipe_path = f"\\\\.\\pipe\\{safe}"
    remote_cmd = (
        'powershell -NoProfile -Command '
        f'"Test-Path -LiteralPath \'{pipe_path}\'"'
    )
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [remote_cmd],
        target.host,
        timeout=ssh_timeout,
        tool="ssh",
        raise_on_exhausted_transient=False,
    )
    if result.returncode != 0:
        return False
    return result.stdout.strip().lower() == "true"


def run_remote(target: TargetConfig, command: str, timeout: int | None = None) -> str:
    """Run a shell command on the target via SSH and return stdout.

    When *timeout* is ``None``, uses the value set by :func:`configure_deploy_timeouts`
    (default remote command ceiling, typically ``command_output_secs`` from env).
    """
    if timeout is None:
        timeout = _DEFAULT_REMOTE_CMD_SECS
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [command],
        target.host,
        timeout=timeout,
        tool="ssh",
    )
    if result.returncode != 0:
        raise DeployError(
            f"Remote command failed (exit {result.returncode}):\n"
            f"  cmd: {command}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def upload(target: TargetConfig, local_path: str | Path, remote_path: str) -> None:
    """SCP a local file to the target."""
    dest = f"{target.user}@{target.host}:{remote_path}"
    result = _run_ssh_cli_with_retry(
        _scp_args(target) + [str(local_path), dest],
        target.host,
        timeout=_SCP_TRANSFER_SECS,
        tool="scp",
    )
    if result.returncode != 0:
        raise DeployError(
            f"SCP upload failed (exit {result.returncode}):\n"
            f"  {local_path} → {dest}\n"
            f"  stderr: {result.stderr.strip()}"
        )


def download(target: TargetConfig, remote_path: str, local_path: str | Path) -> None:
    """SCP a remote file to the local machine."""
    src = f"{target.user}@{target.host}:{remote_path}"
    result = _run_ssh_cli_with_retry(
        _scp_args(target) + [src, str(local_path)],
        target.host,
        timeout=_SCP_TRANSFER_SECS,
        tool="scp",
    )
    if result.returncode != 0:
        raise DeployError(
            f"SCP download failed (exit {result.returncode}):\n"
            f"  {src} → {local_path}\n"
            f"  stderr: {result.stderr.strip()}"
        )


def ensure_work_dir(target: TargetConfig) -> None:
    """Create the work directory on the target if it doesn't exist."""
    if target.work_dir.startswith("C:\\") or "\\" in target.work_dir:
        # Windows path — use PowerShell mkdir
        run_remote(target, f'powershell -Command "New-Item -ItemType Directory -Force -Path \'{target.work_dir}\'"')
    else:
        run_remote(target, f"mkdir -p {target.work_dir}")


def _quote_posix(path: str) -> str:
    """Shell-quote a path for a POSIX shell (bash/sh)."""
    return shlex.quote(path)


def _quote_powershell(path: str) -> str:
    """Quote a path for PowerShell using single-quote style.

    Single quotes in PowerShell are literal-string delimiters; an embedded
    single quote is escaped by doubling it ('' → ').
    """
    return "'" + path.replace("'", "''") + "'"


def execute_background(target: TargetConfig, command: str) -> None:
    """Run a command on the target in the background (fire-and-forget).

    On Windows, uses WMI ``Win32_Process.Create`` so the child process is
    outside the SSH session's job object and survives session close.
    ``Start-Process`` children are killed when OpenSSH tears down the session.

    On Linux, the standard ``nohup … &`` detach works because POSIX SSH does
    not use job objects.
    """
    if target.work_dir.startswith("C:\\") or "\\" in target.work_dir:
        quoted_cmd = f'"{command}"'
        ps_arg = _quote_powershell(quoted_cmd)
        bg_cmd = (
            f"powershell -Command \""
            f"Invoke-WmiMethod -Class Win32_Process -Name Create "
            f"-ArgumentList {ps_arg}\""
        )
    else:
        quoted = _quote_posix(command)
        bg_cmd = f"nohup {quoted} </dev/null >/dev/null 2>&1 &"
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [bg_cmd],
        target.host,
        timeout=_SCP_TRANSFER_SECS,
        tool="ssh",
    )
    if result.returncode != 0:
        raise DeployError(
            f"Background remote command failed (exit {result.returncode}):\n"
            f"  stderr: {result.stderr.strip()}"
        )
