"""
lib/deploy.py — SSH/SCP deployment helpers for Linux and Windows targets.

Uses the system `ssh` and `scp` binaries so no extra Python dependencies
are needed. Both Linux and Windows targets are accessed via SSH
(OpenSSH for Windows — see docs/win11-ssh-setup.md).
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from lib import ScenarioSkipped


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


def _ssh_args(target: TargetConfig) -> list[str]:
    return [
        "ssh",
        "-p", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-i", target.key,
        f"{target.user}@{target.host}",
    ]


def _scp_args(target: TargetConfig) -> list[str]:
    return [
        "scp",
        "-P", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-i", target.key,
    ]


class DeployError(Exception):
    pass


def preflight_ssh(target: TargetConfig) -> None:
    """Check that the target host is reachable via SSH before deploying.

    Uses a short ConnectTimeout (5 s) so that an unreachable host is detected
    quickly instead of surfacing as a cryptic error after a full payload build.
    Call this at the start of any scenario that deploys a payload via SSH.

    Raises:
        DeployError: if the SSH connection cannot be established.
    """
    result = subprocess.run(
        [
            "ssh",
            "-p", str(target.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-i", target.key,
            f"{target.user}@{target.host}",
            "true",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise DeployError(
            f"target {target.host} not reachable via SSH — "
            "check targets.toml and network"
        )


def preflight_dns(target: TargetConfig, domain: str, expected_ip: str) -> None:
    """Check that ``domain`` resolves to ``expected_ip`` on the target machine.

    Runs ``python3 -c '...' <domain>`` (domain shell-escaped) on the remote
    target via SSH and compares the result to ``expected_ip``.

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
            with an actionable message describing the required ``/etc/hosts``
            entry.
    """
    probe = (
        "python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "
        + shlex.quote(domain)
    )
    result = subprocess.run(
        _ssh_args(target) + [probe],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise ScenarioSkipped(
            f"DNS for {domain!r} on {target.host} could not be resolved "
            f"(probe failed: {result.stderr.strip()}); "
            f"add entry to /etc/hosts: '{expected_ip}  {domain}'"
        )
    actual_ip = result.stdout.strip()
    if actual_ip != expected_ip:
        raise ScenarioSkipped(
            f"DNS for {domain!r} on {target.host} resolves to {actual_ip!r} "
            f"not {expected_ip!r}; "
            f"add entry to /etc/hosts: '{expected_ip}  {domain}'"
        )


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
    result = subprocess.run(
        _ssh_args(target) + [remote_cmd],
        capture_output=True,
        text=True,
        timeout=ssh_timeout,
    )
    if result.returncode != 0:
        return False
    return result.stdout.strip().lower() == "true"


def run_remote(target: TargetConfig, command: str, timeout: int = 30) -> str:
    """Run a shell command on the target via SSH and return stdout."""
    result = subprocess.run(
        _ssh_args(target) + [command],
        capture_output=True, text=True, timeout=timeout,
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
    result = subprocess.run(
        _scp_args(target) + [str(local_path), dest],
        capture_output=True, text=True, timeout=60,
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
    result = subprocess.run(
        _scp_args(target) + [src, str(local_path)],
        capture_output=True, text=True, timeout=60,
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

    The command path is quoted before interpolation so that paths containing
    spaces or other shell-significant characters are handled correctly on both
    Linux (POSIX sh quoting via :func:`shlex.quote`) and Windows (PowerShell
    single-quote escaping).
    """
    if target.work_dir.startswith("C:\\") or "\\" in target.work_dir:
        quoted = _quote_powershell(command)
        bg_cmd = f'powershell -Command "Start-Process -FilePath {quoted} -WindowStyle Hidden"'
    else:
        quoted = _quote_posix(command)
        bg_cmd = f"nohup {quoted} </dev/null >/dev/null 2>&1 &"
    subprocess.Popen(
        _ssh_args(target) + [bg_cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
