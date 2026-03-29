"""
lib/deploy.py — SSH/SCP deployment helpers for Linux and Windows targets.

Uses the system `ssh` and `scp` binaries so no extra Python dependencies
are needed. Both Linux and Windows targets are accessed via SSH
(OpenSSH for Windows — see docs/win11-ssh-setup.md).
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


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


def execute_background(target: TargetConfig, command: str) -> None:
    """Run a command on the target in the background (fire-and-forget)."""
    bg_cmd = f"nohup {command} </dev/null >/dev/null 2>&1 &"
    # On Windows use start /b instead
    if target.work_dir.startswith("C:\\") or "\\" in target.work_dir:
        bg_cmd = f'powershell -Command "Start-Process -FilePath {command} -WindowStyle Hidden"'
    subprocess.Popen(
        _ssh_args(target) + [bg_cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
