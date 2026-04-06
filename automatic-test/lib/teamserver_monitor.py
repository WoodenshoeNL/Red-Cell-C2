"""
lib/teamserver_monitor.py — Teamserver CPU/RSS sampling for stress tests (scenario 14).

Supports localhost ``ps`` sampling and remote sampling via SSH when
``[teamserver]`` SSH fields are set in env.toml.
"""

from __future__ import annotations

import ipaddress
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# Default process name for the teamserver binary (see teamserver Cargo.toml).
_TEAMSERVER_COMM = "red-cell"

# Set by :func:`configure_teamserver_ssh_connect_timeout` from ``config/env.toml``.
_SSH_CONNECT_TIMEOUT_SECS = 10


def configure_teamserver_ssh_connect_timeout(secs: float) -> None:
    """Apply ``ssh_connect_secs`` to remote ``ps`` sampling (call once from ``test.py`` main)."""

    global _SSH_CONNECT_TIMEOUT_SECS
    _SSH_CONNECT_TIMEOUT_SECS = max(1, int(secs))


def resolve_teamserver_host(env: dict[str, Any]) -> str:
    """Return the hostname or IP where the teamserver is expected to run.

    Order:
      1. ``env["teamserver"]["host"]`` when present and non-empty
      2. Hostname from ``env["server"]["url"]`` (WebSocket URL)
      3. ``\"127.0.0.1\"`` if the URL has no hostname
    """
    ts = env.get("teamserver")
    if isinstance(ts, dict):
        h = ts.get("host")
        if h is not None and str(h).strip():
            return str(h).strip()
    server = env.get("server") or {}
    url = str(server.get("url", ""))
    parsed = urlparse(url)
    if parsed.hostname:
        # Strip IPv6 brackets if present (urlparse usually returns without them).
        return parsed.hostname
    return "127.0.0.1"


def is_loopback_host(host: str) -> bool:
    """Return True if *host* refers to this machine (loopback)."""
    h = host.strip()
    if not h:
        return True
    low = h.lower()
    if low in ("localhost", "127.0.0.1", "::1"):
        return True
    if (low.startswith("[") and low.endswith("]")) or ("::" in low):
        inner = low.strip("[]")
        if inner == "::1":
            return True
        try:
            addr = ipaddress.ip_address(inner)
            return addr.is_loopback
        except ValueError:
            pass
    try:
        addr = ipaddress.ip_address(h)
        return addr.is_loopback
    except ValueError:
        return False


def parse_ps_cpu_rss_line(text: str) -> tuple[float | None, int | None]:
    """Parse a line like ``12.3  456789`` (``%cpu`` and ``rss`` in KB)."""
    line = text.strip()
    if not line:
        return None, None
    # First line only; drop headers if present
    first = line.splitlines()[0].strip()
    parts = first.replace("\t", " ").split()
    if len(parts) < 2:
        return None, None
    try:
        cpu = float(parts[0])
        rss_kb = int(parts[1])
        return cpu, rss_kb
    except ValueError:
        return None, None


@dataclass
class TeamserverSshConfig:
    """SSH parameters for remote ``ps`` on the teamserver host."""

    host: str
    user: str
    port: int
    key: str


@dataclass
class TeamserverMonitorSettings:
    """Resolved monitoring options from env.toml ``[teamserver]``."""

    host: str
    cpu_limit_pct: float
    rss_limit_mb: float | None
    ssh: TeamserverSshConfig | None = None


def load_teamserver_monitor_settings(
    env: dict[str, Any],
    *,
    default_cpu_limit_pct: float = 80.0,
) -> TeamserverMonitorSettings:
    """Load ``[teamserver]`` limits and optional SSH config."""
    ts = env.get("teamserver")
    if not isinstance(ts, dict):
        ts = {}
    host = resolve_teamserver_host(env)
    cpu_limit = float(ts.get("cpu_limit_pct", default_cpu_limit_pct))
    rss_raw = ts.get("rss_limit_mb")
    rss_limit_mb: float | None
    if rss_raw is None or rss_raw == "":
        rss_limit_mb = None
    else:
        rss_limit_mb = float(rss_raw)

    ssh_user = (ts.get("ssh_user") or "").strip()
    ssh_key = (ts.get("ssh_key") or "").strip()
    ssh_port = int(ts.get("ssh_port", 22))

    ssh: TeamserverSshConfig | None = None
    if ssh_user and ssh_key:
        ssh = TeamserverSshConfig(host=host, user=ssh_user, port=ssh_port, key=ssh_key)

    return TeamserverMonitorSettings(
        host=host,
        cpu_limit_pct=cpu_limit,
        rss_limit_mb=rss_limit_mb,
        ssh=ssh,
    )


def _find_local_teamserver_pid() -> int | None:
    """Return PID of ``red-cell`` or None."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", _TEAMSERVER_COMM],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            if lines:
                return int(lines[0])
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,comm,pcpu"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and _TEAMSERVER_COMM in parts[1]:
                return int(parts[0])
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def sample_local_teamserver_cpu_rss() -> tuple[float | None, int | None]:
    """Sample current CPU%% and RSS (KB) for the local ``red-cell`` process."""
    pid = _find_local_teamserver_pid()
    if pid is None:
        return None, None
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "%cpu=,rss="],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None, None
        return parse_ps_cpu_rss_line(result.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return None, None


def _remote_ps_command() -> str:
    """Shell snippet: print one line ``%%cpu rss_kb`` or empty if not found."""
    # Single-quoted body for bash -lc
    return (
        f'pid=$(pgrep -x {_TEAMSERVER_COMM} 2>/dev/null | head -n1); '
        f'if [ -n "$pid" ]; then ps -p "$pid" -o %cpu=,rss= --no-headers; fi'
    )


def sample_remote_teamserver_cpu_rss(cfg: TeamserverSshConfig) -> tuple[float | None, int | None]:
    """Run ``ps`` on *cfg.host* via SSH; return CPU%% and RSS (KB)."""
    inner = _remote_ps_command()
    remote = "bash -lc " + shlex.quote(inner)
    try:
        result = subprocess.run(
            [
                "ssh",
                "-p",
                str(cfg.port),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "BatchMode=yes",
                "-o",
                f"ConnectTimeout={_SSH_CONNECT_TIMEOUT_SECS}",
                "-i",
                cfg.key,
                f"{cfg.user}@{cfg.host}",
                remote,
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            return None, None
        return parse_ps_cpu_rss_line(result.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return None, None


@dataclass
class ResourceSample:
    """One CPU/RSS observation (monotonic timestamp + optional phase label)."""

    monotonic_t: float
    cpu_pct: float
    rss_kb: int
    phase: str = ""


class TeamserverResourceMonitor(threading.Thread):
    """Background sampler for teamserver CPU and RSS.

    Modes:
      * **local** — ``ps`` on localhost when ``host`` is loopback
      * **remote** — SSH to ``host`` when not loopback and SSH credentials exist
      * **disabled** — no SSH for a non-loopback host, or repeated failures

    Not a ``@dataclass`` — :class:`threading.Thread` requires a hashable instance.
    """

    def __init__(
        self,
        settings: TeamserverMonitorSettings,
        *,
        interval: float = 5.0,
    ) -> None:
        super().__init__(daemon=True)
        self._settings = settings
        self.interval = interval
        self._stop_event = threading.Event()
        self.samples: list[ResourceSample] = []
        self.max_cpu: float = 0.0
        self.max_rss_kb: int = 0
        self._mode: str = "disabled"
        self.disable_reason: str | None = None

    @property
    def mode(self) -> str:
        """``local`` | ``remote`` | ``disabled``."""
        return self._mode

    def configure(self) -> None:
        """Set sampling mode from settings (call before :meth:`start`)."""
        host = self._settings.host
        if is_loopback_host(host):
            self._mode = "local"
            self.disable_reason = None
            return
        if self._settings.ssh is None:
            self._mode = "disabled"
            self.disable_reason = (
                f"teamserver host {host!r} is not loopback; configure "
                f"[teamserver] ssh_user and ssh_key in env.toml for remote CPU/RSS monitoring, "
                "or omit — monitoring skipped"
            )
            return
        self._mode = "remote"
        self.disable_reason = None

    def _sample_once(self) -> tuple[float | None, int | None]:
        if self._mode == "local":
            return sample_local_teamserver_cpu_rss()
        if self._mode == "remote" and self._settings.ssh is not None:
            return sample_remote_teamserver_cpu_rss(self._settings.ssh)
        return None, None

    def run(self) -> None:
        while not self._stop_event.is_set():
            cpu, rss_kb = self._sample_once()
            now = time.monotonic()
            if cpu is not None and rss_kb is not None:
                self.samples.append(
                    ResourceSample(
                        monotonic_t=now,
                        cpu_pct=cpu,
                        rss_kb=rss_kb,
                    )
                )
                if cpu > self.max_cpu:
                    self.max_cpu = cpu
                if rss_kb > self.max_rss_kb:
                    self.max_rss_kb = rss_kb
            self._stop_event.wait(self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        self.join(timeout=15)

    def take_edge_sample(self, phase: str) -> ResourceSample | None:
        """Take a single synchronous sample (start/end of stress loop)."""
        cpu, rss_kb = self._sample_once()
        now = time.monotonic()
        if cpu is None or rss_kb is None:
            return None
        s = ResourceSample(monotonic_t=now, cpu_pct=cpu, rss_kb=rss_kb, phase=phase)
        self.samples.append(s)
        if cpu > self.max_cpu:
            self.max_cpu = cpu
        if rss_kb > self.max_rss_kb:
            self.max_rss_kb = rss_kb
        return s


def format_samples_for_output(samples: list[ResourceSample]) -> str:
    """Human-readable list of samples for scenario logs."""
    lines = []
    for s in samples:
        label = f"{s.phase} " if s.phase else ""
        lines.append(
            f"{label}t={s.monotonic_t:.3f} cpu={s.cpu_pct:.1f}% rss_mb={s.rss_kb / 1024:.1f}"
        )
    return "; ".join(lines) if lines else "(none)"


def assert_resource_limits(
    settings: TeamserverMonitorSettings,
    max_cpu: float,
    max_rss_kb: int,
    had_samples: bool,
) -> list[str]:
    """Return a list of assertion error strings (empty if all checks pass)."""
    errors: list[str] = []
    if not had_samples:
        return errors
    if max_cpu > settings.cpu_limit_pct:
        errors.append(
            f"Teamserver CPU peaked at {max_cpu:.1f}% (limit: {settings.cpu_limit_pct}%)"
        )
    if settings.rss_limit_mb is not None:
        max_rss_mb = max_rss_kb / 1024.0
        if max_rss_mb > settings.rss_limit_mb:
            errors.append(
                f"Teamserver RSS peaked at {max_rss_mb:.1f} MiB "
                f"(limit: {settings.rss_limit_mb} MiB)"
            )
    return errors
