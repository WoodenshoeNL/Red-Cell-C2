"""
lib/resilience.py — helpers for agent resilience scenarios (listener restart, kill-date,
working-hours).
"""

from __future__ import annotations

import time
from typing import Any

from lib.cli import CliConfig, CliError, agent_list


def extract_http_callback_host(env: dict) -> str:
    """Return the hostname from ``server.rest_url`` or ``server.url`` for listener ``hosts``.

    The agent must reach the teamserver at this address; it matches the host used in
    ``env.toml`` / ``targets.toml`` network layout.
    """
    url = (
        env.get("server", {}).get("rest_url")
        or env.get("server", {}).get("url", "")
        or ""
    )
    if "://" in url:
        url = url.split("://", 1)[1]
    host = url.split(":")[0].split("/")[0]
    return host if host else "127.0.0.1"


def http_listener_inner_config(
    name: str,
    port: int,
    env: dict,
    *,
    kill_date: str | None = None,
    working_hours: str | None = None,
) -> dict[str, Any]:
    """Build inner JSON for ``listener create --type http --config-json ...``."""
    host = extract_http_callback_host(env)
    inner: dict[str, Any] = {
        "name": name,
        "host_bind": "0.0.0.0",
        "port_bind": port,
        "host_rotation": "round-robin",
        "hosts": [f"{host}:{port}"],
        "secure": False,
    }
    if kill_date is not None:
        inner["kill_date"] = kill_date
    if working_hours is not None:
        inner["working_hours"] = working_hours
    return inner


def pick_inactive_working_hours(hour: int) -> str:
    """Return ``HH:MM-HH:MM`` that excludes *hour* (0–23) for Demon ``InWorkingHours``.

    Uses a one-hour window that does not overlap the current hour when possible.
    """
    if hour in (2, 3):
        return "10:00-11:00"
    return "02:00-03:00"


def wait_until_agent_absent(
    cli: CliConfig,
    agent_id: str,
    timeout: float = 120.0,
    interval: float = 2.0,
) -> None:
    """Poll ``agent list`` until *agent_id* is no longer present (or timeout)."""
    needle = agent_id.strip().upper()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            agents = agent_list(cli)
            ids = {str(a.get("id", "")).upper() for a in agents}
            if needle not in ids:
                return
        except CliError:
            pass
        time.sleep(interval)
    raise AssertionError(
        f"agent {agent_id!r} still present in agent list after {timeout:.0f}s — "
        "expected implant to stop after kill-date"
    )


def wait_until_agent_exec_ok(
    cli: CliConfig,
    agent_id: str,
    cmd: str,
    *,
    timeout: float = 120.0,
    interval: float = 2.0,
    exec_timeout: int = 20,
) -> dict:
    """Poll ``agent exec`` until it succeeds or *timeout* seconds elapse."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    from lib.cli import agent_exec

    while time.monotonic() < deadline:
        try:
            return agent_exec(cli, agent_id, cmd, wait=True, timeout=exec_timeout)
        except CliError as exc:
            last_err = exc
            time.sleep(interval)
    raise AssertionError(
        f"agent exec did not succeed within {timeout:.0f}s (last error: {last_err})"
    )
