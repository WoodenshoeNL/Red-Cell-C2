"""
lib/resilience.py — helpers for agent resilience scenarios (listener restart, kill-date,
working-hours).
"""

from __future__ import annotations

import time
from typing import Any

from lib.cli import CliConfig, CliError, agent_list
from lib.listeners import normalize_callback_host_for_listener


def extract_http_callback_host(env: dict) -> str:
    """Return the host to bake into agent CONFIG_BYTES for listener ``hosts``.

    Prefers ``[server].callback_host`` — the explicit, routable dev-box address set in
    ``env.toml`` for scenarios that deploy agents to remote VMs. Falls back to deriving
    the host from ``server.rest_url`` / ``server.url`` (loopback-only) when
    ``callback_host`` is unset, matching the canonical ``lib.listeners.http_listener_kwargs``
    resolution so resilience scenarios do not silently bake ``127.0.0.1`` into remote
    agent configs.
    """
    server = env.get("server", {})
    callback_host = server.get("callback_host")
    if callback_host:
        return str(callback_host)
    url = server.get("rest_url") or server.get("url", "") or ""
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
    host = normalize_callback_host_for_listener(extract_http_callback_host(env))
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


def wait_until_agent_dead(
    cli: CliConfig,
    agent_id: str,
    timeout: float = 120.0,
    interval: float = 2.0,
) -> None:
    """Poll ``agent list`` until *agent_id* shows status ``dead`` (or is absent)."""
    needle = agent_id.strip().upper()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            agents = agent_list(cli)
            by_id = {str(a.get("id", "")).upper(): a for a in agents}
            if needle not in by_id:
                return
            if by_id[needle].get("status", "").lower() == "dead":
                return
        except CliError:
            pass
        time.sleep(interval)
    raise AssertionError(
        f"agent {agent_id!r} still alive in agent list after {timeout:.0f}s — "
        "expected implant to stop after kill-date"
    )


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
