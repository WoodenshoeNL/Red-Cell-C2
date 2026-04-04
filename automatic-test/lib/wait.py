"""
lib/wait.py — polling helpers for the test harness.
"""

from __future__ import annotations

import socket
import time
from typing import Callable, TypeVar

from lib.cli import CliConfig, agent_list

T = TypeVar("T")


class TimeoutError(Exception):
    pass


class ScenarioFailed(Exception):
    pass


def wait_for_port(host: str, port: int, timeout: float = 10.0, interval: float = 0.2) -> None:
    """Block until *host:port* accepts a TCP connection or *timeout* seconds elapse.

    Raises :class:`ScenarioFailed` when the port does not open in time.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(interval)
    raise ScenarioFailed(f"port {host}:{port} did not open within {timeout}s")


def poll(
    fn: Callable[[], T],
    predicate: Callable[[T], bool],
    timeout: int = 60,
    interval: float = 2.0,
    description: str = "condition",
) -> T:
    """
    Call fn() every `interval` seconds until predicate(result) is True
    or `timeout` seconds have elapsed.  Returns the last result on success.
    """
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = fn()
            if predicate(result):
                return result
        except Exception as exc:
            last_exc = exc
        time.sleep(interval)
    msg = f"Timed out after {timeout}s waiting for {description}"
    if last_exc:
        msg += f" (last error: {last_exc})"
    raise TimeoutError(msg)


def wait_for_agent(
    cfg: CliConfig,
    timeout: int = 60,
    pre_existing_ids: set[str] | None = None,
) -> dict:
    """Wait until a *new* agent appears in the agent list.

    If *pre_existing_ids* is given, agents whose ``id`` is in that set are
    ignored — this prevents ghost records left by earlier scenarios (e.g.
    scenario 13's synthetic handshake) from being mistaken for a fresh
    checkin.  Returns the first new agent's dict.
    """
    _skip: set[str] = pre_existing_ids or set()

    def get_agents():
        return agent_list(cfg)

    agents = poll(
        fn=get_agents,
        predicate=lambda agents: any(a["id"] not in _skip for a in agents),
        timeout=timeout,
        description="agent checkin",
    )
    return next(a for a in agents if a["id"] not in _skip)


def wait_for_agent_id(cfg: CliConfig, agent_id: str, timeout: int = 60) -> dict:
    """Wait until a specific agent ID appears in the agent list."""
    def get_agents():
        return agent_list(cfg)

    agents = poll(
        fn=get_agents,
        predicate=lambda agents: any(a.get("id") == agent_id for a in agents),
        timeout=timeout,
        description=f"agent {agent_id} checkin",
    )
    return next(a for a in agents if a.get("id") == agent_id)
