"""
lib/wait.py — polling helpers for the test harness.
"""

from __future__ import annotations

import time
from typing import Callable, TypeVar

from lib.cli import CliConfig, agent_list

T = TypeVar("T")


class TimeoutError(Exception):
    pass


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


def wait_for_agent(cfg: CliConfig, timeout: int = 60) -> dict:
    """
    Wait until at least one agent appears in the agent list.
    Returns the first agent's dict.
    """
    def get_agents():
        return agent_list(cfg)

    agents = poll(
        fn=get_agents,
        predicate=lambda agents: len(agents) > 0,
        timeout=timeout,
        description="agent checkin",
    )
    return agents[0]


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
