"""
lib/wait.py — polling helpers for the test harness.
"""

from __future__ import annotations

import random
import socket
import time
from typing import Callable, TypeVar

from lib.cli import CliConfig, agent_list
from lib.deploy import TargetConfig, named_pipe_exists

T = TypeVar("T")


class TimeoutError(Exception):
    pass


class ScenarioFailed(Exception):
    pass


# Set by :func:`configure_wait_defaults` from ``config/env.toml`` ``[timeouts]``.
_POLL_INTERVAL_SECS = 2.0
_DEFAULT_AGENT_CHECKIN_SECS = 60


def configure_wait_defaults(
    *,
    poll_interval_secs: float,
    default_agent_checkin_secs: float,
) -> None:
    """Apply harness poll / check-in defaults (call once from ``test.py`` main)."""

    global _POLL_INTERVAL_SECS, _DEFAULT_AGENT_CHECKIN_SECS
    _POLL_INTERVAL_SECS = float(poll_interval_secs)
    _DEFAULT_AGENT_CHECKIN_SECS = max(1, int(default_agent_checkin_secs))


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


def wait_for_named_pipe(
    target: TargetConfig,
    pipe_name: str,
    timeout: float = 5.0,
    interval: float = 0.2,
) -> None:
    """Block until the SMB named pipe is visible on *target* or *timeout* elapses.

    Polls :func:`lib.deploy.named_pipe_exists` in a loop (same style as
    :func:`wait_for_port`). Raises :class:`ScenarioFailed` if the pipe never
    appears — distinct from an agent checkin timeout later in the scenario.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if named_pipe_exists(target, pipe_name):
            return
        time.sleep(interval)
    raise ScenarioFailed(
        f"SMB named pipe \\\\.\\pipe\\{pipe_name} did not appear on {target.host} "
        f"within {timeout}s (listener may have failed to bind — check teamserver logs)"
    )


def poll(
    fn: Callable[[], T],
    predicate: Callable[[T], bool],
    timeout: int = 60,
    interval: float | None = None,
    description: str = "condition",
    backoff: float = 1.0,
    max_interval: float = 10.0,
    jitter: float = 0.0,
) -> T:
    """Call *fn* until *predicate*(result) is true or *timeout* seconds elapse.

    Between attempts the loop sleeps. With ``backoff=1.0`` (default) and
    ``jitter=0``, sleep duration stays at *interval* (same as legacy behaviour).
    With ``backoff`` greater than 1, the delay grows exponentially up to
    *max_interval*. Each sleep adds uniform random jitter in ``[0, jitter]``.

    ``poll_until`` in older docs refers to this function.
    """
    eff_interval = interval if interval is not None else _POLL_INTERVAL_SECS
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    current_interval = eff_interval
    while time.monotonic() < deadline:
        try:
            result = fn()
            if predicate(result):
                return result
        except Exception as exc:
            last_exc = exc
        sleep_time = current_interval + random.uniform(0.0, jitter)
        time.sleep(min(sleep_time, max_interval))
        current_interval = min(current_interval * backoff, max_interval)
    msg = f"Timed out after {timeout}s waiting for {description}"
    if last_exc:
        msg += f" (last error: {last_exc})"
    raise TimeoutError(msg)


# Backwards-compatible name used in some docs / issue descriptions.
poll_until = poll


def wait_for_agent(
    cfg: CliConfig,
    timeout: int | None = None,
    pre_existing_ids: set[str] | None = None,
) -> dict:
    """Wait until a *new* agent appears in the agent list.

    If *pre_existing_ids* is given, agents whose ``id`` is in that set are
    ignored — this prevents ghost records left by earlier scenarios (e.g.
    scenario 13's synthetic handshake) from being mistaken for a fresh
    checkin.  Returns the first new agent's dict.
    """
    if timeout is None:
        timeout = _DEFAULT_AGENT_CHECKIN_SECS
    _skip: set[str] = pre_existing_ids or set()

    def get_agents():
        return agent_list(cfg)

    agents = poll(
        fn=get_agents,
        predicate=lambda agents: any(a["id"] not in _skip for a in agents),
        timeout=timeout,
        description="agent checkin",
        backoff=1.5,
        max_interval=10.0,
        jitter=0.2,
    )
    return next(a for a in agents if a["id"] not in _skip)


def wait_for_agent_id(cfg: CliConfig, agent_id: str, timeout: int | None = None) -> dict:
    """Wait until a specific agent ID appears in the agent list."""
    if timeout is None:
        timeout = _DEFAULT_AGENT_CHECKIN_SECS

    def get_agents():
        return agent_list(cfg)

    agents = poll(
        fn=get_agents,
        predicate=lambda agents: any(a.get("id") == agent_id for a in agents),
        timeout=timeout,
        description=f"agent {agent_id} checkin",
        backoff=1.5,
        max_interval=10.0,
        jitter=0.2,
    )
    return next(a for a in agents if a.get("id") == agent_id)
