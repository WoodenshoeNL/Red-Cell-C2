"""
lib/agent_timing.py — parse ``agent show`` timestamps and measure check-in cadence.

Used by scenario 24 to verify that configured sleep intervals are reflected in
operator-visible fields and that ``last_seen`` advances on a plausible wall-clock
schedule between callbacks.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from lib.cli import CliConfig, agent_show


def parse_last_seen(ts: str) -> datetime:
    """Parse ``last_seen`` strings returned by ``agent show`` JSON.

    Raises:
        ValueError: if *ts* does not match any known format.
    """
    s = ts.strip().rstrip("Z")
    # Truncate sub-microsecond precision (%f handles up to 6 digits).
    if "." in s:
        head, frac = s.rsplit(".", 1)
        s = f"{head}.{frac[:6]}"
    for fmt in (
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"unparseable last_seen: {ts!r}")


def sleep_interval_seconds(detail: dict[str, Any]) -> int | None:
    """Return configured sleep interval from an ``agent show`` payload, or None."""
    raw = detail.get("sleep_interval")
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def jitter_seconds(detail: dict[str, Any]) -> int | None:
    """Return configured jitter from ``agent show`` (server-defined units)."""
    raw = detail.get("jitter")
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def measure_wall_seconds_between_last_seen_changes(
    cli: CliConfig,
    agent_id: str,
    *,
    poll_interval: float = 2.0,
    timeout: float = 120.0,
) -> float:
    """Return wall-clock seconds between two consecutive ``last_seen`` updates.

    Waits until ``last_seen`` changes once from the initial snapshot, records
    time, then waits until it changes again. The result approximates one sleep
    cycle (plus jitter, scheduling, and network effects).
    """
    detail = agent_show(cli, agent_id)
    last = str(detail.get("last_seen", "")).strip()
    if not last:
        raise AssertionError("agent show returned empty last_seen")

    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        cur = str(agent_show(cli, agent_id).get("last_seen", "")).strip()
        if cur and cur != last:
            last = cur
            break
    else:
        raise AssertionError(
            f"last_seen never changed from initial {last!r} within {timeout:.0f}s"
        )

    t0 = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        cur = str(agent_show(cli, agent_id).get("last_seen", "")).strip()
        if cur and cur != last:
            return time.monotonic() - t0
    raise AssertionError("last_seen did not change a second time within timeout")
