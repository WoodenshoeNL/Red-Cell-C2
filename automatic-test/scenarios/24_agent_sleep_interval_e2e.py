"""
Scenario 24_agent_sleep_interval: Sleep interval in operator view and check-in cadence

Deploy a Demon Linux payload with an explicit ``--sleep`` interval, then:

  1. Assert ``agent show`` reports the same ``sleep_interval`` (seconds).
  2. Measure wall-clock time between two consecutive ``last_seen`` updates — should
     fall within a loose band around the configured sleep (accounts for jitter,
     scheduling, and network latency).

Skip if ctx.linux is None.

This complements scenarios 22–23 (kill-date / working-hours) by validating the
normal callback timer path without waiting for calendar or clock windows.
"""

from __future__ import annotations

import json
import uuid

DESCRIPTION = "Sleep interval reflected in agent details and last_seen cadence"

from lib import ScenarioSkipped


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def run(ctx):
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — no Linux target configured")

    from lib.agent_timing import (
        measure_wall_seconds_between_last_seen_changes,
        parse_last_seen,
        sleep_interval_seconds,
    )
    from lib.cli import agent_kill, agent_show, listener_create, listener_delete, listener_start, listener_stop
    from lib.deploy import DeployError, preflight_ssh, run_remote
    from lib.deploy_agent import deploy_and_checkin
    from lib.resilience import http_listener_inner_config

    try:
        preflight_ssh(ctx.linux)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"test-sleep-24-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)

    timeouts = ctx.env.get("timeouts", {})
    sleep_secs = int(timeouts.get("sleep_interval_e2e", 10))
    measure_timeout = float(timeouts.get("sleep_interval_measure", 180))

    print(f"  [24][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    inner = http_listener_inner_config(listener_name, listener_port, ctx.env)
    listener_create(cli, listener_name, "http", config_json=json.dumps(inner))
    listener_start(cli, listener_name)

    agent_id = None
    try:
        agent = deploy_and_checkin(
            ctx,
            cli,
            target,
            agent_type="demon",
            fmt="bin",
            listener_name=listener_name,
            sleep_secs=sleep_secs,
            label="24",
        )
        agent_id = agent["id"]
        print(f"  [24][checkin] agent online: {agent_id} (payload --sleep {sleep_secs})")

        detail = agent_show(cli, agent_id)
        reported = sleep_interval_seconds(detail)
        assert reported == sleep_secs, (
            f"agent show sleep_interval: expected {sleep_secs}, got {reported!r} "
            f"(full detail keys: {sorted(detail.keys())})"
        )
        print(f"  [24][assert] sleep_interval={reported} matches payload build")

        ls_raw = str(detail.get("last_seen", "")).strip()
        assert ls_raw, "agent show last_seen empty"
        parse_last_seen(ls_raw)
        print(f"  [24][assert] last_seen parses as datetime: {ls_raw!r}")

        print(
            f"  [24][measure] observing last_seen updates (timeout {measure_timeout:.0f}s, "
            "poll every 2s)…"
        )
        gap = measure_wall_seconds_between_last_seen_changes(
            cli,
            agent_id,
            poll_interval=2.0,
            timeout=measure_timeout,
        )
        print(f"  [24][measure] wall seconds between last_seen updates: {gap:.1f}")

        # Loose bounds: allow slow targets and default Demon jitter without flaking CI.
        lo = max(2.0, float(sleep_secs) * 0.35)
        hi = float(sleep_secs) * 3.5 + 20.0
        assert lo <= gap <= hi, (
            f"expected last_seen interval between {lo:.1f}s and {hi:.1f}s "
            f"for sleep={sleep_secs}, got {gap:.1f}s"
        )
        print(f"  [24][assert] cadence within [{lo:.1f}, {hi:.1f}]s — sleep behaviour plausible")

    finally:
        if agent_id:
            print(f"  [24][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [24][cleanup] agent kill failed (non-fatal): {exc}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass
        try:
            run_remote(target, f"rm -f {target.work_dir}/agent-*.bin 2>/dev/null || true", timeout=15)
        except Exception as exc:
            print(f"  [24][cleanup] work_dir cleanup failed (non-fatal): {exc}")
