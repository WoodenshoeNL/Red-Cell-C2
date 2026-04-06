"""
Scenario 22_agent_resilience: Kill-date enforcement

Build a Demon payload with a kill-date shortly after deployment, wait for an
initial checkin, then assert the agent stops calling home after the kill-date
passes (agent record disappears from ``agent list``).

Skip if ctx.linux is None.

Steps:
  1. Compute unix kill timestamp ~45–60s ahead (room for first checkin)
  2. Create HTTP listener with ``kill_date`` embedded (and explicit ``hosts``)
  3. Build + deploy Demon with short sleep (5s)
  4. Wait for first checkin
  5. Wait until wall clock is past kill-date + slack
  6. Assert agent is no longer listed (or remains silent — we treat absent as stopped)
  7. Cleanup
"""

from __future__ import annotations

import json
import time
import uuid

DESCRIPTION = "Kill-date enforcement (agent stops after configured time)"

from lib import ScenarioSkipped


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def run(ctx):
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — no Linux target configured")

    from lib.cli import agent_kill, listener_create, listener_delete, listener_start, listener_stop
    from lib.deploy import DeployError, preflight_ssh, run_remote
    from lib.deploy_agent import deploy_and_checkin
    from lib.resilience import http_listener_inner_config, wait_until_agent_absent

    try:
        preflight_ssh(ctx.linux)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"test-resilience-22-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    sleep_interval = 5

    # Enough time for build + deploy + first checkin before kill-date fires.
    kill_ts = int(time.time()) + 55
    kill_date_str = str(kill_ts)

    print(
        f"  [22][listener] creating listener with kill_date epoch={kill_date_str} "
        f"(~{(kill_ts - int(time.time()))}s from now)"
    )
    inner = http_listener_inner_config(
        listener_name, listener_port, ctx.env, kill_date=kill_date_str
    )
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
            sleep_secs=sleep_interval,
            label="22",
        )
        agent_id = agent["id"]
        print(f"  [22][checkin] agent online: {agent_id}")

        now = int(time.time())
        if now < kill_ts:
            wait_pre = kill_ts - now + 2
            print(f"  [22][wait] sleeping {wait_pre}s until past kill-date (+2s slack)")
            time.sleep(float(wait_pre))
        else:
            print("  [22][wait] kill-date already passed before wait — continuing")

        rk = ctx.timeouts.resilience_kill_date
        absent_timeout = float(rk) if rk is not None else 120.0
        print(
            f"  [22][assert] expecting agent to drop off within {absent_timeout:.0f}s "
            "after kill-date"
        )
        wait_until_agent_absent(cli, agent_id, timeout=absent_timeout, interval=3.0)
        print("  [22][assert] agent no longer listed — kill-date behaviour observed")

    finally:
        if agent_id:
            print(f"  [22][cleanup] killing agent {agent_id} (if still present)")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [22][cleanup] agent kill failed (non-fatal): {exc}")
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
            print(f"  [22][cleanup] work_dir cleanup failed (non-fatal): {exc}")
