"""
Scenario 21_agent_resilience: Agent reconnect after listener restart

Stop the HTTP listener, wait for at least two agent sleep intervals, restart the
listener, then assert the same agent accepts ``agent exec`` again.

Skip if ctx.linux is None.

Steps:
  1. Create + start HTTP listener (explicit ``hosts`` for payload build)
  2. Build + deploy Demon with short sleep (5s)
  3. Wait for checkin, run a baseline command
  4. Stop listener, wait ``2 * sleep_interval`` seconds
  5. Start listener again
  6. Assert ``agent exec`` succeeds (reconnect)
  7. Cleanup
"""

from __future__ import annotations

import json
import time
import uuid

DESCRIPTION = "Agent reconnect after listener restart (HTTP)"

from lib import ScenarioSkipped


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool
    """
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — no Linux target configured")

    from lib.cli import agent_exec, agent_kill, listener_create, listener_delete, listener_start, listener_stop
    from lib.deploy import DeployError, preflight_ssh, run_remote
    from lib.deploy_agent import deploy_and_checkin
    from lib.resilience import http_listener_inner_config, wait_until_agent_exec_ok

    try:
        preflight_ssh(ctx.linux)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    if "phantom" not in available_agents:
        raise ScenarioSkipped(
            "Demon is Windows-only and cannot run on Linux; "
            "add 'phantom' to agents.available in env.toml"
        )

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.linux
    uid = _short_id()
    listener_name = f"test-resilience-21-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    sleep_interval = 5

    print(f"  [21][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    inner = http_listener_inner_config(listener_name, listener_port, ctx.env)
    listener_create(cli, listener_name, "http", config_json=json.dumps(inner))
    listener_start(cli, listener_name)

    agent_id = None
    try:
        agent = deploy_and_checkin(
            ctx,
            cli,
            target,
            agent_type="phantom",
            fmt="elf",
            listener_name=listener_name,
            sleep_secs=sleep_interval,
            label="21",
        )
        agent_id = agent["id"]
        print(f"  [21][cmd] baseline whoami on {agent_id}")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=co)
        assert result.get("output", "").strip(), "baseline whoami returned empty output"

        print(f"  [21][partition] stopping listener (simulated network drop)")
        listener_stop(cli, listener_name)
        wait_s = max(2 * sleep_interval, 10)
        print(f"  [21][partition] waiting {wait_s}s (>= 2 checkin intervals)")
        time.sleep(float(wait_s))

        print(f"  [21][recover] restarting listener")
        listener_start(cli, listener_name)

        rr = ctx.timeouts.resilience_reconnect
        reconnect_timeout = float(rr) if rr is not None else 120.0
        print(
            f"  [21][recover] waiting for agent exec to succeed (timeout {reconnect_timeout:.0f}s)"
        )
        out = wait_until_agent_exec_ok(
            cli,
            agent_id,
            "echo ok",
            timeout=reconnect_timeout,
            interval=3.0,
            exec_timeout=25,
        )
        assert "ok" in (out.get("output") or "").lower() or out.get("exit_code") == 0, (
            f"unexpected exec result after reconnect: {out!r}"
        )
        print("  [21][recover] agent accepted commands after listener restart")

    finally:
        if agent_id:
            print(f"  [21][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [21][cleanup] agent kill failed (non-fatal): {exc}")
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
            print(f"  [21][cleanup] work_dir cleanup failed (non-fatal): {exc}")
