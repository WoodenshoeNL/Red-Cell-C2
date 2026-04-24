"""
Scenario 23_agent_resilience: Working-hours restriction

Deploy with ``working_hours`` that exclude the target's current local time — the
agent must **not** check in.  Then deploy with an unrestricted listener (no
working-hours field) and assert checkin succeeds.

Skip if ctx.linux is None.

Steps:
  1. Read current hour on the Linux target (``date +%H``)
  2. Create listener with ``working_hours`` excluding that hour
  3. Build + deploy Demon — expect **no** checkin within the probe window
  4. Stop/delete listener; kill stray payload process on target
  5. Create listener without working-hours restriction
  6. Build + deploy — expect checkin and a trivial ``agent exec``
  7. Cleanup
"""

from __future__ import annotations

import json
import uuid

DESCRIPTION = "Working-hours restriction (no checkin off-hours; checkin when open)"

from lib import ScenarioSkipped


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def run(ctx):
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — no Linux target configured")

    from lib.cli import agent_exec, agent_kill, listener_create, listener_delete, listener_start, listener_stop
    from lib.deploy import DeployError, preflight_ssh, run_remote
    from lib.deploy_agent import deploy_and_checkin
    from lib.resilience import http_listener_inner_config, pick_inactive_working_hours

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
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    sleep_interval = 5

    hour_s = run_remote(target, "date +%H").strip()
    try:
        hour = int(hour_s)
    except ValueError as exc:
        raise AssertionError(f"could not parse hour from remote date: {hour_s!r}") from exc

    inactive = pick_inactive_working_hours(hour)
    print(f"  [23][target] local hour={hour} (from SSH); inactive window {inactive!r}")

    listener_blocked = f"test-resilience-23a-{uid}"
    print(f"  [23][phase1] listener {listener_blocked!r} with working_hours={inactive!r}")
    inner_blocked = http_listener_inner_config(
        listener_blocked, listener_port, ctx.env, working_hours=inactive
    )
    listener_create(cli, listener_blocked, "http", config_json=json.dumps(inner_blocked))
    listener_start(cli, listener_blocked)

    try:
        none_agent = deploy_and_checkin(
            ctx,
            cli,
            target,
            agent_type="phantom",
            fmt="exe",
            listener_name=listener_blocked,
            sleep_secs=sleep_interval,
            label="23a",
            expect_checkin=False,
        )
        assert none_agent is None, "expected no agent dict when outside working hours"
        print("  [23][phase1] no checkin observed (expected)")
    finally:
        try:
            listener_stop(cli, listener_blocked)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_blocked)
        except Exception:
            pass

    print("  [23][cleanup] stopping stray payload on target (if any)")
    try:
        run_remote(target, "pkill -f 'agent-' || true", timeout=15)
    except Exception as exc:
        print(f"  [23][cleanup] pkill failed (non-fatal): {exc}")

    listener_open = f"test-resilience-23b-{uid}"
    print(f"  [23][phase2] listener {listener_open!r} without working-hours restriction")
    inner_open = http_listener_inner_config(listener_open, listener_port, ctx.env)
    listener_create(cli, listener_open, "http", config_json=json.dumps(inner_open))
    listener_start(cli, listener_open)

    agent_id = None
    try:
        agent = deploy_and_checkin(
            ctx,
            cli,
            target,
            agent_type="phantom",
            fmt="exe",
            listener_name=listener_open,
            sleep_secs=sleep_interval,
            label="23b",
        )
        assert agent is not None
        agent_id = agent["id"]
        print(f"  [23][phase2] agent checked in: {agent_id}")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=co)
        assert result.get("output", "").strip(), "whoami returned empty output after open-window deploy"
        print("  [23][phase2] command succeeded — working-hours scenario complete")
    finally:
        if agent_id:
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [23][cleanup] agent kill failed (non-fatal): {exc}")
        try:
            listener_stop(cli, listener_open)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_open)
        except Exception:
            pass
        try:
            run_remote(target, f"rm -f {target.work_dir}/agent-*.bin 2>/dev/null || true", timeout=15)
        except Exception as exc:
            print(f"  [23][cleanup] work_dir cleanup failed (non-fatal): {exc}")
