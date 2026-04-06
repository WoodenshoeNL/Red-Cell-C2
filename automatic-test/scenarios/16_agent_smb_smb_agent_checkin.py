"""
Scenario 16_agent_smb: End-to-end agent checkin over SMB listener

Deploy a Windows agent whose *initial* C2 channel is an SMB named pipe,
wait for checkin, run command suite.  Runs twice: first with Demon (exe),
then with Specter (exe).  The Specter pass is skipped only when
``"specter"`` is absent from ``agents.available`` in env.toml; if it is
listed and its build fails, the scenario fails so SMB transport regressions
are visible.

This differs from scenario 10 (pivot dispatch): there is no HTTP parent agent
here.  The agent connects directly to the teamserver over the named pipe —
the SMB transport is the *primary* C2 channel, not a pivot relay.

Skip if ctx.windows is None.

Steps (per agent pass):
  1. Create + start SMB listener (named pipe)
  2. Build agent payload (EXE x64) linked to the SMB listener
  3. Deploy via SSH/SCP to Windows 11 test machine
  4. Execute payload in background on target
  5. Wait for agent checkin over the named pipe
  6. Run command suite: whoami, dir C:\\, ipconfig
  7. Kill agent, stop listener, clean up work_dir on target

SMB listener config is read from env.toml [listeners]:
  smb_pipe — named pipe suffix embedded in payloads (default "redcell-c2")
"""

DESCRIPTION = "SMB agent checkin (Demon + Specter over SMB named pipe)"

import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full SMB checkin suite for one agent type.

    Args:
        ctx:         RunContext passed by the harness.
        agent_type:  Agent name passed to ``payload_build`` (e.g. ``"demon"``
                     or ``"specter"``).
        fmt:         Payload format (e.g. ``"exe"``).
        name_prefix: Short prefix used to name the listener and remote files.

    Raises:
        AssertionError on test failure.
        CliError if the payload build fails (propagates as a scenario failure).
    """
    from lib.cli import (
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin
    from lib.wait import wait_for_named_pipe

    cli = ctx.cli
    target = ctx.windows
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"

    smb_cfg = ctx.env.get("listeners", {})
    pipe_base = smb_cfg.get("smb_pipe", "redcell-c2")
    pipe_name = f"{pipe_base}-{uid}"

    # ── Step 1: Create + start SMB listener ─────────────────────────────────
    print(
        f"  [{agent_type}][listener] creating SMB listener {listener_name!r} "
        f"with pipe {pipe_name!r}"
    )
    listener_create(cli, listener_name, "smb", pipe_name=pipe_name)
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")
    print(
        f"  [{agent_type}][listener] waiting for named pipe \\\\.\\pipe\\{pipe_name} "
        "on Windows target"
    )
    wait_for_named_pipe(target, pipe_name, timeout=5.0, interval=0.2)
    print(f"  [{agent_type}][listener] named pipe is visible on target")

    agent_id = None
    try:
        # ── Steps 2-5: Build, deploy, exec, wait for checkin ─────────────────
        agent = deploy_and_checkin(
            ctx, cli, target,
            agent_type=agent_type, fmt=fmt,
            listener_name=listener_name,
            label=agent_type,
        )
        agent_id = agent["id"]

        # ── Step 6: Command suite ────────────────────────────────────────────

        # whoami → DOMAIN\username format
        print(f"  [{agent_type}][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=30)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert "\\" in whoami_out, (
            f"whoami output {whoami_out!r} does not contain '\\' "
            f"— expected DOMAIN\\username format"
        )
        print(f"  [{agent_type}][cmd] whoami passed: {whoami_out!r}")

        # dir C:\ → non-empty output
        print(f"  [{agent_type}][cmd] dir C:\\")
        result = agent_exec(cli, agent_id, "dir C:\\", wait=True, timeout=30)
        dir_out = result.get("output", "").strip()
        assert dir_out, "dir C:\\ returned empty output"
        print(f"  [{agent_type}][cmd] dir C:\\ passed ({len(dir_out.splitlines())} lines)")

        # ipconfig → contains 'IPv4 Address'
        print(f"  [{agent_type}][cmd] ipconfig")
        result = agent_exec(cli, agent_id, "ipconfig", wait=True, timeout=30)
        ipconfig_out = result.get("output", "").strip()
        assert ipconfig_out, "ipconfig returned empty output"
        assert "IPv4 Address" in ipconfig_out, (
            f"ipconfig output does not contain 'IPv4 Address':\n{ipconfig_out[:500]}"
        )
        print(f"  [{agent_type}][cmd] ipconfig passed")

        print(f"  [{agent_type}][suite] all SMB commands passed")

    finally:
        # ── Step 7: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [{agent_type}][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] stopping/deleting SMB listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass

        print(f"  [{agent_type}][cleanup] removing work_dir on target")
        try:
            run_remote(
                target,
                f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                timeout=15,
            )
        except Exception as exc:
            print(f"  [{agent_type}][cleanup] work_dir removal failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] done")


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Skips silently when ctx.windows is None.

    SMB listener config is read from env.toml [listeners]:
      smb_pipe — named pipe suffix embedded in payloads (default "redcell-c2")
    """
    if ctx.windows is None:
        raise ScenarioSkipped("ctx.windows is None — no Windows target configured")
    from lib.deploy import DeployError, preflight_ssh
    try:
        preflight_ssh(ctx.windows)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    # ── Demon pass (primary baseline) ───────────────────────────────────────
    print("\n  === SMB agent pass: demon ===")
    _run_for_agent(ctx, agent_type="demon", fmt="exe", name_prefix="test-smb-demon")

    # ── Specter pass (Rust Windows agent) ───────────────────────────────────
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    print("\n  === SMB agent pass: specter ===")
    if "specter" not in available_agents:
        print("  [specter] SKIPPED — 'specter' not listed in agents.available")
    else:
        _run_for_agent(ctx, agent_type="specter", fmt="exe", name_prefix="test-smb-specter")
