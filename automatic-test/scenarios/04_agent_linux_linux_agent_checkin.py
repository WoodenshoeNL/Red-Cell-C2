"""
Scenario 04_agent_linux: Linux agent checkin

Deploy a Linux agent to Ubuntu, wait for checkin, run command suite.

Demon is a Windows-only agent (Windows PE / Win32 API) and cannot run on
Linux.  This scenario therefore skips when no Linux-capable agent is
available.  The Phantom pass runs only when ``"phantom"`` is listed in
``agents.available`` in env.toml; if it is listed and the payload build
fails, the scenario fails so the regression is caught.

Skip if ctx.linux is None or no Linux-capable agent is available.

Steps (per agent pass):
  1. Create + start HTTP listener
  2. Build agent payload for Linux target
  3. Deploy via SSH/SCP to Ubuntu test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Run command suite: whoami, pwd, ls /, hostname, stat, ls -la, ss/netstat,
     env, /proc/version
  7. Kill agent, stop listener, clean up work_dir on target
"""

DESCRIPTION = "Linux agent checkin (Phantom)"

import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full Linux checkin suite for one agent type.

    Args:
        ctx:         RunContext passed by the harness.
        agent_type:  Agent name passed to ``payload_build`` (e.g. ``"demon"``
                     or ``"phantom"``).
        fmt:         Payload format (e.g. ``"bin"`` or ``"elf"``).
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

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.linux
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [{agent_type}][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    callback_host = ctx.env.get("server", {}).get("callback_host")
    if callback_host:
        import json as _json
        listener_create(cli, listener_name, "http", config_json=_json.dumps({
            "name": listener_name,
            "host_bind": "0.0.0.0",
            "host_rotation": "round-robin",
            "port_bind": listener_port,
            "hosts": [callback_host],
            "secure": False,
            "legacy_mode": False,
        }))
    else:
        listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")

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

        # whoami → contains the expected SSH username
        print(f"  [{agent_type}][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=co)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert target.user in whoami_out, (
            f"whoami output {whoami_out!r} does not contain "
            f"expected user {target.user!r}"
        )
        print(f"  [{agent_type}][cmd] whoami passed: {whoami_out!r}")

        # pwd → returns an absolute path
        print(f"  [{agent_type}][cmd] pwd")
        result = agent_exec(cli, agent_id, "pwd", wait=True, timeout=co)
        pwd_out = result.get("output", "").strip()
        assert pwd_out, "pwd returned empty output"
        assert pwd_out.startswith("/"), (
            f"pwd output is not an absolute path: {pwd_out!r}"
        )
        print(f"  [{agent_type}][cmd] pwd passed: {pwd_out!r}")

        # ls / → non-empty directory listing
        print(f"  [{agent_type}][cmd] ls /")
        result = agent_exec(cli, agent_id, "ls /", wait=True, timeout=co)
        ls_out = result.get("output", "").strip()
        assert ls_out, "ls / returned empty output"
        print(f"  [{agent_type}][cmd] ls / passed ({len(ls_out.splitlines())} entries)")

        # hostname → matches the hostname reported by SSH
        print(f"  [{agent_type}][cmd] hostname")
        expected_hostname = run_remote(target, "hostname").strip()
        result = agent_exec(cli, agent_id, "hostname", wait=True, timeout=co)
        hostname_out = result.get("output", "").strip()
        assert hostname_out, "hostname returned empty output"
        assert hostname_out == expected_hostname, (
            f"hostname mismatch: agent reported {hostname_out!r}, "
            f"SSH reports {expected_hostname!r}"
        )
        print(f"  [{agent_type}][cmd] hostname passed: {hostname_out!r}")

        # stat — file mode bits for a well-known path
        print(f"  [{agent_type}][cmd] stat /etc/hostname")
        result = agent_exec(
            cli, agent_id, "stat -c '%a %n' /etc/hostname", wait=True, timeout=co
        )
        stat_out = result.get("output", "").strip()
        assert stat_out, "stat returned empty output"
        assert "hostname" in stat_out, (
            f"stat output missing expected filename fragment: {stat_out!r}"
        )
        print(f"  [{agent_type}][cmd] stat passed: {stat_out!r}")

        # ls -la — long listing (trimmed)
        print(f"  [{agent_type}][cmd] ls -la / (head)")
        result = agent_exec(cli, agent_id, "ls -la / | head -n 25", wait=True, timeout=co)
        ls_la = result.get("output", "").strip()
        assert ls_la, "ls -la returned empty output"
        assert "total " in ls_la or "drwx" in ls_la, (
            f"ls -la output missing expected long-list markers: {ls_la[:300]!r}"
        )
        print(f"  [{agent_type}][cmd] ls -la passed ({len(ls_la.splitlines())} lines)")

        # Network listeners — prefer ss, fall back to netstat
        print(f"  [{agent_type}][cmd] ss -tln (or netstat)")
        result = agent_exec(
            cli,
            agent_id,
            "ss -tln 2>/dev/null || netstat -tln 2>/dev/null || true",
            wait=True,
            timeout=co,
        )
        ss_out = result.get("output", "").strip()
        assert len(ss_out) > 8, (
            f"ss/netstat output unexpectedly short: {ss_out!r}"
        )
        print(f"  [{agent_type}][cmd] listener table non-empty ({len(ss_out)} chars)")

        # Environment slice
        print(f"  [{agent_type}][cmd] env (head)")
        result = agent_exec(cli, agent_id, "env | head -n 40", wait=True, timeout=co)
        env_out = result.get("output", "").strip()
        assert env_out, "env returned empty output"
        assert "PATH" in env_out, (
            f"env output missing PATH: {env_out[:400]!r}"
        )
        print(f"  [{agent_type}][cmd] env passed (PATH present)")

        # Kernel string from procfs
        print(f"  [{agent_type}][cmd] cat /proc/version")
        result = agent_exec(cli, agent_id, "cat /proc/version", wait=True, timeout=co)
        ver_out = result.get("output", "").strip()
        assert "Linux" in ver_out, (
            f"/proc/version does not look like Linux: {ver_out!r}"
        )
        print(f"  [{agent_type}][cmd] /proc/version passed")

        print(f"  [{agent_type}][suite] all commands passed")

    finally:
        # ── Step 7: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [{agent_type}][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] stopping/deleting listener {listener_name!r}")
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
            run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
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
    Skips silently when ctx.linux is None.
    """
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — no Linux target configured")
    from lib.deploy import DeployError, preflight_ssh
    try:
        preflight_ssh(ctx.linux)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    # Demon is a Windows-only agent (Windows PE + Win32/NTAPI) — it cannot
    # execute on Linux.  Gate on Phantom availability instead.
    available_agents = set(ctx.env.get("agents", {}).get("available", []))
    if "phantom" not in available_agents:
        raise ScenarioSkipped(
            "No Linux-capable agent available — Demon is Windows-only; "
            "add 'phantom' to agents.available in env.toml once Phantom is implemented"
        )

    # ── Phantom pass (Rust Linux ELF agent) ─────────────────────────────────
    print("\n  === Agent pass: phantom ===")
    _run_for_agent(ctx, agent_type="phantom", fmt="elf", name_prefix="test-linux-phantom")
