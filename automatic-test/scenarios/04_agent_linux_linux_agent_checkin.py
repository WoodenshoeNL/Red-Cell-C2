"""
Scenario 04_agent_linux: Linux agent checkin

Deploy a Linux agent to Ubuntu, wait for checkin, run command suite.
Runs once for Demon (always).  The Phantom pass runs only when
``"phantom"`` is listed in ``agents.available`` in env.toml; if it is listed
and the payload build fails, the scenario fails so the regression is caught.

Skip if ctx.linux is None.

Steps (per agent pass):
  1. Create + start HTTP listener
  2. Build agent payload for Linux target
  3. Deploy via SSH/SCP to Ubuntu test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Run command suite: whoami, pwd, ls /, hostname
  7. Kill agent, stop listener, clean up work_dir on target
"""

DESCRIPTION = "Linux agent checkin (Demon + Phantom)"

import os
import tempfile
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
        agent_list,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        payload_build_and_fetch,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import wait_for_agent

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    remote_payload = f"{target.work_dir}/agent-{uid}.bin"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    _fd, local_payload = tempfile.mkstemp(suffix=f".{fmt}")
    os.close(_fd)

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [{agent_type}][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")

    agent_id = None
    try:
        # ── Step 2: Build agent payload ──────────────────────────────────────
        print(f"  [{agent_type}][payload] building {agent_type} {fmt} x64 for Linux target")
        raw = payload_build_and_fetch(
            cli, listener=listener_name, arch="x64", fmt=fmt, agent=agent_type
        )
        assert len(raw) > 0, "payload is empty"
        print(f"  [{agent_type}][payload] built ({len(raw)} bytes)")

        with open(local_payload, "wb") as fh:
            fh.write(raw)

        # ── Step 3: Deploy via SCP ───────────────────────────────────────────
        print(f"  [{agent_type}][deploy] ensuring work dir {target.work_dir!r} on target")
        ensure_work_dir(target)
        print(f"  [{agent_type}][deploy] uploading payload → {remote_payload}")
        upload(target, local_payload, remote_payload)
        run_remote(target, f"chmod +x {remote_payload}")
        print(f"  [{agent_type}][deploy] uploaded")

        # ── Step 4: Execute payload in background ────────────────────────────
        print(f"  [{agent_type}][exec] launching payload in background on target")
        execute_background(target, remote_payload)

        # ── Step 5: Wait for agent checkin ───────────────────────────────────
        checkin_timeout = ctx.env.get("timeouts", {}).get("agent_checkin", 60)
        print(f"  [{agent_type}][wait] waiting up to {checkin_timeout}s for agent checkin")

        agent = wait_for_agent(cli, timeout=checkin_timeout, pre_existing_ids=pre_existing_ids)
        agent_id = agent["id"]
        print(f"  [{agent_type}][wait] agent checked in: {agent_id}")

        # ── Step 6: Command suite ────────────────────────────────────────────

        # whoami → contains the expected SSH username
        print(f"  [{agent_type}][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=30)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert target.user in whoami_out, (
            f"whoami output {whoami_out!r} does not contain "
            f"expected user {target.user!r}"
        )
        print(f"  [{agent_type}][cmd] whoami passed: {whoami_out!r}")

        # pwd → returns an absolute path
        print(f"  [{agent_type}][cmd] pwd")
        result = agent_exec(cli, agent_id, "pwd", wait=True, timeout=30)
        pwd_out = result.get("output", "").strip()
        assert pwd_out, "pwd returned empty output"
        assert pwd_out.startswith("/"), (
            f"pwd output is not an absolute path: {pwd_out!r}"
        )
        print(f"  [{agent_type}][cmd] pwd passed: {pwd_out!r}")

        # ls / → non-empty directory listing
        print(f"  [{agent_type}][cmd] ls /")
        result = agent_exec(cli, agent_id, "ls /", wait=True, timeout=30)
        ls_out = result.get("output", "").strip()
        assert ls_out, "ls / returned empty output"
        print(f"  [{agent_type}][cmd] ls / passed ({len(ls_out.splitlines())} entries)")

        # hostname → matches the hostname reported by SSH
        print(f"  [{agent_type}][cmd] hostname")
        expected_hostname = run_remote(target, "hostname").strip()
        result = agent_exec(cli, agent_id, "hostname", wait=True, timeout=30)
        hostname_out = result.get("output", "").strip()
        assert hostname_out, "hostname returned empty output"
        assert hostname_out == expected_hostname, (
            f"hostname mismatch: agent reported {hostname_out!r}, "
            f"SSH reports {expected_hostname!r}"
        )
        print(f"  [{agent_type}][cmd] hostname passed: {hostname_out!r}")

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

        try:
            os.unlink(local_payload)
        except Exception:
            pass

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

    # ── Demon pass (primary baseline) ───────────────────────────────────────
    print("\n  === Agent pass: demon ===")
    _run_for_agent(ctx, agent_type="demon", fmt="bin", name_prefix="test-linux-demon")

    # ── Phantom pass (Rust Linux agent) ─────────────────────────────────────
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    print("\n  === Agent pass: phantom ===")
    if "phantom" not in available_agents:
        print("  [phantom] SKIPPED — 'phantom' not listed in agents.available")
    else:
        _run_for_agent(ctx, agent_type="phantom", fmt="bin", name_prefix="test-linux-phantom")
