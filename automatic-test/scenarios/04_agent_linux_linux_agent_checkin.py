"""
Scenario 04_agent_linux: Linux agent checkin

Deploy Demon to Ubuntu, wait for checkin, run command suite.

Skip if ctx.linux is None.

Steps:
  1. Create + start HTTP listener
  2. Build Demon bin (x64) for Linux target
  3. Deploy via SSH/SCP to Ubuntu test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Run command suite: whoami, pwd, ls /, hostname
  7. Kill agent, stop listener, clean up work_dir on target
"""

DESCRIPTION = "Linux agent checkin"

import base64
import os
import tempfile
import uuid


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


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
        print("  [skip] ctx.linux is None — no Linux target configured")
        return

    from lib.cli import (
        CliError,
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        payload_build,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import wait_for_agent

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"test-linux-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    remote_payload = f"{target.work_dir}/agent-{uid}.bin"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        from lib.cli import agent_list
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    local_payload = tempfile.mktemp(suffix=".bin")  # cleaned up in finally

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [listener] started")

    agent_id = None
    try:
        # ── Step 2: Build Demon payload ──────────────────────────────────────
        # Use fmt="bin" (raw binary) — the closest format to a Linux-runnable
        # payload until the Linux ELF format (Phantom) is available.
        print("  [payload] building Demon bin x64 for Linux target")
        result = payload_build(
            cli, agent="demon", listener=listener_name, arch="x64", fmt="bin"
        )
        raw = base64.b64decode(result["bytes"])
        assert len(raw) > 0, "payload is empty"
        print(f"  [payload] built ({len(raw)} bytes)")

        with open(local_payload, "wb") as fh:
            fh.write(raw)

        # ── Step 3: Deploy via SCP ───────────────────────────────────────────
        print(f"  [deploy] ensuring work dir {target.work_dir!r} on target")
        ensure_work_dir(target)
        print(f"  [deploy] uploading payload → {remote_payload}")
        upload(target, local_payload, remote_payload)
        run_remote(target, f"chmod +x {remote_payload}")
        print("  [deploy] uploaded")

        # ── Step 4: Execute payload in background ────────────────────────────
        print("  [exec] launching payload in background on target")
        execute_background(target, remote_payload)

        # ── Step 5: Wait for agent checkin ───────────────────────────────────
        checkin_timeout = ctx.env.get("timeouts", {}).get("agent_checkin", 60)
        print(f"  [wait] waiting up to {checkin_timeout}s for agent checkin")

        def _new_agent_appeared():
            agents = agent_list(cli)
            new = [a for a in agents if a["id"] not in pre_existing_ids]
            return new

        from lib.wait import poll, TimeoutError as WaitTimeout
        new_agents = poll(
            fn=_new_agent_appeared,
            predicate=lambda agents: len(agents) > 0,
            timeout=checkin_timeout,
            description="new Linux agent checkin",
        )
        agent_id = new_agents[0]["id"]
        print(f"  [wait] agent checked in: {agent_id}")

        # ── Step 6: Command suite ────────────────────────────────────────────

        # whoami → contains the expected SSH username
        print("  [cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=30)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert target.user in whoami_out, (
            f"whoami output {whoami_out!r} does not contain "
            f"expected user {target.user!r}"
        )
        print(f"  [cmd] whoami passed: {whoami_out!r}")

        # pwd → returns an absolute path
        print("  [cmd] pwd")
        result = agent_exec(cli, agent_id, "pwd", wait=True, timeout=30)
        pwd_out = result.get("output", "").strip()
        assert pwd_out, "pwd returned empty output"
        assert pwd_out.startswith("/"), (
            f"pwd output is not an absolute path: {pwd_out!r}"
        )
        print(f"  [cmd] pwd passed: {pwd_out!r}")

        # ls / → non-empty directory listing
        print("  [cmd] ls /")
        result = agent_exec(cli, agent_id, "ls /", wait=True, timeout=30)
        ls_out = result.get("output", "").strip()
        assert ls_out, "ls / returned empty output"
        print(f"  [cmd] ls / passed ({len(ls_out.splitlines())} entries)")

        # hostname → matches the hostname reported by SSH
        print("  [cmd] hostname")
        expected_hostname = run_remote(target, "hostname").strip()
        result = agent_exec(cli, agent_id, "hostname", wait=True, timeout=30)
        hostname_out = result.get("output", "").strip()
        assert hostname_out, "hostname returned empty output"
        assert hostname_out == expected_hostname, (
            f"hostname mismatch: agent reported {hostname_out!r}, "
            f"SSH reports {expected_hostname!r}"
        )
        print(f"  [cmd] hostname passed: {hostname_out!r}")

        print("  [suite] all commands passed")

    finally:
        # ── Step 7: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [cleanup] stopping/deleting listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass

        print(f"  [cleanup] removing work_dir on target")
        try:
            run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [cleanup] work_dir removal failed (non-fatal): {exc}")

        try:
            os.unlink(local_payload)
        except Exception:
            pass

        print("  [cleanup] done")
