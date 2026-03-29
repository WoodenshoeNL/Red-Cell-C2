"""
Scenario 07_process_ops: Process operations

Steps:
  1. Create + start HTTP listener
  2. Build Demon bin (x64) for Linux target
  3. Deploy via SSH/SCP to Linux test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. List processes via agent → verify known system process (sshd) is present
  7. Spawn a long-running test process on target via SSH → record its PID
  8. Kill the test process via agent exec
  9. Verify the killed PID no longer appears in the process list
 10. Kill agent, stop listener, clean up

Skip if ctx.linux is None.
"""

DESCRIPTION = "Process operations"

import base64
import os
import tempfile
import time
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
        agent_list,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        payload_build,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import poll, TimeoutError as WaitTimeout

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"test-procops-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    remote_payload = f"{target.work_dir}/agent-{uid}.bin"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    local_payload = tempfile.mktemp(suffix=".bin")

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [listener] started")

    agent_id = None
    try:
        # ── Step 2: Build Demon payload ──────────────────────────────────────
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

        new_agents = poll(
            fn=_new_agent_appeared,
            predicate=lambda agents: len(agents) > 0,
            timeout=checkin_timeout,
            description="new Linux agent checkin",
        )
        agent_id = new_agents[0]["id"]
        print(f"  [wait] agent checked in: {agent_id}")

        # ── Step 6: List processes via agent ─────────────────────────────────
        print("  [ps] listing processes via agent exec")
        ps_result = agent_exec(cli, agent_id, "ps aux", wait=True, timeout=30)
        ps_output = ps_result.get("output", "")
        assert ps_output, "ps aux returned empty output"

        # sshd should be running on any standard Linux SSH target
        assert "sshd" in ps_output, (
            "expected 'sshd' in process list but it was not found.\n"
            f"  ps output (first 500 chars): {ps_output[:500]!r}"
        )
        print(f"  [ps] process list received ({len(ps_output)} chars), 'sshd' confirmed present")

        # ── Step 7: Spawn a test process on target via SSH ───────────────────
        # Start a long sleep in the background and capture its PID.
        print("  [spawn] starting sleep process on target via SSH")
        sleep_marker = f"sleep-redcell-{uid}"
        # Use the marker as a unique argument so we can find this exact process.
        pid_str = run_remote(
            target,
            f"bash -c 'sleep 9999 & echo $!'",
            timeout=10,
        ).strip()
        assert pid_str.isdigit(), (
            f"expected a numeric PID from spawn command, got: {pid_str!r}"
        )
        sleep_pid = int(pid_str)
        print(f"  [spawn] sleep process started, PID={sleep_pid}")

        # Verify it's actually running (sanity check via SSH).
        ps_check = run_remote(target, f"ps -p {sleep_pid} -o pid= 2>/dev/null || true", timeout=10)
        assert ps_check.strip() == str(sleep_pid), (
            f"sleep process PID {sleep_pid} not found in ps immediately after spawn"
        )
        print(f"  [spawn] confirmed PID {sleep_pid} is running on target")

        # ── Step 8: Kill the test process via agent ──────────────────────────
        print(f"  [kill] sending 'kill {sleep_pid}' via agent exec")
        kill_result = agent_exec(cli, agent_id, f"kill {sleep_pid}", wait=True, timeout=15)
        print(f"  [kill] kill command dispatched, output: {kill_result.get('output', '(none)')!r}")

        # Give the process a moment to die.
        time.sleep(1)

        # ── Step 9: Verify the killed PID is gone ────────────────────────────
        print(f"  [verify] checking that PID {sleep_pid} is no longer running")
        # ps -p <pid> exits non-zero when the process doesn't exist; capture via || true.
        pid_check = run_remote(
            target,
            f"ps -p {sleep_pid} -o pid= 2>/dev/null || true",
            timeout=10,
        ).strip()
        assert pid_check == "", (
            f"process PID {sleep_pid} is still running after kill — "
            f"ps output: {pid_check!r}"
        )
        print(f"  [verify] PID {sleep_pid} is no longer present in process list — kill confirmed")

        # Also verify via agent ps aux: the killed PID should be absent.
        ps_after_result = agent_exec(cli, agent_id, f"ps -p {sleep_pid}", wait=True, timeout=15)
        ps_after_output = ps_after_result.get("output", "")
        assert str(sleep_pid) not in ps_after_output, (
            f"PID {sleep_pid} still visible in agent ps output after kill: "
            f"{ps_after_output!r}"
        )
        print("  [verify] agent ps confirms PID is absent")

        print("  [suite] all process-operations checks passed")

    finally:
        # ── Step 10: Kill agent, stop listener, clean up ─────────────────────
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

        print("  [cleanup] removing work_dir on target")
        try:
            run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [cleanup] work_dir removal failed (non-fatal): {exc}")

        try:
            os.unlink(local_payload)
        except Exception:
            pass

        print("  [cleanup] done")
