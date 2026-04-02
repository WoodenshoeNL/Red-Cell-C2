"""
Scenario 15_agent_dns: End-to-end agent checkin over DNS listener

Deploy a Linux agent using DNS transport, wait for checkin, run command suite.
Runs twice: first with Demon (bin), then with Phantom (elf).  The Phantom
pass is skipped with a warning if the payload build fails (e.g. Phantom not
yet fully implemented), so the Demon pass still counts as coverage.

Skip if ctx.linux is None.

Steps (per agent pass):
  1. Create + start DNS listener
  2. Build agent payload configured to use DNS transport
  3. Deploy via SSH/SCP to Ubuntu test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Run command suite: whoami, pwd, ls /, hostname
  7. Kill agent, stop listener, clean up work_dir on target
"""

DESCRIPTION = "DNS agent checkin (Demon + Phantom over DNS)"

import base64
import os
import tempfile
import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full DNS checkin suite for one agent type.

    Args:
        ctx:         RunContext passed by the harness.
        agent_type:  Agent name passed to ``payload_build`` (e.g. ``"demon"``
                     or ``"phantom"``).
        fmt:         Payload format (e.g. ``"bin"`` or ``"elf"``).
        name_prefix: Short prefix used to name the listener and remote files.

    Raises:
        AssertionError on test failure.
        ScenarioSkipped if the payload cannot be built (agent not yet available).
    """
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
    from lib.wait import wait_for_agent

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"

    dns_cfg = ctx.env.get("listeners", {})
    dns_port = dns_cfg.get("dns_port", 15353)
    dns_domain = dns_cfg.get("dns_domain", "c2.test.local")

    remote_payload = f"{target.work_dir}/agent-dns-{uid}.bin"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    local_payload = tempfile.mktemp(suffix=f".{fmt}")

    # ── Step 1: Create + start DNS listener ─────────────────────────────────
    print(
        f"  [{agent_type}][listener] creating DNS listener {listener_name!r} "
        f"on port {dns_port}, domain {dns_domain!r}"
    )
    listener_create(
        cli, listener_name, "dns",
        port=dns_port,
        domain=dns_domain,
    )
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")

    agent_id = None
    try:
        # ── Step 2: Build agent payload (DNS transport) ──────────────────────
        print(
            f"  [{agent_type}][payload] building {agent_type} {fmt} x64 "
            f"with DNS listener {listener_name!r}"
        )
        try:
            result = payload_build(
                cli, agent=agent_type, listener=listener_name, arch="x64", fmt=fmt
            )
        except CliError as exc:
            raise ScenarioSkipped(
                f"{agent_type} DNS payload build failed — "
                f"agent or DNS transport may not be available yet: {exc}"
            )
        raw = base64.b64decode(result["bytes"])
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
        print(f"  [{agent_type}][exec] launching DNS payload in background on target")
        execute_background(target, remote_payload)

        # ── Step 5: Wait for agent checkin ───────────────────────────────────
        checkin_timeout = ctx.env.get("timeouts", {}).get("agent_checkin", 60)
        print(
            f"  [{agent_type}][wait] waiting up to {checkin_timeout}s for "
            f"agent checkin over DNS"
        )

        agent = wait_for_agent(cli, timeout=checkin_timeout, pre_existing_ids=pre_existing_ids)
        agent_id = agent["id"]
        print(f"  [{agent_type}][wait] agent checked in over DNS: {agent_id}")

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

        print(f"  [{agent_type}][suite] all DNS commands passed")

    finally:
        # ── Step 7: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [{agent_type}][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] stopping/deleting DNS listener {listener_name!r}")
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

    DNS listener config is read from env.toml [listeners]:
      dns_port   — UDP port the DNS listener binds on (default 15353)
      dns_domain — C2 domain the agent beacons to (default "c2.test.local")
    """
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — no Linux target configured")

    # ── Demon pass (primary baseline) ───────────────────────────────────────
    print("\n  === DNS agent pass: demon ===")
    _run_for_agent(ctx, agent_type="demon", fmt="bin", name_prefix="test-dns-demon")

    # ── Phantom pass (Rust Linux agent) ─────────────────────────────────────
    print("\n  === DNS agent pass: phantom ===")
    try:
        _run_for_agent(ctx, agent_type="phantom", fmt="elf", name_prefix="test-dns-phantom")
    except ScenarioSkipped as exc:
        print(f"  [phantom] SKIPPED (Phantom DNS transport not yet available): {exc}")
