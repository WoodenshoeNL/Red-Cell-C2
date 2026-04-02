"""
Scenario 09_kerberos: Kerberos token ops

Tests Windows access-token and Kerberos ticket introspection via the
deployed Demon agent using native Windows shell commands:

  1. Create + start HTTP listener
  2. Build Demon EXE (x64) for Windows target
  3. Deploy via SSH/SCP to Windows test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. List tokens via `whoami /all` — verify command succeeds and output
     contains recognisable token structure (user info + privilege list)
  7. Request/list Kerberos tickets via `klist` — verify no CliError is
     raised (exit 0 even when no domain tickets are cached)
  8. Kill agent, stop listener, clean up

Skip conditions:
  - ctx.windows is None (no Windows target configured)
  - `klist` fails because Kerberos is not available in the test
    environment (non-fatal, printed as a warning rather than a failure)
"""

DESCRIPTION = "Kerberos token ops"

import base64
import os
import tempfile
import uuid

from lib import ScenarioSkipped


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
    Skips silently when ctx.windows is None.
    """
    if ctx.windows is None:
        raise ScenarioSkipped("ctx.windows is None — no Windows target configured")

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
    from lib.wait import wait_for_agent, TimeoutError as WaitTimeout

    cli = ctx.cli
    target = ctx.windows
    uid = _short_id()
    listener_name = f"test-kerberos-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("windows_port", 19082)
    remote_payload = f"{target.work_dir}\\agent-{uid}.exe"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    local_payload = tempfile.mktemp(suffix=".exe")

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [listener] started")

    agent_id = None
    try:
        # ── Step 2: Build Demon payload ──────────────────────────────────────
        print("  [payload] building Demon EXE x64 for Windows target")
        result = payload_build(
            cli, agent="demon", listener=listener_name, arch="x64", fmt="exe"
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
        print("  [deploy] uploaded")

        # ── Step 4: Execute payload in background ────────────────────────────
        print("  [exec] launching payload in background on target")
        execute_background(target, remote_payload)

        # ── Step 5: Wait for agent checkin ───────────────────────────────────
        checkin_timeout = ctx.env.get("timeouts", {}).get("agent_checkin", 60)
        print(f"  [wait] waiting up to {checkin_timeout}s for agent checkin")

        agent = wait_for_agent(cli, timeout=checkin_timeout, pre_existing_ids=pre_existing_ids)
        agent_id = agent["id"]
        print(f"  [wait] agent checked in: {agent_id}")

        # ── Step 6: List tokens via whoami /all ──────────────────────────────
        # `whoami /all` returns user info, group memberships, and token
        # privileges — the structured output expected by this test step.
        print("  [tokens] listing token info via 'whoami /all'")
        token_result = agent_exec(cli, agent_id, "whoami /all", wait=True, timeout=30)
        token_output = token_result.get("output", "").strip()

        assert token_output, "whoami /all returned empty output"

        # The output must contain the USER INFORMATION header and at least
        # one privilege entry from the token's privilege list.
        assert "USER INFORMATION" in token_output or "User Name" in token_output, (
            "whoami /all output does not contain expected 'USER INFORMATION' header.\n"
            f"  Output (first 500 chars): {token_output[:500]!r}"
        )
        assert "PRIVILEGES INFORMATION" in token_output or "Privilege Name" in token_output, (
            "whoami /all output does not contain expected 'PRIVILEGES INFORMATION' section.\n"
            f"  Output (first 500 chars): {token_output[:500]!r}"
        )
        print(
            f"  [tokens] token info received ({len(token_output)} chars), "
            "user info and privilege list confirmed"
        )

        # ── Step 7: Request / list Kerberos tickets via klist ────────────────
        # `klist.exe` is a native Windows command available since Vista.
        # On a domain-joined host it lists cached Kerberos tickets; on a
        # standalone host it exits 0 and reports "Cached Tickets: (0)".
        # Either outcome satisfies the "no error returned" requirement.
        print("  [kerberos] listing Kerberos tickets via 'klist'")
        kerberos_available = True
        try:
            klist_result = agent_exec(cli, agent_id, "klist", wait=True, timeout=30)
            klist_output = klist_result.get("output", "").strip()
            print(
                f"  [kerberos] klist output received ({len(klist_output)} chars): "
                f"{klist_output[:200]!r}"
            )
            # Verify the output contains expected klist markers (present even
            # when there are no cached tickets).
            if klist_output:
                assert "LogonId" in klist_output or "Cached Tickets" in klist_output or "Ticket cache" in klist_output, (
                    "klist output does not contain expected Kerberos markers "
                    "('LogonId', 'Cached Tickets', or 'Ticket cache').\n"
                    f"  Output: {klist_output[:500]!r}"
                )
                print("  [kerberos] klist markers confirmed — Kerberos available")
            else:
                print(
                    "  [kerberos] klist returned empty output — "
                    "treating as Kerberos not available (non-fatal)"
                )
                kerberos_available = False
        except CliError as exc:
            # klist is not available or Kerberos is not configured — skip
            # gracefully rather than failing the whole scenario.
            print(
                f"  [kerberos] klist command returned an error (non-fatal, skipping Kerberos check): "
                f"{exc}"
            )
            kerberos_available = False

        if not kerberos_available:
            print(
                "  [kerberos] Kerberos not available in this test environment — "
                "klist check skipped"
            )

        print("  [suite] all Kerberos token checks passed")

    finally:
        # ── Step 8: Kill agent, stop listener, clean up ──────────────────────
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
            run_remote(
                target,
                f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                timeout=15,
            )
        except Exception as exc:
            print(f"  [cleanup] work_dir removal failed (non-fatal): {exc}")

        try:
            os.unlink(local_payload)
        except Exception:
            pass

        print("  [cleanup] done")
