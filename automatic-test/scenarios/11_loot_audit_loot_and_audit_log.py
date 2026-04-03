"""
Scenario 11_loot_audit: Loot and audit log

Verifies loot entry creation after a file download and checks that the
audit log faithfully records every operation performed in the scenario.

Test steps:
  1. Record test_start timestamp (before any operations)
  2. Create + start HTTP listener
  3. Build Demon payload (bin for Linux / exe for Windows)
  4. Deploy + execute on target; wait for agent checkin
  5. Run 'whoami' command via agent exec  → audit: agent.task
  6. Download /etc/hostname (Linux) or C:\\Windows\\win.ini (Windows)
     → creates loot entry with kind 'download'
  7. Wait for loot entry of kind 'download' to appear for this agent
  8. Verify loot entry:
       - agent_id  matches the agent that ran the download
       - captured_at is at or after test_start
       - kind == 'download'
  9. Verify audit log (entries since test_start):
       - Contains entry with action 'listener.create'
       - Contains entry with action 'payload.build'
       - Contains entry with action 'agent.task' or 'agent.download'
       - Every returned entry has operator field set to a non-empty string
 10. Export loot to CSV using Python's csv module:
       - Write all loot entries returned by loot list to a temp file
       - Parse the CSV and verify it is well-formed
       - Verify expected columns are present: id, agent_id, kind, name,
         captured_at
 11. Cleanup: kill agent, stop + delete listener, remove remote work_dir

Skip conditions:
  - ctx.linux is None AND ctx.windows is None → no target available
"""

DESCRIPTION = "Loot and audit log"

import csv
import io
import os
import tempfile
import uuid
from datetime import datetime, timezone

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across runs."""
    return uuid.uuid4().hex[:8]


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string (Z suffix)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target_and_fmt(ctx):
    """
    Return (target, payload_fmt, is_windows, remote_src_file).

    Prefers Linux.  Falls back to Windows when Linux is absent.
    Returns (None, None, None, None) when no target is configured.
    """
    if ctx.linux is not None:
        return ctx.linux, "bin", False, "/etc/hostname"
    if ctx.windows is not None:
        return ctx.windows, "exe", True, "C:\\Windows\\win.ini"
    return None, None, None, None


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Skips when no target is configured.
    """
    target, payload_fmt, is_windows, remote_src_file = _target_and_fmt(ctx)
    if target is None:
        raise ScenarioSkipped("no target configured (ctx.linux and ctx.windows are both None)")

    from lib.cli import (
        CliError,
        agent_download,
        agent_exec,
        agent_kill,
        agent_list,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        log_list,
        loot_list,
        payload_build_and_fetch,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import TimeoutError as WaitTimeout
    from lib.wait import poll, wait_for_agent

    cli = ctx.cli
    uid = _short_id()
    target_label = "Windows" if is_windows else "Linux"
    listener_name = f"test-loot-audit-{uid}"
    listener_port = ctx.env.get("listeners", {}).get(
        "windows_port" if is_windows else "linux_port",
        19082 if is_windows else 19081,
    )

    if is_windows:
        remote_payload = f"{target.work_dir}\\agent-{uid}.exe"
    else:
        remote_payload = f"{target.work_dir}/agent-{uid}.bin"

    # ── Step 1: Record test_start before any operations ──────────────────────
    test_start = _utc_now_iso()
    print(f"  [time] scenario start timestamp: {test_start}")

    # Snapshot pre-existing agent and loot IDs.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    try:
        pre_existing_loot_ids = {
            e["id"] for e in loot_list(cli, kind="download")
        }
    except Exception:
        pre_existing_loot_ids = set()

    _fd, local_payload = tempfile.mkstemp(suffix="." + payload_fmt)
    os.close(_fd)
    _fd, local_download_dst = tempfile.mkstemp(suffix=".txt")
    os.close(_fd)

    # ── Step 2: Create + start HTTP listener ─────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [listener] started")

    agent_id = None
    try:
        # ── Step 3: Build Demon payload ───────────────────────────────────────
        print(f"  [payload] building Demon {payload_fmt} x64 for {target_label} target")
        raw = payload_build_and_fetch(
            cli, listener=listener_name, arch="x64", fmt=payload_fmt
        )
        assert len(raw) > 0, "payload is empty"
        print(f"  [payload] built ({len(raw)} bytes)")

        with open(local_payload, "wb") as fh:
            fh.write(raw)

        # ── Step 4: Deploy + execute on target ────────────────────────────────
        print(f"  [deploy] ensuring work dir {target.work_dir!r} on target")
        ensure_work_dir(target)
        print(f"  [deploy] uploading payload → {remote_payload}")
        upload(target, local_payload, remote_payload)
        if not is_windows:
            run_remote(target, f"chmod +x {remote_payload}")
        print("  [deploy] uploaded")

        print("  [exec] launching payload in background on target")
        execute_background(target, remote_payload)

        checkin_timeout = ctx.env.get("timeouts", {}).get("agent_checkin", 60)
        print(f"  [wait] waiting up to {checkin_timeout}s for agent checkin")

        agent = wait_for_agent(cli, timeout=checkin_timeout, pre_existing_ids=pre_existing_ids)
        agent_id = agent["id"]
        print(f"  [wait] agent checked in: {agent_id}")

        # ── Step 5: Run 'whoami' via agent exec → audit: agent.task ──────────
        print("  [exec] sending whoami command (creates agent.task audit entry)")
        exec_result = agent_exec(cli, agent_id, "whoami", wait=True)
        print(f"  [exec] whoami done, job_id={exec_result.get('job_id', '(unknown)')!r}")

        # ── Step 6: Download a file from the agent → creates loot entry ───────
        print(f"  [download] downloading {remote_src_file!r} from agent")
        agent_download(cli, agent_id, src=remote_src_file, dst=local_download_dst)
        print("  [download] download command accepted")

        # ── Step 7: Wait for loot entry of kind 'download' ───────────────────
        loot_timeout = ctx.env.get("timeouts", {}).get("loot_entry", 30)
        print(f"  [wait] waiting up to {loot_timeout}s for 'download' loot entry")

        def _new_download_loot():
            entries = loot_list(cli, kind="download", agent_id=agent_id)
            return [e for e in entries if e["id"] not in pre_existing_loot_ids]

        new_loot = poll(
            fn=_new_download_loot,
            predicate=lambda entries: len(entries) > 0,
            timeout=loot_timeout,
            description="download loot entry",
        )
        loot_entry = new_loot[0]
        loot_id = loot_entry["id"]
        print(
            f"  [loot] download loot entry created: id={loot_id}, "
            f"name={loot_entry.get('name')!r}, "
            f"size={loot_entry.get('size_bytes')} bytes"
        )

        # ── Step 8: Verify loot entry fields ──────────────────────────────────
        assert loot_entry["kind"] == "download", (
            f"expected loot kind 'download', got {loot_entry['kind']!r}"
        )
        assert loot_entry["agent_id"] == agent_id, (
            f"loot entry agent_id mismatch: "
            f"expected {agent_id!r}, got {loot_entry['agent_id']!r}"
        )
        loot_ts = loot_entry.get("captured_at", "")
        assert loot_ts, "loot entry is missing captured_at timestamp"
        assert loot_ts >= test_start, (
            f"loot entry timestamp {loot_ts!r} predates scenario start {test_start!r}"
        )
        print(
            f"  [loot] verified: kind=download, agent_id={agent_id}, "
            f"captured_at={loot_ts}"
        )

        # ── Step 9: Verify audit log ───────────────────────────────────────────
        print(f"  [audit] querying audit log since {test_start}")
        audit_entries = log_list(cli, since=test_start, limit=200)
        print(f"  [audit] {len(audit_entries)} entries found since test_start")

        actions_seen = {e["action"] for e in audit_entries}
        print(f"  [audit] action types seen: {sorted(actions_seen)}")

        # listener.create must be present
        assert "listener.create" in actions_seen, (
            f"audit log missing 'listener.create' entry — "
            f"actions seen: {sorted(actions_seen)}"
        )
        print("  [audit] listener.create ✓")

        # payload.build must be present
        assert "payload.build" in actions_seen, (
            f"audit log missing 'payload.build' entry — "
            f"actions seen: {sorted(actions_seen)}"
        )
        print("  [audit] payload.build ✓")

        # At least one agent command action must be present.
        agent_action_present = bool(
            actions_seen & {"agent.task", "agent.download"}
        )
        assert agent_action_present, (
            f"audit log is missing both 'agent.task' and 'agent.download' entries — "
            f"actions seen: {sorted(actions_seen)}"
        )
        print("  [audit] agent action (agent.task / agent.download) ✓")

        # Every audit entry must have a non-empty operator field.
        entries_missing_operator = [
            e for e in audit_entries
            if not e.get("operator", "").strip()
        ]
        assert len(entries_missing_operator) == 0, (
            f"{len(entries_missing_operator)} audit entries are missing the operator "
            f"field:\n"
            + "\n".join(
                f"  action={e.get('action')!r} ts={e.get('ts')!r}"
                for e in entries_missing_operator[:5]
            )
        )
        print("  [audit] all entries have operator field set ✓")

        # ── Step 10: Export loot to CSV and validate ──────────────────────────
        print("  [csv] exporting loot list to CSV and validating")
        all_loot = loot_list(cli)
        _verify_loot_csv(all_loot)
        print("  [csv] CSV export verified ✓")

        print("  [suite] all loot-audit checks passed")

    finally:
        # ── Step 11: Cleanup ──────────────────────────────────────────────────
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
            if is_windows:
                run_remote(target, f"rmdir /S /Q {target.work_dir}", timeout=15)
            else:
                run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [cleanup] work_dir removal failed (non-fatal): {exc}")

        for path in (local_payload, local_download_dst):
            try:
                os.unlink(path)
            except Exception:
                pass

        print("  [cleanup] done")


# ── CSV helpers ───────────────────────────────────────────────────────────────

# Minimum set of columns that must appear in the exported loot CSV.
_REQUIRED_CSV_COLUMNS = {"id", "agent_id", "kind", "name", "captured_at"}


def _verify_loot_csv(loot_entries: list) -> None:
    """Write *loot_entries* to a CSV string, parse it back, and verify structure.

    Raises AssertionError if:
    - The CSV cannot be parsed.
    - Any required column is absent from the header row.
    - The row count does not match the number of loot entries.
    """
    if not loot_entries:
        # Nothing to validate — emit a header-only CSV and verify it parses.
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=sorted(_REQUIRED_CSV_COLUMNS))
        writer.writeheader()
        _parse_and_check_csv(buf.getvalue(), expected_rows=0)
        return

    # Determine column order from the keys of the first entry.
    fieldnames = list(loot_entries[0].keys())

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for entry in loot_entries:
        # Flatten None values to empty strings for CSV compatibility.
        row = {k: ("" if v is None else str(v)) for k, v in entry.items()}
        writer.writerow(row)

    _parse_and_check_csv(buf.getvalue(), expected_rows=len(loot_entries))


def _parse_and_check_csv(csv_text: str, expected_rows: int) -> None:
    """Parse *csv_text*, check required columns and row count.

    Raises AssertionError on any validation failure.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    try:
        rows = list(reader)
    except csv.Error as exc:
        raise AssertionError(f"loot CSV failed to parse: {exc}") from exc

    headers = set(reader.fieldnames or [])
    missing_cols = _REQUIRED_CSV_COLUMNS - headers
    assert not missing_cols, (
        f"loot CSV is missing required columns: {sorted(missing_cols)}\n"
        f"  actual columns: {sorted(headers)}"
    )

    assert len(rows) == expected_rows, (
        f"loot CSV row count mismatch: expected {expected_rows}, got {len(rows)}"
    )
