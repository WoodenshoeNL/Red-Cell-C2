"""
Scenario 06_file_transfer: File transfer

Upload and download files through an active agent (Linux target).

Steps:
  1. Create + start HTTP listener
  2. Build Demon bin (x64) for Linux target
  3. Deploy via SSH/SCP to Linux test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Upload a known file → verify it appears on target filesystem via SHA-256
  7. Download the uploaded file back → verify contents match original (SHA-256)
  8. Download a system file (/etc/hostname) → verify non-empty bytes
  9. Kill agent, stop listener, clean up

Skip if ctx.linux is None.
"""

DESCRIPTION = "File transfer"

import base64
import hashlib
import os
import tempfile
import uuid


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _sha256_file(path: str) -> str:
    """Return hex SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    """Return hex SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


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
        agent_download,
        agent_exec,
        agent_kill,
        agent_list,
        agent_upload,
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
    listener_name = f"test-ftransfer-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
    remote_payload = f"{target.work_dir}/agent-{uid}.bin"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    local_payload = tempfile.mktemp(suffix=".bin")
    local_upload_src = tempfile.mktemp(suffix=".dat")
    local_download_dst = tempfile.mktemp(suffix=".dat")
    local_sysfile_dst = tempfile.mktemp(suffix=".txt")

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

        # ── Step 6: Upload a known file ──────────────────────────────────────
        # Create a local file with known content and a stable SHA-256.
        upload_content = (
            b"Red Cell C2 file-transfer test\n"
            + uid.encode() + b"\n"
            + b"x" * 4096  # 4 KiB padding to exercise chunked transfer
        )
        with open(local_upload_src, "wb") as fh:
            fh.write(upload_content)
        expected_sha256 = _sha256_bytes(upload_content)
        remote_upload_dst = f"{target.work_dir}/uploaded-{uid}.dat"

        print(f"  [upload] uploading {len(upload_content)} bytes → {remote_upload_dst}")
        agent_upload(cli, agent_id, src=local_upload_src, dst=remote_upload_dst)
        print("  [upload] upload command accepted")

        # Verify file appeared on target filesystem via SSH.
        print("  [upload] verifying file on target via SSH (sha256sum)")
        remote_sha = run_remote(
            target, f"sha256sum {remote_upload_dst}", timeout=15
        ).split()[0]
        assert remote_sha == expected_sha256, (
            f"upload SHA-256 mismatch: expected {expected_sha256!r}, "
            f"got {remote_sha!r}"
        )
        print(f"  [upload] SHA-256 verified: {remote_sha}")

        # ── Step 7: Download the uploaded file back ──────────────────────────
        print(f"  [download] downloading {remote_upload_dst} → local")
        agent_download(cli, agent_id, src=remote_upload_dst, dst=local_download_dst)

        assert os.path.exists(local_download_dst), (
            "agent_download returned success but local file was not created"
        )
        downloaded_sha256 = _sha256_file(local_download_dst)
        assert downloaded_sha256 == expected_sha256, (
            f"round-trip SHA-256 mismatch: expected {expected_sha256!r}, "
            f"got {downloaded_sha256!r}"
        )
        downloaded_size = os.path.getsize(local_download_dst)
        print(
            f"  [download] round-trip verified: {downloaded_size} bytes, "
            f"SHA-256 {downloaded_sha256}"
        )

        # ── Step 8: Download a system file (/etc/hostname) ───────────────────
        print("  [sysfile] downloading /etc/hostname via agent")
        agent_download(cli, agent_id, src="/etc/hostname", dst=local_sysfile_dst)

        assert os.path.exists(local_sysfile_dst), (
            "agent_download of /etc/hostname returned success but local file was not created"
        )
        sysfile_content = open(local_sysfile_dst, "rb").read()
        assert len(sysfile_content) > 0, (
            "downloaded /etc/hostname is empty — expected a non-empty hostname string"
        )
        hostname_str = sysfile_content.decode(errors="replace").strip()
        print(f"  [sysfile] /etc/hostname content: {hostname_str!r} ({len(sysfile_content)} bytes)")

        print("  [suite] all file-transfer checks passed")

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
            run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [cleanup] work_dir removal failed (non-fatal): {exc}")

        for path in (local_payload, local_upload_src, local_download_dst, local_sysfile_dst):
            try:
                os.unlink(path)
            except Exception:
                pass

        print("  [cleanup] done")
