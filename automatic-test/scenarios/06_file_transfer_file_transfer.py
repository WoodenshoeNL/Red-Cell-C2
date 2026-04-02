"""
Scenario 06_file_transfer: File transfer

Upload and download files through an active agent.

Linux passes (Demon bin + Phantom elf): upload/download/SHA-256 against Linux target.
Windows passes (Demon exe + Specter exe): same operations against Windows 11 target.

Phantom/Specter passes run only when listed in ``agents.available`` in env.toml;
build failures for listed agents fail the scenario instead of silently skipping.

Steps (per Linux agent pass):
  1. Create + start HTTP listener
  2. Build agent payload for Linux target
  3. Deploy via SSH/SCP to Linux test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Upload a known file → verify it appears on target filesystem via SHA-256
  7. Download the uploaded file back → verify contents match original (SHA-256)
  8. Download a system file (/etc/hostname) → verify non-empty bytes
  9. Kill agent, stop listener, clean up

Steps (per Windows agent pass):
  Same as above, adapted for Windows paths, certutil SHA-256, and
  C:\\Windows\\win.ini as the system file.

Skip Linux passes if ctx.linux is None.
Skip Windows passes if ctx.windows is None.
"""

DESCRIPTION = "File transfer (Demon + Phantom + Specter)"

import hashlib
import os
import tempfile
import uuid

from lib import ScenarioSkipped


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


def _run_for_agent(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full file-transfer suite for one agent type.

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
        agent_download,
        agent_exec,
        agent_kill,
        agent_list,
        agent_upload,
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

    local_payload = tempfile.mktemp(suffix=f".{fmt}")
    local_upload_src = tempfile.mktemp(suffix=".dat")
    local_download_dst = tempfile.mktemp(suffix=".dat")
    local_sysfile_dst = tempfile.mktemp(suffix=".txt")

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
            cli, listener=listener_name, arch="x64", fmt=fmt
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

        print(f"  [{agent_type}][upload] uploading {len(upload_content)} bytes → {remote_upload_dst}")
        agent_upload(cli, agent_id, src=local_upload_src, dst=remote_upload_dst)
        print(f"  [{agent_type}][upload] upload command accepted")

        # Verify file appeared on target filesystem via SSH.
        print(f"  [{agent_type}][upload] verifying file on target via SSH (sha256sum)")
        remote_sha = run_remote(
            target, f"sha256sum {remote_upload_dst}", timeout=15
        ).split()[0]
        assert remote_sha == expected_sha256, (
            f"upload SHA-256 mismatch: expected {expected_sha256!r}, "
            f"got {remote_sha!r}"
        )
        print(f"  [{agent_type}][upload] SHA-256 verified: {remote_sha}")

        # ── Step 7: Download the uploaded file back ──────────────────────────
        print(f"  [{agent_type}][download] downloading {remote_upload_dst} → local")
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
            f"  [{agent_type}][download] round-trip verified: {downloaded_size} bytes, "
            f"SHA-256 {downloaded_sha256}"
        )

        # ── Step 8: Download a system file (/etc/hostname) ───────────────────
        print(f"  [{agent_type}][sysfile] downloading /etc/hostname via agent")
        agent_download(cli, agent_id, src="/etc/hostname", dst=local_sysfile_dst)

        assert os.path.exists(local_sysfile_dst), (
            "agent_download of /etc/hostname returned success but local file was not created"
        )
        sysfile_content = open(local_sysfile_dst, "rb").read()
        assert len(sysfile_content) > 0, (
            "downloaded /etc/hostname is empty — expected a non-empty hostname string"
        )
        hostname_str = sysfile_content.decode(errors="replace").strip()
        print(f"  [{agent_type}][sysfile] /etc/hostname content: {hostname_str!r} ({len(sysfile_content)} bytes)")

        print(f"  [{agent_type}][suite] all file-transfer checks passed")

    finally:
        # ── Step 9: Kill agent, stop listener, clean up ──────────────────────
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

        for path in (local_payload, local_upload_src, local_download_dst, local_sysfile_dst):
            try:
                os.unlink(path)
            except Exception:
                pass

        print(f"  [{agent_type}][cleanup] done")


def _parse_certutil_hash(output: str) -> str:
    """Extract the SHA-256 hex digest from certutil -hashfile output.

    certutil prints three lines:
      SHA256 hash of <file>:
      <64-char hex digest>
      CertUtil: -hashfile command completed successfully.
    """
    for line in output.splitlines():
        stripped = line.strip()
        if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
            return stripped.lower()
    raise ValueError(f"Could not extract SHA-256 from certutil output:\n{output!r}")


def _run_for_agent_windows(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full file-transfer suite for one Windows agent type.

    Args:
        ctx:         RunContext passed by the harness.
        agent_type:  Agent name passed to ``payload_build`` (e.g. ``"demon"``
                     or ``"specter"``).
        fmt:         Payload format (``"exe"``).
        name_prefix: Short prefix used to name the listener and remote files.

    Raises:
        AssertionError on test failure.
        CliError if the payload build fails (propagates as a scenario failure).
    """
    from lib.cli import (
        agent_download,
        agent_exec,
        agent_kill,
        agent_list,
        agent_upload,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        payload_build_and_fetch,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload
    from lib.wait import wait_for_agent

    cli = ctx.cli
    target = ctx.windows
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("windows_port", 19082)
    remote_payload = f"{target.work_dir}\\agent-{uid}.exe"

    # Collect pre-existing agent IDs so we can identify the new checkin.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    local_payload = tempfile.mktemp(suffix=f".{fmt}")
    local_upload_src = tempfile.mktemp(suffix=".dat")
    local_download_dst = tempfile.mktemp(suffix=".dat")
    local_sysfile_dst = tempfile.mktemp(suffix=".txt")

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [{agent_type}][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")

    agent_id = None
    try:
        # ── Step 2: Build agent payload ──────────────────────────────────────
        print(f"  [{agent_type}][payload] building {agent_type} {fmt} x64 for Windows target")
        raw = payload_build_and_fetch(
            cli, listener=listener_name, arch="x64", fmt=fmt
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

        # ── Step 6: Upload a known file ──────────────────────────────────────
        upload_content = (
            b"Red Cell C2 file-transfer test\n"
            + uid.encode() + b"\n"
            + b"x" * 4096  # 4 KiB padding to exercise chunked transfer
        )
        with open(local_upload_src, "wb") as fh:
            fh.write(upload_content)
        expected_sha256 = _sha256_bytes(upload_content)
        remote_upload_dst = f"{target.work_dir}\\uploaded-{uid}.dat"

        print(f"  [{agent_type}][upload] uploading {len(upload_content)} bytes → {remote_upload_dst}")
        agent_upload(cli, agent_id, src=local_upload_src, dst=remote_upload_dst)
        print(f"  [{agent_type}][upload] upload command accepted")

        # Verify file appeared on target via SSH + certutil.
        print(f"  [{agent_type}][upload] verifying file on target via SSH (certutil)")
        certutil_out = run_remote(
            target,
            f'certutil -hashfile "{remote_upload_dst}" SHA256',
            timeout=15,
        )
        remote_sha = _parse_certutil_hash(certutil_out)
        assert remote_sha == expected_sha256, (
            f"upload SHA-256 mismatch: expected {expected_sha256!r}, "
            f"got {remote_sha!r}"
        )
        print(f"  [{agent_type}][upload] SHA-256 verified: {remote_sha}")

        # ── Step 7: Download the uploaded file back ──────────────────────────
        print(f"  [{agent_type}][download] downloading {remote_upload_dst} → local")
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
            f"  [{agent_type}][download] round-trip verified: {downloaded_size} bytes, "
            f"SHA-256 {downloaded_sha256}"
        )

        # ── Step 8: Download a system file (C:\Windows\win.ini) ──────────────
        win_ini = r"C:\Windows\win.ini"
        print(f"  [{agent_type}][sysfile] downloading {win_ini} via agent")
        agent_download(cli, agent_id, src=win_ini, dst=local_sysfile_dst)

        assert os.path.exists(local_sysfile_dst), (
            f"agent_download of {win_ini} returned success but local file was not created"
        )
        sysfile_content = open(local_sysfile_dst, "rb").read()
        assert len(sysfile_content) > 0, (
            f"downloaded {win_ini} is empty — expected non-empty content"
        )
        print(f"  [{agent_type}][sysfile] {win_ini} content: {len(sysfile_content)} bytes")

        print(f"  [{agent_type}][suite] all file-transfer checks passed")

    finally:
        # ── Step 9: Kill agent, stop listener, clean up ──────────────────────
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
            run_remote(
                target,
                f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                timeout=15,
            )
        except Exception as exc:
            print(f"  [{agent_type}][cleanup] work_dir removal failed (non-fatal): {exc}")

        for path in (local_payload, local_upload_src, local_download_dst, local_sysfile_dst):
            try:
                os.unlink(path)
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
    Skips Linux passes when ctx.linux is None.
    Skips Windows passes when ctx.windows is None.
    """
    ran_any = False
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))

    if ctx.linux is not None:
        ran_any = True
        # ── Demon pass (primary Linux baseline) ─────────────────────────────
        print("\n  === Agent pass: demon (Linux) ===")
        _run_for_agent(ctx, agent_type="demon", fmt="bin", name_prefix="test-ftransfer-demon")

        # ── Phantom pass (Rust Linux agent) ─────────────────────────────────
        print("\n  === Agent pass: phantom (Linux) ===")
        if "phantom" not in available_agents:
            print("  [phantom] SKIPPED — 'phantom' not listed in agents.available")
        else:
            _run_for_agent(ctx, agent_type="phantom", fmt="bin", name_prefix="test-ftransfer-phantom")
    else:
        print("  [skip] ctx.linux is None — skipping Linux agent passes")

    if ctx.windows is not None:
        ran_any = True
        # ── Demon Windows pass ───────────────────────────────────────────────
        print("\n  === Agent pass: demon (Windows) ===")
        _run_for_agent_windows(ctx, agent_type="demon", fmt="exe", name_prefix="test-ftransfer-win-demon")

        # ── Specter pass (Rust Windows agent) ───────────────────────────────
        print("\n  === Agent pass: specter (Windows) ===")
        if "specter" not in available_agents:
            print("  [specter] SKIPPED — 'specter' not listed in agents.available")
        else:
            _run_for_agent_windows(ctx, agent_type="specter", fmt="exe", name_prefix="test-ftransfer-specter")
    else:
        print("  [skip] ctx.windows is None — skipping Windows agent passes")

    if not ran_any:
        raise ScenarioSkipped("neither ctx.linux nor ctx.windows is configured")
