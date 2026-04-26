"""
Scenario 06_file_transfer: File transfer

Upload and download files through an active agent.

Linux passes (Phantom elf): upload/download/SHA-256 against Linux target.
Windows passes (Demon exe + Archon exe + Specter exe): same operations against
Windows 11 target.

Phantom/Archon/Specter passes run only when listed in ``agents.available`` in env.toml;
build failures for listed agents fail the scenario instead of silently skipping.

All payloads are pre-built in parallel (when ``--no-parallel`` is not set) via
:func:`~lib.payload.build_parallel` against shared per-platform listeners, then each
agent pass deploys + runs the file-transfer suite sequentially.

Steps:
  0. Create shared HTTP listener(s); pre-build all needed payloads in parallel
  Per agent pass (Linux):
  1. Deploy pre-built payload via SSH/SCP to Linux test machine
  2. Execute payload in background on target
  3. Wait for agent checkin
  4. Upload a known file → verify it appears on target filesystem via SHA-256
  5. Download the uploaded file back → verify contents match original (SHA-256)
  6. Download a system file (/etc/hostname) → verify non-empty bytes
  7. Kill agent, clean up
  Per agent pass (Windows):
  Same as above, adapted for Windows paths, certutil SHA-256, and
  C:\\Windows\\win.ini as the system file.
  Final: stop + delete shared listener(s)
"""

DESCRIPTION = "File transfer (Demon + Archon + Phantom + Specter)"

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


def _run_for_agent(ctx, agent_type: str, fmt: str,
                   *, listener_name: str, pre_built_payload: bytes) -> None:
    """Run the full file-transfer suite for one Linux agent type.

    Args:
        ctx:               RunContext passed by the harness.
        agent_type:        Agent name (e.g. ``"phantom"``).
        fmt:               Payload format (``"exe"``).
        listener_name:     Name of the pre-created, pre-started listener.
        pre_built_payload: Raw payload bytes from :func:`~lib.payload.build_parallel`.

    Raises:
        AssertionError on test failure.
    """
    from lib.cli import (
        agent_download,
        agent_exec,
        agent_kill,
        agent_upload,
    )
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.linux
    uid = _short_id()

    _fd, local_upload_src = tempfile.mkstemp(suffix=".dat")
    os.close(_fd)
    _fd, local_download_dst = tempfile.mkstemp(suffix=".dat")
    os.close(_fd)
    _fd, local_sysfile_dst = tempfile.mkstemp(suffix=".txt")
    os.close(_fd)

    agent_id = None
    try:
        # ── Deploy, exec, wait for checkin ───────────────────────────────────
        agent = deploy_and_checkin(
            ctx, cli, target,
            agent_type=agent_type, fmt=fmt,
            listener_name=listener_name,
            label=agent_type,
            pre_built_payload=pre_built_payload,
        )
        agent_id = agent["id"]

        # ── Upload a known file ──────────────────────────────────────────────
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

        # ── Download the uploaded file back ──────────────────────────────────
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

        # ── Download a system file (/etc/hostname) ───────────────────────────
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

        # Permissions + long listing on the uploaded path (agent exec coverage)
        print(f"  [{agent_type}][perm] stat uploaded file")
        st = agent_exec(
            cli, agent_id, f"stat -c '%a %n' {remote_upload_dst}", wait=True, timeout=co
        ).get("output", "").strip()
        assert st and remote_upload_dst.split("/")[-1] in st, (
            f"stat of upload path failed or unexpected: {st!r}"
        )
        print(f"  [{agent_type}][perm] stat ok: {st!r}")
        print(f"  [{agent_type}][perm] ls -la work dir (head)")
        ls_agent = agent_exec(
            cli,
            agent_id,
            f"ls -la {target.work_dir} | head -n 30",
            wait=True,
            timeout=co,
        ).get("output", "").strip()
        assert ls_agent and "uploaded-" in ls_agent, (
            f"ls -la did not list uploaded artifact: {ls_agent[:400]!r}"
        )
        print(f"  [{agent_type}][perm] ls -la ok ({len(ls_agent.splitlines())} lines)")

        print(f"  [{agent_type}][suite] all file-transfer checks passed")

    finally:
        # ── Kill agent, clean up ─────────────────────────────────────────────
        if agent_id:
            print(f"  [{agent_type}][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] removing work_dir on target")
        try:
            run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [{agent_type}][cleanup] work_dir removal failed (non-fatal): {exc}")

        for path in (local_upload_src, local_download_dst, local_sysfile_dst):
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


def _run_for_agent_windows(ctx, agent_type: str, fmt: str,
                           *, listener_name: str, pre_built_payload: bytes) -> None:
    """Run the full file-transfer suite for one Windows agent type.

    Args:
        ctx:               RunContext passed by the harness.
        agent_type:        Agent name (e.g. ``"demon"``, ``"specter"``).
        fmt:               Payload format (``"exe"``).
        listener_name:     Name of the pre-created, pre-started listener.
        pre_built_payload: Raw payload bytes from :func:`~lib.payload.build_parallel`.

    Raises:
        AssertionError on test failure.
    """
    from lib.cli import (
        agent_download,
        agent_exec,
        agent_kill,
        agent_upload,
    )
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.windows
    uid = _short_id()

    _fd, local_upload_src = tempfile.mkstemp(suffix=".dat")
    os.close(_fd)
    _fd, local_download_dst = tempfile.mkstemp(suffix=".dat")
    os.close(_fd)
    _fd, local_sysfile_dst = tempfile.mkstemp(suffix=".txt")
    os.close(_fd)

    agent_id = None
    try:
        # ── Deploy, exec, wait for checkin ───────────────────────────────────
        agent = deploy_and_checkin(
            ctx, cli, target,
            agent_type=agent_type, fmt=fmt,
            listener_name=listener_name,
            label=agent_type,
            pre_built_payload=pre_built_payload,
        )
        agent_id = agent["id"]

        # ── Upload a known file ──────────────────────────────────────────────
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

        # ── Download the uploaded file back ──────────────────────────────────
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

        # ── Download a system file (C:\Windows\win.ini) ──────────────────────
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

        print(f"  [{agent_type}][perm] dir uploaded file")
        dir_line = agent_exec(
            cli,
            agent_id,
            f'dir /B "{remote_upload_dst}"',
            wait=True,
            timeout=co,
        ).get("output", "").strip()
        assert dir_line and "uploaded-" in dir_line, (
            f"dir did not show uploaded file: {dir_line[:400]!r}"
        )
        print(f"  [{agent_type}][perm] dir ok")

        print(f"  [{agent_type}][suite] all file-transfer checks passed")

    finally:
        # ── Kill agent, clean up ─────────────────────────────────────────────
        if agent_id:
            print(f"  [{agent_type}][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] removing work_dir on target")
        try:
            run_remote(
                target,
                f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                timeout=15,
            )
        except Exception as exc:
            print(f"  [{agent_type}][cleanup] work_dir removal failed (non-fatal): {exc}")

        for path in (local_upload_src, local_download_dst, local_sysfile_dst):
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
    skipped_reasons: list[str] = []
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    from lib.deploy import DeployError, preflight_ssh
    from lib.cli import listener_create, listener_delete, listener_start, listener_stop
    from lib.listeners import http_listener_kwargs
    from lib.payload import MatrixCell, build_parallel

    cli = ctx.cli
    uid = _short_id()
    listeners_to_cleanup: list[str] = []

    # ── Determine which agents and platforms will run ────────────────────────
    linux_ok = False
    if ctx.linux is not None:
        try:
            preflight_ssh(ctx.linux)
            linux_ok = True
        except DeployError as exc:
            raise ScenarioSkipped(str(exc)) from exc
    else:
        print("  [skip] ctx.linux is None — skipping Linux agent passes")

    windows_ok = False
    if ctx.windows is not None:
        try:
            preflight_ssh(ctx.windows)
            windows_ok = True
        except DeployError as exc:
            raise ScenarioSkipped(str(exc)) from exc
    else:
        print("  [skip] ctx.windows is None — skipping Windows agent passes")

    linux_listener_name = None
    windows_listener_name = None
    linux_has_phantom = linux_ok and "phantom" in available_agents

    # ── Build the cell list for all agents across both platforms ─────────────
    cells: list[MatrixCell] = []
    cell_keys: list[str] = []

    if linux_has_phantom:
        linux_listener_name = f"test-ftransfer-lin-{uid}"
        linux_port = ctx.env.get("listeners", {}).get("linux_port", 19081)
        print(f"\n  [shared] creating Linux HTTP listener {linux_listener_name!r} on port {linux_port}")
        listener_create(cli, linux_listener_name, "http", **http_listener_kwargs(linux_port, ctx.env))
        listener_start(cli, linux_listener_name)
        listeners_to_cleanup.append(linux_listener_name)
        cells.append(MatrixCell(arch="x64", fmt="exe", agent="phantom",
                                listener=linux_listener_name))
        cell_keys.append("phantom")

    win_agents: list[tuple[str, str]] = []
    if windows_ok:
        win_agents.append(("demon", "exe"))
        if "archon" in available_agents:
            win_agents.append(("archon", "exe"))
        if "specter" in available_agents:
            win_agents.append(("specter", "exe"))
        windows_listener_name = f"test-ftransfer-win-{uid}"
        win_port = ctx.env.get("listeners", {}).get("windows_port", 19082)
        print(f"  [shared] creating Windows HTTP listener {windows_listener_name!r} on port {win_port}")
        listener_create(cli, windows_listener_name, "http", **http_listener_kwargs(win_port, ctx.env))
        listener_start(cli, windows_listener_name)
        listeners_to_cleanup.append(windows_listener_name)
        for at, fmt in win_agents:
            cells.append(MatrixCell(arch="x64", fmt=fmt, agent=at,
                                    listener=windows_listener_name))
            cell_keys.append(at)

    if not cells:
        if skipped_reasons:
            raise ScenarioSkipped("; ".join(skipped_reasons))
        raise ScenarioSkipped("neither ctx.linux nor ctx.windows is configured")

    try:
        # ── Pre-build all payloads in parallel ───────────────────────────────
        mode = "parallel" if ctx.payload_parallel else "serial"
        print(f"  [shared] building {len(cells)} payload(s) ({mode})")
        raws = build_parallel(cli, "", cells, parallel=ctx.payload_parallel)
        payloads = dict(zip(cell_keys, raws))

        # ── Linux passes ─────────────────────────────────────────────────────
        if linux_ok:
            print("\n  === Agent pass: phantom (Linux) ===")
            if not linux_has_phantom:
                print(
                    "  [phantom] SKIPPED — Demon is Windows-only; "
                    "add 'phantom' to agents.available in env.toml"
                )
                skipped_reasons.append(
                    "Linux target configured but no available Linux agent"
                    " (add 'phantom' to agents.available)"
                )
            else:
                _run_for_agent(ctx, agent_type="phantom", fmt="exe",
                               listener_name=linux_listener_name,
                               pre_built_payload=payloads["phantom"])
                ran_any = True

        # ── Windows passes ───────────────────────────────────────────────────
        if windows_ok:
            ran_any = True
            print("\n  === Agent pass: demon (Windows) ===")
            _run_for_agent_windows(ctx, agent_type="demon", fmt="exe",
                                   listener_name=windows_listener_name,
                                   pre_built_payload=payloads["demon"])

            print("\n  === Agent pass: archon (Windows) ===")
            if "archon" not in available_agents:
                print("  [archon] SKIPPED — 'archon' not listed in agents.available")
            else:
                _run_for_agent_windows(ctx, agent_type="archon", fmt="exe",
                                       listener_name=windows_listener_name,
                                       pre_built_payload=payloads["archon"])

            print("\n  === Agent pass: specter (Windows) ===")
            if "specter" not in available_agents:
                print("  [specter] SKIPPED — 'specter' not listed in agents.available")
            else:
                _run_for_agent_windows(ctx, agent_type="specter", fmt="exe",
                                       listener_name=windows_listener_name,
                                       pre_built_payload=payloads["specter"])

        if not ran_any:
            if skipped_reasons:
                raise ScenarioSkipped("; ".join(skipped_reasons))
            raise ScenarioSkipped("neither ctx.linux nor ctx.windows is configured")

    finally:
        for name in listeners_to_cleanup:
            print(f"  [shared] stopping/deleting listener {name!r}")
            try:
                listener_stop(cli, name)
            except Exception:
                pass
            try:
                listener_delete(cli, name)
            except Exception:
                pass
