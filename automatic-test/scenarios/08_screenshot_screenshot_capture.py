"""
Scenario 08_screenshot: Screenshot capture

Take a screenshot via agent and verify a loot entry of type 'screenshot' is
created, then download the bytes and validate the image header.

All payloads are pre-built in parallel (when ``--no-parallel`` is not set) via
:func:`~lib.payload.build_parallel`.  On Windows, two separate HTTP listeners
are created: a Demon listener (legacy mode, DemonEnvelope header) and an
Archon/Specter listener (non-legacy, ArchonEnvelope + ECDH).  On Linux, a
single listener is used.  Each agent pass deploys + captures sequentially.

Runs once per agent per target:
  - Windows target: Demon pass (always) + Archon pass (when ``"archon"``
    is listed in ``agents.available``) + Specter pass (when ``"specter"``
    is listed in ``agents.available`` in env.toml).
  - Linux target (only used when ctx.windows is None): Phantom pass (when
    ``"phantom"`` is listed in ``agents.available`` and the target has a
    usable DISPLAY/Xvfb).

Steps:
  0. Create Demon (legacy) and Archon/Specter (non-legacy) HTTP listeners
     (Windows) or a single listener (Linux); pre-build all needed payloads
     in parallel
  Per agent pass:
  1. Snapshot existing screenshot-loot IDs
  2. Deploy pre-built payload via SSH/SCP to the target
  3. Execute payload in background on target
  4. Wait for agent checkin
  5. Send screenshot command via agent exec
  6. Wait for a new loot entry of type 'screenshot' to appear
  7. Download screenshot bytes → verify PNG or BMP header
  8. Kill agent, clean up
  Final: stop + delete all listeners

Note: screenshot capture requires an active display session.  This scenario
targets the Windows test machine which runs an interactive user session.
Headless Linux targets are skipped unless ctx.linux is configured with an
Xvfb display (DISPLAY env var set in targets.toml).  For Linux, a pre-flight
``xdpyinfo`` over SSH runs before deploy so an idle DISPLAY does not produce
empty screenshots that slip past validation.

Skip if neither Windows nor a Linux-with-DISPLAY target is configured.
"""

DESCRIPTION = "Screenshot capture (Demon + Archon + Specter + Phantom)"

import os
import shlex
import tempfile
import uuid

from lib import ScenarioSkipped


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


def _preflight_linux_x11_display(target, display: str) -> None:
    """Verify DISPLAY is usable on the Linux target before deploying the agent.

    Runs ``xdpyinfo`` with ``DISPLAY`` set.  Raises :class:`ScenarioSkipped` when
    Xvfb (or another X server) is not listening — otherwise the agent can
    return an empty screenshot while the scenario still passes weaker checks.
    """
    from lib.deploy import DeployError, run_remote

    cmd = f"DISPLAY={shlex.quote(display)} xdpyinfo"
    try:
        run_remote(target, cmd, timeout=15)
    except DeployError as exc:
        raise ScenarioSkipped(
            f"DISPLAY {display} not available on target; "
            f"run Xvfb {display} -screen 0 1280x720x24 &"
        ) from exc


def _run_for_agent(
    ctx,
    target,
    agent_type: str,
    fmt: str,
    is_windows: bool,
    *,
    listener_name: str,
    pre_built_payload: bytes,
) -> None:
    """Run the full screenshot-capture suite for one agent type.

    Args:
        ctx:               RunContext passed by the harness.
        target:            The concrete target (windows or linux) to deploy to.
        agent_type:        Agent name (``"demon"``, ``"specter"`` or ``"phantom"``).
        fmt:               Payload format — always ``"exe"``.
        is_windows:        True when running against the Windows target.
        listener_name:     Name of the pre-created, pre-started listener.
        pre_built_payload: Raw payload bytes from :func:`~lib.payload.build_parallel`.

    Raises:
        AssertionError on test failure.
    """
    from lib.cli import (
        agent_exec,
        agent_kill,
        loot_download,
        loot_list,
    )
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin
    from lib.wait import poll

    cli = ctx.cli

    # Snapshot pre-existing screenshot loot IDs so this pass only picks up
    # entries it produced (prior passes in the same run will add to the set).
    try:
        pre_existing_loot_ids = {entry["id"] for entry in loot_list(cli, kind="screenshot")}
    except Exception:
        pre_existing_loot_ids = set()

    _fd, local_screenshot = tempfile.mkstemp(suffix=".png")
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

        # ── Send screenshot command ──────────────────────────────────────────
        print(f"  [{agent_type}][screenshot] sending screenshot command via agent exec")
        screenshot_result = agent_exec(cli, agent_id, "screenshot", wait=False)
        job_id = screenshot_result.get("job_id", "(unknown)")
        print(f"  [{agent_type}][screenshot] screenshot command queued, job_id={job_id!r}")

        # ── Wait for new loot entry of type screenshot ───────────────────────
        loot_timeout = int(ctx.timeouts.screenshot_loot)
        print(f"  [{agent_type}][wait] waiting up to {loot_timeout}s for screenshot loot entry")

        def _new_screenshot_loot():
            entries = loot_list(cli, kind="screenshot", agent_id=agent_id)
            return [e for e in entries if e["id"] not in pre_existing_loot_ids]

        new_loot = poll(
            fn=_new_screenshot_loot,
            predicate=lambda entries: len(entries) > 0,
            timeout=loot_timeout,
            description="screenshot loot entry",
        )
        loot_entry = new_loot[0]
        loot_id = loot_entry["id"]
        print(
            f"  [{agent_type}][loot] screenshot loot entry created: id={loot_id}, "
            f"name={loot_entry.get('name')!r}, "
            f"size={loot_entry.get('size_bytes')} bytes"
        )

        assert loot_entry["kind"] == "screenshot", (
            f"expected loot kind 'screenshot', got {loot_entry['kind']!r}"
        )
        loot_sz = loot_entry.get("size_bytes") or 0
        assert loot_sz > 0, (
            f"screenshot loot entry {loot_id} has empty or unknown size "
            f"(size_bytes={loot_entry.get('size_bytes')!r}); "
            "non-zero bytes are required to validate capture"
        )
        assert loot_entry.get("has_data", False), (
            f"loot entry {loot_id} has no binary data available for download"
        )

        # ── Download screenshot bytes and verify image header ────────────────
        print(f"  [{agent_type}][download] downloading loot #{loot_id} → {local_screenshot}")
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
            f"  [{agent_type}][download] verified {fmt_name} image header, "
            f"{file_size} bytes, loot id={loot_id}"
        )

        print(f"  [{agent_type}][suite] all screenshot checks passed")

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
            if is_windows:
                run_remote(
                    target,
                    f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                    timeout=15,
                )
            else:
                run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [{agent_type}][cleanup] work_dir removal failed (non-fatal): {exc}")

        try:
            os.unlink(local_screenshot)
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
    Skips silently when no suitable target is configured.
    """
    from lib.deploy import DeployError, preflight_ssh
    from lib.cli import listener_create, listener_delete, listener_start, listener_stop
    from lib.listeners import http_listener_kwargs
    from lib.payload import MatrixCell, build_parallel

    cli = ctx.cli
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    uid = _short_id()

    # Prefer Windows — it has an interactive display session by default.
    if ctx.windows is not None:
        try:
            preflight_ssh(ctx.windows)
        except DeployError as exc:
            raise ScenarioSkipped(str(exc)) from exc

        has_archon = "archon" in available_agents
        has_specter = "specter" in available_agents
        listeners_cfg = ctx.env.get("listeners", {})
        listeners_to_cleanup: list[str] = []

        # Demon listener (legacy_mode — DemonEnvelope header)
        demon_listener_name = f"test-screenshot-demon-{uid}"
        demon_port = listeners_cfg.get("windows_demon_port", 19083)
        print(f"\n  [demon] creating HTTP listener {demon_listener_name!r} on port {demon_port}")
        listener_create(cli, demon_listener_name, "http",
                        **http_listener_kwargs(demon_port, ctx.env, agent_type="demon"))
        listener_start(cli, demon_listener_name)
        listeners_to_cleanup.append(demon_listener_name)

        # Archon/Specter listener (non-legacy — ArchonEnvelope + ECDH)
        archon_listener_name: str | None = None
        if has_archon or has_specter:
            archon_listener_name = f"test-screenshot-archon-{uid}"
            archon_port = listeners_cfg.get("windows_port", 19082)
            print(f"  [archon] creating HTTP listener {archon_listener_name!r} on port {archon_port}")
            listener_create(cli, archon_listener_name, "http",
                            **http_listener_kwargs(archon_port, ctx.env))
            listener_start(cli, archon_listener_name)
            listeners_to_cleanup.append(archon_listener_name)

        try:
            # ── Pre-build all payloads in parallel ───────────────────────────
            cells: list[MatrixCell] = [
                MatrixCell(arch="x64", fmt="exe", agent="demon",
                           listener=demon_listener_name),
            ]
            cell_keys: list[str] = ["demon"]
            if has_archon:
                cells.append(MatrixCell(arch="x64", fmt="exe", agent="archon",
                                        listener=archon_listener_name))
                cell_keys.append("archon")
            if has_specter:
                cells.append(MatrixCell(arch="x64", fmt="exe", agent="specter",
                                        listener=archon_listener_name))
                cell_keys.append("specter")

            mode = "parallel" if ctx.payload_parallel else "serial"
            print(f"  [shared] building {len(cells)} payload(s) ({mode})")
            raws = build_parallel(cli, "", cells, parallel=ctx.payload_parallel)
            payloads = dict(zip(cell_keys, raws))

            # ── Demon pass (primary Windows baseline) ────────────────────────
            print("\n  === Agent pass: demon (Windows) ===")
            _run_for_agent(
                ctx, ctx.windows,
                agent_type="demon", fmt="exe", is_windows=True,
                listener_name=demon_listener_name,
                pre_built_payload=payloads["demon"],
            )

            # ── Archon pass ──────────────────────────────────────────────────
            print("\n  === Agent pass: archon (Windows) ===")
            if not has_archon:
                print("  [archon] SKIPPED — 'archon' not listed in agents.available")
            else:
                _run_for_agent(
                    ctx, ctx.windows,
                    agent_type="archon", fmt="exe", is_windows=True,
                    listener_name=archon_listener_name,
                    pre_built_payload=payloads["archon"],
                )

            # ── Specter pass ─────────────────────────────────────────────────
            print("\n  === Agent pass: specter (Windows) ===")
            if not has_specter:
                print("  [specter] SKIPPED — 'specter' not listed in agents.available")
            else:
                _run_for_agent(
                    ctx, ctx.windows,
                    agent_type="specter", fmt="exe", is_windows=True,
                    listener_name=archon_listener_name,
                    pre_built_payload=payloads["specter"],
                )

        finally:
            for name in listeners_to_cleanup:
                print(f"\n  [shared] stopping/deleting listener {name!r}")
                try:
                    listener_stop(cli, name)
                except Exception:
                    pass
                try:
                    listener_delete(cli, name)
                except Exception:
                    pass
        return

    # Linux fallback — only attempt with a configured DISPLAY.
    if ctx.linux is not None:
        display = getattr(ctx.linux, "display", None) or ctx.env.get("linux", {}).get("display")
        if not display:
            raise ScenarioSkipped(
                "no suitable screenshot target configured — "
                "need Windows target or Linux with DISPLAY/Xvfb"
            )
        if "phantom" not in available_agents:
            raise ScenarioSkipped(
                "Linux screenshot target selected but Demon is Windows-only; "
                "add 'phantom' to agents.available in env.toml"
            )
        try:
            preflight_ssh(ctx.linux)
        except DeployError as exc:
            raise ScenarioSkipped(str(exc)) from exc
        _preflight_linux_x11_display(ctx.linux, display)

        listener_name = f"test-screenshot-lin-{uid}"
        linux_port = ctx.env.get("listeners", {}).get("linux_port", 19081)

        print(f"\n  [shared] creating HTTP listener {listener_name!r} on port {linux_port}")
        listener_create(cli, listener_name, "http", **http_listener_kwargs(linux_port, ctx.env))
        listener_start(cli, listener_name)
        print(f"  [shared] listener started")

        try:
            cells = [MatrixCell(arch="x64", fmt="exe", agent="phantom")]
            mode = "parallel" if ctx.payload_parallel else "serial"
            print(f"  [shared] building 1 payload ({mode})")
            raws = build_parallel(cli, listener_name, cells, parallel=ctx.payload_parallel)

            print("\n  === Agent pass: phantom (Linux) ===")
            _run_for_agent(
                ctx, ctx.linux,
                agent_type="phantom", fmt="exe", is_windows=False,
                listener_name=listener_name,
                pre_built_payload=raws[0],
            )
        finally:
            print(f"\n  [shared] stopping/deleting listener {listener_name!r}")
            try:
                listener_stop(cli, listener_name)
            except Exception:
                pass
            try:
                listener_delete(cli, listener_name)
            except Exception:
                pass
        return

    raise ScenarioSkipped(
        "no suitable screenshot target configured — "
        "need Windows target or Linux with DISPLAY/Xvfb"
    )
