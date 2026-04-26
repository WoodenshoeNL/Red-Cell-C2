"""
Scenario 05_agent_windows: Windows agent checkin

Deploy a Windows agent to Windows 11 via SSH, wait for checkin, run command suite.
Runs once for Demon (always).  The Archon and Specter passes run only when
``"archon"`` / ``"specter"`` is listed in ``agents.available`` in env.toml; if
one is listed and its payload build fails, the scenario fails so the regression
is caught.

All payloads are pre-built in parallel (when ``--no-parallel`` is not set) via
:func:`~lib.payload.build_parallel`.  Two separate HTTP listeners are created:
a Demon listener (legacy mode, DemonEnvelope header) and an Archon/Specter
listener (non-legacy, ArchonEnvelope + ECDH).  Each agent pass deploys + runs
the command suite sequentially.

Skip if ctx.windows is None.

Steps:
  0. Create Demon (legacy) and Archon/Specter (non-legacy) HTTP listeners;
     pre-build all needed payloads in parallel
  Per agent pass:
  1. Deploy pre-built payload via SSH/SCP to Windows 11 test machine
  2. Execute payload in background on target
  3. Wait for agent checkin
  4. Run command suite: whoami, dir C:\\, ipconfig, PowerShell, reg query,
     sc query, tasklist /m, netstat -ano, arp -a
  5. Kill agent, clean up work_dir on target
  Final: stop + delete both listeners
"""

DESCRIPTION = "Windows agent checkin (Demon + Archon + Specter)"

import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str,
                   *, listener_name: str, pre_built_payload: bytes) -> None:
    """Run the full Windows checkin suite for one agent type.

    Args:
        ctx:               RunContext passed by the harness.
        agent_type:        Agent name (e.g. ``"demon"``, ``"specter"``).
        fmt:               Payload format (e.g. ``"exe"``).
        listener_name:     Name of the pre-created, pre-started listener.
        pre_built_payload: Raw payload bytes from :func:`~lib.payload.build_parallel`.

    Raises:
        AssertionError on test failure.
    """
    from lib.cli import agent_exec, agent_kill
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.windows

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

        # ── Command suite ────────────────────────────────────────────────────

        # whoami → DOMAIN\username format
        print(f"  [{agent_type}][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=co)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert "\\" in whoami_out, (
            f"whoami output {whoami_out!r} does not contain '\\' "
            f"— expected DOMAIN\\username format"
        )
        print(f"  [{agent_type}][cmd] whoami passed: {whoami_out!r}")

        # dir C:\ → non-empty output
        print(f"  [{agent_type}][cmd] dir C:\\")
        result = agent_exec(cli, agent_id, "dir C:\\", wait=True, timeout=co)
        dir_out = result.get("output", "").strip()
        assert dir_out, "dir C:\\ returned empty output"
        print(f"  [{agent_type}][cmd] dir C:\\ passed ({len(dir_out.splitlines())} lines)")

        # ipconfig → contains 'IPv4 Address'
        print(f"  [{agent_type}][cmd] ipconfig")
        result = agent_exec(cli, agent_id, "ipconfig", wait=True, timeout=co)
        ipconfig_out = result.get("output", "").strip()
        assert ipconfig_out, "ipconfig returned empty output"
        assert "IPv4 Address" in ipconfig_out, (
            f"ipconfig output does not contain 'IPv4 Address':\n{ipconfig_out[:500]}"
        )
        print(f"  [{agent_type}][cmd] ipconfig passed")

        # PowerShell — distinct from cmd.exe
        print(f"  [{agent_type}][cmd] powershell Write-Output")
        result = agent_exec(
            cli,
            agent_id,
            'powershell -NoProfile -Command "Write-Output PS_MARKER_OK"',
            wait=True,
            timeout=co,
        )
        ps_out = result.get("output", "").strip()
        assert "PS_MARKER_OK" in ps_out, (
            f"PowerShell output missing marker: {ps_out[:500]!r}"
        )
        print(f"  [{agent_type}][cmd] powershell passed")

        # Registry read
        print(f"  [{agent_type}][cmd] reg query ProgramFilesDir")
        result = agent_exec(
            cli,
            agent_id,
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir',
            wait=True,
            timeout=co,
        )
        reg_out = result.get("output", "").strip()
        assert reg_out and (
            "ProgramFilesDir" in reg_out or "REG_" in reg_out
        ), f"unexpected reg query output: {reg_out[:500]!r}"
        print(f"  [{agent_type}][cmd] reg query passed")

        # Service enumeration
        print(f"  [{agent_type}][cmd] sc query eventlog")
        result = agent_exec(cli, agent_id, "sc query eventlog", wait=True, timeout=co)
        sc_out = result.get("output", "").strip()
        assert sc_out and "STATE" in sc_out.upper(), (
            f"sc query output missing STATE: {sc_out[:500]!r}"
        )
        print(f"  [{agent_type}][cmd] sc query passed")

        # Loaded modules
        print(f"  [{agent_type}][cmd] tasklist /m ntdll.dll")
        result = agent_exec(
            cli, agent_id, "tasklist /m ntdll.dll", wait=True, timeout=45
        )
        tlm_out = result.get("output", "").strip()
        assert tlm_out and "ntdll" in tlm_out.lower(), (
            f"tasklist /m output missing ntdll: {tlm_out[:500]!r}"
        )
        print(f"  [{agent_type}][cmd] tasklist /m passed")

        # TCP/UDP endpoints
        print(f"  [{agent_type}][cmd] netstat -ano")
        result = agent_exec(cli, agent_id, "netstat -ano", wait=True, timeout=45)
        ns_out = result.get("output", "").strip()
        assert ns_out and ("TCP" in ns_out or "UDP" in ns_out), (
            f"netstat output missing TCP/UDP table: {ns_out[:500]!r}"
        )
        print(f"  [{agent_type}][cmd] netstat -ano passed")

        # ARP cache
        print(f"  [{agent_type}][cmd] arp -a")
        result = agent_exec(cli, agent_id, "arp -a", wait=True, timeout=co)
        arp_out = result.get("output", "").strip()
        assert arp_out and (
            "Interface" in arp_out or "dynamic" in arp_out.lower() or "static" in arp_out.lower()
        ), f"arp output missing expected markers: {arp_out[:500]!r}"
        print(f"  [{agent_type}][cmd] arp -a passed")

        print(f"  [{agent_type}][suite] all commands passed")

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

        print(f"  [{agent_type}][cleanup] done")


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
    from lib.deploy import DeployError, preflight_ssh
    try:
        preflight_ssh(ctx.windows)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    from lib.cli import listener_create, listener_delete, listener_start, listener_stop
    from lib.listeners import http_listener_kwargs
    from lib.payload import MatrixCell, build_parallel

    cli = ctx.cli
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))

    has_archon = "archon" in available_agents
    has_specter = "specter" in available_agents

    uid = _short_id()
    listeners_cfg = ctx.env.get("listeners", {})
    listeners_to_cleanup: list[str] = []

    # ── Demon listener (legacy_mode — DemonEnvelope header) ──────────────────
    demon_listener_name = f"test-windows-demon-{uid}"
    demon_port = listeners_cfg.get("windows_demon_port", 19083)
    print(f"\n  [demon] creating HTTP listener {demon_listener_name!r} on port {demon_port}")
    listener_create(cli, demon_listener_name, "http",
                    **http_listener_kwargs(demon_port, ctx.env, agent_type="demon"))
    listener_start(cli, demon_listener_name)
    listeners_to_cleanup.append(demon_listener_name)

    # ── Archon/Specter listener (non-legacy — ArchonEnvelope + ECDH) ─────────
    archon_listener_name: str | None = None
    if has_archon or has_specter:
        archon_listener_name = f"test-windows-archon-{uid}"
        archon_port = listeners_cfg.get("windows_port", 19082)
        print(f"  [archon] creating HTTP listener {archon_listener_name!r} on port {archon_port}")
        listener_create(cli, archon_listener_name, "http",
                        **http_listener_kwargs(archon_port, ctx.env))
        listener_start(cli, archon_listener_name)
        listeners_to_cleanup.append(archon_listener_name)

    try:
        # ── Pre-build all payloads in parallel ───────────────────────────────
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

        # ── Demon pass (primary baseline) ────────────────────────────────────
        print("\n  === Agent pass: demon ===")
        _run_for_agent(ctx, agent_type="demon", fmt="exe",
                       listener_name=demon_listener_name,
                       pre_built_payload=payloads["demon"])

        # ── Archon pass (C/ASM fork of Demon, ECDH transport) ────────────────
        print("\n  === Agent pass: archon ===")
        if not has_archon:
            print("  [archon] SKIPPED — 'archon' not listed in agents.available")
        else:
            _run_for_agent(ctx, agent_type="archon", fmt="exe",
                           listener_name=archon_listener_name,
                           pre_built_payload=payloads["archon"])

        # ── Specter pass (Rust Windows agent) ────────────────────────────────
        print("\n  === Agent pass: specter ===")
        if not has_specter:
            print("  [specter] SKIPPED — 'specter' not listed in agents.available")
        else:
            _run_for_agent(ctx, agent_type="specter", fmt="exe",
                           listener_name=archon_listener_name,
                           pre_built_payload=payloads["specter"])

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
