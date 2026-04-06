"""
Scenario 05_agent_windows: Windows agent checkin

Deploy a Windows agent to Windows 11 via SSH, wait for checkin, run command suite.
Runs once for Demon (always).  The Specter pass runs only when
``"specter"`` is listed in ``agents.available`` in env.toml; if it is listed
and the payload build fails, the scenario fails so the regression is caught.

Skip if ctx.windows is None.

Steps (per agent pass):
  1. Create + start HTTP listener
  2. Build agent payload (EXE x64) for Windows target
  3. Deploy via SSH/SCP to Windows 11 test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Run command suite: whoami, dir C:\\, ipconfig, PowerShell, reg query,
     sc query, tasklist /m, netstat -ano, arp -a
  7. Kill agent, stop listener, clean up work_dir on target
"""

DESCRIPTION = "Windows agent checkin (Demon + Specter)"

import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full Windows checkin suite for one agent type.

    Args:
        ctx:         RunContext passed by the harness.
        agent_type:  Agent name passed to ``payload_build`` (e.g. ``"demon"``
                     or ``"specter"``).
        fmt:         Payload format (e.g. ``"exe"``).
        name_prefix: Short prefix used to name the listener and remote files.

    Raises:
        AssertionError on test failure.
        CliError if the payload build fails (propagates as a scenario failure).
    """
    from lib.cli import (
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin

    cli = ctx.cli
    target = ctx.windows
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("windows_port", 19082)

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [{agent_type}][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")

    agent_id = None
    try:
        # ── Steps 2-5: Build, deploy, exec, wait for checkin ─────────────────
        agent = deploy_and_checkin(
            ctx, cli, target,
            agent_type=agent_type, fmt=fmt,
            listener_name=listener_name,
            label=agent_type,
        )
        agent_id = agent["id"]

        # ── Step 6: Command suite ────────────────────────────────────────────

        # whoami → DOMAIN\username format
        print(f"  [{agent_type}][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=30)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert "\\" in whoami_out, (
            f"whoami output {whoami_out!r} does not contain '\\' "
            f"— expected DOMAIN\\username format"
        )
        print(f"  [{agent_type}][cmd] whoami passed: {whoami_out!r}")

        # dir C:\ → non-empty output
        print(f"  [{agent_type}][cmd] dir C:\\")
        result = agent_exec(cli, agent_id, "dir C:\\", wait=True, timeout=30)
        dir_out = result.get("output", "").strip()
        assert dir_out, "dir C:\\ returned empty output"
        print(f"  [{agent_type}][cmd] dir C:\\ passed ({len(dir_out.splitlines())} lines)")

        # ipconfig → contains 'IPv4 Address'
        print(f"  [{agent_type}][cmd] ipconfig")
        result = agent_exec(cli, agent_id, "ipconfig", wait=True, timeout=30)
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
            timeout=30,
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
            timeout=30,
        )
        reg_out = result.get("output", "").strip()
        assert reg_out and (
            "ProgramFilesDir" in reg_out or "REG_" in reg_out
        ), f"unexpected reg query output: {reg_out[:500]!r}"
        print(f"  [{agent_type}][cmd] reg query passed")

        # Service enumeration
        print(f"  [{agent_type}][cmd] sc query eventlog")
        result = agent_exec(cli, agent_id, "sc query eventlog", wait=True, timeout=30)
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
        result = agent_exec(cli, agent_id, "arp -a", wait=True, timeout=30)
        arp_out = result.get("output", "").strip()
        assert arp_out and (
            "Interface" in arp_out or "dynamic" in arp_out.lower() or "static" in arp_out.lower()
        ), f"arp output missing expected markers: {arp_out[:500]!r}"
        print(f"  [{agent_type}][cmd] arp -a passed")

        print(f"  [{agent_type}][suite] all commands passed")

    finally:
        # ── Step 7: Kill agent, stop listener, clean up ──────────────────────
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

    # ── Demon pass (primary baseline) ───────────────────────────────────────
    print("\n  === Agent pass: demon ===")
    _run_for_agent(ctx, agent_type="demon", fmt="exe", name_prefix="test-windows-demon")

    # ── Specter pass (Rust Windows agent) ───────────────────────────────────
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    print("\n  === Agent pass: specter ===")
    if "specter" not in available_agents:
        print("  [specter] SKIPPED — 'specter' not listed in agents.available")
    else:
        _run_for_agent(ctx, agent_type="specter", fmt="exe", name_prefix="test-windows-specter")
