"""
Scenario 07_process_ops: Process operations

Linux passes (Phantom elf): process list, spawn, kill, and verify
against Linux target via ``ps`` / ``kill``.

Windows passes (Demon exe + Archon exe + Specter exe): same operations against
Windows 11 target via ``tasklist`` / ``taskkill``.

Phantom/Archon/Specter passes run only when listed in ``agents.available`` in env.toml;
build failures for listed agents fail the scenario instead of silently skipping.

All payloads are pre-built in parallel (when ``--no-parallel`` is not set) via
:func:`~lib.payload.build_parallel` against shared per-platform listeners, then each
agent pass deploys + runs the process-operations suite sequentially.

Steps:
  0. Create shared HTTP listener(s); pre-build all needed payloads in parallel
  Per agent pass (Linux):
  1. Deploy pre-built payload via SSH/SCP to Linux test machine
  2. Execute payload in background on target
  3. Wait for agent checkin
  4. List processes via agent → verify known system process (sshd) is present
  5. Spawn a long-running test process on target via SSH → record its PID
  6. Kill the test process via agent exec
  7. Verify the killed PID no longer appears in the process list
  8. Kill agent, clean up
  Per agent pass (Windows):
  Same as above, using tasklist / taskkill and svchost.exe as the known
  system process.
  Final: stop + delete shared listener(s)
"""

DESCRIPTION = "Process operations (Demon + Archon + Phantom + Specter)"

import time
import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str,
                   *, listener_name: str, pre_built_payload: bytes) -> None:
    """Run the full process-operations suite for one Linux agent type.

    Args:
        ctx:               RunContext passed by the harness.
        agent_type:        Agent name (e.g. ``"phantom"``).
        fmt:               Payload format (``"exe"``).
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
    ssh = int(ctx.timeouts.ssh_connect)
    target = ctx.linux

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

        # ── List processes via agent ─────────────────────────────────────────
        print(f"  [{agent_type}][ps] listing processes via agent exec")
        ps_result = agent_exec(cli, agent_id, "ps aux", wait=True, timeout=co)
        ps_output = ps_result.get("output", "")
        assert ps_output, "ps aux returned empty output"

        # sshd should be running on any standard Linux SSH target
        assert "sshd" in ps_output, (
            "expected 'sshd' in process list but it was not found.\n"
            f"  ps output (first 500 chars): {ps_output[:500]!r}"
        )
        print(f"  [{agent_type}][ps] process list received ({len(ps_output)} chars), 'sshd' confirmed present")

        # Listening sockets (agent-side network introspection)
        print(f"  [{agent_type}][net] ss -tln (head)")
        ss_result = agent_exec(
            cli, agent_id, "ss -tln 2>/dev/null | head -n 40", wait=True, timeout=co
        )
        ss_out = ss_result.get("output", "").strip()
        assert ss_out and len(ss_out) > 5, (
            f"ss output unexpectedly short: {ss_out!r}"
        )
        print(f"  [{agent_type}][net] ss table non-empty ({len(ss_out)} chars)")

        # ── Spawn a test process on target via SSH ───────────────────────────
        print(f"  [{agent_type}][spawn] starting sleep process on target via SSH")
        pid_str = run_remote(
            target,
            f"bash -c 'sleep 9999 & echo $!'",
            timeout=ssh,
        ).strip()
        assert pid_str.isdigit(), (
            f"expected a numeric PID from spawn command, got: {pid_str!r}"
        )
        sleep_pid = int(pid_str)
        print(f"  [{agent_type}][spawn] sleep process started, PID={sleep_pid}")

        # Verify it's actually running (sanity check via SSH).
        ps_check = run_remote(target, f"ps -p {sleep_pid} -o pid= 2>/dev/null || true", timeout=ssh)
        assert ps_check.strip() == str(sleep_pid), (
            f"sleep process PID {sleep_pid} not found in ps immediately after spawn"
        )
        print(f"  [{agent_type}][spawn] confirmed PID {sleep_pid} is running on target")

        # ── Kill the test process via agent ──────────────────────────────────
        print(f"  [{agent_type}][kill] sending 'kill {sleep_pid}' via agent exec")
        kill_result = agent_exec(cli, agent_id, f"kill {sleep_pid}", wait=True, timeout=15)
        print(f"  [{agent_type}][kill] kill command dispatched, output: {kill_result.get('output', '(none)')!r}")

        # Give the process a moment to die.
        time.sleep(1)

        # ── Verify the killed PID is gone ────────────────────────────────────
        print(f"  [{agent_type}][verify] checking that PID {sleep_pid} is no longer running")
        pid_check = run_remote(
            target,
            f"ps -p {sleep_pid} -o pid= 2>/dev/null || true",
            timeout=ssh,
        ).strip()
        assert pid_check == "", (
            f"process PID {sleep_pid} is still running after kill — "
            f"ps output: {pid_check!r}"
        )
        print(f"  [{agent_type}][verify] PID {sleep_pid} is no longer present in process list — kill confirmed")

        # Also verify via agent ps aux: the killed PID should be absent.
        ps_after_result = agent_exec(cli, agent_id, f"ps -p {sleep_pid}", wait=True, timeout=15)
        ps_after_output = ps_after_result.get("output", "")
        assert str(sleep_pid) not in ps_after_output, (
            f"PID {sleep_pid} still visible in agent ps output after kill: "
            f"{ps_after_output!r}"
        )
        print(f"  [{agent_type}][verify] agent ps confirms PID is absent")

        print(f"  [{agent_type}][suite] all process-operations checks passed")

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

        print(f"  [{agent_type}][cleanup] done")


def _run_for_agent_windows(ctx, agent_type: str, fmt: str,
                           *, listener_name: str, pre_built_payload: bytes) -> None:
    """Run the full process-operations suite for one Windows agent type.

    Args:
        ctx:               RunContext passed by the harness.
        agent_type:        Agent name (e.g. ``"demon"``, ``"specter"``).
        fmt:               Payload format (``"exe"``).
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
    ssh = int(ctx.timeouts.ssh_connect)
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

        # ── List processes via agent ─────────────────────────────────────────
        print(f"  [{agent_type}][ps] listing processes via agent exec (tasklist)")
        ps_result = agent_exec(cli, agent_id, "tasklist", wait=True, timeout=co)
        ps_output = ps_result.get("output", "")
        assert ps_output, "tasklist returned empty output"

        # svchost.exe is always running on any standard Windows target.
        assert "svchost.exe" in ps_output, (
            "expected 'svchost.exe' in process list but it was not found.\n"
            f"  tasklist output (first 500 chars): {ps_output[:500]!r}"
        )
        print(f"  [{agent_type}][ps] process list received ({len(ps_output)} chars), 'svchost.exe' confirmed present")

        print(f"  [{agent_type}][mod] tasklist /m ntdll.dll (sample)")
        tlm = agent_exec(
            cli, agent_id, "tasklist /m ntdll.dll", wait=True, timeout=45
        ).get("output", "").strip()
        assert tlm and "ntdll" in tlm.lower(), (
            f"tasklist /m output missing ntdll: {tlm[:400]!r}"
        )
        print(f"  [{agent_type}][mod] tasklist /m ok")

        print(f"  [{agent_type}][net] netstat -ano")
        ns = agent_exec(cli, agent_id, "netstat -ano", wait=True, timeout=45).get(
            "output", ""
        ).strip()
        assert ns and ("TCP" in ns or "UDP" in ns), (
            f"netstat output missing protocol table: {ns[:400]!r}"
        )
        print(f"  [{agent_type}][net] netstat ok ({len(ns)} chars)")

        # ── Spawn a test process on target via SSH ───────────────────────────
        print(f"  [{agent_type}][spawn] starting sleep process on target via SSH")
        pid_str = run_remote(
            target,
            (
                'powershell -Command "'
                "$p = Start-Process -PassThru -WindowStyle Hidden powershell "
                "-ArgumentList '-Command','Start-Sleep 9999'; "
                '$p.Id"'
            ),
            timeout=15,
        ).strip()
        assert pid_str.isdigit(), (
            f"expected a numeric PID from spawn command, got: {pid_str!r}"
        )
        sleep_pid = int(pid_str)
        print(f"  [{agent_type}][spawn] sleep process started, PID={sleep_pid}")

        # Verify it's actually running (sanity check via SSH).
        ps_check = run_remote(
            target,
            f'tasklist /FI "PID eq {sleep_pid}" /FO CSV /NH 2>NUL',
            timeout=ssh,
        )
        assert str(sleep_pid) in ps_check, (
            f"sleep process PID {sleep_pid} not found in tasklist immediately after spawn;\n"
            f"  tasklist output: {ps_check!r}"
        )
        print(f"  [{agent_type}][spawn] confirmed PID {sleep_pid} is running on target")

        # ── Kill the test process via agent ──────────────────────────────────
        print(f"  [{agent_type}][kill] sending 'taskkill /PID {sleep_pid} /F' via agent exec")
        kill_result = agent_exec(
            cli, agent_id, f"taskkill /PID {sleep_pid} /F", wait=True, timeout=15
        )
        print(f"  [{agent_type}][kill] kill command dispatched, output: {kill_result.get('output', '(none)')!r}")

        # Give the process a moment to die.
        time.sleep(1)

        # ── Verify the killed PID is gone ────────────────────────────────────
        print(f"  [{agent_type}][verify] checking that PID {sleep_pid} is no longer running")
        pid_check = run_remote(
            target,
            f'tasklist /FI "PID eq {sleep_pid}" /FO CSV /NH 2>NUL',
            timeout=ssh,
        ).strip()
        assert str(sleep_pid) not in pid_check, (
            f"process PID {sleep_pid} is still running after taskkill — "
            f"tasklist output: {pid_check!r}"
        )
        print(f"  [{agent_type}][verify] PID {sleep_pid} is no longer present in process list — kill confirmed")

        # Also verify via agent tasklist: the killed PID should be absent.
        ps_after_result = agent_exec(
            cli, agent_id, f"tasklist /FI \"PID eq {sleep_pid}\"", wait=True, timeout=15
        )
        ps_after_output = ps_after_result.get("output", "")
        assert str(sleep_pid) not in ps_after_output, (
            f"PID {sleep_pid} still visible in agent tasklist output after kill: "
            f"{ps_after_output!r}"
        )
        print(f"  [{agent_type}][verify] agent tasklist confirms PID is absent")

        print(f"  [{agent_type}][suite] all process-operations checks passed")

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
    demon_listener_name: str | None = None
    archon_listener_name: str | None = None
    linux_has_phantom = linux_ok and "phantom" in available_agents
    has_archon = "archon" in available_agents
    has_specter = "specter" in available_agents
    listeners_cfg = ctx.env.get("listeners", {})

    # ── Build the cell list for all agents across both platforms ─────────────
    cells: list[MatrixCell] = []
    cell_keys: list[str] = []

    if linux_has_phantom:
        linux_listener_name = f"test-procops-lin-{uid}"
        linux_port = listeners_cfg.get("linux_port", 19081)
        print(f"\n  [shared] creating Linux HTTP listener {linux_listener_name!r} on port {linux_port}")
        listener_create(cli, linux_listener_name, "http", **http_listener_kwargs(linux_port, ctx.env))
        listener_start(cli, linux_listener_name)
        listeners_to_cleanup.append(linux_listener_name)
        cells.append(MatrixCell(arch="x64", fmt="exe", agent="phantom",
                                listener=linux_listener_name))
        cell_keys.append("phantom")

    if windows_ok:
        # Demon listener (legacy_mode — DemonEnvelope header)
        demon_listener_name = f"test-procops-demon-{uid}"
        demon_port = listeners_cfg.get("windows_demon_port", 19083)
        print(f"\n  [demon] creating HTTP listener {demon_listener_name!r} on port {demon_port}")
        listener_create(cli, demon_listener_name, "http",
                        **http_listener_kwargs(demon_port, ctx.env, agent_type="demon"))
        listener_start(cli, demon_listener_name)
        listeners_to_cleanup.append(demon_listener_name)
        cells.append(MatrixCell(arch="x64", fmt="exe", agent="demon",
                                listener=demon_listener_name))
        cell_keys.append("demon")

        # Archon/Specter listener (non-legacy — ArchonEnvelope + ECDH)
        if has_archon or has_specter:
            archon_listener_name = f"test-procops-archon-{uid}"
            archon_port = listeners_cfg.get("windows_port", 19082)
            print(f"  [archon] creating HTTP listener {archon_listener_name!r} on port {archon_port}")
            listener_create(cli, archon_listener_name, "http",
                            **http_listener_kwargs(archon_port, ctx.env))
            listener_start(cli, archon_listener_name)
            listeners_to_cleanup.append(archon_listener_name)
            if has_archon:
                cells.append(MatrixCell(arch="x64", fmt="exe", agent="archon",
                                        listener=archon_listener_name))
                cell_keys.append("archon")
            if has_specter:
                cells.append(MatrixCell(arch="x64", fmt="exe", agent="specter",
                                        listener=archon_listener_name))
                cell_keys.append("specter")

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
                                   listener_name=demon_listener_name,
                                   pre_built_payload=payloads["demon"])

            print("\n  === Agent pass: archon (Windows) ===")
            if not has_archon:
                print("  [archon] SKIPPED — 'archon' not listed in agents.available")
            else:
                _run_for_agent_windows(ctx, agent_type="archon", fmt="exe",
                                       listener_name=archon_listener_name,
                                       pre_built_payload=payloads["archon"])

            print("\n  === Agent pass: specter (Windows) ===")
            if not has_specter:
                print("  [specter] SKIPPED — 'specter' not listed in agents.available")
            else:
                _run_for_agent_windows(ctx, agent_type="specter", fmt="exe",
                                       listener_name=archon_listener_name,
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
