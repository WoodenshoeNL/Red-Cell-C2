"""
lib/deploy_agent.py — high-level deploy-and-checkin helper for the test harness.

Encapsulates the repeated build → deploy → execute → wait-for-checkin sequence
so individual scenarios can focus on their unique post-checkin assertions.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from typing import Callable

from lib.cli import CliConfig, agent_list, payload_build_and_fetch
from lib.deploy import (
    TargetConfig,
    defender_add_process_exclusion,
    ensure_work_dir,
    execute_background,
    firewall_allow_program,
    run_remote,
    upload,
)
from lib.wait import TimeoutError as WaitTimeoutError, wait_for_agent


def deploy_and_checkin(
    ctx,
    cli: CliConfig,
    target: TargetConfig,
    agent_type: str,
    fmt: str,
    listener_name: str,
    checkin_timeout: int = 60,
    pre_existing_ids: set[str] | None = None,
    arch: str = "x64",
    label: str | None = None,
    sleep_secs: int | None = None,
    expect_checkin: bool = True,
    no_checkin_timeout: int | None = None,
    pre_built_payload: bytes | None = None,
    checkin_periodic_interval: float | None = None,
    checkin_periodic_callback: Callable[[], None] | None = None,
) -> dict | None:
    """Build, deploy, execute, and wait for a single agent checkin.

    Handles the repeated boilerplate across scenarios:

    1. Snapshot pre-existing agent IDs (unless supplied by the caller).
    2. Build a payload via the CLI.
    3. Upload to the target via SCP; ``chmod +x`` on Linux targets.
    4. Execute the payload in the background.
    5. Wait for the new agent to check in.

    Listener creation / teardown and post-checkin assertions remain the
    responsibility of the calling scenario.  The local payload temp file is
    always cleaned up before this function returns (success *or* failure).

    Args:
        ctx:              RunContext — used to read ``timeouts.agent_checkin``
                          from env.toml (overrides *checkin_timeout* when set).
        cli:              CliConfig driving red-cell-cli.
        target:           TargetConfig for the deployment target.
        agent_type:       Agent name passed to ``payload build`` (e.g.
                          ``"demon"``, ``"phantom"``, ``"archon"``).
        fmt:              Payload format (``"exe"``, ``"dll"``, or ``"bin"``;
                          Rust agents like Phantom/Specter only accept ``"exe"``).
        listener_name:    Name of the pre-created, pre-started listener.
        checkin_timeout:  Fallback timeout in seconds; overridden by
                          ``timeouts.agent_checkin`` in env.toml when present.
        pre_existing_ids: Agent IDs already present before this call.
                          Collected automatically when *None*.
        arch:             Payload architecture (default ``"x64"``).
        label:            Print-tag prefix, e.g. ``"demon"`` → ``[demon][payload]``.
                          Defaults to *agent_type* when *None*.
        sleep_secs:       Passed to ``payload build --sleep`` (agent callback interval).
        expect_checkin:   When ``False``, wait up to *no_checkin_timeout* and expect
                          **no** new agent (working-hours / blocked scenarios).
        no_checkin_timeout: Seconds to wait for absence of checkin when *expect_checkin*
                          is ``False``.  Defaults to ``timeouts.working_hours_probe``
                          from env or ``45``.
        pre_built_payload: When provided, skip the build step and use these raw
                          bytes directly.  Useful when payloads have already been
                          compiled in parallel via :func:`~lib.payload.build_parallel`.
        checkin_periodic_interval: If set with *checkin_periodic_callback*, invoked
                          every N seconds while waiting for check-in (diagnostics).
        checkin_periodic_callback: Callable run on that interval; must not raise.

    Returns:
        The agent dict from :func:`~lib.wait.wait_for_agent`, or ``None`` when
        *expect_checkin* is ``False`` and no agent appears (expected).

    Raises:
        AssertionError: if the built payload is empty, or if *expect_checkin* is
                          ``False`` but an agent checks in anyway.
        lib.deploy.DeployError: if SCP upload or a remote command fails.
        lib.wait.TimeoutError: if *expect_checkin* is ``True`` and no agent checks in.
    """
    tag = label if label is not None else agent_type
    t = getattr(ctx, "timeouts", None)
    if t is not None:
        timeout = int(t.agent_checkin)
    else:
        timeout = int(ctx.env.get("timeouts", {}).get("agent_checkin", checkin_timeout))

    # Step 1 — snapshot pre-existing agents so we can identify the new checkin.
    if pre_existing_ids is None:
        try:
            pre_existing_ids = {a["id"] for a in agent_list(cli)}
        except Exception:
            pre_existing_ids = set()

    uid = uuid.uuid4().hex[:8]
    is_windows = target.platform == "windows"
    sep = "\\" if is_windows else "/"
    remote_payload = f"{target.work_dir}{sep}agent-{uid}.{fmt}"

    _fd, local_payload = tempfile.mkstemp(suffix=f".{fmt}")
    os.close(_fd)
    try:
        # Step 2 — build payload (or use pre-built bytes).
        if pre_built_payload is not None:
            raw = pre_built_payload
            print(f"  [{tag}][payload] using pre-built {agent_type} {fmt} {arch} ({len(raw)} bytes)")
        else:
            print(f"  [{tag}][payload] building {agent_type} {fmt} {arch}")
            raw = payload_build_and_fetch(
                cli,
                listener=listener_name,
                arch=arch,
                fmt=fmt,
                agent=agent_type,
                sleep_secs=sleep_secs,
            )
            print(f"  [{tag}][payload] built ({len(raw)} bytes)")
        assert len(raw) > 0, f"{agent_type} payload is empty"

        with open(local_payload, "wb") as fh:
            fh.write(raw)

        # Step 3 — deploy via SCP.
        print(f"  [{tag}][deploy] ensuring work dir {target.work_dir!r} on target")
        ensure_work_dir(target)
        print(f"  [{tag}][deploy] uploading payload → {remote_payload}")
        upload(target, local_payload, remote_payload)
        if not is_windows:
            run_remote(target, f"chmod +x {remote_payload}")
        print(f"  [{tag}][deploy] uploaded")

        if is_windows:
            try:
                print(f"  [{tag}][deploy] Defender process exclusion (payload basename)")
                defender_add_process_exclusion(target, remote_payload)
            except Exception as exc:
                print(f"  [{tag}][deploy] Defender process exclusion failed (non-fatal): {exc}")
            try:
                print(f"  [{tag}][deploy] outbound firewall allow rule for payload exe")
                firewall_allow_program(target, remote_payload)
            except Exception as exc:
                print(f"  [{tag}][deploy] firewall allow rule failed (non-fatal): {exc}")

        # Step 4 — execute payload in background.
        print(f"  [{tag}][exec] launching payload in background on target")
        execute_background(target, remote_payload)

    finally:
        try:
            os.unlink(local_payload)
        except OSError:
            pass

    # Step 5 — wait for agent checkin (outside the finally so failure propagates cleanly).
    if not expect_checkin:
        probe = no_checkin_timeout
        if probe is None:
            tw = getattr(ctx, "timeouts", None)
            if tw is not None and tw.working_hours_probe is not None:
                probe = int(tw.working_hours_probe)
            else:
                probe = int(ctx.env.get("timeouts", {}).get("working_hours_probe", 45))
        print(f"  [{tag}][wait] expecting NO checkin within {probe}s (working-hours probe)")
        try:
            agent = wait_for_agent(cli, timeout=probe, pre_existing_ids=pre_existing_ids)
        except WaitTimeoutError:
            print(f"  [{tag}][wait] no checkin (expected)")
            return None
        raise AssertionError(
            f"agent {agent.get('id')!r} checked in unexpectedly — outside working hours"
        )

    print(f"  [{tag}][wait] waiting up to {timeout}s for agent checkin")
    agent = wait_for_agent(
        cli,
        timeout=timeout,
        pre_existing_ids=pre_existing_ids,
        periodic_interval=checkin_periodic_interval,
        periodic_callback=checkin_periodic_callback,
    )
    print(f"  [{tag}][wait] agent checked in: {agent['id']}")
    return agent
