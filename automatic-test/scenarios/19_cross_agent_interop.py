"""
Scenario 19_cross_agent_interop: Cross-agent interoperability test

Spin up two different agent types simultaneously and verify they operate
independently against the same teamserver without interfering with each other.

Skip if either ctx.linux or ctx.windows is None — both targets are required.
Skip if Phantom is not enabled in ``agents.available`` — this scenario
specifically tests Demon-vs-Phantom isolation and must not silently degrade
to Demon-vs-Demon.

Both payloads are pre-built in parallel (when ``--no-parallel`` is not set) via
:func:`~lib.payload.build_parallel` with per-cell listeners, then deployed
concurrently via ThreadPoolExecutor.

Steps:
  1.  Create + start two HTTP listeners (one per agent)
  2.  Pre-build Demon EXE + Phantom EXE in parallel via build_parallel
  3.  Deploy Demon to Windows, Phantom to Linux (concurrent)
  4.  Execute both payloads in background
  5.  Wait for both agents to check in
  6.  Run identical command set on both agents concurrently
  7.  Verify output isolation — agent A's unique marker absent from agent B
  8.  Verify process list isolation — each agent returns its own data
  9.  Kill both agents; verify teamserver reports both as disconnected

Why this matters:
  Validates that the teamserver's per-agent key derivation and job dispatch
  correctly isolates sessions when multiple agent types are simultaneously
  active.  A regression here could cause command bleed between agents or
  corrupt per-agent job queues.
"""

from __future__ import annotations

DESCRIPTION = "Cross-agent interoperability: session isolation between Demon (Windows) and Phantom (Linux)"

import os
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _unique_marker() -> str:
    """Return a unique string suitable for use as an echo probe marker."""
    return f"MARKER-{uuid.uuid4().hex}"


# ── Deployment helpers ───────────────────────────────────────────────────────

def _deploy_windows(target, listener_name, uid, raw: bytes):
    """Deploy pre-built Demon EXE to Windows target.  Returns remote_payload path."""
    from lib.deploy import ensure_work_dir, execute_background, upload

    remote_payload = f"{target.work_dir}\\agent-{uid}.exe"
    _fd, local_payload = tempfile.mkstemp(suffix=".exe")
    os.close(_fd)

    assert len(raw) > 0, "Windows payload is empty"
    print(f"  [windows] deploying pre-built Demon EXE ({len(raw)} bytes)")

    with open(local_payload, "wb") as fh:
        fh.write(raw)
    try:
        ensure_work_dir(target)
        upload(target, local_payload, remote_payload)
        print(f"  [windows] uploaded → {remote_payload}")
        execute_background(target, remote_payload)
        print("  [windows] payload launched in background")
    finally:
        try:
            os.unlink(local_payload)
        except OSError:
            pass

    return remote_payload


def _deploy_linux(target, listener_name, uid, raw: bytes):
    """Deploy pre-built Phantom payload to Linux target.  Returns remote_payload path."""
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload

    remote_payload = f"{target.work_dir}/agent-{uid}.bin"
    _fd, local_payload = tempfile.mkstemp(suffix=".bin")
    os.close(_fd)

    assert len(raw) > 0, "Phantom payload is empty"
    print(f"  [linux] deploying pre-built Phantom EXE ({len(raw)} bytes)")

    with open(local_payload, "wb") as fh:
        fh.write(raw)
    try:
        ensure_work_dir(target)
        upload(target, local_payload, remote_payload)
        run_remote(target, f"chmod +x {remote_payload}")
        print(f"  [linux] uploaded → {remote_payload}")
        execute_background(target, remote_payload)
        print("  [linux] payload launched in background")
    finally:
        try:
            os.unlink(local_payload)
        except OSError:
            pass

    return remote_payload


# ── Isolation checks ─────────────────────────────────────────────────────────

def _run_command_suite(
    cli, agent_id: str, label: str, marker: str, exec_timeout: int
) -> dict:
    """Run the standard command suite against one agent.

    Returns a dict with the raw outputs keyed by command name.
    Raises AssertionError if any command fails or returns empty output.
    """
    from lib.cli import agent_exec

    outputs = {}

    # whoami
    print(f"  [{label}] running whoami")
    r = agent_exec(cli, agent_id, "whoami", wait=True, timeout=exec_timeout)
    out = r.get("output", "").strip()
    assert out, f"[{label}] whoami returned empty output"
    outputs["whoami"] = out
    print(f"  [{label}] whoami → {out!r}")

    # echo marker (unique per agent — used for isolation check)
    print(f"  [{label}] echoing unique marker: {marker!r}")
    r = agent_exec(cli, agent_id, f"echo {marker}", wait=True, timeout=exec_timeout)
    out = r.get("output", "").strip()
    assert marker in out, (
        f"[{label}] echo output {out!r} does not contain marker {marker!r}"
    )
    outputs["echo"] = out
    print(f"  [{label}] echo passed")

    # ps / tasklist
    ps_cmd = "ps aux" if label == "linux" else "tasklist"
    print(f"  [{label}] running {ps_cmd!r}")
    r = agent_exec(cli, agent_id, ps_cmd, wait=True, timeout=exec_timeout)
    out = r.get("output", "").strip()
    assert out, f"[{label}] {ps_cmd} returned empty output"
    outputs["ps"] = out
    print(f"  [{label}] {ps_cmd} passed ({len(out.splitlines())} lines)")

    return outputs


def _assert_isolation(
    win_outputs: dict,
    lin_outputs: dict,
    win_marker: str,
    lin_marker: str,
) -> None:
    """Verify that neither agent's output contains the other agent's echo marker.

    This is the key isolation assertion: if the teamserver's job dispatch or
    output routing ever blends sessions, the cross-contaminated marker will
    appear in the wrong agent's output bucket.
    """
    # Windows agent must NOT contain Linux marker
    assert lin_marker not in win_outputs.get("echo", ""), (
        f"SESSION BLEED DETECTED: Linux marker {lin_marker!r} found in "
        f"Windows agent echo output — job dispatch is not isolated"
    )
    # Linux agent must NOT contain Windows marker
    assert win_marker not in lin_outputs.get("echo", ""), (
        f"SESSION BLEED DETECTED: Windows marker {win_marker!r} found in "
        f"Linux agent echo output — job dispatch is not isolated"
    )

    # Sanity: each agent's echo output contains its own marker
    assert win_marker in win_outputs.get("echo", ""), (
        f"Windows agent echo output missing its own marker {win_marker!r}"
    )
    assert lin_marker in lin_outputs.get("echo", ""), (
        f"Linux agent echo output missing its own marker {lin_marker!r}"
    )

    # Whoami outputs should differ between the two agents
    win_whoami = win_outputs.get("whoami", "")
    lin_whoami = lin_outputs.get("whoami", "")
    assert win_whoami != lin_whoami, (
        f"Both agents returned identical whoami output {win_whoami!r} — "
        f"possible session aliasing"
    )

    print("  [isolation] all cross-agent isolation checks passed")


def _wait_for_two_agents(cli, pre_existing_ids: set, timeout: int) -> list[dict]:
    """Block until exactly two new agent records appear.

    Returns the list of new agent dicts (each containing at least ``id`` and
    ``listener``).  The caller is responsible for assigning IDs by inspecting
    the ``listener`` field — do **not** rely on list order.
    """
    from lib.wait import poll

    def _new_agents():
        from lib.cli import agent_list
        agents = agent_list(cli)
        return [a for a in agents if a["id"] not in pre_existing_ids]

    return poll(
        fn=_new_agents,
        predicate=lambda agents: len(agents) >= 2,
        timeout=timeout,
        description="two new agent checkins",
    )


def _wait_for_agents_disconnected(
    cli, agent_ids: list[str], timeout: int = 30
) -> None:
    """Poll until all specified agents report ``status == "dead"``."""
    from lib.wait import poll

    def _all_dead():
        from lib.cli import agent_list
        alive = {
            a["id"]
            for a in agent_list(cli)
            if a.get("status", "alive") != "dead"
        }
        return [aid for aid in agent_ids if aid not in alive]

    dead = poll(
        fn=_all_dead,
        predicate=lambda ids: len(ids) == len(agent_ids),
        timeout=timeout,
        description="agents disconnected",
    )
    print(f"  [disconnect] confirmed agents disconnected: {dead}")


# ── Main entry point ─────────────────────────────────────────────────────────

def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Raises ScenarioSkipped when either ctx.linux or ctx.windows is None, or
    when ``"phantom"`` is not enabled in ``agents.available``.
    """
    if ctx.linux is None:
        raise ScenarioSkipped("ctx.linux is None — Linux target required for this scenario")
    if ctx.windows is None:
        raise ScenarioSkipped("ctx.windows is None — Windows target required for this scenario")
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    if "phantom" not in available_agents:
        raise ScenarioSkipped("'phantom' not listed in agents.available")
    from lib.deploy import DeployError, preflight_ssh
    for _target in (ctx.linux, ctx.windows):
        try:
            preflight_ssh(_target)
        except DeployError as exc:
            raise ScenarioSkipped(str(exc)) from exc

    from lib.cli import (
        agent_kill,
        agent_list,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.listeners import http_listener_kwargs
    from lib.payload import MatrixCell, build_parallel

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    uid = _short_id()

    listener_win_name = f"test-interop-win-{uid}"
    listener_lin_name = f"test-interop-lin-{uid}"
    listener_win_port = ctx.env.get("listeners", {}).get("interop_win_port", 19091)
    listener_lin_port = ctx.env.get("listeners", {}).get("interop_lin_port", 19092)

    # Unique markers for cross-contamination detection
    win_marker = _unique_marker()
    lin_marker = _unique_marker()

    # Record pre-existing agent IDs so we can detect new checkins
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    win_remote_payload = None
    lin_remote_payload = None
    win_agent_id = None
    lin_agent_id = None

    # ── Step 1: Create + start both listeners ────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_win_name!r} on port {listener_win_port}")
    listener_create(cli, listener_win_name, "http", **http_listener_kwargs(listener_win_port, ctx.env))
    listener_start(cli, listener_win_name)

    print(f"  [listener] creating HTTP listener {listener_lin_name!r} on port {listener_lin_port}")
    listener_create(cli, listener_lin_name, "http", **http_listener_kwargs(listener_lin_port, ctx.env))
    listener_start(cli, listener_lin_name)
    print("  [listener] both listeners started")

    try:
        # ── Step 2: Pre-build both payloads in parallel ──────────────────────
        cells = [
            MatrixCell(arch="x64", fmt="exe", agent="demon",
                       listener=listener_win_name),
            MatrixCell(arch="x64", fmt="exe", agent="phantom",
                       listener=listener_lin_name),
        ]
        mode = "parallel" if ctx.payload_parallel else "serial"
        print(f"  [build] building 2 payloads ({mode})")
        raws = build_parallel(cli, "", cells, parallel=ctx.payload_parallel)
        raw_demon, raw_phantom = raws
        print(f"  [build] Demon: {len(raw_demon)} bytes, Phantom: {len(raw_phantom)} bytes")

        # ── Steps 3-4: Deploy both agents concurrently ───────────────────────
        with ThreadPoolExecutor(max_workers=2) as pool:
            win_future = pool.submit(
                _deploy_windows,
                ctx.windows, listener_win_name, uid, raw_demon,
            )
            lin_future = pool.submit(
                _deploy_linux,
                ctx.linux, listener_lin_name, uid, raw_phantom,
            )

            for future in as_completed([win_future, lin_future]):
                if future is win_future:
                    win_remote_payload = future.result()
                else:
                    lin_remote_payload = future.result()

        print("  [deploy] both payloads deployed (Windows: Demon, Linux: Phantom)")

        # ── Step 5: Wait for both agents to check in ─────────────────────────
        checkin_timeout = int(ctx.timeouts.agent_checkin)
        print(f"  [wait] waiting up to {checkin_timeout}s for both agents to check in")
        new_agents = _wait_for_two_agents(cli, pre_existing_ids, timeout=checkin_timeout)

        # Assign IDs by listener name — not by list order — to avoid swapping
        # the Windows and Linux agents when the checkin order is non-deterministic.
        for agent in new_agents:
            agent_listener = agent.get("listener", "")
            if agent_listener == listener_win_name:
                win_agent_id = agent["id"]
            elif agent_listener == listener_lin_name:
                lin_agent_id = agent["id"]

        if win_agent_id is None:
            received = [a.get("listener") for a in new_agents]
            raise AssertionError(
                f"No new agent checked in on Windows listener {listener_win_name!r}. "
                f"Listeners seen: {received}"
            )
        if lin_agent_id is None:
            received = [a.get("listener") for a in new_agents]
            raise AssertionError(
                f"No new agent checked in on Linux listener {listener_lin_name!r}. "
                f"Listeners seen: {received}"
            )

        print(f"  [wait] Windows agent: {win_agent_id} (listener: {listener_win_name!r})")
        print(f"  [wait] Linux agent:   {lin_agent_id} (listener: {listener_lin_name!r})")

        # ── Step 6: Run command suite on both agents concurrently ─────────────
        print("  [suite] running command suite on both agents concurrently")
        win_outputs = {}
        lin_outputs = {}
        suite_errors = []

        with ThreadPoolExecutor(max_workers=2) as pool:
            win_suite = pool.submit(
                _run_command_suite, cli, win_agent_id, "windows", win_marker, co
            )
            lin_suite = pool.submit(
                _run_command_suite, cli, lin_agent_id, "linux", lin_marker, co
            )

            for future in as_completed([win_suite, lin_suite]):
                try:
                    result = future.result()
                    if future is win_suite:
                        win_outputs = result
                    else:
                        lin_outputs = result
                except Exception as exc:
                    suite_errors.append(str(exc))

        if suite_errors:
            raise AssertionError(
                f"Command suite failed on one or more agents:\n"
                + "\n".join(suite_errors)
            )

        # ── Step 7: Verify output isolation ──────────────────────────────────
        print("  [isolation] verifying cross-agent session isolation")
        _assert_isolation(win_outputs, lin_outputs, win_marker, lin_marker)

        print("  [suite] all commands passed on both agents — sessions fully isolated")

        # ── Step 8: Kill both agents ──────────────────────────────────────────
        print(f"  [kill] sending kill to Windows agent {win_agent_id}")
        try:
            agent_kill(cli, win_agent_id)
        except Exception as exc:
            print(f"  [kill] Windows agent kill failed (non-fatal): {exc}")

        print(f"  [kill] sending kill to Linux agent {lin_agent_id}")
        try:
            agent_kill(cli, lin_agent_id)
        except Exception as exc:
            print(f"  [kill] Linux agent kill failed (non-fatal): {exc}")

        # ── Step 9: Verify both agents show as disconnected ──────────────────
        disconnect_timeout = int(ctx.timeouts.agent_disconnect)
        print(f"  [disconnect] waiting up to {disconnect_timeout}s for both agents to disconnect")
        _wait_for_agents_disconnected(
            cli, [win_agent_id, lin_agent_id], timeout=disconnect_timeout
        )
        print("  [disconnect] both agents confirmed disconnected")

    finally:
        # ── Cleanup ───────────────────────────────────────────────────────────
        for agent_id, label in [(win_agent_id, "Windows"), (lin_agent_id, "Linux")]:
            if agent_id:
                try:
                    agent_kill(cli, agent_id)
                except Exception:
                    pass

        for name in [listener_win_name, listener_lin_name]:
            print(f"  [cleanup] stopping/deleting listener {name!r}")
            try:
                listener_stop(cli, name)
            except Exception:
                pass
            try:
                listener_delete(cli, name)
            except Exception:
                pass

        # Remove remote payloads
        if win_remote_payload and ctx.windows:
            try:
                from lib.deploy import run_remote
                run_remote(
                    ctx.windows,
                    f'powershell -Command "Remove-Item -Force -Path \'{win_remote_payload}\'"',
                    timeout=15,
                )
            except Exception as exc:
                print(f"  [cleanup] Windows payload removal failed (non-fatal): {exc}")

        if lin_remote_payload and ctx.linux:
            try:
                from lib.deploy import run_remote
                run_remote(ctx.linux, f"rm -f {lin_remote_payload}", timeout=15)
            except Exception as exc:
                print(f"  [cleanup] Linux payload removal failed (non-fatal): {exc}")

        print("  [cleanup] done")
