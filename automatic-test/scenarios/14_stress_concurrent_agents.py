"""
Scenario 14_stress_concurrent_agents: Concurrent agent stress test

Runs two passes:
  - Demon: 10 concurrent agents on Windows (full stress baseline)
  - Phantom: 5 concurrent agents on Linux (Rust agent stability check)

The Phantom pass runs only when ``"phantom"`` is listed in
``agents.available`` in env.toml; if it is listed and the payload build
fails, the scenario fails so the regression is caught.

Listeners are created upfront in :func:`run` (one per active agent type)
and both payloads are pre-built via
:func:`~lib.payload.build_parallel` so builds overlap.

Steps:
  1.  Create + start per-agent-type HTTP listeners (shared across all agents
      of that type)
  2.  Pre-build all payloads in parallel via ``build_parallel``
  3.  For each agent pass:

      a.  Upload N copies of the pre-built payload; execute each in background
      b.  Wait for all N agents to check in (deadline: 30 s)
      c.  Start CPU monitoring in a background thread
      d.  For RUN_SECONDS: issue shell exec to all agents in parallel every
          EXEC_INTERVAL s, checking for cross-agent marker bleed each round
      e.  Assert teamserver CPU (and optional RSS) stayed below configured
          limits throughout the run
      f.  Assert teamserver produced no ERROR-level log entries
      g.  Kill all agents; verify disconnected; clean up remote payloads

  4.  Stop + delete all listeners

Pass criteria:
  - All N agents check in within 30 s
  - No agent drops connection during the run
  - All shell exec commands return correct output (no cross-agent bleed)
  - Teamserver CPU < configured limit (default 80 %), optional RSS cap — sampled
    via local ``ps`` or SSH to ``[teamserver]`` host when SSH is configured
  - Teamserver does not crash or produce ERROR-level log entries
"""

from __future__ import annotations

DESCRIPTION = "Stress test: concurrent agents on Linux target (Demon + Phantom)"

# Demon stress parameters
DEMON_AGENT_COUNT = 10
DEMON_RUN_SECONDS = 60

# Phantom stress parameters (smaller scale — validates stability, not max throughput)
PHANTOM_AGENT_COUNT = 5
PHANTOM_RUN_SECONDS = 30

EXEC_INTERVAL = 10       # seconds between parallel exec rounds during the run
CPU_LIMIT_PCT = 80.0     # default max teamserver CPU % (override via env.toml [teamserver])

import os
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, Future

from lib import ScenarioSkipped
from lib.teamserver_monitor import (
    TeamserverResourceMonitor,
    assert_resource_limits,
    format_samples_for_output,
    load_teamserver_monitor_settings,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _unique_marker() -> str:
    return f"STRESS-{uuid.uuid4().hex}"


def _wait_for_n_agents(
    cli, pre_existing_ids: set, n: int, timeout: int, poll_interval: float
) -> list[str]:
    """Block until at least n new agent IDs appear.  Returns list of new IDs."""
    from lib.wait import poll

    def _new_agents():
        from lib.cli import agent_list
        agents = agent_list(cli)
        return [a["id"] for a in agents if a["id"] not in pre_existing_ids]

    new_ids = poll(
        fn=_new_agents,
        predicate=lambda ids: len(ids) >= n,
        timeout=timeout,
        interval=poll_interval,
        description=f"{n} new agent checkins",
    )
    return new_ids


def _exec_one(cli, agent_id: str, marker: str, label: str, exec_timeout: int) -> dict:
    """Issue ``echo <marker>`` to one agent and return result dict."""
    from lib.cli import agent_exec, CliError

    try:
        r = agent_exec(cli, agent_id, f"echo {marker}", wait=True, timeout=exec_timeout)
        out = r.get("output", "").strip()
        return {
            "agent_id": agent_id,
            "label": label,
            "marker": marker,
            "output": out,
            "ok": True,
            "error": None,
        }
    except CliError as exc:
        return {
            "agent_id": agent_id,
            "label": label,
            "marker": marker,
            "output": "",
            "ok": False,
            "error": str(exc),
        }


def _exec_round(
    cli, agent_ids: list[str], markers: dict[str, str], exec_timeout: int
) -> list[dict]:
    """Issue ``echo <marker>`` to all agents concurrently.  Returns list of result dicts."""
    with ThreadPoolExecutor(max_workers=len(agent_ids)) as pool:
        futures: list[Future] = [
            pool.submit(_exec_one, cli, aid, markers[aid], f"agent-{i}", exec_timeout)
            for i, aid in enumerate(agent_ids)
        ]
        results = [f.result() for f in as_completed(futures)]
    return results


def _assert_exec_round(results: list[dict], round_num: int) -> None:
    """Assert all results are ok and contain the correct marker (no bleed)."""
    failures = []
    for r in results:
        if not r["ok"]:
            failures.append(
                f"  agent {r['agent_id']}: exec failed — {r['error']}"
            )
            continue
        if r["marker"] not in r["output"]:
            failures.append(
                f"  agent {r['agent_id']}: marker {r['marker']!r} not in "
                f"output {r['output']!r}"
            )
        # Cross-bleed check: no other marker should appear in this output
        for other_aid, other_marker in [
            (k, v) for k, v in
            {aid: m for aid, m in [(rr["agent_id"], rr["marker"]) for rr in results]}.items()
            if k != r["agent_id"]
        ]:
            if other_marker in r["output"]:
                failures.append(
                    f"  SESSION BLEED (round {round_num}): agent {r['agent_id']} output "
                    f"contains marker for agent {other_aid}: {other_marker!r}"
                )

    if failures:
        raise AssertionError(
            f"Exec round {round_num} failures:\n" + "\n".join(failures)
        )


# ── Per-agent-type stress runner ──────────────────────────────────────────────

def _run_stress_for_agent(
    ctx,
    target,
    agent_type: str,
    fmt: str,
    pre_built_payload: bytes,
    agent_count: int,
    run_seconds: int,
) -> None:
    """Run the concurrent stress test for one agent type using a pre-built payload.

    Args:
        ctx:               RunContext passed by the harness.
        target:            TargetConfig for the machine to deploy agents to.
        agent_type:        Agent name (e.g. ``"demon"`` or ``"phantom"``).
        fmt:               Payload format (``"exe"``).
        pre_built_payload: Raw payload bytes from :func:`~lib.payload.build_parallel`.
        agent_count:       Number of concurrent agent instances to spawn.
        run_seconds:       Duration of the load-run phase in seconds.

    Raises:
        AssertionError on test failure.
    """
    from lib.cli import (
        CliError,
        agent_kill,
        agent_list,
        log_list,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    checkin_deadline = int(ctx.timeouts.stress_concurrent_checkin)
    poll_iv = float(ctx.timeouts.poll_interval)
    ssh = int(ctx.timeouts.ssh_connect)
    uid = _short_id()

    # Record pre-existing agent IDs.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    remote_payloads: list[str] = []
    agent_ids: list[str] = []

    _fd, local_payload = tempfile.mkstemp(suffix=f".{fmt}")
    os.close(_fd)
    with open(local_payload, "wb") as fh:
        fh.write(pre_built_payload)

    try:
        # ── Step 1: Upload agent_count copies and launch each ─────────────
        print(f"  [{agent_type}][deploy] ensuring work dir on target")
        ensure_work_dir(target)

        _win = target.work_dir.startswith("C:\\") or "\\" in target.work_dir
        _sep = "\\" if _win else "/"
        for i in range(agent_count):
            remote_path = f"{target.work_dir}{_sep}stress-agent-{uid}-{i:02d}.{fmt}"
            remote_payloads.append(remote_path)
            upload(target, local_payload, remote_path)
            if not _win:
                run_remote(target, f"chmod +x {remote_path}")
            execute_background(target, remote_path)
            print(f"  [{agent_type}][deploy] launched agent {i+1}/{agent_count}: {remote_path}")

        # ── Step 2: Wait for all agents to check in ──────────────────────────
        print(
            f"  [{agent_type}][wait] waiting up to {checkin_deadline}s for "
            f"{agent_count} agents to check in"
        )
        checkin_start = time.monotonic()
        agent_ids = _wait_for_n_agents(
            cli,
            pre_existing_ids,
            agent_count,
            timeout=checkin_deadline,
            poll_interval=poll_iv,
        )
        checkin_elapsed = time.monotonic() - checkin_start
        assert len(agent_ids) >= agent_count, (
            f"Only {len(agent_ids)}/{agent_count} agents checked in within "
            f"{checkin_deadline}s"
        )
        print(
            f"  [{agent_type}][wait] all {agent_count} agents checked in in "
            f"{checkin_elapsed:.1f}s: {agent_ids}"
        )

        # Assign one unique marker per agent for the entire run.
        markers: dict[str, str] = {aid: _unique_marker() for aid in agent_ids}

        # ── Step 3: Teamserver CPU/RSS monitoring (local ps or remote SSH) ────
        ts_settings = load_teamserver_monitor_settings(
            ctx.env, default_cpu_limit_pct=CPU_LIMIT_PCT
        )
        cpu_monitor = TeamserverResourceMonitor(ts_settings, interval=5.0)
        cpu_monitor.configure()
        if cpu_monitor.disable_reason:
            print(f"  [{agent_type}][cpu] {cpu_monitor.disable_reason}")
        edge_start = cpu_monitor.take_edge_sample("stress_start")
        cpu_monitor.start()

        run_start = time.monotonic()
        round_num = 0
        exec_errors: list[str] = []

        # ── Step 4: Run for run_seconds, issuing exec rounds every EXEC_INTERVAL
        print(
            f"  [{agent_type}][run] starting {run_seconds}s load run "
            f"(exec rounds every {EXEC_INTERVAL}s)"
        )
        while time.monotonic() - run_start < run_seconds:
            round_num += 1
            print(
                f"  [{agent_type}][run] exec round {round_num} "
                f"(t+{time.monotonic()-run_start:.0f}s)"
            )
            results = _exec_round(cli, agent_ids, markers, co)

            # Check for failures without raising immediately — collect all errors.
            try:
                _assert_exec_round(results, round_num)
                ok_count = sum(1 for r in results if r["ok"])
                print(
                    f"  [{agent_type}][run] round {round_num}: "
                    f"{ok_count}/{len(results)} ok, no bleed detected"
                )
            except AssertionError as exc:
                exec_errors.append(str(exc))
                print(f"  [{agent_type}][run] round {round_num} FAILED: {exc}")

            # Check all agents still alive.
            try:
                current_agents = {a["id"] for a in agent_list(cli)}
                missing = [aid for aid in agent_ids if aid not in current_agents]
                if missing:
                    exec_errors.append(
                        f"Round {round_num}: agents dropped connection: {missing}"
                    )
                    print(f"  [{agent_type}][run] WARNING: agents dropped: {missing}")
            except CliError as exc:
                print(f"  [{agent_type}][run] agent list failed (non-fatal): {exc}")

            # Wait until next exec interval (or run end).
            elapsed = time.monotonic() - run_start
            sleep_time = max(
                0.0,
                EXEC_INTERVAL - (time.monotonic() - run_start) % EXEC_INTERVAL,
            )
            remaining = run_seconds - elapsed
            if remaining > 0:
                time.sleep(min(sleep_time, remaining))

        run_elapsed = time.monotonic() - run_start
        print(f"  [{agent_type}][run] completed {run_elapsed:.1f}s run, {round_num} exec rounds")

        # ── Step 5: Stop monitor, edge sample, assert CPU/RSS limits ─────────
        cpu_monitor.stop()
        edge_end = cpu_monitor.take_edge_sample("stress_end")
        had_samples = bool(cpu_monitor.samples)
        samples_summary = format_samples_for_output(cpu_monitor.samples)
        def _edge_s(e):
            if e is None:
                return "none"
            return f"cpu={e.cpu_pct:.1f}% rss_mib={e.rss_kb / 1024:.1f}"

        print(
            f"  [{agent_type}][cpu] teamserver={ts_settings.host!r} mode={cpu_monitor.mode} "
            f"max_cpu={cpu_monitor.max_cpu:.1f}% max_rss={cpu_monitor.max_rss_kb / 1024:.1f}MiB "
            f"edge_start={_edge_s(edge_start)} edge_end={_edge_s(edge_end)}"
        )
        print(f"  [{agent_type}][cpu] samples: {samples_summary}")
        if not had_samples and cpu_monitor._mode != "disabled":
            print(
                f"  [{agent_type}][cpu] no teamserver process samples — "
                f"CPU/RSS checks skipped (is red-cell running on {ts_settings.host!r}?)"
            )
        limit_errs = assert_resource_limits(
            ts_settings,
            cpu_monitor.max_cpu,
            cpu_monitor.max_rss_kb,
            had_samples,
        )
        exec_errors.extend(limit_errs)

        # ── Step 6: Check for ERROR log entries ──────────────────────────────
        print(f"  [{agent_type}][log] checking for ERROR-level log entries")
        try:
            log_entries = log_list(cli, limit=200)
            error_entries = [
                e for e in log_entries
                if str(e.get("result_status", "")).upper() == "ERROR"
                or str(e.get("level", "")).upper() == "ERROR"
            ]
            if error_entries:
                sample = error_entries[:3]
                exec_errors.append(
                    f"Teamserver produced {len(error_entries)} ERROR-level log "
                    f"entries during the run:\n"
                    + "\n".join(f"  {e}" for e in sample)
                )
                print(f"  [{agent_type}][log] WARNING: {len(error_entries)} error log entries found")
            else:
                print(f"  [{agent_type}][log] no ERROR-level log entries — ok")
        except CliError as exc:
            print(f"  [{agent_type}][log] audit log unavailable (non-fatal): {exc}")

        # Raise collected errors now.
        if exec_errors:
            raise AssertionError(
                f"Stress test failures ({len(exec_errors)}):\n"
                + "\n\n".join(exec_errors)
            )

        print(
            f"  [{agent_type}][pass] all {agent_count} agents stable for "
            f"{run_seconds}s, no bleed, no errors"
        )

    finally:
        # ── Cleanup (agents + remote payloads; listeners are managed by run()) ─
        try:
            os.unlink(local_payload)
        except OSError:
            pass

        for aid in agent_ids:
            try:
                agent_kill(cli, aid)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] kill agent {aid} failed (non-fatal): {exc}")

        # Remove remote payloads.
        _win_cleanup = target.work_dir.startswith("C:\\") or "\\" in target.work_dir
        for rp in remote_payloads:
            try:
                if _win_cleanup:
                    run_remote(target, f'del /f /q "{rp}"', timeout=ssh)
                else:
                    run_remote(target, f"rm -f {rp}", timeout=ssh)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] remove {rp} failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] done")


# ── Main entry point ──────────────────────────────────────────────────────────

def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Skips silently when no agent passes can run.
    """
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    from lib.cli import listener_create, listener_delete, listener_start, listener_stop
    from lib.listeners import http_listener_kwargs
    from lib.payload import MatrixCell, build_parallel

    cli = ctx.cli
    uid = _short_id()
    listeners_to_cleanup: list[str] = []
    skipped_reasons: list[str] = []

    # ── Determine which agent passes will run ────────────────────────────────
    run_demon = ctx.windows is not None and "demon" in available_agents
    run_phantom = ctx.linux is not None and "phantom" in available_agents

    if not run_demon and ctx.windows is None:
        print("  [demon] SKIPPED — ctx.windows is None (Windows target required for Demon)")
    elif not run_demon:
        print("  [demon] SKIPPED — 'demon' not listed in agents.available")

    if not run_phantom and ctx.linux is None:
        print("  [phantom] SKIPPED — ctx.linux is None (Linux target required for Phantom)")
    elif not run_phantom:
        print("  [phantom] SKIPPED — 'phantom' not listed in agents.available")
        skipped_reasons.append(
            "Linux target configured but no available Linux agent"
            " (add 'phantom' to agents.available)"
        )

    if not run_demon and not run_phantom:
        if skipped_reasons:
            raise ScenarioSkipped("; ".join(skipped_reasons))
        raise ScenarioSkipped(
            "no agent passes could run: Windows target needed for Demon, "
            "Linux target + phantom in agents.available needed for Phantom"
        )

    # ── Step 1: Create + start per-agent-type listeners ──────────────────────
    cells: list[MatrixCell] = []
    cell_keys: list[str] = []

    demon_listener_name: str | None = None
    phantom_listener_name: str | None = None

    listeners_cfg = ctx.env.get("listeners", {})

    if run_demon:
        demon_port = listeners_cfg.get("stress_demon_port", 19093)
        demon_listener_name = f"test-stress-demon-{uid}"
        print(f"\n  [shared] creating Demon HTTP listener {demon_listener_name!r} on port {demon_port}")
        kw = http_listener_kwargs(demon_port, ctx.env)
        if "hosts" in kw:
            kw["legacy_mode"] = True
        listener_create(cli, demon_listener_name, "http", **kw)
        listener_start(cli, demon_listener_name)
        listeners_to_cleanup.append(demon_listener_name)
        cells.append(MatrixCell(arch="x64", fmt="exe", agent="demon",
                                listener=demon_listener_name))
        cell_keys.append("demon")

    if run_phantom:
        phantom_port = listeners_cfg.get("stress_phantom_port", 19094)
        phantom_listener_name = f"test-stress-phantom-{uid}"
        print(f"  [shared] creating Phantom HTTP listener {phantom_listener_name!r} on port {phantom_port}")
        listener_create(cli, phantom_listener_name, "http",
                        **http_listener_kwargs(phantom_port, ctx.env))
        listener_start(cli, phantom_listener_name)
        listeners_to_cleanup.append(phantom_listener_name)
        cells.append(MatrixCell(arch="x64", fmt="exe", agent="phantom",
                                listener=phantom_listener_name))
        cell_keys.append("phantom")

    try:
        # ── Step 2: Pre-build all payloads in parallel ───────────────────────
        mode = "parallel" if ctx.payload_parallel else "serial"
        print(f"  [shared] building {len(cells)} payload(s) ({mode})")
        raws = build_parallel(cli, "", cells, parallel=ctx.payload_parallel)
        payloads = dict(zip(cell_keys, raws))
        for key, raw in payloads.items():
            assert len(raw) > 0, f"{key} payload is empty"
            print(f"  [shared] {key}: {len(raw)} bytes")

        # ── Step 3: Run each stress pass sequentially ────────────────────────
        if run_demon:
            print("\n  === Agent pass: demon ===")
            _run_stress_for_agent(
                ctx,
                target=ctx.windows,
                agent_type="demon",
                fmt="exe",
                pre_built_payload=payloads["demon"],
                agent_count=DEMON_AGENT_COUNT,
                run_seconds=DEMON_RUN_SECONDS,
            )

        if run_phantom:
            print("\n  === Agent pass: phantom ===")
            _run_stress_for_agent(
                ctx,
                target=ctx.linux,
                agent_type="phantom",
                fmt="exe",
                pre_built_payload=payloads["phantom"],
                agent_count=PHANTOM_AGENT_COUNT,
                run_seconds=PHANTOM_RUN_SECONDS,
            )

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
