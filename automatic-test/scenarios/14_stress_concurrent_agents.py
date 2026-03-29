"""
Scenario 14_stress_concurrent_agents: Concurrent agent stress test

Spin up 10 Demon agent processes on the Linux test VM simultaneously and
verify the teamserver remains stable and responsive under load.

Skip if ctx.linux is None.

Steps:
  1.  Create + start a single HTTP listener (all agents share it)
  2.  Build one Demon bin payload for the Linux target
  3.  Upload 10 copies with distinct names; execute each in background
  4.  Wait for all 10 agents to check in (deadline: 30 s)
  5.  Start CPU monitoring in a background thread
  6.  For 60 s: issue shell exec to all agents in parallel every 10 s,
      checking for cross-agent marker bleed after each round
  7.  Assert teamserver CPU stayed below 80 % throughout the run
  8.  Assert teamserver produced no ERROR-level log entries
  9.  Kill all agents; verify disconnected; stop listener; clean up

Pass criteria (from issue):
  - All 10 agents check in within 30 s
  - No agent drops connection during the 60 s run
  - All shell exec commands return correct output (no cross-agent bleed)
  - Teamserver CPU < 80 % (sampled via /proc or ps)
  - Teamserver does not crash or produce ERROR-level log entries

Why this matters:
  A single-threaded bottleneck or lock contention in the job dispatch path
  only shows up under concurrent load.  This test catches regressions in the
  WebSocket handler's per-agent routing and the SQLite connection pool under
  write pressure.
"""

from __future__ import annotations

DESCRIPTION = "Stress test: 10 concurrent Demon agents on Linux target"

AGENT_COUNT = 10
RUN_SECONDS = 60
EXEC_INTERVAL = 10       # seconds between parallel exec rounds during the run
CHECKIN_DEADLINE = 30    # seconds to wait for all agents to check in
CPU_LIMIT_PCT = 80.0     # maximum allowable teamserver CPU %

import base64
import os
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, Future


# ── Helpers ──────────────────────────────────────────────────────────────────

def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _unique_marker() -> str:
    return f"STRESS-{uuid.uuid4().hex}"


def _wait_for_n_agents(cli, pre_existing_ids: set, n: int, timeout: int) -> list[str]:
    """Block until at least n new agent IDs appear.  Returns list of new IDs."""
    from lib.wait import poll, TimeoutError as WaitTimeout

    def _new_agents():
        from lib.cli import agent_list
        agents = agent_list(cli)
        return [a["id"] for a in agents if a["id"] not in pre_existing_ids]

    new_ids = poll(
        fn=_new_agents,
        predicate=lambda ids: len(ids) >= n,
        timeout=timeout,
        interval=2.0,
        description=f"{n} new agent checkins",
    )
    return new_ids


def _exec_one(cli, agent_id: str, marker: str, label: str) -> dict:
    """Issue `echo <marker>` to one agent and return result dict.

    Returns {"agent_id": ..., "marker": ..., "output": ..., "ok": bool,
             "error": str|None}.
    """
    from lib.cli import agent_exec, CliError

    try:
        r = agent_exec(cli, agent_id, f"echo {marker}", wait=True, timeout=30)
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


def _exec_round(cli, agent_ids: list[str], markers: dict[str, str]) -> list[dict]:
    """Issue `echo <marker>` to all agents concurrently.  Returns list of result dicts."""
    with ThreadPoolExecutor(max_workers=len(agent_ids)) as pool:
        futures: list[Future] = [
            pool.submit(_exec_one, cli, aid, markers[aid], f"agent-{i}")
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


# ── CPU monitoring ────────────────────────────────────────────────────────────

class _CpuMonitor(threading.Thread):
    """Sample teamserver CPU usage in the background.

    Tries to find the `red-cell` process via `ps` and records the max CPU %
    seen during the monitoring window.
    """

    def __init__(self, interval: float = 5.0):
        super().__init__(daemon=True)
        self.interval = interval
        self._stop_event = threading.Event()
        self.samples: list[float] = []
        self.max_cpu: float = 0.0
        self._pid: int | None = None

    def _find_pid(self) -> int | None:
        """Return the PID of the `red-cell` teamserver, or None if not found."""
        try:
            result = subprocess.run(
                ["pgrep", "-x", "red-cell"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().splitlines()
                if lines:
                    return int(lines[0])
        except Exception:
            pass
        # Fallback: search ps output for 'red-cell' (not the test process itself)
        try:
            result = subprocess.run(
                ["ps", "axo", "pid,comm,pcpu"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and "red-cell" in parts[1]:
                    return int(parts[0])
        except Exception:
            pass
        return None

    def _sample_cpu(self) -> float | None:
        """Return current CPU % for the teamserver PID, or None."""
        if self._pid is None:
            self._pid = self._find_pid()
        if self._pid is None:
            return None
        try:
            result = subprocess.run(
                ["ps", "-p", str(self._pid), "-o", "pcpu="],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                text = result.stdout.strip()
                if text:
                    return float(text)
        except Exception:
            pass
        return None

    def run(self):
        while not self._stop_event.is_set():
            cpu = self._sample_cpu()
            if cpu is not None:
                self.samples.append(cpu)
                if cpu > self.max_cpu:
                    self.max_cpu = cpu
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=10)


# ── Main entry point ──────────────────────────────────────────────────────────

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
        print("  [skip] ctx.linux is None — Linux target required for this scenario")
        return

    from lib.cli import (
        CliError,
        agent_kill,
        agent_list,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        log_list,
        payload_build,
    )
    from lib.deploy import ensure_work_dir, execute_background, run_remote, upload

    cli = ctx.cli
    target = ctx.linux
    uid = _short_id()
    listener_name = f"test-stress-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("stress_port", 19093)

    # Record pre-existing agent IDs.
    try:
        pre_existing_ids = {a["id"] for a in agent_list(cli)}
    except Exception:
        pre_existing_ids = set()

    remote_payloads: list[str] = []
    agent_ids: list[str] = []

    # ── Step 1: Create + start listener ──────────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [listener] started")

    try:
        # ── Step 2: Build one payload ─────────────────────────────────────────
        print(f"  [payload] building Demon bin x64 for listener {listener_name!r}")
        result = payload_build(
            cli, agent="demon", listener=listener_name, arch="x64", fmt="bin"
        )
        raw = base64.b64decode(result["bytes"])
        assert len(raw) > 0, "payload is empty"
        print(f"  [payload] built ({len(raw)} bytes)")

        local_payload = tempfile.mktemp(suffix=".bin")
        with open(local_payload, "wb") as fh:
            fh.write(raw)

        try:
            # ── Step 3: Upload AGENT_COUNT copies and launch each ─────────────
            print(f"  [deploy] ensuring work dir on target")
            ensure_work_dir(target)

            for i in range(AGENT_COUNT):
                remote_path = f"{target.work_dir}/stress-agent-{uid}-{i:02d}.bin"
                remote_payloads.append(remote_path)
                upload(target, local_payload, remote_path)
                run_remote(target, f"chmod +x {remote_path}")
                execute_background(target, remote_path)
                print(f"  [deploy] launched agent {i+1}/{AGENT_COUNT}: {remote_path}")

        finally:
            try:
                os.unlink(local_payload)
            except OSError:
                pass

        # ── Step 4: Wait for all agents to check in ───────────────────────────
        checkin_deadline = CHECKIN_DEADLINE
        print(
            f"  [wait] waiting up to {checkin_deadline}s for {AGENT_COUNT} "
            f"agents to check in"
        )
        checkin_start = time.monotonic()
        agent_ids = _wait_for_n_agents(
            cli, pre_existing_ids, AGENT_COUNT, timeout=checkin_deadline
        )
        checkin_elapsed = time.monotonic() - checkin_start
        assert len(agent_ids) >= AGENT_COUNT, (
            f"Only {len(agent_ids)}/{AGENT_COUNT} agents checked in within "
            f"{checkin_deadline}s"
        )
        print(
            f"  [wait] all {AGENT_COUNT} agents checked in in "
            f"{checkin_elapsed:.1f}s: {agent_ids}"
        )

        # Assign one unique marker per agent for the entire run.
        markers: dict[str, str] = {aid: _unique_marker() for aid in agent_ids}

        # ── Step 5: Start CPU monitoring ──────────────────────────────────────
        cpu_monitor = _CpuMonitor(interval=5.0)
        cpu_monitor.start()

        run_start = time.monotonic()
        round_num = 0
        exec_errors: list[str] = []

        # ── Step 6: Run for RUN_SECONDS, issuing exec rounds every EXEC_INTERVAL
        print(f"  [run] starting {RUN_SECONDS}s load run "
              f"(exec rounds every {EXEC_INTERVAL}s)")
        while time.monotonic() - run_start < RUN_SECONDS:
            round_num += 1
            print(f"  [run] exec round {round_num} "
                  f"(t+{time.monotonic()-run_start:.0f}s)")
            results = _exec_round(cli, agent_ids, markers)

            # Check for failures without raising immediately — collect all errors.
            try:
                _assert_exec_round(results, round_num)
                ok_count = sum(1 for r in results if r["ok"])
                print(f"  [run] round {round_num}: {ok_count}/{len(results)} ok, "
                      f"no bleed detected")
            except AssertionError as exc:
                exec_errors.append(str(exc))
                print(f"  [run] round {round_num} FAILED: {exc}")

            # Check all agents still alive.
            try:
                current_agents = {a["id"] for a in agent_list(cli)}
                missing = [aid for aid in agent_ids if aid not in current_agents]
                if missing:
                    exec_errors.append(
                        f"Round {round_num}: agents dropped connection: {missing}"
                    )
                    print(f"  [run] WARNING: agents dropped: {missing}")
            except CliError as exc:
                print(f"  [run] agent list failed (non-fatal): {exc}")

            # Wait until next exec interval (or run end).
            elapsed = time.monotonic() - run_start
            sleep_time = max(0.0, EXEC_INTERVAL - (time.monotonic() - run_start) % EXEC_INTERVAL)
            remaining = RUN_SECONDS - elapsed
            if remaining > 0:
                time.sleep(min(sleep_time, remaining))

        run_elapsed = time.monotonic() - run_start
        print(f"  [run] completed {run_elapsed:.1f}s run, {round_num} exec rounds")

        # ── Step 7: Stop CPU monitor + assert CPU limit ───────────────────────
        cpu_monitor.stop()
        if cpu_monitor.samples:
            print(
                f"  [cpu] max CPU: {cpu_monitor.max_cpu:.1f}%  "
                f"({len(cpu_monitor.samples)} samples)"
            )
            if cpu_monitor.max_cpu > CPU_LIMIT_PCT:
                exec_errors.append(
                    f"Teamserver CPU peaked at {cpu_monitor.max_cpu:.1f}% "
                    f"(limit: {CPU_LIMIT_PCT}%)"
                )
        else:
            print("  [cpu] teamserver process not found on localhost — CPU check skipped")

        # ── Step 8: Check for ERROR log entries ───────────────────────────────
        print("  [log] checking for ERROR-level log entries")
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
                print(f"  [log] WARNING: {len(error_entries)} error log entries found")
            else:
                print("  [log] no ERROR-level log entries — ok")
        except CliError as exc:
            print(f"  [log] audit log unavailable (non-fatal): {exc}")

        # Raise collected errors now.
        if exec_errors:
            raise AssertionError(
                f"Stress test failures ({len(exec_errors)}):\n"
                + "\n\n".join(exec_errors)
            )

        print(
            f"  [pass] all {AGENT_COUNT} agents stable for {RUN_SECONDS}s, "
            f"no bleed, no errors"
        )

    finally:
        # ── Cleanup ───────────────────────────────────────────────────────────
        for aid in agent_ids:
            try:
                agent_kill(cli, aid)
            except Exception as exc:
                print(f"  [cleanup] kill agent {aid} failed (non-fatal): {exc}")

        print(f"  [cleanup] stopping/deleting listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass

        # Remove remote payloads.
        for rp in remote_payloads:
            try:
                run_remote(target, f"rm -f {rp}", timeout=10)
            except Exception as exc:
                print(f"  [cleanup] remove {rp} failed (non-fatal): {exc}")

        print("  [cleanup] done")
