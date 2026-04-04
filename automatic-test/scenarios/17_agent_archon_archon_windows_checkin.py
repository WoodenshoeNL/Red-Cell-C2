"""
Scenario 17_agent_archon: Archon agent Windows checkin

Archon is a C/ASM fork of Demon.  This scenario exercises the Archon-specific
test surface: build via Makefile, Windows checkin, and any Archon-specific
command extensions that exist at the time of the run.

The scenario is skip-gated only when ``"archon"`` is absent from
``agents.available`` in env.toml. If Archon is configured as available,
any payload build failure is treated as a hard failure so the harness does
not silently fall back to Demon semantics.

Skip conditions:
  - ctx.windows is None (no Windows target configured)
  - ``"archon"`` is not listed in ``agents.available`` in env.toml

Steps:
  1. Create + start HTTP listener
  2. Build Archon payload (EXE x64)
  3. Deploy via SSH/SCP to Windows 11 test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. Run baseline command suite: whoami, dir C:\\\\, ipconfig
  7. Run Archon-specific command extensions (if any are defined in env.toml)
  8. Kill agent, stop listener, clean up work_dir on target
"""

DESCRIPTION = "Archon agent Windows checkin (Makefile build + Archon extensions)"

import uuid

from lib import ScenarioSkipped
from lib.deploy_agent import deploy_and_checkin


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_archon_extensions(cli, agent_id: str, extensions: list[dict]) -> None:
    """Execute Archon-specific commands listed in env.toml ``[archon.extensions]``.

    Each entry in *extensions* must have:
      - ``cmd``   (str)  — the shell command to run
      - ``match`` (str)  — substring that must appear in the output

    Args:
        cli:        CliConfig used to drive red-cell-cli.
        agent_id:   ID of the checked-in Archon agent.
        extensions: List of extension dicts from env.toml.

    Raises:
        AssertionError if any extension command fails its assertion.
    """
    from lib.cli import agent_exec

    if not extensions:
        print("  [archon][extensions] no Archon-specific extensions configured — skipping")
        return

    for entry in extensions:
        cmd = entry.get("cmd", "")
        match = entry.get("match", "")
        if not cmd:
            continue
        print(f"  [archon][extensions] running: {cmd!r}")
        result = agent_exec(cli, agent_id, cmd, wait=True, timeout=30)
        output = result.get("output", "").strip()
        assert output, f"Archon extension command {cmd!r} returned empty output"
        if match:
            assert match in output, (
                f"Archon extension command {cmd!r} output did not contain {match!r}:\n"
                f"{output[:500]}"
            )
        print(f"  [archon][extensions] {cmd!r} passed")


def run(ctx) -> None:
    """Run the Archon Windows checkin scenario.

    Args:
        ctx: RunContext with attributes:
            cli     — CliConfig (red-cell-cli wrapper)
            linux   — TargetConfig | None
            windows — TargetConfig | None
            env     — raw env.toml dict
            dry_run — bool

    Raises:
        AssertionError with a descriptive message on any test failure.
        ScenarioSkipped when no Windows target is configured or when Archon
        is not enabled in ``agents.available``.
    """
    if ctx.windows is None:
        raise ScenarioSkipped("ctx.windows is None — no Windows target configured")
    available_agents = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    if "archon" not in available_agents:
        raise ScenarioSkipped("'archon' not listed in agents.available")
    from lib.deploy import DeployError, preflight_ssh
    try:
        preflight_ssh(ctx.windows)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    from lib.cli import (
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.deploy import run_remote

    cli = ctx.cli
    target = ctx.windows
    uid = _short_id()
    listener_name = f"test-archon-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("windows_port", 19082)

    # Archon-specific extension commands from env.toml.
    # Canonical TOML format:  [[archon.extensions]]  (array-of-tables → list[dict])
    # Legacy single-entry:    [archon.extensions]    (table → dict) — normalised below.
    _ext_raw = ctx.env.get("archon", {}).get("extensions", [])
    archon_extensions: list[dict] = (
        [_ext_raw] if isinstance(_ext_raw, dict) else list(_ext_raw)
    )

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [archon][listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port)
    listener_start(cli, listener_name)
    print("  [archon][listener] started")

    agent_id = None
    try:
        # ── Steps 2-5: Build, deploy, exec, wait for checkin ─────────────────
        agent = deploy_and_checkin(
            ctx, cli, target,
            agent_type="archon", fmt="exe",
            listener_name=listener_name,
            label="archon",
        )
        agent_id = agent["id"]

        # ── Step 6: Baseline command suite ───────────────────────────────────

        # whoami → DOMAIN\username format
        print("  [archon][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=30)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert "\\" in whoami_out, (
            f"whoami output {whoami_out!r} does not contain '\\' "
            f"— expected DOMAIN\\username format"
        )
        print(f"  [archon][cmd] whoami passed: {whoami_out!r}")

        # dir C:\ → non-empty output
        print("  [archon][cmd] dir C:\\")
        result = agent_exec(cli, agent_id, "dir C:\\", wait=True, timeout=30)
        dir_out = result.get("output", "").strip()
        assert dir_out, "dir C:\\ returned empty output"
        print(f"  [archon][cmd] dir C:\\ passed ({len(dir_out.splitlines())} lines)")

        # ipconfig → contains 'IPv4 Address'
        print("  [archon][cmd] ipconfig")
        result = agent_exec(cli, agent_id, "ipconfig", wait=True, timeout=30)
        ipconfig_out = result.get("output", "").strip()
        assert ipconfig_out, "ipconfig returned empty output"
        assert "IPv4 Address" in ipconfig_out, (
            f"ipconfig output does not contain 'IPv4 Address':\n{ipconfig_out[:500]}"
        )
        print("  [archon][cmd] ipconfig passed")

        print("  [archon][suite] baseline commands passed")

        # ── Step 7: Archon-specific extensions ───────────────────────────────
        _run_archon_extensions(cli, agent_id, archon_extensions)

        print("  [archon][suite] all checks passed")

    finally:
        # ── Step 8: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [archon][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [archon][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [archon][cleanup] stopping/deleting listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass

        print("  [archon][cleanup] removing work_dir on target")
        try:
            run_remote(
                target,
                f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                timeout=15,
            )
        except Exception as exc:
            print(f"  [archon][cleanup] work_dir removal failed (non-fatal): {exc}")

        print("  [archon][cleanup] done")
