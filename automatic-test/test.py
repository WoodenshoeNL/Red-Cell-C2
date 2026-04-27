#!/usr/bin/env python3
"""
test.py — Red Cell C2 automated end-to-end test harness.

Uses red-cell-cli to drive the full teamserver → agent flow against real
target machines (Linux and/or Windows).

Usage:
    python3 test.py --scenario all
    python3 test.py --scenario 01 02 04
    python3 test.py --scenario all --target linux
    python3 test.py --dry-run

Config:
    config/env.toml      — teamserver URL + credentials
    config/targets.toml  — test machine SSH details (gitignored)
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from dataclasses import dataclass
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent))

from lib import ScenarioSkipped
from lib.cli import CliConfig, CliError, status as cli_status
from lib.config import (
    ConfigError,
    load_env,
    load_targets,
    make_cli_config_from_parsed,
    parse_env_config,
    TimeoutsConfig,
    timeouts_to_env_dict,
)
from lib.deploy import TargetConfig, configure_deploy_timeouts
from lib.teamserver_monitor import configure_teamserver_ssh_connect_timeout
from lib.wait import configure_wait_defaults
from lib.failure_diagnostics import build_failure_diagnostic_report, create_run_dir, write_scenario_failure_file


# ── Config loading ───────────────────────────────────────────────────────────
# ``load_env`` / ``load_targets`` live in ``lib.config`` (schema validation).


def make_target(cfg: dict) -> TargetConfig:
    return TargetConfig(
        host=cfg["host"],
        port=cfg.get("port", 22),
        user=cfg["user"],
        work_dir=cfg["work_dir"],
        key=cfg.get("key", ""),
        display=cfg.get("display", ""),
    )


# ── Toolchain pre-flight ─────────────────────────────────────────────────────

_TOOLCHAIN_TOOLS = [
    ("x86_64-w64-mingw32-gcc", ["x86_64-w64-mingw32-gcc", "--version"]),
    ("nasm",                   ["nasm", "--version"]),
]


def _payload_scenario_ids(scenarios_dir: Path) -> frozenset[str]:
    """Return IDs of every scenario file that calls payload_build_and_fetch.

    Scans scenario source text so the set stays accurate automatically as new
    payload-building scenarios are added without requiring manual updates here.
    """
    ids: set[str] = set()
    for p in sorted(scenarios_dir.glob("[0-9][0-9]_*.py")):
        if "payload_build_and_fetch" in p.read_text(encoding="utf-8"):
            ids.add(p.stem[:2])
    return frozenset(ids)


def check_toolchain(selected_ids: set[str], scenarios_dir: Path | None = None) -> bool:
    """Return True if all required toolchain tools are present.

    Only checks when at least one payload-building scenario is selected.
    Prints a clear, actionable error for each missing tool so the operator
    knows exactly what to install before retrying.

    *scenarios_dir* defaults to the ``scenarios/`` directory next to this
    file; pass an explicit path in tests to point at a temporary directory.
    """
    if scenarios_dir is None:
        scenarios_dir = Path(__file__).parent / "scenarios"

    payload_scenarios = _payload_scenario_ids(scenarios_dir)
    if not (selected_ids & payload_scenarios):
        return True  # no payload scenarios selected — nothing to check

    print(f"\n{'─' * 60}")
    print("  Toolchain pre-flight")
    print(f"{'─' * 60}")

    all_ok = True
    for name, cmd in _TOOLCHAIN_TOOLS:
        if shutil.which(cmd[0]) is None:
            _install = {"x86_64-w64-mingw32-gcc": "mingw-w64", "nasm": "nasm"}.get(name, name)
            print(
                f"  ✗ {name}: not found\n"
                f"    Install it with: apt install {_install}\n"
                f"    Payload builds will fail without this tool."
            )
            all_ok = False
            continue
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"  ✓ {name}: present")
        except subprocess.CalledProcessError as exc:
            print(
                f"  ✗ {name}: returned exit code {exc.returncode}\n"
                f"    {exc.stderr.decode(errors='replace').strip()}"
            )
            all_ok = False

    return all_ok


# ── SSH target pre-flight ────────────────────────────────────────────────────

def _ssh_deploy_scenario_ids(scenarios_dir: Path) -> frozenset[str]:
    """Return IDs of every scenario that deploys payloads via SSH.

    Scans scenario source text for ``from lib.deploy import`` so the set stays
    accurate automatically as new deploy scenarios are added.
    """
    ids: set[str] = set()
    for p in sorted(scenarios_dir.glob("[0-9][0-9]_*.py")):
        if "from lib.deploy import" in p.read_text(encoding="utf-8"):
            ids.add(p.stem[:2])
    return frozenset(ids)


def check_ssh_targets(
    targets: list,
    selected_ids: set,
    scenarios_dir: Path | None = None,
) -> None:
    """Run SSH pre-flight connectivity checks for all configured targets.

    Only checks when at least one SSH-deploy scenario is selected.
    Prints a pass/fail line per target but does NOT abort — individual
    scenarios raise :class:`lib.ScenarioSkipped` when a target is unreachable.

    *targets* is a list of ``(label, TargetConfig | None)`` pairs.
    *scenarios_dir* defaults to the ``scenarios/`` directory next to this
    file; pass an explicit path in tests to point at a temporary directory.
    """
    if scenarios_dir is None:
        scenarios_dir = Path(__file__).parent / "scenarios"

    deploy_scenarios = _ssh_deploy_scenario_ids(scenarios_dir)
    if not (selected_ids & deploy_scenarios):
        return

    from lib.deploy import DeployError, preflight_ssh

    print(f"\n{'─' * 60}")
    print("  SSH target pre-flight")
    print(f"{'─' * 60}")

    for label, target in targets:
        if target is None:
            print(f"  - {label}: not configured")
            continue
        try:
            preflight_ssh(target)
            print(f"  ✓ {label} ({target.host}): reachable")
        except DeployError as exc:
            print(f"  ✗ {label} ({target.host}): {exc}")
        except Exception as exc:
            print(f"  ✗ {label} ({target.host}): unexpected error — {exc}")


# ── Unit tests ───────────────────────────────────────────────────────────────

TESTS_DIR = Path(__file__).parent / "tests"


def run_unit_tests() -> bool:
    """Discover and run unit tests under ``tests/``.

    Returns ``True`` if all tests passed, ``False`` otherwise.
    """
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(TESTS_DIR), pattern="test_*.py")

    print(f"\n{'─' * 60}")
    print("  Unit tests (tests/)")
    print(f"{'─' * 60}")

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    if result.wasSuccessful():
        print(f"  ✓ {result.testsRun} unit test(s) passed")
    else:
        failures = len(result.failures) + len(result.errors)
        print(f"  ✗ {failures} unit test(s) failed (ran {result.testsRun})")

    return result.wasSuccessful()


# ── Scenario discovery ───────────────────────────────────────────────────────

SCENARIOS_DIR = Path(__file__).parent / "scenarios"

def discover_scenarios() -> dict[str, Path]:
    """Return ordered dict of scenario_id → module path."""
    scenarios = {}
    for p in sorted(SCENARIOS_DIR.glob("[0-9][0-9]_*.py")):
        sid = p.stem[:2]
        scenarios[sid] = p
    return scenarios


# ── Runner ───────────────────────────────────────────────────────────────────

@dataclass
class RunContext:
    cli: CliConfig
    linux: TargetConfig | None
    windows: TargetConfig | None
    windows2: TargetConfig | None
    env: dict
    timeouts: TimeoutsConfig
    dry_run: bool
    #: When false, payload matrix scenarios use serial ``--wait`` builds (``--no-parallel``).
    payload_parallel: bool = True


_RATE_LIMIT_EXIT_CODE = 6
_RATE_LIMIT_DEFAULT_WAIT_SECS = 60
_RATE_LIMIT_MAX_WAITS = 3


def _parse_retry_after(exc: CliError) -> int:
    """Extract Retry-After seconds from a rate-limit CliError message."""
    m = re.search(r"retry after Some\((\d+)\)", str(exc))
    if m:
        return int(m.group(1))
    return _RATE_LIMIT_DEFAULT_WAIT_SECS


def _wait_out_rate_limit(cli_cfg: CliConfig) -> None:
    """If the server is rate-limiting us, sleep until the window resets."""
    for attempt in range(_RATE_LIMIT_MAX_WAITS):
        try:
            cli_status(cli_cfg)
            return
        except CliError as exc:
            if exc.exit_code != _RATE_LIMIT_EXIT_CODE:
                return
            wait = _parse_retry_after(exc)
            print(
                f"  [RATE LIMIT] waiting {wait}s before next scenario "
                f"(attempt {attempt + 1}/{_RATE_LIMIT_MAX_WAITS})..."
            )
            time.sleep(wait)


def run_scenario(
    scenario_id: str, path: Path, ctx: RunContext, run_dir: Path,
) -> tuple[str, Path | None]:
    """Load and run a scenario module.

    Returns ``(status, report_path)`` where *status* is one of:

        ``"passed"``  — scenario ran and all assertions succeeded
        ``"skipped"`` — scenario raised :class:`lib.ScenarioSkipped` (not a failure)
        ``"failed"``  — scenario raised any other exception

    *report_path* is set when a failed run wrote a failure file inside *run_dir*.
    """
    module_name = f"scenarios.{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    print(f"\n{'─' * 60}")
    print(f"  Scenario {scenario_id}: {getattr(mod, 'DESCRIPTION', path.stem)}")
    print(f"{'─' * 60}")

    if ctx.dry_run:
        print("  [DRY RUN] skipping execution")
        return "passed", None

    _wait_out_rate_limit(ctx.cli)

    start = time.monotonic()
    try:
        mod.run(ctx)
        elapsed = time.monotonic() - start
        print(f"  ✓ PASSED ({elapsed:.1f}s)")
        return "passed", None
    except ScenarioSkipped as exc:
        elapsed = time.monotonic() - start
        print(f"  ~ SKIPPED ({elapsed:.1f}s): {exc}")
        return "skipped", None
    except CliError as exc:
        if exc.exit_code != _RATE_LIMIT_EXIT_CODE:
            elapsed = time.monotonic() - start
            print(f"  ✗ FAILED ({elapsed:.1f}s): {exc}")
            title = getattr(mod, "DESCRIPTION", path.stem)
            text = build_failure_diagnostic_report(
                ctx, scenario_id, title, exc, log_lines=100
            )
            print(text, end="")
            report_path = write_scenario_failure_file(
                run_dir, scenario_id, text
            )
            print(f"  Diagnostic report written to: {report_path}")
            return "failed", report_path
        wait = _parse_retry_after(exc)
        elapsed = time.monotonic() - start
        print(
            f"  [RATE LIMIT] hit during scenario ({elapsed:.1f}s), "
            f"waiting {wait}s and retrying once..."
        )
        time.sleep(wait)
        _wait_out_rate_limit(ctx.cli)
        start = time.monotonic()
        try:
            mod.run(ctx)
            elapsed = time.monotonic() - start
            print(f"  ✓ PASSED on retry ({elapsed:.1f}s)")
            return "passed", None
        except ScenarioSkipped as exc2:
            elapsed = time.monotonic() - start
            print(f"  ~ SKIPPED on retry ({elapsed:.1f}s): {exc2}")
            return "skipped", None
        except Exception as exc2:
            elapsed = time.monotonic() - start
            print(f"  ✗ FAILED on retry ({elapsed:.1f}s): {exc2}")
            title = getattr(mod, "DESCRIPTION", path.stem)
            text = build_failure_diagnostic_report(
                ctx, scenario_id, title, exc2, log_lines=100
            )
            print(text, end="")
            report_path = write_scenario_failure_file(
                run_dir, scenario_id, text
            )
            print(f"  Diagnostic report written to: {report_path}")
            return "failed", report_path
    except Exception as exc:
        elapsed = time.monotonic() - start
        print(f"  ✗ FAILED ({elapsed:.1f}s): {exc}")
        title = getattr(mod, "DESCRIPTION", path.stem)
        text = build_failure_diagnostic_report(
            ctx, scenario_id, title, exc, log_lines=100
        )
        print(text, end="")
        report_path = write_scenario_failure_file(
            run_dir, scenario_id, text
        )
        print(f"  Diagnostic report written to: {report_path}")
        return "failed", report_path


# ── Cert fingerprint auto-derive ─────────────────────────────────────────────

def _auto_derive_cert_fingerprint(cli_cfg: CliConfig) -> CliConfig:
    """Return a copy of *cli_cfg* with cert_fingerprint set from the server.

    When cert_fingerprint is not in env.toml, derive it via openssl so
    self-signed teamserver certs work without hardcoding machine-specific
    values.  Silently returns the original config if derivation fails (e.g.
    server not running yet, no openssl in PATH).
    """
    from dataclasses import replace
    from urllib.parse import urlparse

    server = cli_cfg.server
    parsed = urlparse(server)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme in ("https", "wss") else 80)

    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}"],
            input=b"",
            capture_output=True,
            timeout=5,
        )
        fp_result = subprocess.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
            input=result.stdout,
            capture_output=True,
            timeout=5,
        )
        fp_line = fp_result.stdout.decode().strip()
        # Expected: "SHA256 Fingerprint=XX:XX:..."
        if "=" in fp_line:
            fp = fp_line.split("=", 1)[1].replace(":", "").lower()
            if len(fp) == 64:
                return replace(cli_cfg, cert_fingerprint=fp)
    except Exception:
        pass

    return cli_cfg


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Red Cell C2 automated test harness")
    parser.add_argument(
        "--scenario", nargs="+", default=["all"],
        help="Scenario IDs to run (e.g. 01 04) or 'all'",
    )
    parser.add_argument(
        "--target", choices=["linux", "windows", "both"], default="both",
        help="Which target(s) to use for deploy scenarios",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate config and discover scenarios without running them",
    )
    parser.add_argument(
        "--unit", action="store_true",
        help="Run only the unit tests in tests/ and exit",
    )
    parser.add_argument(
        "--skip-unit", action="store_true",
        help="Skip the unit-test pre-flight and go straight to scenarios",
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Build payload matrix serially (payload build --wait) instead of "
        "detach+build-wait in parallel (for debugging hot spots)",
    )
    parser.add_argument(
        "--config-dir", type=Path, default=Path(__file__).parent / "config",
        help="Path to config directory",
    )
    args = parser.parse_args()

    # --unit: run only unit tests then exit (no scenarios, no config required)
    if args.unit:
        ok = run_unit_tests()
        sys.exit(0 if ok else 1)

    config_dir = args.config_dir
    try:
        env = load_env(config_dir / "env.toml")
        targets_raw = load_targets(config_dir / "targets.toml")
    except ConfigError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    env_cfg = parse_env_config(env)
    tmo = env_cfg.timeouts
    configure_deploy_timeouts(
        ssh_connect_secs=tmo.ssh_connect,
        scp_transfer_secs=tmo.scp_transfer,
        default_remote_cmd_secs=tmo.command_output,
    )
    configure_wait_defaults(
        poll_interval_secs=tmo.poll_interval,
        default_agent_checkin_secs=tmo.agent_checkin,
    )
    configure_teamserver_ssh_connect_timeout(tmo.ssh_connect)

    base_timeouts = env.get("timeouts")
    if not isinstance(base_timeouts, dict):
        base_timeouts = {}
    env = {**env, "timeouts": {**base_timeouts, **timeouts_to_env_dict(tmo)}}

    cli_cfg = make_cli_config_from_parsed(env_cfg, env)

    # When no cert_fingerprint is configured, auto-derive it from the server's
    # TLS certificate so self-signed certs work without hardcoding machine-
    # specific values in env.toml.
    if cli_cfg.cert_fingerprint is None:
        cli_cfg = _auto_derive_cert_fingerprint(cli_cfg)

    # Apply --target filter before constructing TargetConfig objects so that
    # an intentionally-incomplete stanza for the disabled target does not
    # trigger the key-validation ValueError before filtering takes effect.
    use_linux = args.target in ("linux", "both")
    use_windows = args.target in ("windows", "both")

    linux_target = make_target(targets_raw["linux"]) if (use_linux and "linux" in targets_raw) else None
    windows_target = make_target(targets_raw["windows"]) if (use_windows and "windows" in targets_raw) else None
    windows2_target = make_target(targets_raw["windows2"]) if (use_windows and "windows2" in targets_raw) else None

    ctx = RunContext(
        cli=cli_cfg,
        linux=linux_target,
        windows=windows_target,
        windows2=windows2_target,
        env=env,
        timeouts=tmo,
        dry_run=args.dry_run,
        payload_parallel=not args.no_parallel,
    )

    all_scenarios = discover_scenarios()
    if not all_scenarios:
        print(f"[ERROR] No scenario files found in {SCENARIOS_DIR}")
        sys.exit(1)

    if "all" in args.scenario:
        selected = list(all_scenarios.items())
    else:
        selected = []
        for sid in args.scenario:
            sid = sid.zfill(2)
            if sid not in all_scenarios:
                print(f"[ERROR] Unknown scenario: {sid}")
                print(f"Available: {', '.join(all_scenarios.keys())}")
                sys.exit(1)
            selected.append((sid, all_scenarios[sid]))

    print(f"\nRed Cell C2 — automated test harness")
    print(f"Server:   {env['server']['url']}")
    print(f"Linux:    {linux_target.host if linux_target else 'disabled'}")
    print(f"Windows:  {windows_target.host if windows_target else 'disabled'}")
    print(f"Windows2: {windows2_target.host if windows2_target else 'disabled'}")
    print(f"Dry run:  {ctx.dry_run}")
    print(f"Scenarios: {', '.join(sid for sid, _ in selected)}")

    # Pre-flight: run unit tests before touching any infrastructure.
    # Skip when --skip-unit is given or when this is a dry run.
    if not ctx.dry_run and not args.skip_unit:
        if not run_unit_tests():
            print("\n[ERROR] Unit tests failed — aborting scenario run.")
            sys.exit(1)

    # Pre-flight: verify payload-build toolchain tools are present when any
    # payload scenario is selected.  A missing compiler or assembler produces
    # a cryptic build error deep inside scenario 03; catching it here gives
    # the operator a clear, actionable message before anything runs.
    if not ctx.dry_run:
        selected_ids = {sid for sid, _ in selected}
        if not check_toolchain(selected_ids):
            print(
                "\n[ERROR] Toolchain pre-flight failed — install the missing "
                "tools listed above and retry."
            )
            sys.exit(1)

    # Pre-flight: check SSH connectivity for all configured targets upfront so
    # unreachable hosts are reported before any scenario begins.  This does not
    # abort the run — scenarios raise ScenarioSkipped individually when a target
    # they need is unreachable.
    if not ctx.dry_run:
        selected_ids = {sid for sid, _ in selected}
        check_ssh_targets(
            [
                ("linux", linux_target),
                ("windows", windows_target),
                ("windows2", windows2_target),
            ],
            selected_ids,
        )

    # Pre-flight: clean up leftover listeners from prior runs.  Listeners
    # persisted in the teamserver's SQLite DB may still be bound to ports
    # that new scenarios need, causing cascading "Address already in use"
    # failures.  Stop and delete everything except the profile's default
    # listener.
    if not ctx.dry_run:
        from lib.cli import CliError, listener_delete, listener_list, listener_stop
        from lib.listeners import collect_env_listener_bind_ports, resolve_listener_row_status

        print(f"\n{'─' * 60}")
        print("  Listener cleanup (leftover from prior runs)")
        print(f"{'─' * 60}")
        autotest_bind_ports = collect_env_listener_bind_ports(env)
        if autotest_bind_ports:
            ports_txt = ", ".join(str(p) for p in sorted(autotest_bind_ports))
            print(f"  (env.toml [listeners] ports: {ports_txt})")
        try:
            for round_idx in range(1, 4):
                try:
                    existing = listener_list(cli_cfg)
                except CliError as exc:
                    print(f"  ✗ listener list failed: {exc}")
                    break
                if not isinstance(existing, list):
                    print(
                        f"  ✗ listener list returned {type(existing).__name__!r}, expected a list"
                    )
                    break
                to_clean = [lsnr for lsnr in existing if lsnr.get("name") != "default"]
                if not to_clean:
                    if round_idx == 1:
                        print("  (no non-default listeners — OK)")
                    break
                print(
                    f"  Pass {round_idx}/3: removing {len(to_clean)} non-default "
                    "listener(s) (SQLite may restore Running listeners from prior runs)"
                )
                for lsnr in to_clean:
                    name = lsnr.get("name", "")
                    if not name:
                        continue
                    st = resolve_listener_row_status(lsnr)
                    # Always stop before delete: stop is idempotent, and a missing/flat
                    # `status` field would otherwise skip stop while the OS socket stays bound.
                    try:
                        listener_stop(cli_cfg, name)
                    except CliError as exc:
                        print(f"  ✗ listener_stop({name!r}) failed: {exc}")
                    try:
                        listener_delete(cli_cfg, name)
                        detail = f" (list status={st!r})" if st else " (list status missing — still deleted)"
                        print(f"  ✓ cleaned up: {name}{detail}")
                    except CliError as exc:
                        print(f"  ✗ listener_delete({name!r}) failed: {exc}")
            # Final check so cascading port-in-use is visible in the log
            try:
                final = listener_list(cli_cfg)
            except CliError as exc:
                print(f"  ✗ final listener list failed: {exc}")
            else:
                if isinstance(final, list):
                    leftover = [r for r in final if r.get("name") != "default"]
                    if leftover:
                        names = ", ".join(repr(x.get("name", "?")) for x in leftover)
                        hint = ""
                        if autotest_bind_ports:
                            hint = (
                                " If bind errors persist, stop the teamserver, remove its SQLite "
                                "file for this profile, or clear listeners via the operator UI."
                            )
                        print(
                            f"  ✗ non-default listener(s) still present after cleanup: {names}.{hint}"
                        )
        except Exception as exc:
            print(f"  ✗ unexpected error during cleanup: {exc}")

    automatic_test_root = Path(__file__).resolve().parent
    run_dir = create_run_dir(automatic_test_root)
    print(f"Run dir:  {run_dir}")

    passed = failed = skipped = 0
    failure_reports: list[Path] = []
    for sid, path in selected:
        outcome, report_path = run_scenario(sid, path, ctx, run_dir)
        if outcome == "passed":
            passed += 1
        elif outcome == "skipped":
            skipped += 1
        else:
            failed += 1
            if report_path is not None:
                failure_reports.append(report_path)

    total = passed + failed + skipped
    print(f"\n{'═' * 60}")
    skip_note = f", {skipped} skipped" if skipped else ""
    print(f"  Results: {passed} passed, {failed} failed{skip_note} out of {total} scenarios")
    if failure_reports:
        print("  Failure diagnostic reports:")
        for fp in failure_reports:
            print(f"    {fp}")
    print(f"{'═' * 60}\n")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
