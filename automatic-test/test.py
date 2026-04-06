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
from lib.cli import CliConfig
from lib.config import ConfigError, load_env, load_targets, make_cli_config
from lib.deploy import TargetConfig
from lib.failure_diagnostics import build_failure_diagnostic_report, write_scenario_failure_file


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
    dry_run: bool


def run_scenario(scenario_id: str, path: Path, ctx: RunContext) -> tuple[str, Path | None]:
    """Load and run a scenario module.

    Returns ``(status, report_path)`` where *status* is one of:

        ``"passed"``  — scenario ran and all assertions succeeded
        ``"skipped"`` — scenario raised :class:`lib.ScenarioSkipped` (not a failure)
        ``"failed"``  — scenario raised any other exception

    *report_path* is set when a failed run wrote ``test-results/.../scenario_NN_failure.txt``.
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

    automatic_test_root = Path(__file__).resolve().parent
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
    except Exception as exc:
        elapsed = time.monotonic() - start
        print(f"  ✗ FAILED ({elapsed:.1f}s): {exc}")
        title = getattr(mod, "DESCRIPTION", path.stem)
        text = build_failure_diagnostic_report(
            ctx, scenario_id, title, exc, log_lines=100
        )
        print(text, end="")
        report_path = write_scenario_failure_file(
            automatic_test_root, scenario_id, text
        )
        print(f"  Diagnostic report written to: {report_path}")
        return "failed", report_path


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

    cli_cfg = make_cli_config(env)

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
        dry_run=args.dry_run,
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

    passed = failed = skipped = 0
    failure_reports: list[Path] = []
    for sid, path in selected:
        outcome, report_path = run_scenario(sid, path, ctx)
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
