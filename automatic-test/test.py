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
import os
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent))

from lib.cli import CliConfig
from lib.deploy import TargetConfig


# ── Config loading ───────────────────────────────────────────────────────────

def load_env(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_targets(path: Path) -> dict:
    if not path.exists():
        print(f"[WARN] {path} not found — deploy scenarios will be skipped.")
        print(f"       Copy {path.with_suffix('.example')} to {path} and fill in your values.")
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def make_cli_config(env: dict) -> CliConfig:
    return CliConfig(
        server=env["server"]["url"],
        token=env["operator"]["password"],  # resolved to a real token at runtime
        timeout=env.get("timeouts", {}).get("command_output", 30),
    )


def make_target(cfg: dict) -> TargetConfig:
    return TargetConfig(
        host=cfg["host"],
        port=cfg.get("port", 22),
        user=cfg["user"],
        work_dir=cfg["work_dir"],
        key=cfg.get("key") or None,
        password=cfg.get("password") or None,
    )


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
    linux: Optional[TargetConfig]
    windows: Optional[TargetConfig]
    env: dict
    dry_run: bool


def run_scenario(scenario_id: str, path: Path, ctx: RunContext) -> bool:
    """Load and run a scenario module. Returns True on pass, False on fail."""
    module_name = f"scenarios.{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    print(f"\n{'─' * 60}")
    print(f"  Scenario {scenario_id}: {getattr(mod, 'DESCRIPTION', path.stem)}")
    print(f"{'─' * 60}")

    if ctx.dry_run:
        print("  [DRY RUN] skipping execution")
        return True

    start = time.monotonic()
    try:
        mod.run(ctx)
        elapsed = time.monotonic() - start
        print(f"  ✓ PASSED ({elapsed:.1f}s)")
        return True
    except Exception as exc:
        elapsed = time.monotonic() - start
        print(f"  ✗ FAILED ({elapsed:.1f}s): {exc}")
        return False


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
        "--config-dir", type=Path, default=Path(__file__).parent / "config",
        help="Path to config directory",
    )
    args = parser.parse_args()

    config_dir = args.config_dir
    env = load_env(config_dir / "env.toml")
    targets_raw = load_targets(config_dir / "targets.toml")

    cli_cfg = make_cli_config(env)
    linux_target = make_target(targets_raw["linux"]) if "linux" in targets_raw else None
    windows_target = make_target(targets_raw["windows"]) if "windows" in targets_raw else None

    if args.target == "linux":
        windows_target = None
    elif args.target == "windows":
        linux_target = None

    ctx = RunContext(
        cli=cli_cfg,
        linux=linux_target,
        windows=windows_target,
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
    print(f"Dry run:  {ctx.dry_run}")
    print(f"Scenarios: {', '.join(sid for sid, _ in selected)}")

    passed = failed = 0
    for sid, path in selected:
        ok = run_scenario(sid, path, ctx)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n{'═' * 60}")
    print(f"  Results: {passed} passed, {failed} failed out of {passed + failed} scenarios")
    print(f"{'═' * 60}\n")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
