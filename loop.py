#!/usr/bin/env python3
"""
loop.py — Unified agent loop runner for Red Cell C2

Replaces: claude_loop.sh, claude_arch_loop.sh, claude_dev_loop.sh,
          claude_test_loop.sh, codex_loop.sh, codex_arch_loop.sh,
          codex_qa_loop.sh, codex_test_loop.sh, cursor_loop.sh
"""

import argparse
import fcntl
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_DIR = SCRIPT_DIR / "logs"

# Default sleep between iterations (seconds) when --sleep is not specified
DEFAULT_SLEEP = {
    "dev":         0,
    "qa":          20 * 60,    # 20 minutes
    "arch":        120 * 60,   # 120 minutes
    "quality":     30 * 60,    # 30 minutes
    "coverage":    30 * 60,    # 30 minutes
    "maintenance": 60 * 60,    # 60 minutes
    "feature":     0,          # default iterations=1, so sleep is irrelevant
    "autotest":    240 * 60,   # 4 hours — full suite is ~20 min, want time for dev loop
}

# Loop types that default to 1 iteration instead of running forever.
# User can override with --iterations N; --iterations 0 means unlimited.
DEFAULT_ITERATIONS = {
    "feature": 1,
}

# Dev loop timing constants (seconds)
DEV_SLEEP_NO_WORK     = 600    # wait when no tasks are ready
DEV_SLEEP_BETWEEN     = 15     # wait between tasks when --sleep not set
DEV_SLEEP_TOKEN_LIMIT = 1200   # wait after Claude context limit hit
DEV_CLEAN_EVERY       = 1      # run build-artifact cleanup every N dev iterations
DEV_MAX_TURNS         = 150    # max turns per dev session; agent commits WIP and resumes next iteration
MAX_CONSECUTIVE_CAP_OUTS = 2  # escalate after this many consecutive cap-outs on the same bead

# Valid zone names and their corresponding source paths
ZONES = {
    "client-cli": ["client-cli/"],
    "client":     ["client/"],
    "teamserver": ["teamserver/"],
    "common":     ["common/"],
    "archon":     ["agent/archon/"],
    "phantom":    ["agent/phantom/"],
    "specter":    ["agent/specter/"],
    "autotest":   ["automatic-test/"],
}

# Dev loops use agent-specific prompts (Co-Authored-By differs per agent)
DEV_PROMPTS = {
    "claude": "prompts/CLAUDE_DEV_PROMPT.md",
    "codex":  "prompts/CODEX_PROMPT.md",
    "cursor": "prompts/CURSOR_PROMPT.md",
}

# Lite QA prompt run after each dev task (agent-independent)
DEV_LITEQA_PROMPT = "prompts/DEV_LITEQA_PROMPT.md"
DEV_LITEQA_MAX_TURNS = 50

# Cap-out post-mortem prompt run when a dev session hits the turn/token limit
DEV_LITEQA_CAPOUT_PROMPT = "prompts/DEV_LITEQA_CAPOUT_PROMPT.md"
DEV_LITEQA_CAPOUT_MAX_TURNS = 30

# Pre-claim QA prompt run before claiming a bead (agent-independent)
PRE_CLAIM_QA_PROMPT = "prompts/PRE_CLAIM_QA_PROMPT.md"
PRE_CLAIM_QA_MAX_TURNS = 20

# Review loops use a single best-of prompt per loop type (agent-independent)
REVIEW_PROMPTS = {
    "qa":       "prompts/CLAUDE_PROMPT.md",        # identical across agents
    "arch":     "prompts/CLAUDE_ARCH_PROMPT.md",   # Claude version is more thorough
    "quality":  "prompts/CLAUDE_TEST_PROMPT.md",   # quality-focused test review
    "coverage": "prompts/CODEX_TEST_PROMPT.md",    # breadth-focused coverage scan
    "feature":  "prompts/CLAUDE_FEATURE_PROMPT.md", # feature completeness + integration gaps
    "autotest": "prompts/CLAUDE_AUTOTEST_PROMPT.md", # run autotest suite, classify failures, file beads
}

# Review loop types that write a per-run timestamped log in addition to the rolling log
PER_RUN_LOG_LOOPS = {"arch", "quality", "coverage", "feature", "autotest"}

# Loops that run against the live working tree (need real teamserver, gitignored
# config files like env.toml/targets.toml, the actual target/release binary).
# Skip the worktree isolation that the regular review_loop applies.
LIVE_WORKTREE_LOOPS = {"autotest"}


# ── Logging ────────────────────────────────────────────────────────────────────

class Logger:
    def __init__(self, agent_id: str, log_file: Path):
        self.agent_id = agent_id
        self.log_file = log_file
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def _format(self, msg: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{ts}] [{self.agent_id}] {msg}"

    def log(self, msg: str):
        line = self._format(msg)
        print(line, flush=True)
        with open(self.log_file, "a") as f:
            f.write(line + "\n")

    def banner(self, lines: list):
        sep = "=" * 56
        self.log(sep)
        for line in lines:
            self.log(f"  {line}")
        self.log(sep)


# ── Stop signal ────────────────────────────────────────────────────────────────

def stop_requested() -> bool:
    return (SCRIPT_DIR / ".stop").exists()


# ── Git / Beads helpers ────────────────────────────────────────────────────────

def git(args: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(SCRIPT_DIR)] + args,
        capture_output=True, text=True, **kwargs
    )


def br(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["br"] + args,
        capture_output=True, text=True, cwd=str(SCRIPT_DIR)
    )


def git_pull_rebase(log: Logger) -> bool:
    r = git(["pull", "--rebase", "--quiet"])
    if r.returncode == 0:
        log.log("git pull --rebase: ok")
        return True
    log.log("WARNING: git pull --rebase failed, continuing with local state")
    return False


def git_pull_ff(log: Logger) -> bool:
    r = git(["pull", "--ff-only", "--quiet"])
    if r.returncode == 0:
        log.log("git pull --ff-only: ok")
        return True
    log.log("WARNING: git pull --ff-only failed")
    return False


# ── Agent invocation ───────────────────────────────────────────────────────────

def build_agent_cmd(agent: str, model: str, max_turns: int = 0) -> tuple:
    """
    Returns (cmd, uses_stdin).
    Claude and Codex read the prompt from stdin; Cursor takes it as a positional arg.
    max_turns: if > 0, pass --max-turns to the Claude CLI (Claude only).
    """
    if agent == "claude":
        cmd = ["claude", "-p", "--dangerously-skip-permissions", "--verbose", "--output-format", "stream-json"]
        if model:
            cmd += ["--model", model]
        if max_turns > 0:
            cmd += ["--max-turns", str(max_turns)]
        return cmd, True

    if agent == "codex":
        return ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox"], True

    if agent == "cursor":
        # prompt is injected as positional arg at call time
        cmd = [
            "agent", "--print", "--yolo", "--trust", "--approve-mcps",
            "--workspace", str(SCRIPT_DIR),
        ]
        if model:
            cmd += ["--model", model]
        return cmd, False

    raise ValueError(f"Unknown agent: {agent}")


def run_agent(
    agent: str,
    model: str,
    prompt_content: str,
    log: Logger,
    extra_log_file: Path = None,
    cwd: Path = None,
    extra_env: dict = None,
    max_turns: int = 0,
) -> tuple:
    """
    Run the agent with prompt_content. Streams output to terminal and log files.
    Returns (exit_code, full_output_text, result_subtype).

    For claude (stream-json mode): raw JSON is written to log files; human-readable
    tool/text events are printed to the terminal. The returned text is the extracted
    final response from the result event. result_subtype is the Claude result event
    subtype (e.g. 'success', 'max_turns', 'error_max_tokens'); empty string for
    non-Claude agents.

    cwd: working directory for the agent subprocess (defaults to SCRIPT_DIR).
    extra_env: additional environment variables merged into the subprocess environment.
    max_turns: if > 0, pass --max-turns to Claude CLI (Claude only).
    """
    cmd, uses_stdin = build_agent_cmd(agent, model, max_turns=max_turns)
    is_stream_json = agent == "claude"
    run_cwd = str(cwd or SCRIPT_DIR)
    run_env = {**os.environ, **(extra_env or {})}

    if not uses_stdin:
        # Cursor: prompt is the final positional argument
        proc = subprocess.Popen(
            cmd + [prompt_content],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=run_cwd, env=run_env,
        )
    else:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=run_cwd, env=run_env,
        )

        def _write_stdin():
            try:
                proc.stdin.write(prompt_content)
                proc.stdin.close()
            except BrokenPipeError:
                pass

        threading.Thread(target=_write_stdin, daemon=True).start()

    log_handles = [open(log.log_file, "a")]
    if extra_log_file:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_handles.append(open(extra_log_file, "w"))

    raw_lines = []
    seen_result = False
    try:
        for line in proc.stdout:
            # Always write raw line to log files
            for fh in log_handles:
                fh.write(line)
                fh.flush()
            raw_lines.append(line)

            if is_stream_json:
                stripped = line.strip()
                if stripped:
                    try:
                        event = json.loads(stripped)
                        formatted = format_stream_event(event)
                        if formatted is not None:
                            print(formatted, flush=True)
                        if event.get("type") == "result":
                            seen_result = True
                            break
                    except json.JSONDecodeError:
                        print(line, end="", flush=True)
            else:
                print(line, end="", flush=True)
    finally:
        for fh in log_handles:
            fh.close()

    if seen_result:
        # Claude signalled end_turn but may not close stdout; don't wait for EOF.
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    else:
        proc.wait()

    if is_stream_json:
        return proc.returncode, extract_text_from_stream(raw_lines), extract_result_subtype_from_stream(raw_lines)
    return proc.returncode, "".join(raw_lines), ""


# ── Sleep with jitter ──────────────────────────────────────────────────────────

def do_sleep(seconds: float, jitter_seconds: float, log: Logger):
    if seconds <= 0 and jitter_seconds <= 0:
        return

    if jitter_seconds > 0:
        delta = random.uniform(-jitter_seconds, jitter_seconds)
        actual = max(0.0, seconds + delta)
    else:
        actual = seconds

    if actual <= 0:
        return

    wake_str = datetime.fromtimestamp(time.time() + actual).strftime("%H:%M:%S")
    mins = actual / 60
    if jitter_seconds > 0:
        log.log(
            f"Next run in {mins:.0f}m (at {wake_str})"
            f"  [jitter ±{jitter_seconds/60:.0f}m applied]"
        )
    else:
        log.log(f"Next run in {mins:.0f}m (at {wake_str})")

    time.sleep(actual)


# ── Output parsing ────────────────────────────────────────────────────────────

def extract_session_summary(output: str) -> list:
    """
    Extract the structured session summary block from agent output.
    Returns a list of lines between === SESSION SUMMARY === and === END SUMMARY ===,
    or an empty list if no summary block is found.
    """
    lines = output.splitlines()
    in_summary = False
    result = []
    for line in lines:
        stripped = line.strip()
        if "=== SESSION SUMMARY ===" in stripped:
            in_summary = True
            continue
        if "=== END SUMMARY ===" in stripped:
            break
        if in_summary and stripped:
            result.append(stripped)
    return result


def format_stream_event(event: dict) -> str | None:
    """
    Convert a claude stream-json event to a human-readable line.
    Returns None for events that should be silently skipped.
    """
    t = event.get("type", "")

    if t == "tool_use":
        name = event.get("name", "?")
        inp = event.get("input", {})
        if name == "Read":
            detail = inp.get("file_path", "?")
        elif name == "Bash":
            detail = inp.get("command", "?").strip().replace("\n", "; ")[:120]
        elif name == "Grep":
            detail = f"'{inp.get('pattern', '')}' in {inp.get('path', inp.get('directory', '.'))}"
        elif name == "Glob":
            detail = inp.get("pattern", "?")
        elif name in ("Edit", "Write"):
            detail = inp.get("file_path", "?")
        elif name == "Agent":
            detail = inp.get("description", inp.get("prompt", "?"))[:100]
        else:
            detail = str(inp)[:100]
        return f"  [{name}] {detail}"

    if t == "assistant":
        texts = [
            b.get("text", "")
            for b in event.get("message", {}).get("content", [])
            if b.get("type") == "text"
        ]
        combined = " ".join(texts).strip()
        return combined if combined else None

    if t == "result":
        subtype = event.get("subtype", "unknown")
        duration = event.get("duration_ms", 0) / 1000
        cost = event.get("total_cost_usd", 0)
        turns = event.get("num_turns", "?")
        return f"  [result] {subtype} — {turns} turns, {duration:.0f}s, ${cost:.4f}"

    return None  # skip system, tool_result, etc.


def extract_result_subtype_from_stream(raw_lines: list) -> str:
    """Return the subtype field from the Claude result event, e.g. 'success', 'max_turns', 'error_max_tokens'."""
    for line in reversed(raw_lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
            if event.get("type") == "result":
                return event.get("subtype", "")
        except json.JSONDecodeError:
            pass
    return ""


def extract_text_from_stream(raw_lines: list) -> str:
    """
    Extract the final text response from a claude stream-json session.
    Pulls from the 'result' event, falling back to concatenated assistant text blocks.
    """
    for line in reversed(raw_lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
            if event.get("type") == "result":
                return event.get("result", "")
        except json.JSONDecodeError:
            pass
    # Fallback: collect assistant text blocks in order
    texts = []
    for line in raw_lines:
        try:
            event = json.loads(line.strip())
            if event.get("type") == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if block.get("type") == "text":
                        texts.append(block.get("text", ""))
        except json.JSONDecodeError:
            pass
    return "\n".join(texts)


# ── Zone constraint ────────────────────────────────────────────────────────────

# Zone → Rust package names for scoped builds/tests.
# None means use --workspace (changes can affect all crates, e.g. common).
# []   means no Rust crate at all (C/ASM or Python zone — skip cargo entirely).
ZONE_PACKAGES = {
    "teamserver": ["red-cell"],       # red-cell-common is a dep — checked transitively
    "client":     ["red-cell-client"],
    "client-cli": ["red-cell-cli"],
    "common":     None,      # --workspace: changes here can break any crate
    "archon":     [],        # C/ASM — no Rust crate
    "phantom":    [],        # Rust agent — built separately, not in workspace
    "specter":    [],        # Rust agent — built separately, not in workspace
    "autotest":   [],        # Python — no Rust crate
}


def build_zone_block(zones: list) -> str:
    """Build a zone constraint block for injection into agent prompts."""
    if not zones:
        return ""
    allowed_paths = []
    for z in zones:
        allowed_paths.extend(ZONES.get(z, [f"{z}/"]))
    paths_list = "\n".join(f"- `{p}`" for p in allowed_paths)

    # Compute cargo flags for all named zones.
    # None entry → --workspace; [] entry → no Rust; list → -p <pkg> ...
    pkgs_seen: set = set()
    pkgs_ordered: list = []
    use_workspace = False
    has_no_rust = False
    for z in zones:
        packages = ZONE_PACKAGES.get(z)
        if packages is None:
            use_workspace = True
        elif len(packages) == 0:
            has_no_rust = True
        else:
            for pkg in packages:
                if pkg not in pkgs_seen:
                    pkgs_seen.add(pkg)
                    pkgs_ordered.append(pkg)

    if use_workspace:
        cargo_flags = "--workspace"
    elif pkgs_ordered:
        cargo_flags = " ".join(f"-p {pkg}" for pkg in pkgs_ordered)
    else:
        cargo_flags = None  # pure agent zone — no Rust

    if cargo_flags:
        cargo_scope_section = f"""
### Cargo scope for this zone

Use **`{cargo_flags}`** for all cargo commands (check, nextest, clippy).
Do NOT use `--workspace` unless explicitly listed above.
"""
    elif has_no_rust:
        cargo_scope_section = """
### Cargo scope for this zone

This zone has no Rust crate — skip all cargo commands.
"""
    else:
        cargo_scope_section = ""

    return f"""
---

## Zone Constraint

You are operating in zone(s): {', '.join(f'`{z}`' for z in zones)}

**STRICT**: Only modify files inside:
{paths_list}
{cargo_scope_section}
### If a test outside your zone fails

Before filing a bug, check `docs/known-failures.md`:

```bash
grep -i "<test name or keyword>" docs/known-failures.md
```

If it is already listed, do NOT create a new issue — the bug is tracked. Link your task
to the existing issue if relevant: `br dep add <existing-id> <your-task-id>`

If it is NOT listed, search for duplicates then create a beads issue:
```bash
br search "<key phrase from title>"
br create \\
  --title="bug: <test name> — <one-line symptom>" \\
  --description="**Failing test**: <exact test name>
**Repro command**: <exact cargo test command that reproduces it>
**Full error output**:
```
<paste the complete test failure output here — do not truncate>
```
**Context**: Encountered while working on <your-issue-id> in zone(s): {', '.join(f'`{z}`' for z in zones)}.
This is outside my zone — needs teamserver/common/client follow-up." \\
  --type=bug \\
  --priority=2 \\
  --labels=zone:<other-zone>
```

### If work in another zone is required (not a test failure)

```bash
br search "<key phrase from title>"
br create --title="..." --description="..." --type=task --priority=<N> --labels=zone:<zone>
```
"""


# ── Dev loop helpers ───────────────────────────────────────────────────────────

def issue_status_from_jsonl(task_id: str) -> str:
    """Read the last status entry for task_id directly from the JSONL file."""
    jsonl = SCRIPT_DIR / ".beads" / "issues.jsonl"
    if not jsonl.exists():
        return ""
    last = None
    try:
        with open(jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get("id") == task_id:
                        last = e
                except json.JSONDecodeError:
                    pass
        return (last or {}).get("status", "")
    except Exception:
        return ""


def issue_status(task_id: str) -> str:
    """Query issue status via the br CLI."""
    r = br(["show", task_id, "--json"])
    if r.returncode != 0:
        return ""
    try:
        issues = json.loads(r.stdout)
        if issues:
            return issues[0].get("status", "")
    except Exception:
        pass
    return ""


def issue_title(task_id: str) -> str:
    """Query issue title via the br CLI. Returns empty string on failure."""
    r = br(["show", task_id, "--json"])
    if r.returncode != 0:
        return ""
    try:
        issues = json.loads(r.stdout)
        if issues:
            return issues[0].get("title", "")
    except Exception:
        pass
    return ""


def repair_db_if_needed(log: Logger, rename_prefix: bool):
    """Rebuild the beads SQLite DB from JSONL if schema drift is detected."""
    r = br(["stats", "--json"])
    combined = r.stdout + r.stderr
    if '"DATABASE_ERROR"' not in combined:
        return
    log.log("DB schema error detected — rebuilding from JSONL")
    db = SCRIPT_DIR / ".beads" / "beads.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    args = ["sync", "--import-only", "--quiet"]
    if rename_prefix:
        args.insert(2, "--rename-prefix")
    r = br(args)
    if r.returncode == 0:
        log.log("DB rebuilt successfully")
    else:
        log.log("WARNING: DB rebuild failed")


DEBUG_SIZE_LIMIT_GB   = 4      # nuke target/* build subdirs when total target/ exceeds this size
MIN_FREE_DISK_GB      = 30.0  # bail if less than this many GB free before starting a session


def check_disk_space(log: Logger) -> bool:
    """
    Return True if there is enough free disk space to proceed.
    Logs a warning and returns False if free space is below MIN_FREE_DISK_GB.
    Called once at the top of each dev loop iteration so the agent never starts
    a session that will ENOSPC mid-build (which wastes the entire session).
    """
    try:
        stat = os.statvfs(SCRIPT_DIR)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
        if free_gb < MIN_FREE_DISK_GB:
            log.log(
                f"PREFLIGHT FAIL: only {free_gb:.1f} GB free on disk "
                f"(need {MIN_FREE_DISK_GB} GB) — skipping iteration to avoid ENOSPC"
            )
            return False
        log.log(f"preflight: disk OK ({free_gb:.1f} GB free)")
        return True
    except OSError as e:
        log.log(f"WARNING: could not check disk space: {e}")
        return True   # don't block on stat failure


def kill_stale_cargo_processes(log: Logger):
    """
    Kill cargo/rustc processes older than 1 hour that are not associated with the
    current loop process tree.  These stale processes hold the Cargo build-directory
    file lock and block all subsequent cargo check / nextest / clippy invocations.

    Safe because:
    - We only kill processes older than STALE_CARGO_AGE_SECS (1 hour).
    - We skip any process whose PID is in our own process group.
    - We use SIGTERM first, SIGKILL only if still alive after 3 s.
    """
    import signal

    STALE_CARGO_AGE_SECS = 3600
    our_pgid = os.getpgrp()

    try:
        result = subprocess.run(
            ["pgrep", "-a", "-x", "cargo"],
            capture_output=True, text=True,
        )
        pids = []
        for line in result.stdout.splitlines():
            parts = line.split(None, 1)
            if not parts:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            # Skip processes in our own process group
            try:
                if os.getpgid(pid) == our_pgid:
                    continue
            except OSError:
                continue
            # Check process age via /proc/<pid>/stat
            try:
                with open(f"/proc/{pid}/stat") as f:
                    fields = f.read().split()
                # Field 22 (0-indexed 21) is starttime in clock ticks
                starttime_ticks = int(fields[21])
                hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
                with open("/proc/stat") as f:
                    for l in f:
                        if l.startswith("btime"):
                            boot_time = int(l.split()[1])
                            break
                    else:
                        continue
                start_epoch = boot_time + starttime_ticks / hz
                age_secs = time.time() - start_epoch
                if age_secs >= STALE_CARGO_AGE_SECS:
                    pids.append((pid, age_secs))
            except (OSError, IndexError, ValueError):
                continue

        if not pids:
            log.log("preflight: no stale cargo processes found")
            return

        for pid, age in pids:
            log.log(f"preflight: killing stale cargo PID {pid} (age {age/3600:.1f}h)")
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
        time.sleep(3)
        for pid, _ in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass   # already gone — good
        log.log(f"preflight: killed {len(pids)} stale cargo process(es)")

    except FileNotFoundError:
        log.log("preflight: pgrep not available — skipping stale-cargo check")


def _dir_size_gb(path) -> float:
    """Return the total size of a directory tree in GB."""
    total = 0
    for entry in os.scandir(path):
        try:
            if entry.is_dir(follow_symlinks=False):
                total += int(subprocess.run(
                    ["du", "-sb", entry.path],
                    capture_output=True, text=True,
                ).stdout.split()[0])
            else:
                total += entry.stat(follow_symlinks=False).st_size
        except (OSError, IndexError, ValueError):
            pass
    return total / (1024 ** 3)


def clean_build_artifacts(log: Logger, force: bool = False):
    """
    Remove stale Rust build artifacts to keep target/ from growing unboundedly.

    Strategy:
    - Measure total target/ size (debug + all codex-* alternate target dirs).
    - If total exceeds DEBUG_SIZE_LIMIT_GB (or force=True), nuke heavyweight subdirs
      (incremental, deps, build, .fingerprint) in every target profile dir.
    - Uses ignore_errors=True on rmtree to survive races with concurrent cargo
      processes that may be writing into the same dirs.

    force=True: skip the size threshold check and always clean. Used before starting
    a new agent session to guarantee the session doesn't inherit stale artifact bloat.

    Called after every review-loop iteration and every DEV_CLEAN_EVERY dev iterations.
    Also called unconditionally (force=True) before each dev agent session starts.
    """
    import shutil

    target_root = SCRIPT_DIR / "target"
    if not target_root.exists():
        return

    # Collect all cargo profile dirs inside target/.
    # Detect by presence of at least one heavyweight subdir rather than name-matching,
    # so any agent-specific CARGO_TARGET_DIR (codex-*, cursor-*, etc.) is caught
    # automatically without needing to update this list when new profiles appear.
    heavyweight_markers = {"deps", "build", "incremental", ".fingerprint"}
    profile_dirs = []
    for entry in target_root.iterdir():
        if not entry.is_dir():
            continue
        children = {e.name for e in entry.iterdir()} if entry.is_dir() else set()
        if children & heavyweight_markers:
            profile_dirs.append(entry)

    if not profile_dirs:
        return

    total_gb = sum(_dir_size_gb(d) for d in profile_dirs)
    if not force and total_gb < DEBUG_SIZE_LIMIT_GB:
        log.log(f"build cache: target/ build dirs are {total_gb:.1f} GB — under limit, skipping")
        return

    if _cargo_target_locked(target_root):
        log.log("build cache: cargo build in progress — skipping cleanup to avoid mid-build wipe")
        return

    reason = "pre-session forced clean" if force else f"exceeds {DEBUG_SIZE_LIMIT_GB} GB limit"
    log.log(f"build cache: target/ build dirs are {total_gb:.1f} GB — {reason}, nuking")

    heavyweight_dirs = ["incremental", "deps", "build", ".fingerprint"]
    removed = []
    for profile in profile_dirs:
        for name in heavyweight_dirs:
            d = profile / name
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
                if not d.exists():
                    removed.append(f"{profile.name}/{name}")
    if removed:
        log.log(f"build cache: removed {', '.join(removed)}")


WORKTREE_MAX_AGE_SECS = 3600   # remove /tmp/red-cell* worktrees older than 1 hour


def _cargo_target_locked(target_dir: Path) -> bool:
    """
    Return True if any cargo build is actively writing into target_dir.

    Cargo holds an exclusive flock on <target>/<profile>/.cargo-lock for the
    entire duration of a build.  We try a non-blocking LOCK_EX on every
    .cargo-lock file found inside target_dir; if any attempt fails with EWOULDBLOCK
    the directory is in active use and must not be cleaned.
    """
    import glob as _glob
    for lock_path in _glob.iglob(str(target_dir / "*" / ".cargo-lock")):
        try:
            fd = os.open(lock_path, os.O_RDONLY)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            return True   # lock is held — build in progress
        finally:
            os.close(fd)
    return False


def _path_within_tree(path: Path, root: Path) -> bool:
    """
    Return True if path resolves to root or to a directory/file under root.

    Used to detect processes whose cwd lives inside a Cargo target directory.
    """
    try:
        p = path.resolve()
        r = root.resolve()
    except OSError:
        return False
    try:
        p.relative_to(r)
        return True
    except ValueError:
        return False


# Commands that legitimately hold files open inside a Cargo target directory.
# A shell, editor, or test binary with CWD inside target/ must NOT block cleanup.
# "build-script-build" exceeds the 15-char comm limit; the exe-basename fallback
# covers it.
_CARGO_BUILD_COMMS: frozenset[str] = frozenset(
    {
        "cargo",
        "rustc",
        "cargo-nextest",
        "nextest",
        "cc1",
        "ld",
        "ar",
        "build-script-build",
        "build-script-bui",  # comm-truncated form of build-script-build
    }
)


def _is_cargo_build_process(pid_dir: Path) -> bool:
    """
    Return True if the process in pid_dir is a cargo / rustc / build-tool binary.

    Reads /proc/<pid>/comm first (fast kernel short-name, ≤15 chars).
    Falls back to the basename of /proc/<pid>/exe for names that get truncated.
    Returns False on any read error so callers stay conservative only where needed.
    """
    comm_path = pid_dir / "comm"
    try:
        comm = comm_path.read_text().strip()
        if comm in _CARGO_BUILD_COMMS:
            return True
    except OSError:
        pass

    exe_path = pid_dir / "exe"
    try:
        exe_name = Path(os.readlink(str(exe_path))).name
        if exe_name in _CARGO_BUILD_COMMS:
            return True
    except OSError:
        pass

    return False


def _stable_cargo_target_in_use(target_dir: Path, _proc_root: Path | None = None) -> bool:
    """
    Return True if a cargo/rustc/nextest process is actively using target_dir.

    Cargo holds .cargo-lock only while compiling; ``cargo nextest`` releases it
    before running tests.  ``clean_tmp_cargo_targets`` must not delete
    ``debug/deps`` during that window or nextest's [double-spawn] exec hits
    ENOENT (see red-cell-c2-sl2cm / red-cell-c2-5jieq).

    We only block on processes whose command name is in ``_CARGO_BUILD_COMMS``.
    A long-lived shell, editor, or test binary with CWD inside the target dir is
    not a risk to ``debug/deps`` and must not prevent cleanup.
    """
    try:
        resolved_root = target_dir.resolve()
    except OSError:
        return True

    proc = _proc_root if _proc_root is not None else Path("/proc")
    try:
        pid_dirs = [e for e in proc.iterdir() if e.name.isdigit()]
    except OSError:
        return False

    for pid_dir in pid_dirs:
        # Only consider this process if it is a cargo/rust build tool.
        if not _is_cargo_build_process(pid_dir):
            continue

        cwd_link = pid_dir / "cwd"
        try:
            cwd = cwd_link.readlink()
        except OSError:
            cwd = None
        if cwd is not None and _path_within_tree(cwd, resolved_root):
            return True

        env_path = pid_dir / "environ"
        try:
            raw = env_path.read_bytes()
        except OSError:
            continue
        for chunk in raw.split(b"\0"):
            if not chunk.startswith(b"CARGO_TARGET_DIR="):
                continue
            rest = chunk[len(b"CARGO_TARGET_DIR="):]
            try:
                val = rest.decode("utf-8")
            except UnicodeDecodeError:
                val = rest.decode("utf-8", errors="replace")
            env_path_val = Path(val).expanduser()
            if _path_within_tree(env_path_val, resolved_root):
                return True
            if val.rstrip("/") == str(resolved_root).rstrip("/"):
                return True
            break

    return False


def _active_worktree_paths() -> set:
    """
    Return the set of /tmp/red-cell* root paths that are, or contain, the
    working directory of at least one currently running process.

    Uses /proc/PID/cwd (Linux only). Silently ignores entries we cannot
    read (permission errors, races with short-lived processes, etc.).

    This is used by clean_tmp_worktrees() to skip worktrees that still have
    active processes (cargo, git, Claude Code sub-agents, etc.) inside them,
    preventing the cleanup from destroying a live loop's workspace.
    """
    active: set = set()
    try:
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                # os.readlink is a single syscall — fast, no stat, no resolve
                cwd_str = os.readlink(pid_dir / "cwd")
            except OSError:
                continue
            if not cwd_str.startswith("/tmp/"):
                continue
            # Extract the top-level /tmp/<name> component
            rest = cwd_str[len("/tmp/"):]
            top_name = rest.split("/")[0]
            if top_name.startswith(("red-cell", "redcell")):
                active.add("/tmp/" + top_name)
    except OSError:
        pass
    return active


def clean_tmp_worktrees(log: Logger):
    """
    Remove stale git worktrees under /tmp that were created by QA/arch review runs.

    Each review loop iteration creates a worktree in /tmp (e.g. /tmp/red-cell-qa-*)
    via Claude Code's isolation: worktree feature. Every worktree accumulates its own
    cargo build artifacts. Without cleanup these fill the disk within hours.

    Strategy:
    1. git worktree prune  — removes entries whose directory is already gone.
    2. For each remaining /tmp/red-cell* worktree:
       a. Skip if any process currently has its CWD inside this worktree — it is
          still active (running agent, cargo build, git operation, etc.).
       b. Skip if the directory is younger than WORKTREE_MAX_AGE_SECS.
       c. Otherwise: nuke cargo artifacts first, then git worktree remove --force,
          falling back to shutil.rmtree if git refuses.
    """
    import shutil, time as _time

    # Step 1: prune stale registrations
    subprocess.run(
        ["git", "worktree", "prune"],
        capture_output=True, cwd=str(SCRIPT_DIR),
    )

    # Step 2: list all worktrees, find /tmp/red-cell* ones past their age limit
    r = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        capture_output=True, text=True, cwd=str(SCRIPT_DIR),
    )
    if r.returncode != 0:
        return

    worktree_paths = [
        line.split(" ", 1)[1]
        for line in r.stdout.splitlines()
        if line.startswith("worktree ")
    ]

    # Snapshot active worktrees once — avoids repeated /proc scans per iteration
    active_worktrees = _active_worktree_paths()

    now = _time.time()
    removed = []
    skipped_active = []
    for path_str in worktree_paths:
        p = Path(path_str)
        # Only touch /tmp/red-cell* dirs — never the main worktree or .claude/worktrees
        if not path_str.startswith("/tmp/") or not p.name.startswith(("red-cell", "redcell")):
            continue

        # Skip worktrees that have at least one process currently running inside them
        if path_str in active_worktrees:
            skipped_active.append(p.name)
            continue

        try:
            age = now - p.stat().st_mtime
        except OSError:
            continue
        if age < WORKTREE_MAX_AGE_SECS:
            continue

        # Remove cargo artifacts inside the worktree first to avoid slow rmtree
        for subdir in ["target/debug", "target/release"]:
            td = p / subdir
            if td.exists():
                try:
                    shutil.rmtree(td)
                except OSError:
                    pass

        # Remove the worktree registration + directory
        rm = subprocess.run(
            ["git", "worktree", "remove", "--force", path_str],
            capture_output=True, cwd=str(SCRIPT_DIR),
        )
        if rm.returncode != 0 and p.exists():
            # git couldn't remove it (e.g. untracked files) — force via rm
            try:
                shutil.rmtree(p)
                subprocess.run(
                    ["git", "worktree", "prune"],
                    capture_output=True, cwd=str(SCRIPT_DIR),
                )
            except OSError as e:
                log.log(f"worktree cleanup: could not remove {p}: {e}")
                continue
        removed.append(p.name)

    if skipped_active:
        log.log(
            f"worktree cleanup: skipped {len(skipped_active)} active worktree(s)"
            f" (processes still running): {', '.join(skipped_active)}"
        )
    if removed:
        log.log(f"worktree cleanup: removed {len(removed)} stale worktree(s): {', '.join(removed)}")
    else:
        log.log("worktree cleanup: nothing to remove")


TMP_CARGO_MAX_AGE_SECS = 7200   # remove non-worktree /tmp/red-cell* cargo dirs older than 2 hours
TMP_CARGO_SIZE_LIMIT_GB = 5     # also clean heavyweight subdirs of review target when it exceeds this
TMP_CARGO_HARD_LIMIT_GB = 15    # force clean even if _stable_cargo_target_in_use; .cargo-lock still respected


def _clean_cargo_target_inplace(
    target_dir: Path,
    label: str,
    size_limit_gb: float,
    log: Logger,
    hard_limit_gb: float = TMP_CARGO_HARD_LIMIT_GB,
):
    """
    Clean heavyweight subdirs inside a stable cargo target dir when it exceeds
    size_limit_gb.  Never deletes the directory itself so incremental builds survive.

    Cargo lays out target/ as <profile>/{deps,build,incremental,.fingerprint}
    for host-only builds, or <triple>/<profile>/{...} for cross-compile targets.
    We handle both shapes — without the depth-2 fallback, cross-compile
    heavyweights (musl, mingw) accumulate forever (red-cell-c2-drxmc).

    hard_limit_gb: when size >= this threshold the _stable_cargo_target_in_use
    check is bypassed and the dir is cleaned unconditionally (modulo .cargo-lock,
    which is checked by the caller).  Unbounded disk growth is worse than a
    recoverable test ENOENT.
    """
    import shutil as _shutil
    size_gb = _dir_size_gb(target_dir)
    if size_gb < size_limit_gb:
        return
    if _stable_cargo_target_in_use(target_dir):
        if size_gb < hard_limit_gb:
            log.log(
                f"tmp cargo: {label} — in use (cwd or CARGO_TARGET_DIR), "
                "deferring heavyweight clean"
            )
            return
        log.log(
            f"tmp cargo: {label} is {size_gb:.1f} GB >= hard limit {hard_limit_gb:.0f} GB — "
            "forcing clean despite in-use check"
        )
    log.log(f"tmp cargo: {label} is {size_gb:.1f} GB — cleaning heavyweight subdirs")
    heavyweight_dirs = ["incremental", "deps", "build", ".fingerprint"]
    profile_markers = {"deps", "build", "incremental", ".fingerprint"}
    cleaned = []

    def _clean_profile(profile: Path, prefix: str = "") -> bool:
        try:
            children = {e.name for e in profile.iterdir()}
        except OSError:
            return False
        if not children & profile_markers:
            return False
        for name in heavyweight_dirs:
            d = profile / name
            if d.exists():
                _shutil.rmtree(d, ignore_errors=True)
                if not d.exists():
                    cleaned.append(f"{prefix}{profile.name}/{name}")
        return True

    for entry in target_dir.iterdir():
        if not entry.is_dir():
            continue
        # Depth 1: <profile>/{deps,...} — host-only builds.
        if _clean_profile(entry):
            continue
        # Depth 2: <triple>/<profile>/{deps,...} — cross-compile (musl, mingw, ...).
        try:
            for sub in entry.iterdir():
                if sub.is_dir():
                    _clean_profile(sub, prefix=f"{entry.name}/")
        except OSError:
            continue

    if cleaned:
        log.log(f"tmp cargo: cleaned {label}/{{{','.join(cleaned)}}}")


def clean_tmp_cargo_targets(log: Logger, force: bool = False):
    """
    Remove stale Cargo target directories under /tmp that are NOT git worktrees.

    Review loops keep stable dirs (REVIEW_CARGO_TARGET for arch/quality/coverage,
    QA_CARGO_TARGET for qa) and dev loops keep per-zone stable dirs
    (/tmp/red-cell-target-<zone>).  All other
    /tmp/red-cell* dirs that aren't git worktrees are swept and deleted when stale.

    Strategy:
    - Stable dirs (review + dev zone): clean heavyweight subdirs in-place when they
      exceed TMP_CARGO_SIZE_LIMIT_GB.  Never delete — preserves incremental cache.
      Skip entirely if a cargo build is actively holding the lock.
      Defer cleaning if processes reference the dir via cwd or CARGO_TARGET_DIR
      (nextest releases .cargo-lock before executing tests; see
      _stable_cargo_target_in_use).
    - Transient dirs (everything else): remove entirely if older than
      TMP_CARGO_MAX_AGE_SECS and no process has its CWD inside them.

    force=True: clean all stable dirs unconditionally regardless of size. Used in
    pre-session cleanup so the zone target dir is always wiped before a new agent
    session starts, not just when it happens to exceed TMP_CARGO_SIZE_LIMIT_GB.
    """
    import shutil, time as _time

    # Collect paths that are registered git worktrees — never touch those here.
    r = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        capture_output=True, text=True, cwd=str(SCRIPT_DIR),
    )
    registered_worktrees = set()
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if line.startswith("worktree "):
                registered_worktrees.add(line.split(" ", 1)[1])

    active = _active_worktree_paths()
    now = _time.time()
    removed = []

    try:
        tmp_entries = list(Path("/tmp").iterdir())
    except OSError:
        return

    # Identify all stable cargo target dirs: review target + dev zone targets.
    # These are cleaned in-place (never deleted) to preserve incremental build cache.
    stable_targets: dict[str, Path] = {str(REVIEW_CARGO_TARGET): REVIEW_CARGO_TARGET}
    for entry in tmp_entries:
        if entry.name.startswith("red-cell-target-") and entry.is_dir():
            path_str = str(entry)
            if path_str not in registered_worktrees:
                stable_targets[path_str] = entry

    size_limit = 0.0 if force else TMP_CARGO_SIZE_LIMIT_GB
    for path_str, target_dir in stable_targets.items():
        if not target_dir.exists():
            continue
        if _cargo_target_locked(target_dir):
            log.log(f"tmp cargo: {target_dir.name} — build in progress, skipping")
            continue
        label = target_dir.name
        _clean_cargo_target_inplace(target_dir, label, size_limit, log)

    # Sweep all remaining /tmp/red-cell* dirs that are plain transient cargo caches.
    for entry in tmp_entries:
        if not entry.name.startswith(("red-cell", "redcell")):
            continue
        path_str = str(entry)
        if path_str in stable_targets:
            continue  # already handled above
        if path_str in registered_worktrees:
            continue  # let clean_tmp_worktrees handle these
        if path_str in active:
            continue  # process still running inside (CWD check)
        if not entry.is_dir():
            continue
        try:
            age = now - entry.stat().st_mtime
        except OSError:
            continue
        if age < TMP_CARGO_MAX_AGE_SECS:
            continue
        shutil.rmtree(entry, ignore_errors=True)
        if not entry.exists():
            removed.append(entry.name)

    if removed:
        log.log(f"tmp cargo: removed {len(removed)} stale dir(s): {', '.join(removed)}")


def reset_stuck_tasks(log: Logger, stale_threshold_secs: int):
    """Reset any in_progress tasks that have been stuck longer than the threshold."""
    r = br(["list", "--status=in_progress", "--json"])
    if r.returncode != 0:
        return
    try:
        issues = json.loads(r.stdout)
    except Exception:
        return
    now = datetime.now(timezone.utc)
    for issue in issues:
        ts = issue.get("updated_at") or issue.get("created_at", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if (now - dt).total_seconds() > stale_threshold_secs:
                tid = issue["id"]
                log.log(
                    f"SAFEGUARD: {tid} stuck in_progress for"
                    f" >{stale_threshold_secs}s — resetting to open"
                )
                r2 = br(["update", tid, "--status=open"])
                if r2.returncode == 0:
                    log.log(f"SAFEGUARD: {tid} reset to open")
                else:
                    log.log(f"WARNING: failed to reset {tid}")
        except ValueError:
            pass


def extract_cap_out_checkpoint(output: str, summary: list) -> str:
    """Return a short checkpoint string from a capped-out session."""
    if summary:
        return "\n".join(summary)[:2048]
    return output[-2048:].strip() if output else ""


def release_cap_out_bead(task_id: str, checkpoint: str, agent_id: str, log: Logger, cause: str = "turn_limit") -> None:
    """Reset a cap-out bead to open and prepend a checkpoint note, preserving prior checkpoints."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_entry = (
        f"--- CAP-OUT CHECKPOINT {ts} (auto-reset by {agent_id}) ---\n\n{checkpoint}"
        if checkpoint
        else f"--- CAP-OUT {ts}: session hit {cause.replace('_', ' ')}. Auto-reset by {agent_id}. ---"
    )

    # Read existing notes so we can prepend rather than overwrite.
    existing_notes = ""
    show_r = br(["show", task_id, "--json"])
    if show_r.returncode == 0:
        try:
            data = json.loads(show_r.stdout)
            existing_notes = (data[0].get("notes") or "") if data else ""
        except (json.JSONDecodeError, IndexError, KeyError):
            pass

    if existing_notes:
        combined = f"{new_entry}\n\n{existing_notes}"
    else:
        combined = new_entry

    # Cap total note length so br update never rejects an oversized payload.
    if len(combined) > 4000:
        log.log(f"WARNING: cap-out notes for {task_id} truncated from {len(combined)} to 4000 chars — oldest checkpoint(s) may be lost")
    note = combined[:4000]
    r = br(["update", task_id, "--notes", note, "--status=open", "--owner", ""])
    if r.returncode != 0:
        log.log(
            f"WARNING: br update {task_id} failed (rc={r.returncode}) — "
            "skipping checkpoint commit to avoid false-positive"
        )
        return
    commit_beads_if_dirty(f"release {task_id} after cap-out [{agent_id}]", log)
    log.log(f"CAP-OUT: {task_id} reset to open, checkpoint written")


def extract_pre_claim_verdict(output: str) -> tuple:
    """
    Parse the PRE-CLAIM QA RESULT block from agent output.

    Returns (verdict, reason) where verdict is one of 'PASS', 'REFINED', 'BLOCKED',
    or 'UNKNOWN' if the block is missing or malformed.
    """
    start = output.rfind("=== PRE-CLAIM QA RESULT ===")
    end = output.find("=== END PRE-CLAIM QA ===", start)
    if start == -1 or end == -1:
        return "UNKNOWN", "pre-claim agent produced no structured result block"

    block = output[start:end]
    verdict = "UNKNOWN"
    reason = ""
    for line in block.splitlines():
        if line.startswith("Verdict:"):
            verdict = line.split(":", 1)[1].strip().upper()
        elif line.startswith("Reason:"):
            reason = line.split(":", 1)[1].strip()

    if verdict not in ("PASS", "REFINED", "BLOCKED"):
        verdict = "UNKNOWN"
    return verdict, reason


def run_pre_claim_qa(
    task_id: str,
    agent: str,
    model: str,
    agent_id: str,
    max_turns: int,
    log: Logger,
) -> tuple:
    """
    Run the pre-claim quality gate for a candidate bead.

    Returns (verdict, reason) where verdict is 'PASS', 'REFINED', 'BLOCKED',
    or 'UNKNOWN' (treated as PASS to avoid blocking on gate failures).
    """
    prompt_file = SCRIPT_DIR / PRE_CLAIM_QA_PROMPT
    if not prompt_file.exists():
        log.log(f"WARNING: pre-claim QA prompt not found at {prompt_file} — skipping gate")
        return "PASS", "prompt file missing"

    template = prompt_file.read_text()
    issue_details = br(["show", task_id]).stdout.strip() or f"Issue ID: {task_id}"
    prompt = (
        template
        .replace("{ISSUE_ID}", task_id)
        .replace("{AGENT_ID}", agent_id)
        .replace("{MAX_TURNS}", str(max_turns))
    )
    prompt += f"\n\n---\n\n## Bead Details\n\n{issue_details}\n"

    log.log(f"Running pre-claim QA on {task_id} (max {max_turns} turns)...")
    _exit, output, _ = run_agent(
        agent, model, prompt, log,
        max_turns=max_turns if agent == "claude" else 0,
    )

    verdict, reason = extract_pre_claim_verdict(output)
    log.log(f"Pre-claim QA [{task_id}]: verdict={verdict} reason={reason}")

    if verdict == "UNKNOWN":
        log.log(
            f"WARNING: pre-claim agent returned no structured verdict for {task_id}"
            f" — treating as PASS"
        )
        return "PASS", reason

    return verdict, reason


def filter_cap_out_candidates(
    candidates: list,
    cap_out_pending_skip: set,
) -> tuple:
    """
    Prefer candidates not in cap_out_pending_skip.
    Falls back to all candidates when every candidate is in the skip set
    (i.e. it is the only ready bead).

    Returns (filtered_candidates, skip_entries_consumed).
    """
    non_skipped = [c for c in candidates if c not in cap_out_pending_skip]
    result = non_skipped if non_skipped else candidates
    consumed = set(candidates) & cap_out_pending_skip
    return result, consumed


def find_resumable_task(agent_id: str) -> str:
    """
    Find a task this agent previously claimed that is still in_progress.
    Used to resume interrupted sessions without creating a second claim commit.
    """
    r = br(["list", "--status=in_progress", "--json"])
    if r.returncode != 0:
        return ""
    try:
        issues = json.loads(r.stdout)
    except Exception:
        return ""
    for issue in issues:
        tid = issue["id"]
        r2 = git([
            "log", "--oneline",
            f"--grep=chore: claim {tid} [{agent_id}]",
            "--max-count=1",
        ])
        if r2.stdout.strip():
            return tid
    return ""


def claim_task(task_id: str, agent_id: str, log: Logger, rename_prefix: bool) -> bool:
    """
    Claim a task with optimistic git locking.
    Pushes the claim commit immediately so other agents see it.
    Returns True on success, False if another agent beat us or something went wrong.
    """
    r = git(["rev-parse", "HEAD"])
    if r.returncode != 0:
        return False
    head_before = r.stdout.strip()

    # Bypass stale DB: check JSONL directly to detect double-claim
    if issue_status_from_jsonl(task_id) == "in_progress":
        log.log(
            f"CLAIM SKIP: {task_id} already in_progress in JSONL"
            f" (stale DB) — forcing DB rebuild"
        )
        db = SCRIPT_DIR / ".beads" / "beads.db"
        for suffix in ("", "-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)
        return False

    if br(["update", task_id, "--status=in_progress"]).returncode != 0:
        return False
    if br(["sync", "--flush-only"]).returncode != 0:
        return False

    # If JSONL didn't change, another agent's state may have already overwritten it
    if git(["diff", "--quiet", "--", ".beads/issues.jsonl"]).returncode == 0:
        log.log(f"CLAIM SKIP: {task_id} produced no JSONL change — refreshing")
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)
        return False

    git(["add", ".beads/issues.jsonl"])
    if git(["commit", "-m", f"chore: claim {task_id} [{agent_id}]", "--quiet"]).returncode != 0:
        log.log(f"CLAIM SKIP: failed to create claim commit for {task_id}")
        git(["restore", "--staged", ".beads/issues.jsonl"])
        git(["checkout", "--", ".beads/issues.jsonl"])
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)
        return False

    r = git(["rev-parse", "HEAD"])
    claim_commit = r.stdout.strip() if r.returncode == 0 else ""

    if git(["push", "--quiet"]).returncode == 0:
        git(["pull", "--ff-only", "--quiet"])
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)

        # Verify claim commit is still reachable (no force-push from another agent)
        if claim_commit:
            r2 = git(["merge-base", "--is-ancestor", claim_commit, "HEAD"])
            if r2.returncode != 0:
                log.log(f"CLAIM VERIFY FAILED: claim commit for {task_id} no longer on branch")
                return False

        final = issue_status(task_id)
        if final != "in_progress":
            log.log(
                f"CLAIM VERIFY FAILED: {task_id} expected in_progress,"
                f" got '{final or 'unknown'}'"
            )
            return False

        return True

    # Push failed — another agent pushed first
    log.log(f"CLAIM CONFLICT: another agent claimed {task_id} first — releasing")
    git(["reset", head_before, "--mixed", "--quiet"])
    git(["checkout", "--", ".beads/issues.jsonl"])
    git(["pull", "--ff-only", "--quiet"])
    args = ["sync", "--import-only", "--quiet"]
    if rename_prefix:
        args.insert(2, "--rename-prefix")
    br(args)
    return False


def normalize_codex_ids(log: Logger, agent_id: str):
    """
    Codex-only: normalise any red-xxx IDs to red-cell-c2-xxx prefix.
    Runs after br sync --import-only --rename-prefix may have updated the DB.
    """
    if br(["sync", "--flush-only", "--quiet"]).returncode == 0:
        return
    if br(["sync", "--flush-only", "--force", "--quiet"]).returncode != 0:
        return
    if git(["diff", "--quiet", "--", ".beads/issues.jsonl"]).returncode == 0:
        return  # nothing changed
    git(["add", ".beads/issues.jsonl"])
    r = git([
        "commit", "-m",
        f"chore: normalize issue IDs to red-cell-c2 prefix [{agent_id}]",
        "--quiet",
    ])
    if r.returncode == 0:
        if git(["push", "--quiet"]).returncode == 0:
            log.log("Normalized issue IDs in JSONL and pushed")
        else:
            log.log("WARNING: could not push normalized JSONL")


# ── Dev loop ───────────────────────────────────────────────────────────────────

def dev_loop(args, log: Logger):
    agent = args.agent
    rename_prefix = (agent == "codex")
    node_id = getattr(args, "_node_id_resolved", socket.gethostname())
    agent_id = f"{node_id}-{agent}"
    stale_secs = args.stale_threshold * 60

    # Sleep between tasks: use --sleep if given, else DEV_SLEEP_BETWEEN
    if args.sleep is not None:
        sleep_secs = args.sleep * 60
    else:
        sleep_secs = DEV_SLEEP_BETWEEN
    jitter_secs = args.jitter * 60

    prompt_file = SCRIPT_DIR / DEV_PROMPTS[agent]
    if not prompt_file.exists():
        log.log(f"ERROR: {prompt_file} not found. Exiting.")
        sys.exit(1)

    zones = args.zone or []
    max_iters = args.iterations
    iteration = 0

    zone_desc = ", ".join(zones) if zones else "all zones"
    dev_light = getattr(args, "dev_light", False)
    lite_qa_mode = "off (--dev-light)" if dev_light else "on"
    pre_claim_qa_turns = getattr(args, "pre_claim_qa_turns", PRE_CLAIM_QA_MAX_TURNS)
    pre_claim_qa_mode = (
        "off (--dev-light)" if dev_light
        else f"on (max {pre_claim_qa_turns} turns)"
    )
    log.banner([
        f"{agent.title()} development loop starting",
        f"Agent ID:  {agent_id}",
        f"Prompt:    {prompt_file.name}",
        f"Log:       {log.log_file.name}",
        f"Max runs:  {'unlimited' if max_iters == 0 else max_iters}",
        f"Stale thr: {args.stale_threshold}m",
        f"Zones:     {zone_desc}",
        f"Lite QA:   {lite_qa_mode}",
        f"Pre-claim: {pre_claim_qa_mode}",
    ])

    lock_path = SCRIPT_DIR / ".agent-claim.lock"
    lock_fd = open(lock_path, "w")

    # Cap-out tracking: consecutive cap-outs per bead and one-iteration skip list.
    cap_out_streak: dict = {}      # task_id → consecutive cap-out count
    cap_out_pending_skip: set = set()  # task_ids to skip on the next selection pass
    # Pre-claim QA tracking: beads that failed the QA gate this session.
    # Reset when the entire candidate pool is exhausted so reformulated beads can be re-evaluated.
    pre_claim_blocked_skip: set = set()

    while True:
        if stop_requested():
            log.log("STOP signal detected (.stop file exists). Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        label = f"{iteration + 1} of {max_iters}" if max_iters > 0 else str(iteration + 1)
        log.log(f"=== {agent.title()} dev loop iteration {label} ===")
        iteration += 1

        # Acquire local claim lock (non-blocking)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log.log("WARNING: failed to acquire local claim lock")
            time.sleep(DEV_SLEEP_NO_WORK)
            continue

        if not git_pull_ff(log):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            time.sleep(DEV_SLEEP_NO_WORK)
            continue

        # Sync issues from remote
        sync_args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            sync_args.insert(2, "--rename-prefix")
        r = br(sync_args)
        log.log("br sync import: ok" if r.returncode == 0 else "WARNING: br sync import failed, continuing")

        if rename_prefix:
            normalize_codex_ids(log, agent_id)

        repair_db_if_needed(log, rename_prefix)
        reset_stuck_tasks(log, stale_secs)

        # Preflight: kill stale cargo processes and verify disk space
        kill_stale_cargo_processes(log)
        if not check_disk_space(log):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            clean_build_artifacts(log)
            clean_tmp_worktrees(log)
            clean_tmp_cargo_targets(log)
            time.sleep(DEV_SLEEP_NO_WORK)
            continue

        # Find the next task to work on
        next_id = ""

        # Claude only: resume a task interrupted in a prior session
        is_resume = False
        if agent == "claude":
            next_id = find_resumable_task(agent_id)
            if next_id:
                is_resume = True
                title = issue_title(next_id)
                title_suffix = f" — {title}" if title else ""
                log.log(f"Resuming previously claimed task {next_id}{title_suffix} (skipping re-claim)")

        if not next_id:
            r = br(["ready", "--json"])
            candidates = []
            if r.returncode == 0:
                try:
                    issues = json.loads(r.stdout)
                    # Apply zone filter if specified.
                    # br ready --json omits labels, so cross-reference with
                    # br list --status=open --json which includes them.
                    if zones:
                        zone_labels = {f"zone:{z}" for z in zones}
                        # br ready caps at 20; re-query with a high limit so
                        # lower-priority zone issues aren't silently excluded.
                        r_wide = br(["ready", "--json", "--limit", "500"])
                        if r_wide.returncode == 0:
                            issues = json.loads(r_wide.stdout)
                        ready_ids = {i["id"] for i in issues}
                        r2 = br(["list", "--status=open", "--json", "--limit", "0"])
                        if r2.returncode == 0:
                            all_open = json.loads(r2.stdout)
                            labeled = {
                                i["id"]: i for i in all_open
                                if zone_labels.intersection(set(i.get("labels", [])))
                            }
                            issues = [
                                labeled[iid] for iid in ready_ids
                                if iid in labeled
                            ]
                    tasks = [i for i in issues if i.get("issue_type", "task") != "epic"]
                    pool = tasks if tasks else issues
                    candidates = [i["id"] for i in pool[:20]]
                except Exception:
                    pass

            if not candidates:
                log.log(f"No ready work found. Sleeping {DEV_SLEEP_NO_WORK}s...")
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                time.sleep(DEV_SLEEP_NO_WORK)
                continue

            # Prefer candidates not recently cap-outed; fall back to all if necessary.
            prioritized, skip_consumed = filter_cap_out_candidates(candidates, cap_out_pending_skip)
            cap_out_pending_skip.difference_update(skip_consumed)
            if skip_consumed and len(prioritized) < len(candidates):
                log.log(
                    f"CAP-OUT skip: deferring {skip_consumed} for 1 iteration"
                    f" — {len(prioritized)} other candidate(s) available"
                )

            # Skip beads that already received a BLOCKED pre-claim verdict this session.
            # Falls back to all candidates when every candidate is blocked, then resets the
            # skip set so reformulated beads can be re-evaluated next iteration.
            non_blocked = [c for c in prioritized if c not in pre_claim_blocked_skip]
            if non_blocked:
                prioritized = non_blocked
            else:
                # Pool exhausted: every candidate has been BLOCKED this session.
                # Reset so the loop can re-evaluate in case beads were reformulated.
                blocked_consumed = set(prioritized) & pre_claim_blocked_skip
                pre_claim_blocked_skip.difference_update(blocked_consumed)
                log.log(
                    f"PRE-CLAIM BLOCKED skip reset: all {len(candidates)} candidate(s)"
                    f" were blocked — re-evaluating pool"
                )
                prioritized = []  # defer re-evaluation to next iteration; avoid burning QA turns on reset iteration

            for candidate in prioritized:
                if issue_status_from_jsonl(candidate) == "in_progress":
                    log.log(f"Skipping candidate already in_progress in JSONL: {candidate}")
                    continue
                log.log(f"Selected task: {candidate}")

                # Pre-claim QA gate: verify bead body accuracy before claiming.
                # Skipped when --dev-light is set or for non-claude agents (no max_turns support).
                if not dev_light and agent == "claude":
                    pq_verdict, pq_reason = run_pre_claim_qa(
                        candidate, agent, args.model, agent_id,
                        max_turns=pre_claim_qa_turns, log=log,
                    )
                    # Sweep up any bead updates the QA agent made before deciding.
                    commit_beads_if_dirty(
                        f"pre-claim-qa refine {candidate} [{agent_id}]", log
                    )
                    if pq_verdict == "BLOCKED":
                        pre_claim_blocked_skip.add(candidate)
                        log.log(
                            f"PRE-CLAIM BLOCKED [{candidate}]: {pq_reason}"
                            f" — skipping this candidate (added to session skip set)"
                        )
                        continue

                if claim_task(candidate, agent_id, log, rename_prefix):
                    next_id = candidate
                    break

        if not next_id:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            log.log("Could not claim any ready task — retrying after backoff")
            time.sleep(random.randint(5, 25))
            continue

        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        title = issue_title(next_id)
        title_suffix = f" — {title}" if title else ""
        log.log(f"Claimed {next_id}{title_suffix}")

        # Build runtime prompt (base template + injected task context)
        dev_prompt = prompt_file.read_text()
        task_details = br(["show", next_id]).stdout.strip() or f"See issue ID: {next_id}"
        ready_output = br(["ready"]).stdout or ""
        ready_lines = "\n".join(ready_output.splitlines()[:15])
        in_progress = br(["list", "--status=in_progress"]).stdout.strip() or "None"

        # Auto-detect zone from task labels when --zone was not passed.
        # This ensures CARGO_FLAGS is scoped even in "all zones" mode.
        effective_zones = list(zones) if zones else []
        if not effective_zones:
            r_task = br(["show", next_id, "--json"])
            if r_task.returncode == 0:
                try:
                    task_data = json.loads(r_task.stdout)
                    for label in task_data.get("labels", []):
                        if label.startswith("zone:"):
                            z = label[5:]
                            if z in ZONES:
                                effective_zones.append(z)
                except Exception:
                    pass
            if effective_zones:
                log.log(f"Auto-detected zone(s) from task labels: {', '.join(effective_zones)}")

        zone_block = build_zone_block(effective_zones)

        resume_block = ""
        if is_resume:
            wip = git(["log", "--oneline", "-5", "--grep", f"wip: interrupted {next_id}"]).stdout.strip()
            resume_block = f"""
---

## Resume Context

This is a **resumed session** — a previous run reached the {DEV_MAX_TURNS}-turn limit and
committed a WIP checkpoint. Your prior work is preserved in git.

**Start by orienting yourself:**
```bash
git log --oneline -5          # see the WIP commit and what came before it
git diff HEAD~1 HEAD          # see exactly what was done in the last session
git status                    # check for any remaining uncommitted changes
```
{"Last WIP commit: " + wip if wip else ""}
Do NOT re-implement work that is already committed. Pick up from where the previous
session left off and complete the remaining implementation.
"""

        runtime_prompt = f"""{dev_prompt}

---

## Your Current Task

**Issue ID**: `{next_id}`
**Agent**: `{agent_id}`

{task_details}
{zone_block}{resume_block}
---

## Current Beads State

### Ready to Work (unblocked, top 15)
{ready_lines}

### Currently In Progress
{in_progress}

---

**IMPORTANT**: This task has already been claimed by the loop script.
Do NOT run `br update {next_id} --status=in_progress` — it is already `in_progress`.
Start directly with understanding the task and implementing it.
"""

        # Set a stable per-zone CARGO_TARGET_DIR so concurrent zone-scoped loops
        # never contend on the same target/ directory lock.
        dev_extra_env: dict = {}
        if effective_zones:
            zone_target = dev_zone_target_dir(effective_zones)
            if zone_target is not None:
                dev_extra_env["CARGO_TARGET_DIR"] = str(zone_target)
                log.log(f"CARGO_TARGET_DIR: {zone_target}")

        before_sha = git(["rev-parse", "HEAD"]).stdout.strip()

        # Force-clean build artifacts before every session. A 150-turn session can
        # compile multiple crates many times and accumulate tens of GB in target/.
        # Both the main target/ and the per-zone CARGO_TARGET_DIR in /tmp must be
        # wiped — clean_build_artifacts covers target/, clean_tmp_cargo_targets(force)
        # covers /tmp/red-cell-target-<zone> regardless of its current size.
        clean_build_artifacts(log, force=True)
        clean_tmp_worktrees(log)
        clean_tmp_cargo_targets(log, force=True)

        log.log(f"Running {agent.title()} on task {next_id}...")
        exit_code, output, result_subtype = run_agent(
            agent, args.model, runtime_prompt, log,
            max_turns=DEV_MAX_TURNS if agent == "claude" else 0,
            extra_env=dev_extra_env or None,
        )

        max_turns_hit = result_subtype in ("max_turns", "error_max_turns")
        token_limit_hit = agent == "claude" and (
            "Context limit reached" in output or result_subtype == "error_max_tokens"
        )

        # Detect rate limiting — agent was unable to do any work
        rate_limited = (
            "out of extra usage" in output.lower()
            or ("rate_limit" in output.lower() and '"rejected"' in output.lower())
        )

        if rate_limited:
            log.log(f"RATE LIMITED: releasing task {next_id} back to open")
            br(["update", next_id, "--status=open"])
            br(["sync", "--flush-only"])
            git(["add", ".beads/issues.jsonl"])
            r = git(["diff", "--cached", "--quiet"])
            if r.returncode != 0:
                git(["commit", "-m", f"chore: release {next_id} after rate limit [{agent_id}]", "--quiet"])
                git(["push", "--quiet"])
            log.log("========================LOOP=========================")
            # Parse reset time from output if available, otherwise default to 20 min
            import re as _re
            reset_match = _re.search(r'resets?\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)', output, _re.IGNORECASE)
            if reset_match:
                log.log(f"Rate limit resets at {reset_match.group(1)} — sleeping 20m")
            else:
                log.log("Rate limit detected — sleeping 20m")
            time.sleep(1200)
            continue

        if exit_code != 0:
            log.log(f"WARNING: {agent.title()} exited with code {exit_code} for task {next_id}")
        else:
            log.log(f"{agent.title()} completed task {next_id}")

        # Extract and log the session summary if present
        summary = extract_session_summary(output)
        if summary:
            for line in summary:
                log.log(f"  {line}")
        else:
            # Fallback: log the last few non-empty lines of output
            tail = [l.strip() for l in output.splitlines() if l.strip()][-5:]
            if tail:
                log.log("  (no structured summary — last output lines:)")
                for line in tail:
                    log.log(f"  {line}")

        # Sweep up beads changes the agent made (br update/close/create) so the
        # working tree stays clean for the next git pull --rebase. Runs for all
        # agents — codex/cursor previously had no equivalent. Done before the
        # Claude WIP block so beads-only changes get a clean chore message
        # instead of being mislabeled as 'wip: interrupted'.
        commit_beads_if_dirty(f"post-agent sweep for {next_id} [{agent_id}]", log)

        # WIP-commit any uncommitted changes the agent left behind. Originally
        # added for Claude's max-turn handoff (resume on next iteration via
        # find_resumable_task), but codex/cursor leave dirty trees too when
        # they skip their prompt's commit step — the WIP commit is the only
        # safety net that keeps git pull --rebase working in the next iter.
        # Auto-resume remains Claude-only (find_resumable_task at line 1450).
        git(["add", "-A"])
        if git(["diff", "--cached", "--quiet"]).returncode != 0:
            log.log(f"WIP: committing uncommitted changes for {next_id}")
            r = git(["commit", "-m", f"wip: interrupted {next_id} [{agent_id}]", "--quiet"])
            if r.returncode == 0:
                git(["fetch", "origin", "--quiet"])
                git(["rebase", "origin/main", "--quiet"])
                if git(["push", "--quiet"]).returncode == 0:
                    log.log("WIP: pushed")
                else:
                    log.log("WARNING: WIP push failed")
            else:
                log.log("WARNING: WIP commit failed — unstaging")
                git(["restore", "--staged", "."])

        # Lite QA: second agent pass reviewing code quality of this task's changes.
        # Skipped when --dev-light is set, or when the dev run was incomplete
        # (max turns hit, token limit, or rate limited).
        if (
            not getattr(args, "dev_light", False)
            and not max_turns_hit
            and not token_limit_hit
        ):
            liteqa_prompt_file = SCRIPT_DIR / DEV_LITEQA_PROMPT
            if liteqa_prompt_file.exists():
                liteqa_template = liteqa_prompt_file.read_text()
                issue_details = br(["show", next_id]).stdout.strip() or f"Issue ID: {next_id}"
                liteqa_prompt = liteqa_template.replace("{ISSUE_ID}", next_id) \
                                               .replace("{BEFORE_SHA}", before_sha or "HEAD~1") \
                                               .replace("{AGENT_ID}", agent_id)
                liteqa_prompt += f"\n\n---\n\n## Issue Details\n\n{issue_details}\n"
                log.log(f"Running lite QA on task {next_id} (range: {(before_sha or 'HEAD~1')[:8]}..HEAD)...")
                lq_exit, lq_output, _ = run_agent(
                    agent, args.model, liteqa_prompt, log,
                    max_turns=DEV_LITEQA_MAX_TURNS if agent == "claude" else 0,
                    extra_env=dev_extra_env or None,
                )
                if lq_exit != 0:
                    log.log(f"WARNING: lite QA exited with code {lq_exit}")
                else:
                    log.log(f"Lite QA completed for task {next_id}")
            else:
                log.log(f"WARNING: lite QA prompt not found at {liteqa_prompt_file} — skipping")

            # Lite QA may have run br update/create — sweep before iteration ends.
            commit_beads_if_dirty(f"post-lite-qa sweep for {next_id} [{agent_id}]", log)

        # Cap-out post-mortem: run when the dev session hit the turn or token limit.
        # Analyses the dead session's transcript, writes a checkpoint note to the bead
        # body, and corrects any misinformation — so the next session doesn't repeat the
        # same wrong path.  Runs before release_cap_out_bead so the body is updated while
        # the bead is still in the current state.
        if (
            not getattr(args, "dev_light", False)
            and (max_turns_hit or token_limit_hit)
        ):
            capout_prompt_file = SCRIPT_DIR / DEV_LITEQA_CAPOUT_PROMPT
            if capout_prompt_file.exists():
                capout_template = capout_prompt_file.read_text()
                issue_details = br(["show", next_id]).stdout.strip() or f"Issue ID: {next_id}"
                transcript_tail = output[-5120:] if len(output) > 5120 else output
                capout_prompt = (
                    capout_template
                    .replace("{ISSUE_ID}", next_id)
                    .replace("{AGENT_ID}", agent_id)
                    .replace("{MAX_TURNS}", str(DEV_LITEQA_CAPOUT_MAX_TURNS))
                )
                capout_prompt += f"\n\n---\n\n## Issue Details\n\n{issue_details}\n"
                capout_prompt += (
                    f"\n\n---\n\n## Dead Session's Final Output (last 5 KB)\n\n"
                    f"```\n{transcript_tail}\n```\n"
                )
                log.log(f"Running cap-out lite QA on task {next_id}...")
                cq_exit, _cq_output, _ = run_agent(
                    agent, args.model, capout_prompt, log,
                    max_turns=DEV_LITEQA_CAPOUT_MAX_TURNS if agent == "claude" else 0,
                    extra_env=dev_extra_env or None,
                )
                if cq_exit != 0:
                    log.log(f"WARNING: cap-out lite QA exited with code {cq_exit}")
                else:
                    log.log(f"Cap-out lite QA completed for task {next_id}")
            else:
                log.log(
                    f"WARNING: cap-out lite QA prompt not found at {capout_prompt_file}"
                    f" — skipping"
                )

            # Cap-out QA may have run br update — sweep before release.
            commit_beads_if_dirty(f"post-capout-qa sweep for {next_id} [{agent_id}]", log)

        final_status = issue_status_from_jsonl(next_id)
        cap_out = max_turns_hit or token_limit_hit
        # Determine cause before the shared cap-out block so both branches can use it.
        cap_out_cause = "token_limit" if token_limit_hit else "turn_limit"
        if final_status == "in_progress" and not cap_out:
            log.log(
                f"Task {next_id} still in_progress after agent ran"
                f" — will resume on next iteration"
            )
        elif final_status not in ("in_progress", "open") and not cap_out:
            # Bead was closed or moved to a terminal state — reset any cap-out streak.
            cap_out_streak.pop(next_id, None)

        log.log("========================LOOP=========================")

        # Periodically clean up stale build artifacts and tmp worktrees
        if iteration % DEV_CLEAN_EVERY == 0:
            clean_build_artifacts(log)
            clean_tmp_worktrees(log)
            clean_tmp_cargo_targets(log)

        if cap_out:
            # Unified cap-out handling for both turn-limit and token-limit exhaustion.
            # cap_out_cause is set above ("turn_limit" or "token_limit").
            log_prefix = "TOKEN-LIMIT" if cap_out_cause == "token_limit" else "CAP-OUT"
            checkpoint = extract_cap_out_checkpoint(output, summary)
            release_cap_out_bead(next_id, checkpoint, agent_id, log, cause=cap_out_cause)
            streak = cap_out_streak.get(next_id, 0) + 1
            cap_out_streak[next_id] = streak
            cap_out_pending_skip.add(next_id)
            log.log(
                f"{log_prefix} [{next_id}] streak={streak}: bead released to open,"
                f" skip 1 iteration"
            )
            if streak >= MAX_CONSECUTIVE_CAP_OUTS:
                # Unified escalation message: always includes cause so both paths are explicit.
                log.log(
                    f"ESCALATE [{next_id}]: {streak} consecutive cap-outs ({cap_out_cause}) —"
                    f" issue likely needs refinement before next attempt"
                )
            if token_limit_hit:
                log.log(f"Token limit hit — sleeping {DEV_SLEEP_TOKEN_LIMIT}s before next iteration")
                time.sleep(DEV_SLEEP_TOKEN_LIMIT)
            # turn_limit: no sleep — immediately proceed to the next task (different due to skip).
        else:
            do_sleep(sleep_secs, jitter_secs, log)


# ── Review loop worktree isolation ────────────────────────────────────────────
#
# Each review loop run gets its own git worktree so it can never touch the main
# checkout's working tree (and destroy a concurrent dev agent's uncommitted changes).
#
# The Cargo build cache is kept at a stable path between runs so incremental builds
# work — only changed files trigger recompilation.

# Stable Cargo target dir for arch/quality/coverage review loop runs.
REVIEW_CARGO_TARGET = Path("/tmp/red-cell-review-target")

# Stable Cargo target dir for QA review loop runs — kept separate from REVIEW_CARGO_TARGET
# so that a QA worktree tear-down cannot delete binaries a concurrent arch/quality run is
# executing, which caused intermittent nextest double-spawn failures.
# Uses the "red-cell-target-" prefix so clean_tmp_cargo_targets auto-discovers it.
QA_CARGO_TARGET = Path("/tmp/red-cell-target-qa")

# Prefix for per-zone stable Cargo target dirs used by dev loops.
# e.g. /tmp/red-cell-target-teamserver, /tmp/red-cell-target-client-cli
DEV_ZONE_TARGET_PREFIX = "/tmp/red-cell-target-"


def dev_zone_target_dir(effective_zones: list) -> "Path | None":
    """
    Return a stable CARGO_TARGET_DIR path for the given effective zones, or None
    if none of the zones contain a Rust crate (C/ASM or Python zones only).

    Single Rust zone  → /tmp/red-cell-target-<zone>
    Multiple zones    → /tmp/red-cell-target-<zone1>-<zone2>-... (sorted)

    Zones with an empty ZONE_PACKAGES entry (archon, phantom, specter, autotest)
    are skipped because they have no cargo workspace crate.
    """
    rust_zones = [
        z for z in effective_zones
        # None means --workspace (has Rust); [] means no Rust crate
        if ZONE_PACKAGES.get(z) is None or len(ZONE_PACKAGES.get(z, [])) > 0
    ]
    if not rust_zones:
        return None
    suffix = "-".join(sorted(rust_zones))
    return Path(f"{DEV_ZONE_TARGET_PREFIX}{suffix}")


# ── Maintenance loop ──────────────────────────────────────────────────────────

MAINTENANCE_STASH_MAX_AGE_DAYS = 14   # prune git stashes older than this
MAINTENANCE_PROGRESS_FILE = SCRIPT_DIR / ".maintenance-progress.json"


def _free_disk_gb() -> float:
    stat = os.statvfs(SCRIPT_DIR)
    return (stat.f_bavail * stat.f_frsize) / (1024 ** 3)


def _find_loop_processes() -> list[dict]:
    """Find running loop.py processes and their loop types."""
    result = subprocess.run(
        ["pgrep", "-af", "loop.py"],
        capture_output=True, text=True,
    )
    loops = []
    our_pid = os.getpid()
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == our_pid:
            continue
        cmdline = parts[1] if len(parts) > 1 else ""
        loop_type = "unknown"
        for lt in ["dev", "qa", "arch", "quality", "coverage", "maintenance"]:
            if f"--loop {lt}" in cmdline or f"--loop={lt}" in cmdline:
                loop_type = lt
                break
        loops.append({"pid": pid, "type": loop_type, "cmd": cmdline})
    return loops


def _git_has_conflicts() -> bool:
    r = git(["status", "--porcelain"])
    return any(line.startswith("UU ") or line.startswith("AA ") for line in r.stdout.splitlines())


def _git_has_stale_rebase() -> bool:
    return (SCRIPT_DIR / ".git" / "rebase-merge").exists() or \
           (SCRIPT_DIR / ".git" / "rebase-apply").exists()


def _git_is_diverged() -> bool:
    r = git(["status", "--porcelain", "-b"])
    first_line = r.stdout.splitlines()[0] if r.stdout.strip() else ""
    return "diverged" in first_line


def _dev_loop_is_running(loops: list[dict]) -> bool:
    return any(lp["type"] == "dev" for lp in loops)


def _last_commit_age_secs() -> float:
    r = git(["log", "-1", "--format=%ct"])
    if r.returncode != 0 or not r.stdout.strip():
        return 0
    try:
        return time.time() - int(r.stdout.strip())
    except ValueError:
        return 0


def _load_progress() -> dict:
    try:
        return json.loads(MAINTENANCE_PROGRESS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_progress(data: dict):
    MAINTENANCE_PROGRESS_FILE.write_text(json.dumps(data, indent=2) + "\n")


def maint_check_disk(log: Logger) -> list[str]:
    """Check disk space and clean up if needed. Returns list of actions taken."""
    actions = []
    free = _free_disk_gb()
    log.log(f"disk: {free:.1f} GB free")

    if free >= MIN_FREE_DISK_GB:
        return actions

    log.log(f"disk: LOW — {free:.1f} GB free (threshold: {MIN_FREE_DISK_GB} GB)")

    # 1. Clean /tmp worktrees (biggest wins, safe)
    clean_tmp_worktrees(log)
    clean_tmp_cargo_targets(log)
    free = _free_disk_gb()
    actions.append(f"cleaned tmp worktrees/cargo ({free:.1f} GB free after)")

    if free >= MIN_FREE_DISK_GB:
        return actions

    # 2. Clean main target/ build artifacts (only if no cargo build running)
    target_root = SCRIPT_DIR / "target"
    if target_root.exists() and not _cargo_target_locked(target_root):
        clean_build_artifacts(log)
        free = _free_disk_gb()
        actions.append(f"cleaned main target/ ({free:.1f} GB free after)")

    if free >= MIN_FREE_DISK_GB:
        return actions

    # 3. Clean claude task output files in /tmp
    import glob as _glob
    import shutil as _shutil
    for d in _glob.glob("/tmp/claude-*"):
        p = Path(d)
        if p.is_dir():
            try:
                age = time.time() - p.stat().st_mtime
                if age > 3600:  # older than 1 hour
                    _shutil.rmtree(p, ignore_errors=True)
                    actions.append(f"removed {p.name}")
            except OSError:
                pass

    free = _free_disk_gb()
    if free < MIN_FREE_DISK_GB:
        log.log(f"disk: CRITICAL — still only {free:.1f} GB free after cleanup")
        actions.append("CRITICAL: disk still low after all cleanup attempts")

    return actions


def maint_check_git(log: Logger, loops: list[dict]) -> list[str]:
    """Check and fix git issues. Returns list of actions taken."""
    actions = []
    dev_running = _dev_loop_is_running(loops)

    # 1. Stale rebase state (exactly what broke the user's pull)
    if _git_has_stale_rebase():
        if dev_running:
            log.log("git: stale rebase-merge dir found but dev loop is running — deferring")
            actions.append("deferred: stale rebase state (dev loop active)")
        else:
            log.log("git: aborting stale rebase")
            git(["rebase", "--abort"])
            actions.append("aborted stale rebase")

    # 2. Merge conflicts in tracked files
    if _git_has_conflicts():
        # Check if it's just .beads/issues.jsonl (safe to auto-resolve)
        r = git(["diff", "--name-only", "--diff-filter=U"])
        conflicted = [f.strip() for f in r.stdout.splitlines() if f.strip()]

        if conflicted == [".beads/issues.jsonl"]:
            log.log("git: auto-resolving .beads/issues.jsonl conflict (accept theirs)")
            git(["checkout", "--theirs", ".beads/issues.jsonl"])
            git(["add", ".beads/issues.jsonl"])
            # Check if we're in a rebase
            if _git_has_stale_rebase():
                git(["rebase", "--continue"])
                actions.append("auto-resolved .beads conflict during rebase")
            else:
                git(["commit", "--no-edit"])
                actions.append("auto-resolved .beads conflict")
        elif dev_running:
            log.log(f"git: merge conflicts in {conflicted} — dev loop running, deferring")
            actions.append(f"deferred: merge conflicts in {conflicted}")
        else:
            log.log(f"git: merge conflicts in {conflicted} — accepting theirs")
            for f in conflicted:
                git(["checkout", "--theirs", f])
                git(["add", f])
            if _git_has_stale_rebase():
                git(["rebase", "--continue"])
            else:
                git(["commit", "-m", "chore(maintenance): auto-resolve merge conflicts"])
            actions.append(f"auto-resolved conflicts in {conflicted}")

    # 3. Diverged branch — try to rebase
    if _git_is_diverged():
        if dev_running:
            log.log("git: branch diverged but dev loop is running — deferring")
            actions.append("deferred: branch diverged (dev loop active)")
        else:
            log.log("git: branch diverged — attempting rebase")
            r = git(["pull", "--rebase"])
            if r.returncode == 0:
                actions.append("rebased diverged branch")
            else:
                log.log(f"git: rebase failed: {r.stderr.strip()}")
                git(["rebase", "--abort"])
                actions.append("rebase failed, aborted — needs manual attention")

    # 4. Try a pull to ensure we're up to date
    if not _git_has_conflicts() and not _git_has_stale_rebase():
        r = git(["pull", "--ff-only", "--quiet"])
        if r.returncode == 0:
            log.log("git: pull --ff-only OK")
        else:
            # ff-only failed — not critical, dev loop will handle it
            log.log("git: pull --ff-only failed (non-fast-forward) — dev loop will handle")

    # 5. Remote reachability
    r = git(["ls-remote", "--exit-code", "--quiet", "origin", "HEAD"])
    if r.returncode != 0:
        log.log("git: WARNING — cannot reach remote origin")
        actions.append("WARNING: remote unreachable")
    else:
        log.log("git: remote OK")

    return actions


def maint_check_stop_file(log: Logger) -> list[str]:
    """Remove stale .stop file (>1h) and push the removal to unblock remote agents."""
    actions = []
    stop_file = SCRIPT_DIR / ".stop"
    if not stop_file.exists():
        return actions

    try:
        age_hours = (time.time() - stop_file.stat().st_mtime) / 3600
    except OSError:
        actions.append(".stop file present (could not check age)")
        return actions

    if age_hours < 1:
        log.log(f"stop: .stop file exists ({age_hours:.1f}h old) — too recent to remove")
        actions.append(f".stop file present ({age_hours:.1f}h old)")
        return actions

    log.log(f"stop: .stop file is {age_hours:.1f}h old — removing and pushing")
    stop_file.unlink()
    git(["add", ".stop"])
    git(["commit", "-m", "chore(maintenance): remove stale .stop file"])
    r = git(["push"])
    if r.returncode == 0:
        log.log("stop: .stop removed and pushed")
        actions.append(f"removed stale .stop file ({age_hours:.1f}h old) and pushed")
    else:
        log.log(f"stop: .stop removed locally but push failed: {r.stderr.strip()}")
        actions.append(f"removed stale .stop file locally (push failed)")
    return actions


def maint_check_processes(log: Logger, loops: list[dict]) -> list[str]:
    """Check loop processes and stale cargo processes."""
    actions = []

    # Report running loops
    if loops:
        for lp in loops:
            log.log(f"process: loop.py PID {lp['pid']} type={lp['type']}")
    else:
        log.log("process: no other loop.py processes found")
        actions.append("WARNING: no dev/qa/arch loops running")

    dev_loops = [lp for lp in loops if lp["type"] == "dev"]
    if not dev_loops:
        actions.append("WARNING: no dev loop running")

    # Check for progress — is the last commit older than 2 hours?
    # (suggests loops are stuck, not just idle)
    if dev_loops:
        age = _last_commit_age_secs()
        age_hours = age / 3600
        log.log(f"process: last commit {age_hours:.1f}h ago")

        progress = _load_progress()
        prev_head = progress.get("last_head", "")
        r = git(["rev-parse", "HEAD"])
        current_head = r.stdout.strip() if r.returncode == 0 else ""

        if prev_head and current_head == prev_head:
            stall_count = progress.get("stall_count", 0) + 1
            progress["stall_count"] = stall_count
            hours_stalled = stall_count  # each maint run ≈ 1 hour
            if hours_stalled >= 3:
                log.log(
                    f"process: WARNING — HEAD unchanged for {hours_stalled} maintenance cycles "
                    f"({hours_stalled}h) — dev loops may be stuck"
                )
                actions.append(f"WARNING: no commits for {hours_stalled} consecutive checks")
        else:
            progress["stall_count"] = 0

        progress["last_head"] = current_head
        _save_progress(progress)

    # Kill stale cargo processes
    kill_stale_cargo_processes(log)

    return actions


def maint_clean_tmp_sqlite(log: Logger) -> list[str]:
    """
    Remove stale red-cell SQLite files left behind in /tmp by the teamserver.

    Integration tests and the teamserver itself create per-run SQLite databases
    in /tmp (red-cell-agent-registry-*.sqlite* and red-cell-teamserver-db-*.sqlite*).
    These are never cleaned up automatically and can accumulate to tens of GB and
    hundreds of thousands of files.  Remove any that are older than 1 hour.
    """
    actions = []
    cutoff = time.time() - 3600
    removed = 0
    try:
        for entry in Path("/tmp").iterdir():
            if not entry.name.startswith("red-cell-"):
                continue
            if not any(entry.name.endswith(s) for s in (".sqlite", ".sqlite-wal", ".sqlite-shm")):
                continue
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                pass
    except OSError:
        pass
    if removed:
        log.log(f"tmp sqlite: removed {removed} stale red-cell *.sqlite* file(s)")
        actions.append(f"removed {removed} stale tmp sqlite file(s)")
    else:
        log.log("tmp sqlite: nothing to remove")
    return actions


def maint_prune_stashes(log: Logger) -> list[str]:
    """Prune git stashes older than MAINTENANCE_STASH_MAX_AGE_DAYS."""
    actions = []
    r = git(["stash", "list", "--format=%gd %ci"])
    if r.returncode != 0 or not r.stdout.strip():
        return actions

    cutoff = time.time() - MAINTENANCE_STASH_MAX_AGE_DAYS * 86400
    stale_indices = []
    for line in r.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        ref = parts[0]  # stash@{N}
        date_str = parts[1].strip()
        try:
            dt = datetime.fromisoformat(date_str.replace(" +", "+").replace(" -", "-"))
            if dt.timestamp() < cutoff:
                stale_indices.append(ref)
        except ValueError:
            continue

    if not stale_indices:
        log.log(f"stash: {r.stdout.strip().count(chr(10)) + 1} stash(es), none older than {MAINTENANCE_STASH_MAX_AGE_DAYS}d")
        return actions

    # Drop from highest index to lowest to avoid shifting
    log.log(f"stash: dropping {len(stale_indices)} stash(es) older than {MAINTENANCE_STASH_MAX_AGE_DAYS}d")
    for ref in reversed(stale_indices):
        git(["stash", "drop", ref])
    actions.append(f"pruned {len(stale_indices)} old stash(es)")
    return actions


def maintenance_loop(args, log: Logger):
    """
    Maintenance loop — keeps the development environment healthy.

    Runs hourly by default. Checks disk space, git state, running processes,
    and cleans up stale artifacts. Goal: maximize unattended dev loop uptime.
    """
    if args.sleep is not None:
        sleep_secs = args.sleep * 60
    else:
        sleep_secs = DEFAULT_SLEEP["maintenance"]
    jitter_secs = args.jitter * 60
    max_iters = args.iterations

    log.banner([
        "Maintenance loop starting",
        f"Interval:  {sleep_secs / 60:.0f}m",
        f"Max runs:  {'unlimited' if max_iters == 0 else max_iters}",
    ])

    iteration = 0

    while True:
        if stop_requested():
            log.log("STOP signal detected. Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        iteration += 1
        log.log(f"=== Maintenance run {iteration} ===")
        all_actions = []

        # Discover running loops first — many checks depend on this
        loops = _find_loop_processes()

        # 1. Stop file check
        all_actions.extend(maint_check_stop_file(log))

        # 2. Disk space — fix first, everything else depends on having disk
        all_actions.extend(maint_check_disk(log))

        # 3. Git health — unblock pulls so dev loops can pick up new work
        all_actions.extend(maint_check_git(log, loops))

        # 4. Process health — stale cargo, stuck loops
        all_actions.extend(maint_check_processes(log, loops))

        # 5. Stash pruning
        all_actions.extend(maint_prune_stashes(log))

        # 6. Worktree and tmp cleanup (even if disk is fine, prevent accumulation)
        clean_tmp_worktrees(log)
        clean_tmp_cargo_targets(log)

        # 7. Stale SQLite files left by teamserver/integration tests
        all_actions.extend(maint_clean_tmp_sqlite(log))

        # 8. Sweep up any uncommitted .beads/issues.jsonl changes — catches
        # human-side `br update` calls and any agent leaks the dev/review
        # loops missed.
        if commit_beads_if_dirty("maintenance sweep of uncommitted JSONL", log):
            all_actions.append("swept uncommitted .beads/issues.jsonl")

        # Summary
        if all_actions:
            log.log("--- Actions this run ---")
            for a in all_actions:
                log.log(f"  • {a}")
        else:
            log.log("--- All clear, no issues found ---")

        log.log(f"=== Maintenance run {iteration} complete ===")

        if max_iters > 0 and iteration >= max_iters:
            break

        do_sleep(sleep_secs, jitter_secs, log)


def create_review_worktree(loop_type: str, log: Logger) -> Path | None:
    """
    Create a temporary git worktree at HEAD for a single review loop run.
    Returns the worktree path, or None if creation fails (caller falls back to SCRIPT_DIR).

    A symlink worktree/.beads -> SCRIPT_DIR/.beads is created so that `br` commands
    run inside the worktree resolve to the same database and JSONL as the main checkout.
    """
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix=f"red-cell-{loop_type}-", dir="/tmp"))
    tmp.rmdir()  # git worktree add requires the target not to exist

    r = subprocess.run(
        ["git", "worktree", "add", "--detach", str(tmp), "HEAD"],
        capture_output=True, text=True, cwd=str(SCRIPT_DIR),
    )
    if r.returncode != 0:
        log.log(f"WARNING: could not create review worktree: {r.stderr.strip()}")
        return None

    # Symlink .beads into the worktree so `br` uses the main repo's database.
    # git worktree add checks out .beads/issues.jsonl (tracked), so the directory
    # already exists — remove it before creating the symlink.
    import shutil
    beads_link = tmp / ".beads"
    if beads_link.is_symlink() or beads_link.is_file():
        beads_link.unlink()
    elif beads_link.is_dir():
        shutil.rmtree(beads_link)
    beads_link.symlink_to(SCRIPT_DIR / ".beads")

    log.log(f"Review worktree: {tmp}")
    return tmp


def harvest_worktree_beads(worktree_path: Path, log: Logger):
    """
    Safety-net: flush the main beads DB to JSONL and push if the review agent left
    uncommitted changes (e.g. it filed issues but its own git push failed).

    The worktree has a .beads symlink pointing at SCRIPT_DIR/.beads, so all `br`
    calls made inside the worktree already write to the main DB. We just need to
    ensure the JSONL is flushed and any diff is committed and pushed.
    """
    # Flush the DB (which the agent wrote to via the symlink) to JSONL.
    br(["sync", "--flush-only", "--quiet"])

    # Nothing to do if JSONL is clean.
    if git(["diff", "--quiet", "--", ".beads/issues.jsonl"]).returncode == 0:
        log.log("harvest: no unflushed beads changes")
        return

    retries = 3
    for attempt in range(retries):
        pull_r = git(["pull", "--rebase", "--quiet"])
        if pull_r.returncode != 0:
            git(["rebase", "--abort"])
            log.log(f"harvest: pull --rebase failed on attempt {attempt + 1}/{retries}, retrying")
            continue

        # After the pull, check again — the rebase may have already incorporated
        # the same changes from another agent's push.
        if git(["diff", "--quiet", "--", ".beads/issues.jsonl"]).returncode == 0:
            log.log("harvest: changes incorporated by rebase — nothing to commit")
            return

        git(["add", ".beads/issues.jsonl"])
        msg = "chore: harvest unflushed beads issues from review worktree"
        if git(["commit", "-m", msg, "--quiet"]).returncode != 0:
            git(["restore", "--staged", ".beads/issues.jsonl"])
            log.log(f"harvest: commit failed on attempt {attempt + 1}/{retries}, retrying")
            continue

        if git(["push", "--quiet"]).returncode == 0:
            log.log("harvest: pushed unflushed beads issues")
            return

        git(["reset", "HEAD~1", "--mixed", "--quiet"])
        log.log(f"harvest: push attempt {attempt + 1}/{retries} failed, retrying")

    log.log("WARNING: harvest: could not push after {retries} attempts — issues saved locally")


# Tracked cross-VM state files that loops/agents may write but forget to commit.
# Both leak into the main tree via the worktree .beads symlink; both block
# `git pull --rebase` in the next loop iteration if left dirty.
SWEPT_STATE_FILES = [
    ".beads/issues.jsonl",
    ".beads/qa_checkpoint",
]


def commit_beads_if_dirty(reason: str, log: Logger) -> bool:
    """
    Sweep up dirty cross-VM state files (see SWEPT_STATE_FILES).

    Flushes the beads DB → JSONL, then commits + pushes any of the watched
    files that are dirty. Catches:
      - agent `br update` / `br close` / `br create` left uncommitted
      - QA prompt `echo $HEAD_SHA > .beads/qa_checkpoint` left uncommitted
      - human `br update` on the same VM (via the maintenance-tick sweep)

    Returns True if a commit was made; False if nothing to do.
    """
    br(["sync", "--flush-only", "--quiet"])

    dirty = [
        path for path in SWEPT_STATE_FILES
        if git(["diff", "--quiet", "--", path]).returncode != 0
    ]
    if not dirty:
        return False

    git(["add", "--"] + dirty)
    if git(["diff", "--cached", "--quiet"]).returncode == 0:
        return False

    if git(["commit", "-m", f"chore(beads): {reason}", "--quiet"]).returncode != 0:
        for path in dirty:
            git(["restore", "--staged", "--", path])
        log.log(f"WARNING: beads sweep commit failed: {reason}")
        return False

    if git(["push", "--quiet"]).returncode == 0:
        log.log(f"beads: swept {','.join(dirty)} ({reason})")
    else:
        log.log(f"WARNING: beads sweep push failed (local commit retained): {reason}")
    return True


def remove_review_worktree(worktree_path: Path, log: Logger):
    """Remove a review worktree (but leave the shared cargo target dir intact)."""
    import shutil

    r = subprocess.run(
        ["git", "worktree", "remove", "--force", str(worktree_path)],
        capture_output=True, cwd=str(SCRIPT_DIR),
    )
    if r.returncode != 0 and worktree_path.exists():
        try:
            shutil.rmtree(worktree_path)
        except OSError as e:
            log.log(f"WARNING: could not remove worktree {worktree_path}: {e}")
        subprocess.run(
            ["git", "worktree", "prune"],
            capture_output=True, cwd=str(SCRIPT_DIR),
        )
    log.log(f"Removed review worktree: {worktree_path.name}")


# ── Autotest loop helpers ─────────────────────────────────────────────────────

AUTOTEST_PROFILE = "profiles/autotest.yaotl"
AUTOTEST_PORT = 40156
AUTOTEST_CONFIG_DIR = "automatic-test/config-autotest"
AUTOTEST_BUILD_TIMEOUT = 30 * 60     # 30 min — covers cold full release build
AUTOTEST_TEAMSERVER_READY_TIMEOUT = 30
# Cap sccache disk use during autotest release builds (avoids unbounded ~/.cache/sccache growth).
AUTOTEST_SCCACHE_CACHE_SIZE_DEFAULT = "5G"
AUTOTEST_SCCACHE_PREP_TIMEOUT_SECS = 120


def _autotest_cargo_compile_env(
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Environment for autotest ``cargo build --release`` invocations.

    Sets ``SCCACHE_CACHE_SIZE`` when not already present so the sccache daemon
    LRU-evicts instead of filling the filesystem. Respect a pre-set
    ``SCCACHE_CACHE_SIZE``; otherwise use ``RC_AUTOTEST_SCCACHE_CACHE_SIZE`` or
    :data:`AUTOTEST_SCCACHE_CACHE_SIZE_DEFAULT`.
    """
    out = dict(base if base is not None else os.environ)
    if "SCCACHE_CACHE_SIZE" not in out:
        out["SCCACHE_CACHE_SIZE"] = os.environ.get(
            "RC_AUTOTEST_SCCACHE_CACHE_SIZE",
            AUTOTEST_SCCACHE_CACHE_SIZE_DEFAULT,
        )
    return out


def autotest_sccache_prep(log: Logger, compile_env: dict[str, str]) -> None:
    """Stop the sccache daemon before a heavy compile.

    Lets the subsequent build spawn a fresh server that reads ``SCCACHE_CACHE_SIZE``
    from *compile_env* (so an older long-lived daemon cannot ignore the cap).
    Best-effort only: failures are logged and ignored. Skip when
    ``RC_AUTOTEST_SKIP_SCCACHE_PREP=1`` or ``sccache`` is not in ``PATH``.
    """
    if os.environ.get("RC_AUTOTEST_SKIP_SCCACHE_PREP") == "1":
        log.log("autotest sccache prep: skipped (RC_AUTOTEST_SKIP_SCCACHE_PREP=1)")
        return
    if not shutil.which("sccache"):
        log.log("autotest sccache prep: sccache not in PATH, skipping")
        return
    for phase, argv in (("stop-server", ["sccache", "--stop-server"]),):
        try:
            proc = subprocess.run(
                argv,
                cwd=str(SCRIPT_DIR),
                env=compile_env,
                capture_output=True,
                text=True,
                timeout=AUTOTEST_SCCACHE_PREP_TIMEOUT_SECS,
            )
            if proc.returncode != 0:
                tail = (proc.stderr or proc.stdout or "").strip()
                excerpt = tail[:400] + ("..." if len(tail) > 400 else "")
                log.log(
                    f"autotest sccache {phase}: non-zero exit {proc.returncode}"
                    + (f" — {excerpt}" if excerpt else "")
                )
        except subprocess.TimeoutExpired:
            log.log(
                f"autotest sccache {phase}: timed out after "
                f"{AUTOTEST_SCCACHE_PREP_TIMEOUT_SECS}s"
            )
        except OSError as exc:
            log.log(f"autotest sccache {phase}: {exc}")
    log.log(
        "autotest sccache prep: done "
        f"(SCCACHE_CACHE_SIZE={compile_env.get('SCCACHE_CACHE_SIZE', '')})"
    )


def autotest_safety_banner(log: Logger, no_confirm: bool):
    """Print destructive-action banner; 10s countdown unless --no-confirm."""
    log.banner([
        "AUTOTEST LOOP — DESTRUCTIVE TO TEAMSERVER STATE",
        f"Will kill + restart teamserver on :{AUTOTEST_PORT}, deploy agents",
        "to test VMs, overwrite profiles/autotest.sqlite.",
        "DO NOT run on a host with active operator sessions.",
    ])
    if no_confirm or os.environ.get("RC_AUTOTEST_NO_CONFIRM") == "1":
        log.log("--no-confirm / RC_AUTOTEST_NO_CONFIRM set, skipping countdown")
        return
    log.log("Press Ctrl-C within 10 seconds to abort.")
    try:
        for i in range(10, 0, -1):
            sys.stderr.write(f"\rstarting in {i:2d}s ...")
            sys.stderr.flush()
            time.sleep(1)
        sys.stderr.write("\r" + " " * 40 + "\r")
        sys.stderr.flush()
    except KeyboardInterrupt:
        log.log("Aborted by operator.")
        sys.exit(0)


def autotest_compile_release(log: Logger) -> tuple[bool, Path]:
    """Run cargo build --release --workspace, capturing stdout+stderr.

    Returns ``(success, build_log_path)``.  The log is always written so the
    agent can read it for context regardless of build outcome.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOG_DIR / f"autotest_build_{ts}.log"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    compile_env = _autotest_cargo_compile_env()
    log.log(f"compiling: cargo build --release --workspace -> {log_path.name}")
    autotest_sccache_prep(log, compile_env)
    try:
        with open(log_path, "w") as fh:
            proc = subprocess.run(
                ["cargo", "build", "--release", "--workspace"],
                cwd=str(SCRIPT_DIR),
                env=compile_env,
                stdout=fh,
                stderr=subprocess.STDOUT,
                timeout=AUTOTEST_BUILD_TIMEOUT,
            )
        ok = proc.returncode == 0
        log.log(f"compile {'OK' if ok else 'FAILED'} (exit {proc.returncode})")
        return ok, log_path
    except subprocess.TimeoutExpired:
        log.log(f"compile TIMED OUT after {AUTOTEST_BUILD_TIMEOUT}s")
        return False, log_path


def autotest_teamserver_pid() -> "int | None":
    """Return PID of any process bound to AUTOTEST_PORT, else None."""
    try:
        result = subprocess.run(
            ["ss", "-ltnp", f"sport = :{AUTOTEST_PORT}"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    for line in result.stdout.splitlines():
        m = re.search(r"pid=(\d+)", line)
        if m:
            return int(m.group(1))
    return None


def autotest_port_listening() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", AUTOTEST_PORT), timeout=1):
            return True
    except OSError:
        return False


def autotest_start_or_restart_teamserver(log: Logger) -> bool:
    """Kill any teamserver on AUTOTEST_PORT, start a fresh one, poll until ready.

    Returns True iff the teamserver becomes ready within the timeout window.
    """
    pid = autotest_teamserver_pid()
    if pid:
        log.log(f"killing existing autotest teamserver (PID {pid})")
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                if not autotest_port_listening():
                    break
                time.sleep(0.5)
            if autotest_port_listening():
                log.log("teamserver did not exit on SIGTERM, sending SIGKILL")
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                time.sleep(1)
        except ProcessLookupError:
            pass

    binary = SCRIPT_DIR / "target/release/red-cell"
    profile = SCRIPT_DIR / AUTOTEST_PROFILE
    if not binary.exists():
        log.log(f"ERROR: {binary} missing — compile must run first")
        return False
    if not profile.exists():
        log.log(f"ERROR: {profile} missing")
        return False

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts_log = LOG_DIR / "teamserver-autotest.log"
    log.log(f"starting teamserver: {binary.name} --profile {profile.name}")
    with open(ts_log, "a") as fh:
        fh.write(f"\n=== {datetime.now().isoformat()} starting autotest teamserver ===\n")

    proc = subprocess.Popen(
        [str(binary), "--profile", str(profile)],
        cwd=str(SCRIPT_DIR),
        stdout=open(ts_log, "a"),
        stderr=subprocess.STDOUT,
    )
    log.log(f"teamserver PID {proc.pid}, polling :{AUTOTEST_PORT}")

    deadline = time.monotonic() + AUTOTEST_TEAMSERVER_READY_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log.log(f"teamserver exited prematurely (code {proc.returncode}); see {ts_log.name}")
            return False
        if autotest_port_listening():
            log.log(f"teamserver ready on :{AUTOTEST_PORT}")
            return True
        time.sleep(0.5)

    log.log(f"teamserver did not become ready within {AUTOTEST_TEAMSERVER_READY_TIMEOUT}s")
    return False


def autotest_kill_target_vm_orphans(log: Logger):
    """SSH to each test VM and pkill leftover agent-* payloads from prior runs.

    Best-effort: SSH/auth failures are logged but do not abort the iteration.
    Reads ``automatic-test/config-autotest/targets.toml`` (or the symlinked
    target file).  Skipped silently when targets.toml is absent.
    """
    targets_path = SCRIPT_DIR / AUTOTEST_CONFIG_DIR / "targets.toml"
    if not targets_path.exists():
        log.log("no targets.toml in config-autotest, skipping orphan cleanup")
        return

    try:
        try:
            import tomllib
        except ImportError:  # py3.10
            import tomli as tomllib
        with open(targets_path, "rb") as f:
            targets = tomllib.load(f)
    except Exception as exc:
        log.log(f"could not parse targets.toml: {exc}")
        return

    for name, cfg in targets.items():
        if not isinstance(cfg, dict):
            continue
        host = cfg.get("host")
        user = cfg.get("user")
        key = cfg.get("key")
        if not (host and user and key):
            continue
        key_path = os.path.expanduser(str(key))
        work_dir = str(cfg.get("work_dir", ""))
        is_windows = "\\" in work_dir or work_dir.startswith("C:")
        if is_windows:
            remote_cmd = (
                "powershell -NoProfile -Command "
                "\"Get-Process | Where-Object { $_.Path -like 'C:\\Temp\\rc-test\\agent-*' } "
                "| Stop-Process -Force -ErrorAction SilentlyContinue\""
            )
        else:
            # Bracket-trick: the regex [a]gent- matches the literal text "agent-"
            # but the pattern as written ('[a]gent-') does NOT appear in the
            # ssh-spawned shell's own command line, so pkill cannot accidentally
            # match itself and kill the connection (which would exit 255).
            remote_cmd = "pkill -f '/tmp/rc-test/[a]gent-' || true"
        try:
            result = subprocess.run(
                ["ssh", "-i", key_path,
                 "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5",
                 "-o", "StrictHostKeyChecking=no",
                 f"{user}@{host}", remote_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                log.log(f"orphan cleanup on {name} ({host}): done")
            else:
                log.log(f"orphan cleanup on {name} ({host}): exit {result.returncode}")
        except subprocess.TimeoutExpired:
            log.log(f"orphan cleanup on {name} ({host}): SSH timeout (skipped)")
        except Exception as exc:
            log.log(f"orphan cleanup on {name} ({host}): {exc}")


# ── Review loops (qa, arch, quality, coverage) ─────────────────────────────────

def review_loop(args, log: Logger):
    loop_type = args.loop
    agent = args.agent
    zones = args.zone or []

    prompt_file = SCRIPT_DIR / REVIEW_PROMPTS[loop_type]
    if not prompt_file.exists():
        log.log(f"ERROR: {prompt_file} not found. Exiting.")
        sys.exit(1)

    if args.sleep is not None:
        sleep_secs = args.sleep * 60
    else:
        sleep_secs = DEFAULT_SLEEP[loop_type]
    jitter_secs = args.jitter * 60

    max_iters = args.iterations
    iteration = 0
    per_run = loop_type in PER_RUN_LOG_LOOPS

    sleep_desc = f"{sleep_secs//60:.0f}m"
    if jitter_secs:
        sleep_desc += f" ±{jitter_secs//60:.0f}m jitter"

    zone_desc = ", ".join(zones) if zones else "all zones"
    zone_block = build_zone_block(zones)

    log.banner([
        f"{agent.title()} {loop_type} loop starting",
        f"Prompt:   {prompt_file.name}",
        f"Log:      {log.log_file.name}",
        f"Sleep:    {sleep_desc}",
        f"Max runs: {'unlimited' if max_iters == 0 else max_iters}",
        f"Zones:    {zone_desc}",
    ])

    # Autotest is destructive (kills + restarts teamserver, deploys to test VMs).
    # Show a banner + 10s countdown so an operator who started this on the wrong
    # host can abort. --no-confirm / RC_AUTOTEST_NO_CONFIRM=1 skips the wait.
    if loop_type == "autotest":
        autotest_safety_banner(log, getattr(args, "no_confirm", False))

    while True:
        if stop_requested():
            log.log("STOP signal detected (.stop file exists). Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        label = f"{iteration + 1} of {max_iters}" if max_iters > 0 else str(iteration + 1)
        log.log(f"=== {loop_type.title()} review run {label} ===")

        pull_rebase_ok = git_pull_rebase(log)

        # Run the review agent in an isolated worktree so it can never touch the main
        # checkout's working tree (which may have a concurrent dev agent's uncommitted
        # changes). Use a stable per-loop-type Cargo target dir for incremental builds.
        # QA gets its own dir so a worktree tear-down cannot delete binaries a concurrent
        # arch/quality run is executing (was causing nextest double-spawn failures).
        #
        # Live-tree loops (autotest) bypass this — they need the real working tree
        # because they talk to the running teamserver, use the actual target/release
        # binaries, and read host-specific gitignored config files (env.toml,
        # targets.toml) that don't exist in a worktree.
        if loop_type in LIVE_WORKTREE_LOOPS:
            worktree_path = None
            run_cwd = SCRIPT_DIR
            run_env = {}
        else:
            worktree_path = create_review_worktree(loop_type, log)
            run_cwd = worktree_path or SCRIPT_DIR
            cargo_target = QA_CARGO_TARGET if loop_type == "qa" else REVIEW_CARGO_TARGET
            run_env = {"CARGO_TARGET_DIR": str(cargo_target)}

        # Autotest loop: compile, start teamserver, kill VM orphans, and pass the
        # build status to the agent via env vars. Agent's prompt branches on
        # RC_AUTOTEST_BUILD_OK to decide whether to run scenarios or troubleshoot
        # the build failure.
        if loop_type == "autotest":
            build_ok, build_log = autotest_compile_release(log)
            ts_ok = False
            if build_ok:
                ts_ok = autotest_start_or_restart_teamserver(log)
                if not ts_ok:
                    log.log(
                        "WARNING: teamserver did not become ready; agent will see "
                        "RC_AUTOTEST_TEAMSERVER_OK=0 and switch to troubleshooting mode"
                    )
            else:
                log.log("compile failed; skipping teamserver start")
            autotest_kill_target_vm_orphans(log)

            run_env.update({
                "RC_AUTOTEST_BUILD_OK":          "1" if build_ok else "0",
                "RC_AUTOTEST_BUILD_LOG":         str(build_log),
                "RC_AUTOTEST_TEAMSERVER_OK":     "1" if ts_ok else "0",
                "RC_AUTOTEST_PULL_REBASE_OK":    "1" if pull_rebase_ok else "0",
                "RC_AUTOTEST_CONFIG_DIR":        AUTOTEST_CONFIG_DIR,
                "RC_AUTOTEST_PROFILE":           AUTOTEST_PROFILE,
                "RC_AUTOTEST_PORT":              str(AUTOTEST_PORT),
            })

        extra_log = None
        if per_run:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            extra_log = LOG_DIR / f"{agent}_{loop_type}_{ts}.log"
            log.log(f"Run log: {extra_log.name}")

        prompt_content = prompt_file.read_text()
        if zone_block:
            prompt_content = f"{prompt_content}\n{zone_block}"
        exit_code, _, _ = run_agent(
            agent, args.model, prompt_content, log, extra_log,
            cwd=run_cwd, extra_env=run_env,
        )

        if worktree_path:
            harvest_worktree_beads(worktree_path, log)
            remove_review_worktree(worktree_path, log)

        # Sweep any post-harvest beads changes (and cover live-tree loops like
        # autotest, which skip harvest entirely).
        commit_beads_if_dirty(f"post-{loop_type} sweep [{args.agent}]", log)

        if exit_code != 0:
            log.log(f"WARNING: {agent.title()} exited with code {exit_code}")
        else:
            log.log(f"{loop_type.title()} review completed successfully")

        # Clean up stale build artifacts and any leftover tmp worktrees.
        clean_build_artifacts(log)
        clean_tmp_worktrees(log)
        clean_tmp_cargo_targets(log)

        iteration += 1

        if stop_requested():
            log.log("STOP signal detected after review. Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        log.log("========================LOOP=========================")
        do_sleep(sleep_secs, jitter_secs, log)


# ── Argument parsing ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="loop.py",
        description="Unified agent loop runner for Red Cell C2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
loop types:
  dev          Development — claims beads tasks, implements them, then runs a lite QA pass
  qa           QA review   — reviews recent commits, files issues (default sleep: 20m)
  arch         Architecture review — deep full-codebase analysis  (default sleep: 120m)
  quality      Test quality review — evaluates quality of existing tests (default sleep: 30m)
  coverage     Test coverage scan  — finds untested public functions    (default sleep: 30m)
  maintenance  Infrastructure health — disk, git, process checks       (default sleep: 60m)
  feature      Feature completeness — what's planned vs built, integration gaps (default: 1 run)
  autotest     Run automatic-test E2E suite — classify failures, file beads     (default sleep: 240m)

examples:
  ./loop.py --agent claude --loop dev
  ./loop.py --agent claude --loop dev  --zone client-cli
  ./loop.py --agent codex  --loop dev  --zone teamserver
  ./loop.py --agent cursor --loop dev  --zone client-cli client
  ./loop.py --agent claude --loop dev  --sleep 0 --iterations 1
  ./loop.py --agent claude --loop dev  --dev-light          # skip pre-claim QA + lite QA (original behaviour)
  ./loop.py --agent claude --loop dev  --pre-claim-qa-turns 10  # faster pre-claim gate
  ./loop.py --agent codex  --loop qa   --sleep 20
  ./loop.py --agent claude --loop arch --zone teamserver
  ./loop.py --agent claude --loop arch --sleep 120 --jitter 15
  ./loop.py --agent cursor --loop coverage --zone common --iterations 3
  ./loop.py --agent claude --loop dev  --pre-sleep 5 --model claude-opus-4-6
  ./loop.py --loop maintenance                        # hourly health checks
  ./loop.py --loop maintenance --sleep 30             # every 30 minutes
  ./loop.py --agent claude --loop feature --zone teamserver client-cli
  ./loop.py --agent claude --loop feature --zone teamserver phantom
  ./loop.py --agent claude --loop feature --zone teamserver  # single zone
  ./loop.py --agent claude --loop autotest                   # full E2E suite, 4h cadence
  ./loop.py --agent claude --loop autotest --iterations 1    # one-shot run + report
  ./loop.py --agent claude --loop autotest --sleep 60        # hourly cadence (heavy)
""",
    )
    parser.add_argument(
        "--agent",
        choices=["claude", "codex", "cursor"],
        default="claude",
        help="Agent to use (default: claude)",
    )
    parser.add_argument(
        "--loop",
        choices=["dev", "qa", "arch", "quality", "coverage", "maintenance", "feature", "autotest"],
        default="dev",
        help="Loop type to run (default: dev)",
    )
    parser.add_argument(
        "--pre-sleep",
        type=float, default=0, metavar="MINUTES",
        help="Sleep N minutes before the first run (default: 0)",
    )
    parser.add_argument(
        "--sleep",
        type=float, default=None, metavar="MINUTES",
        help=(
            "Sleep N minutes after each iteration. "
            "If omitted, uses per-loop defaults: dev=0, qa=20, arch=120, "
            "quality/coverage=30, maintenance=60, autotest=240"
        ),
    )
    parser.add_argument(
        "--jitter",
        type=float, default=0, metavar="MINUTES",
        help="Apply ±N minutes of random jitter to --sleep (default: 0)",
    )
    parser.add_argument(
        "--iterations",
        type=int, default=None, metavar="N",
        help=(
            "Max iterations before exit; 0 = run forever. "
            "Default varies by loop type: feature=1, all others=0 (unlimited)."
        ),
    )
    parser.add_argument(
        "--model",
        default=None, metavar="MODEL",
        help=(
            "Claude model to use (claude agent only). "
            "Example: claude-opus-4-6. Default: claude-sonnet-4-6"
        ),
    )
    parser.add_argument(
        "--zone",
        nargs="+",
        choices=list(ZONES.keys()),
        metavar="ZONE",
        help=(
            "Restrict loop to one or more zones: "
            + ", ".join(ZONES.keys())
            + ". Omit to work across all zones. "
            "Example: --zone client-cli  or  --zone teamserver common"
        ),
    )
    parser.add_argument(
        "--stale-threshold",
        type=int, default=120, metavar="MINUTES",
        help=(
            "Minutes before a stuck in_progress task is auto-reset to open "
            "(dev loop only, default: 120)"
        ),
    )
    parser.add_argument(
        "--node-id",
        default=None, metavar="ID",
        help=(
            "Unique identifier for this machine, used in claim/wip commit tags. "
            "Overrides the hostname so multiple VMs with the same hostname can be "
            "distinguished in the git log. "
            "Can also be set via the RC_NODE_ID environment variable. "
            "Default: socket.gethostname(). "
            "Example: --node-id desktop-dev01  →  tags become [desktop-dev01-claude]"
        ),
    )
    parser.add_argument(
        "--dev-light",
        action="store_true",
        default=False,
        help=(
            "Dev loop only: skip the lite QA pass and pre-claim QA gate after/before "
            "each task. Use this to get the original single-agent-call behaviour."
        ),
    )
    parser.add_argument(
        "--pre-claim-qa-turns",
        type=int, default=PRE_CLAIM_QA_MAX_TURNS, metavar="N",
        dest="pre_claim_qa_turns",
        help=(
            f"Dev loop only: max turns for the pre-claim QA gate (default: {PRE_CLAIM_QA_MAX_TURNS}). "
            "Increase for complex beads, decrease to save time. --dev-light disables the gate entirely."
        ),
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        default=False,
        help=(
            "Autotest loop only: skip the 10-second 'destructive action' "
            "countdown banner. Equivalent to RC_AUTOTEST_NO_CONFIRM=1."
        ),
    )
    return parser.parse_args()


# ── Main ───────────────────────────────────────────────────────────────────────

def resolve_node_id(args) -> str:
    """
    Return the node identifier to use in commit tags and log messages.
    Resolution order (first wins):
      1. --node-id CLI flag
      2. RC_NODE_ID environment variable
      3. .node-id file in the repo root (gitignored, auto-created on first run)

    On first run (no .node-id file), generates and persists:
        <hostname>-<4 random lowercase alphanumeric chars>
    e.g. "ubuntu-c2-dev01-a3kx"

    This guarantees uniqueness across machines with identical hostnames without
    any manual setup.
    """
    if args.node_id:
        return args.node_id
    env = os.environ.get("RC_NODE_ID", "").strip()
    if env:
        return env
    node_id_file = SCRIPT_DIR / ".node-id"
    if node_id_file.exists():
        val = node_id_file.read_text().strip()
        if val:
            return val
    # First run: generate and persist a unique node ID
    import random as _random
    import string as _string
    suffix = "".join(_random.choices(_string.ascii_lowercase + _string.digits, k=4))
    node_id = f"{socket.gethostname()}-{suffix}"
    node_id_file.write_text(node_id + "\n")
    return node_id


def main():
    args = parse_args()

    if args.model and args.agent != "claude":
        print("ERROR: --model is only applicable with --agent claude", file=sys.stderr)
        sys.exit(1)

    # Resolve --iterations default (None means "use loop-type default")
    if args.iterations is None:
        args.iterations = DEFAULT_ITERATIONS.get(args.loop, 0)

    node_id = resolve_node_id(args)
    args._node_id_resolved = node_id   # stash for dev_loop / review_loop

    # Maintenance loop doesn't use an agent — use a fixed log identity
    if args.loop == "maintenance":
        log = Logger(
            agent_id=f"{node_id}-maintenance",
            log_file=LOG_DIR / "maintenance.log",
        )
    else:
        log = Logger(
            agent_id=f"{node_id}-{args.agent}",
            log_file=LOG_DIR / f"{args.agent}_{args.loop}.log",
        )

    if args.pre_sleep > 0:
        log.log(f"Pre-sleep: waiting {args.pre_sleep}m before first run...")
        time.sleep(args.pre_sleep * 60)

    if args.loop == "dev":
        dev_loop(args, log)
    elif args.loop == "maintenance":
        maintenance_loop(args, log)
    else:
        review_loop(args, log)


if __name__ == "__main__":
    main()
