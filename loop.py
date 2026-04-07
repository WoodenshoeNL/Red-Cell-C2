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
    "dev":      0,
    "qa":       20 * 60,    # 20 minutes
    "arch":     120 * 60,   # 120 minutes
    "quality":  30 * 60,    # 30 minutes
    "coverage": 30 * 60,    # 30 minutes
}

# Dev loop timing constants (seconds)
DEV_SLEEP_NO_WORK     = 60     # wait when no tasks are ready
DEV_SLEEP_BETWEEN     = 15     # wait between tasks when --sleep not set
DEV_SLEEP_TOKEN_LIMIT = 1200   # wait after Claude context limit hit
DEV_CLEAN_EVERY       = 1      # run build-artifact cleanup every N dev iterations
DEV_MAX_TURNS         = 150    # max turns per dev session; agent commits WIP and resumes next iteration

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

# Review loops use a single best-of prompt per loop type (agent-independent)
REVIEW_PROMPTS = {
    "qa":       "prompts/CLAUDE_PROMPT.md",        # identical across agents
    "arch":     "prompts/CLAUDE_ARCH_PROMPT.md",   # Claude version is more thorough
    "quality":  "prompts/CLAUDE_TEST_PROMPT.md",   # quality-focused test review
    "coverage": "prompts/CODEX_TEST_PROMPT.md",    # breadth-focused coverage scan
}

# Review loop types that write a per-run timestamped log in addition to the rolling log
PER_RUN_LOG_LOOPS = {"arch", "quality", "coverage"}


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
\`\`\`
<paste the complete test failure output here — do not truncate>
\`\`\`
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


DEBUG_SIZE_LIMIT_GB   = 8      # nuke target/* build subdirs when total target/ exceeds this size
MIN_FREE_DISK_GB      = 5.0   # bail if less than this many GB free before starting a session


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


def clean_build_artifacts(log: Logger):
    """
    Remove stale Rust build artifacts to keep target/ from growing unboundedly.

    Strategy:
    - Measure total target/ size (debug + all codex-* alternate target dirs).
    - If total exceeds DEBUG_SIZE_LIMIT_GB, nuke heavyweight subdirs
      (incremental, deps, build, .fingerprint) in every target profile dir.
    - Uses ignore_errors=True on rmtree to survive races with concurrent cargo
      processes that may be writing into the same dirs.

    Called after every review-loop iteration and every DEV_CLEAN_EVERY dev iterations.
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
    if total_gb < DEBUG_SIZE_LIMIT_GB:
        log.log(f"build cache: target/ build dirs are {total_gb:.1f} GB — under limit, skipping")
        return

    if _cargo_target_locked(target_root):
        log.log("build cache: cargo build in progress — skipping cleanup to avoid mid-build wipe")
        return

    log.log(f"build cache: target/ build dirs are {total_gb:.1f} GB — exceeds {DEBUG_SIZE_LIMIT_GB} GB limit, nuking")

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


def _clean_cargo_target_inplace(target_dir: Path, label: str, size_limit_gb: float, log: Logger):
    """
    Clean heavyweight subdirs inside a stable cargo target dir when it exceeds
    size_limit_gb.  Never deletes the directory itself so incremental builds survive.

    Cargo lays out target/ as <profile>/{deps,build,incremental,.fingerprint}.
    We iterate profile subdirs and remove those heavyweight children.
    """
    import shutil as _shutil
    size_gb = _dir_size_gb(target_dir)
    if size_gb < size_limit_gb:
        return
    log.log(f"tmp cargo: {label} is {size_gb:.1f} GB — cleaning heavyweight subdirs")
    heavyweight_dirs = ["incremental", "deps", "build", ".fingerprint"]
    cleaned = []
    for profile in target_dir.iterdir():
        if not profile.is_dir():
            continue
        children = {e.name for e in profile.iterdir()}
        if not children & {"deps", "build", "incremental", ".fingerprint"}:
            continue
        for name in heavyweight_dirs:
            d = profile / name
            if d.exists():
                _shutil.rmtree(d, ignore_errors=True)
                if not d.exists():
                    cleaned.append(f"{profile.name}/{name}")
    if cleaned:
        log.log(f"tmp cargo: cleaned {label}/{{{','.join(cleaned)}}}")


def clean_tmp_cargo_targets(log: Logger):
    """
    Remove stale Cargo target directories under /tmp that are NOT git worktrees.

    The review loop keeps a stable shared target dir (REVIEW_CARGO_TARGET) and dev
    loops keep per-zone stable dirs (/tmp/red-cell-target-<zone>).  All other
    /tmp/red-cell* dirs that aren't git worktrees are swept and deleted when stale.

    Strategy:
    - Stable dirs (review + dev zone): clean heavyweight subdirs in-place when they
      exceed TMP_CARGO_SIZE_LIMIT_GB.  Never delete — preserves incremental cache.
      Skip entirely if a cargo build is actively holding the lock.
    - Transient dirs (everything else): remove entirely if older than
      TMP_CARGO_MAX_AGE_SECS and no process has its CWD inside them.
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

    for path_str, target_dir in stable_targets.items():
        if not target_dir.exists():
            continue
        if _cargo_target_locked(target_dir):
            log.log(f"tmp cargo: {target_dir.name} — build in progress, skipping")
            continue
        label = target_dir.name
        _clean_cargo_target_inplace(target_dir, label, TMP_CARGO_SIZE_LIMIT_GB, log)

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
    log.banner([
        f"{agent.title()} development loop starting",
        f"Agent ID:  {agent_id}",
        f"Prompt:    {prompt_file.name}",
        f"Log:       {log.log_file.name}",
        f"Max runs:  {'unlimited' if max_iters == 0 else max_iters}",
        f"Stale thr: {args.stale_threshold}m",
        f"Zones:     {zone_desc}",
    ])

    lock_path = SCRIPT_DIR / ".agent-claim.lock"
    lock_fd = open(lock_path, "w")

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
                log.log(f"Resuming previously claimed task {next_id} (skipping re-claim)")

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

            for candidate in candidates:
                if issue_status_from_jsonl(candidate) == "in_progress":
                    log.log(f"Skipping candidate already in_progress in JSONL: {candidate}")
                    continue
                log.log(f"Selected task: {candidate}")
                if claim_task(candidate, agent_id, log, rename_prefix):
                    next_id = candidate
                    break

        if not next_id:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            log.log("Could not claim any ready task — retrying after backoff")
            time.sleep(random.randint(5, 25))
            continue

        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        log.log(f"Claimed {next_id}")

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

        # Claude only: commit any uncommitted changes left by a token-limit interruption
        if agent == "claude":
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

        final_status = issue_status_from_jsonl(next_id)
        if final_status == "in_progress":
            log.log(
                f"Task {next_id} still in_progress after agent ran"
                f" — will resume on next iteration"
            )

        log.log("========================LOOP=========================")

        # Periodically clean up stale build artifacts and tmp worktrees
        if iteration % DEV_CLEAN_EVERY == 0:
            clean_build_artifacts(log)
            clean_tmp_worktrees(log)
            clean_tmp_cargo_targets(log)

        if max_turns_hit:
            log.log(f"Max turns ({DEV_MAX_TURNS}) reached — resuming task {next_id} immediately")
            # No sleep: resume on the very next iteration. find_resumable_task will
            # pick up the still-in_progress task and the WIP commit provides context.
        elif token_limit_hit:
            log.log(f"Token limit hit — sleeping {DEV_SLEEP_TOKEN_LIMIT}s before next iteration")
            time.sleep(DEV_SLEEP_TOKEN_LIMIT)
        else:
            do_sleep(sleep_secs, jitter_secs, log)


# ── Review loop worktree isolation ────────────────────────────────────────────
#
# Each review loop run gets its own git worktree so it can never touch the main
# checkout's working tree (and destroy a concurrent dev agent's uncommitted changes).
#
# The Cargo build cache is kept at a stable path between runs so incremental builds
# work — only changed files trigger recompilation.

# Stable Cargo target dir for all review loop runs. Kept between runs for incremental builds.
REVIEW_CARGO_TARGET = Path("/tmp/red-cell-review-target")

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


def create_review_worktree(loop_type: str, log: Logger) -> Path | None:
    """
    Create a temporary git worktree at HEAD for a single review loop run.
    Returns the worktree path, or None if creation fails (caller falls back to SCRIPT_DIR).
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
    log.log(f"Review worktree: {tmp}")
    return tmp


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

    while True:
        if stop_requested():
            log.log("STOP signal detected (.stop file exists). Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        label = f"{iteration + 1} of {max_iters}" if max_iters > 0 else str(iteration + 1)
        log.log(f"=== {loop_type.title()} review run {label} ===")

        git_pull_rebase(log)

        # Run the review agent in an isolated worktree so it can never touch the main
        # checkout's working tree (which may have a concurrent dev agent's uncommitted
        # changes). Use a stable shared Cargo target dir for incremental builds.
        worktree_path = create_review_worktree(loop_type, log)
        run_cwd = worktree_path or SCRIPT_DIR
        run_env: dict = {"CARGO_TARGET_DIR": str(REVIEW_CARGO_TARGET)}

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
            remove_review_worktree(worktree_path, log)

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
  dev       Development — claims beads tasks and implements them
  qa        QA review   — reviews recent commits, files issues (default sleep: 20m)
  arch      Architecture review — deep full-codebase analysis  (default sleep: 120m)
  quality   Test quality review — evaluates quality of existing tests (default sleep: 30m)
  coverage  Test coverage scan  — finds untested public functions    (default sleep: 30m)

examples:
  ./loop.py --agent claude --loop dev
  ./loop.py --agent claude --loop dev  --zone client-cli
  ./loop.py --agent codex  --loop dev  --zone teamserver
  ./loop.py --agent cursor --loop dev  --zone client-cli client
  ./loop.py --agent claude --loop dev  --sleep 0 --iterations 1
  ./loop.py --agent codex  --loop qa   --sleep 20
  ./loop.py --agent claude --loop arch --zone teamserver
  ./loop.py --agent claude --loop arch --sleep 120 --jitter 15
  ./loop.py --agent cursor --loop coverage --zone common --iterations 3
  ./loop.py --agent claude --loop dev  --pre-sleep 5 --model claude-opus-4-6
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
        choices=["dev", "qa", "arch", "quality", "coverage"],
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
            "If omitted, uses per-loop defaults: dev=0, qa=20, arch=120, quality/coverage=30"
        ),
    )
    parser.add_argument(
        "--jitter",
        type=float, default=0, metavar="MINUTES",
        help="Apply ±N minutes of random jitter to --sleep (default: 0)",
    )
    parser.add_argument(
        "--iterations",
        type=int, default=0, metavar="N",
        help="Max iterations before exit; 0 = run forever (default: 0)",
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
    return parser.parse_args()


# ── Main ───────────────────────────────────────────────────────────────────────

def resolve_node_id(args) -> str:
    """
    Return the node identifier to use in commit tags and log messages.
    Resolution order (first wins):
      1. --node-id CLI flag
      2. RC_NODE_ID environment variable
      3. socket.gethostname()
    """
    if args.node_id:
        return args.node_id
    env = os.environ.get("RC_NODE_ID", "").strip()
    if env:
        return env
    return socket.gethostname()


def main():
    args = parse_args()

    if args.model and args.agent != "claude":
        print("ERROR: --model is only applicable with --agent claude", file=sys.stderr)
        sys.exit(1)

    node_id = resolve_node_id(args)
    args._node_id_resolved = node_id   # stash for dev_loop / review_loop

    log = Logger(
        agent_id=f"{node_id}-{args.agent}",
        log_file=LOG_DIR / f"{args.agent}_{args.loop}.log",
    )

    if args.pre_sleep > 0:
        log.log(f"Pre-sleep: waiting {args.pre_sleep}m before first run...")
        time.sleep(args.pre_sleep * 60)

    if args.loop == "dev":
        dev_loop(args, log)
    else:
        review_loop(args, log)


if __name__ == "__main__":
    main()
