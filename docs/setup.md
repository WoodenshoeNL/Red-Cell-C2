# New VM Setup

1. **Install `br`** (beads_rust issue tracker):
   ```bash
   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/beads_rust/main/install.sh" | bash
   ```
2. **Clone the repo** (or `git pull` if already cloned) — `br` auto-imports issues from `.beads/issues.jsonl` on first use.
3. **Tune systemd-oomd** so cargo builds don't trigger terminal/desktop OOM kills:
   ```bash
   ./oomd-setup.sh   # idempotent, prompts for sudo
   ```
4. **Install loop-log rotation** (otherwise `logs/claude_dev.log` grows to hundreds of MB):
   ```bash
   ./logrotate-setup.sh   # idempotent, prompts for sudo
   ```
5. **Verify**: `br ready` should show available work.

## Stopping a Dev Loop

Both the Claude and Codex dev loops check for a `.stop` file at the repo root before each
pass. If the file exists the agent halts cleanly without claiming new work.

**To stop a locally running loop:**
```bash
touch .stop
```

**To stop a remote/cloud loop (e.g. Codex):**
```bash
touch .stop && git add .stop && git commit -m "chore: stop dev loop" && git push
```

**To resume after stopping:**
```bash
rm .stop && git add .stop && git commit -m "chore: resume dev loop" && git push
# or locally:
rm .stop
```

The `.stop` file is intentionally not gitignored so it can be pushed to stop remote agents.
