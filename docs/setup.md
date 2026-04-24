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
5. **Seed the autotest config** (only needed if you will run `automatic-test/test.py`):
   ```bash
   cp automatic-test/config/env.toml.example automatic-test/config/env.toml
   cp automatic-test/config/targets.toml.example automatic-test/config/targets.toml
   ```
   Both files are gitignored (host-specific). Edit `env.toml` and set
   `[server].callback_host` to this machine's IP as seen from the target VMs:
   ```bash
   ip route get <linux-target-ip> | grep -oP 'src \K[0-9.]+'
   ```
   The harness will auto-seed `env.toml` on first run if missing, but will
   warn until `callback_host` is set.
6. **Verify**: `br ready` should show available work.

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
