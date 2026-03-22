#!/bin/bash
# Red-Cell-C2 session start script
# Run on any machine at the start of a session — first time or switching VMs.
# Idempotent: safe to run as many times as you like.
#
# What it does:
#   1. Checks required tools are installed
#   2. git pull to get latest work from other VMs
#   3. Enforces br issue_prefix = red-cell-c2
#   4. Installs the MinGW payload build toolchains into data/
#   5. Rebuilds beads DB from JSONL
#   6. Shows open issues count and any in_progress tasks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail() { echo -e "${RED}[fail]${NC}  $*"; }

echo "=== Red-Cell-C2 session start ==="
echo ""

# ── 1. Required tools ──────────────────────────────────────────────────────────
check_tool() {
    local name="$1" cmd="${2:-$1}" install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        ok "$name: $(${cmd} --version 2>/dev/null | head -1)"
    else
        fail "$name not found. $install_hint"
        MISSING=1
    fi
}

MISSING=0
check_tool "git"     git     "sudo apt install git"
check_tool "uv"      uv      "curl -LsSf https://astral.sh/uv/install.sh | sh"
check_tool "br"      br      "Download from the project releases page and place in /usr/local/bin"
check_tool "claude"  claude  "npm install -g @anthropic-ai/claude-code  (needs Node.js)"
check_tool "codex"   codex   "npm install -g @openai/codex              (needs Node.js)"

if [[ "$MISSING" -eq 1 ]]; then
    echo ""
    warn "Some tools are missing. Install them and re-run this script."
    exit 1
fi

if ! uv python find --managed-python 3.12 &>/dev/null; then
    echo "Installing Python via uv..."
    uv python install 3.12
fi

UV_PYTHON="$(uv python find --managed-python 3.12)"
ok "Python: $UV_PYTHON"

# ── 2. Git sync ───────────────────────────────────────────────────────────────
echo ""
echo "--- Git sync ---"

# Check for uncommitted local changes that would block pull
if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "You have uncommitted local changes:"
    git status --short
    echo ""
    warn "Skipping git pull — commit or stash your changes first."
else
    CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
    UPSTREAM="$(git rev-parse --abbrev-ref '@{u}' 2>/dev/null || echo '')"
    if [[ -z "$UPSTREAM" ]]; then
        warn "No upstream configured for branch '$CURRENT_BRANCH' — skipping pull"
    else
        BEFORE="$(git rev-parse HEAD)"
        if git pull --ff-only --quiet 2>/dev/null; then
            AFTER="$(git rev-parse HEAD)"
            if [[ "$BEFORE" == "$AFTER" ]]; then
                ok "git: already up to date"
            else
                NEW_COMMITS="$(git log --oneline "$BEFORE..$AFTER" | wc -l | tr -d ' ')"
                ok "git: pulled $NEW_COMMITS new commit(s)"
                git log --oneline "$BEFORE..$AFTER" | sed 's/^/        /'
            fi
            if [[ -f "$SCRIPT_DIR/.stop" ]]; then
                rm "$SCRIPT_DIR/.stop"
                ok ".stop file removed — agent loops can run"
            fi
        else
            warn "git pull --ff-only failed (diverged?). Check manually:"
            echo "  git status; git log --oneline -5"
        fi
    fi
fi

# ── 4. br config — issue_prefix must match project config ─────────────────────
echo ""
echo "--- br config ---"

EXPECTED_PREFIX="red-cell-c2"
ACTUAL_PREFIX="$(br config get issue_prefix 2>/dev/null || echo '')"

if [[ "$ACTUAL_PREFIX" == "$EXPECTED_PREFIX" ]]; then
    ok "br issue_prefix: $ACTUAL_PREFIX"
else
    warn "br issue_prefix is '$ACTUAL_PREFIX', expected '$EXPECTED_PREFIX'. Fixing..."
    br config set issue_prefix "$EXPECTED_PREFIX"
    ok "br issue_prefix set to $EXPECTED_PREFIX"
fi

# ── 5. Payload build toolchains ────────────────────────────────────────────────
echo ""
echo "--- payload toolchains ---"

"$SCRIPT_DIR/scripts/install-toolchains.sh"

# ── 6. Build / refresh the beads DB from JSONL ────────────────────────────────
echo ""
echo "--- beads DB ---"

DB_PATH="$SCRIPT_DIR/.beads/beads.db"
if [[ -f "$DB_PATH" ]]; then
    ok "DB exists — running incremental import"
else
    warn "No DB found — building from JSONL"
fi

if br sync --import-only --rename-prefix --quiet 2>/dev/null; then
    OPEN_COUNT="$(br list --status=open --json 2>/dev/null | "$UV_PYTHON" -c 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get("issues",[])))' 2>/dev/null || echo '?')"
    ok "beads DB ready ($OPEN_COUNT open issues)"
else
    fail "br sync failed — check br version and JSONL integrity"
    exit 1
fi

# If --rename-prefix renamed IDs, the DB is ahead of JSONL and subsequent
# flushes will be blocked by the Stale DB Guard.  Heal this now.
if ! br sync --flush-only --quiet 2>/dev/null; then
    if br sync --flush-only --force --quiet 2>/dev/null; then
        if ! git diff --quiet -- .beads/issues.jsonl 2>/dev/null; then
            warn "Renamed issue IDs written to JSONL — committing and pushing"
            git add .beads/issues.jsonl
            git commit -m "chore: normalize issue IDs to red-cell-c2 prefix" --quiet \
                && git push --quiet \
                && ok "Normalized JSONL pushed" \
                || warn "Could not push — commit manually: git push"
        fi
    fi
fi

# Show any tasks currently in_progress (left over from another VM's session)
IN_PROGRESS="$(br list --status=in_progress --json 2>/dev/null | "$UV_PYTHON" -c '
import json, sys
issues = json.load(sys.stdin)
if not isinstance(issues, list): issues = issues.get("issues", [])
for i in issues:
    print(f"  {i[\"id\"]}  {i[\"title\"][:60]}")
' 2>/dev/null || echo '')"
if [[ -n "$IN_PROGRESS" ]]; then
    warn "Tasks currently in_progress (may be stale from another VM):"
    echo "$IN_PROGRESS"
fi

# ── 7. Git identity ────────────────────────────────────────────────────────────
echo ""
echo "--- Git identity ---"
GIT_USER="$(git config user.name 2>/dev/null || echo '')"
GIT_EMAIL="$(git config user.email 2>/dev/null || echo '')"

if [[ -z "$GIT_USER" || -z "$GIT_EMAIL" ]]; then
    warn "Git identity not set."
    echo "  Run: git config --global user.name  'Your Name'"
    echo "       git config --global user.email 'you@example.com'"
else
    ok "Git identity: $GIT_USER <$GIT_EMAIL>"
fi

# ── 8. cargo-sweep — build artifact cleaner ────────────────────────────────────
echo ""
echo "--- cargo-sweep ---"
if command -v cargo-sweep &>/dev/null; then
    ok "cargo-sweep: $(cargo-sweep --version 2>/dev/null | head -1)"
else
    warn "cargo-sweep not found — installing (needed for auto build-cache cleanup)"
    if cargo install cargo-sweep --quiet 2>/dev/null; then
        ok "cargo-sweep installed"
    else
        warn "cargo-sweep install failed — loop.py will fall back to manual incremental cleanup"
    fi
fi

# ── 9. Logs directory ─────────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/logs"
ok "logs/ directory ready"

# ── 10. Summary ───────────────────────────────────────────────────────────────
echo ""
HOSTNAME_ID="${HOSTNAME:-$(hostname)}"
echo "=== Ready on ${HOSTNAME_ID} ==="
echo ""
echo "Agent loops (dev):"
echo "  ./loop.py --agent claude --loop dev                        # ${HOSTNAME_ID}-claude, all zones"
echo "  ./loop.py --agent claude --loop dev --zone client-cli      # ${HOSTNAME_ID}-claude, client-cli only"
echo "  ./loop.py --agent codex  --loop dev --zone teamserver      # ${HOSTNAME_ID}-codex,  teamserver only"
echo "  ./loop.py --agent cursor --loop dev --zone client client-cli  # ${HOSTNAME_ID}-cursor, client zones"
echo ""
echo "Agent loops (review):"
echo "  ./loop.py --agent claude --loop qa                         # ${HOSTNAME_ID}-claude, QA (all zones)"
echo "  ./loop.py --agent claude --loop arch                       # ${HOSTNAME_ID}-claude, arch review"
echo "  ./loop.py --agent claude --loop quality                    # ${HOSTNAME_ID}-claude, test quality"
