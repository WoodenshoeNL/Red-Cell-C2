#!/bin/bash
# Machine setup script for Red-Cell-C2
# Run this once on a new machine after cloning the repo.
# Idempotent — safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail() { echo -e "${RED}[fail]${NC}  $*"; }

echo "=== Red-Cell-C2 machine setup ==="
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
check_tool "python3" python3 "sudo apt install python3"
check_tool "br"      br      "Download from the project releases page and place in /usr/local/bin"
check_tool "claude"  claude  "npm install -g @anthropic-ai/claude-code  (needs Node.js)"
check_tool "codex"   codex   "npm install -g @openai/codex              (needs Node.js)"

if [[ "$MISSING" -eq 1 ]]; then
    echo ""
    warn "Some tools are missing. Install them and re-run this script."
    exit 1
fi

# ── 2. br config — issue_prefix must match project config ─────────────────────
echo ""
echo "--- Configuring br ---"

EXPECTED_PREFIX="red-cell-c2"
ACTUAL_PREFIX="$(br config get issue_prefix 2>/dev/null || echo '')"

if [[ "$ACTUAL_PREFIX" == "$EXPECTED_PREFIX" ]]; then
    ok "br issue_prefix: $ACTUAL_PREFIX"
else
    warn "br issue_prefix is '$ACTUAL_PREFIX', expected '$EXPECTED_PREFIX'. Fixing..."
    br config set issue_prefix "$EXPECTED_PREFIX"
    ok "br issue_prefix set to $EXPECTED_PREFIX"
fi

# ── 3. Build / refresh the beads DB from JSONL ────────────────────────────────
echo ""
echo "--- Building beads DB ---"

DB_PATH="$SCRIPT_DIR/.beads/beads.db"
if [[ -f "$DB_PATH" ]]; then
    ok "DB exists — running incremental import"
else
    warn "No DB found — building from JSONL"
fi

if br sync --import-only --rename-prefix --quiet 2>/dev/null; then
    OPEN_COUNT="$(br list --status=open --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get("issues",[])))' 2>/dev/null || echo '?')"
    ok "beads DB ready ($OPEN_COUNT open issues)"
else
    fail "br sync failed — check br version and JSONL integrity"
    exit 1
fi

# ── 4. Git identity ────────────────────────────────────────────────────────────
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

# ── 5. Logs directory ─────────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/logs"
ok "logs/ directory ready"

# ── 6. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete ==="
echo ""
echo "To start the agent loops:"
echo "  ./codex_loop.sh          # Codex dev agent"
echo "  ./claude_loop.sh         # Claude QA agent"
echo "  ./cursor_loop.sh         # Cursor dev agent"
echo ""
HOSTNAME_SUFFIX="${HOSTNAME:-$(hostname)}"
echo "This machine's agent IDs will be: ${HOSTNAME_SUFFIX}-codex, ${HOSTNAME_SUFFIX}-codex (QA), etc."
