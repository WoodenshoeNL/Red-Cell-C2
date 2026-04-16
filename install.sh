#!/bin/bash
# install.sh — Production installer for Red-Cell-C2
#
# Installs system dependencies and payload build toolchains on a Ubuntu/Debian
# server or workstation that will run the teamserver and/or client.
#
# Must be run as root or with sudo.
#
# Usage:
#   sudo ./install.sh                  # install everything (teamserver + client + agents)
#   sudo ./install.sh --teamserver     # teamserver only
#   sudo ./install.sh --client         # client only
#   sudo ./install.sh --agents         # Rust cross-compile targets for Phantom + Specter
#   sudo ./install.sh --teamserver --client  # explicit combination

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail() { echo -e "${RED}[fail]${NC}  $*"; }
info() { echo -e "${BOLD}[--]${NC}    $*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────

INSTALL_TEAMSERVER=0
INSTALL_CLIENT=0
INSTALL_AGENTS=0

for arg in "$@"; do
    case "$arg" in
        --teamserver) INSTALL_TEAMSERVER=1 ;;
        --client)     INSTALL_CLIENT=1 ;;
        --agents)     INSTALL_AGENTS=1 ;;
        --help|-h)
            echo "Usage: sudo $0 [--teamserver] [--client] [--agents]"
            echo "  (no flags = install all)"
            exit 0
            ;;
        *)
            fail "Unknown argument: $arg"
            echo "Usage: sudo $0 [--teamserver] [--client] [--agents]"
            exit 1
            ;;
    esac
done

# Default: install all if no flags given
if [[ "$INSTALL_TEAMSERVER" -eq 0 && "$INSTALL_CLIENT" -eq 0 && "$INSTALL_AGENTS" -eq 0 ]]; then
    INSTALL_TEAMSERVER=1
    INSTALL_CLIENT=1
    INSTALL_AGENTS=1
fi

# ── Sudo / root check ─────────────────────────────────────────────────────────

if [[ "$EUID" -ne 0 ]]; then
    fail "This script must be run as root or with sudo."
    echo "  Run: sudo $0 $*"
    exit 1
fi

# ── Distro check ─────────────────────────────────────────────────────────────

if ! command -v apt-get &>/dev/null; then
    fail "apt-get not found. This installer supports Ubuntu/Debian only."
    exit 1
fi

# ── Header ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}=== Red-Cell-C2 Production Installer ===${NC}"
WHAT_INSTALLING=()
[[ "$INSTALL_TEAMSERVER" -eq 1 ]] && WHAT_INSTALLING+=("teamserver")
[[ "$INSTALL_CLIENT"     -eq 1 ]] && WHAT_INSTALLING+=("client")
[[ "$INSTALL_AGENTS"     -eq 1 ]] && WHAT_INSTALLING+=("agent toolchains")
info "Installing: $(IFS='+'; echo "${WHAT_INSTALLING[*]}")"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────

echo "--- system packages ---"

# Packages required by both teamserver and client:
#   ca-certificates / curl / wget  — used to install uv and fetch artifacts
COMMON_PKGS=(
    ca-certificates
    curl
    wget
)

# Teamserver-only packages:
#   nasm          — assembler used by the Demon payload builder
#   libsqlite3-0  — SQLite runtime (sqlx)
TEAMSERVER_PKGS=(
    nasm
    libsqlite3-0
)

# Client-only packages (eframe GUI + rfd file dialog on Linux):
#   libxcb-*         — X11 client library and extensions
#   libxkbcommon*    — keyboard handling
#   libgl1           — OpenGL runtime for eframe renderer
#   libfontconfig1   — font discovery
#   libfreetype6     — font rasteriser
#   libgtk-3-0       — GTK3 runtime for rfd native file dialogs
CLIENT_PKGS=(
    libxcb1
    libxcb-render0
    libxcb-shape0
    libxcb-xfixes0
    libxkbcommon0
    libxkbcommon-x11-0
    libgl1
    libfontconfig1
    libfreetype6
    libgtk-3-0
)

PKGS=("${COMMON_PKGS[@]}")
[[ "$INSTALL_TEAMSERVER" -eq 1 ]] && PKGS+=("${TEAMSERVER_PKGS[@]}")
[[ "$INSTALL_CLIENT"     -eq 1 ]] && PKGS+=("${CLIENT_PKGS[@]}")

info "Updating package lists..."
apt-get update -qq

info "Installing packages: ${PKGS[*]}"
apt-get install -y --no-install-recommends "${PKGS[@]}"
ok "system packages installed"

# ── 2. uv + Python ────────────────────────────────────────────────────────────

echo ""
echo "--- uv + Python ---"

if command -v uv &>/dev/null; then
    ok "uv already present: $(uv --version)"
else
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
    ok "uv installed: $(uv --version)"
fi

uv python install 3.12

# Resolve the lib directory for the uv-managed Python 3.12
PYTHON_BIN="$(uv python find 3.12 2>/dev/null || uv python find)"
PYTHON_LIB_DIR="$(realpath "$(dirname "$PYTHON_BIN")/../lib")"

# Register with runtime dynamic linker (needed at run time)
echo "$PYTHON_LIB_DIR" > /etc/ld.so.conf.d/uv-python.conf
ldconfig
ok "libpython registered with ldconfig: $PYTHON_LIB_DIR"

# Create the linker symlink libpython3.12.so in /usr/lib/x86_64-linux-gnu so
# lld can find it at build time. The system already ships libpython3.12.so.1.0
# there; we just add the unversioned symlink that libpython3.12-dev would
# normally provide. Using a relative target keeps this self-contained.
if [[ ! -e /usr/lib/x86_64-linux-gnu/libpython3.12.so ]]; then
    ln -sf libpython3.12.so.1.0 /usr/lib/x86_64-linux-gnu/libpython3.12.so
    ok "linker symlink: /usr/lib/x86_64-linux-gnu/libpython3.12.so -> libpython3.12.so.1.0"
else
    ok "linker symlink already present: /usr/lib/x86_64-linux-gnu/libpython3.12.so"
fi
ldconfig

# ── 3. Payload build toolchains (teamserver only) ─────────────────────────────

if [[ "$INSTALL_TEAMSERVER" -eq 1 ]]; then
    echo ""
    echo "--- payload build toolchains ---"
    # Run as the original (non-root) user if invoked via sudo, so file ownership
    # matches the user who will run the teamserver.
    TOOLCHAIN_SCRIPT="$SCRIPT_DIR/scripts/install-toolchains.sh"
    if [[ ! -f "$TOOLCHAIN_SCRIPT" ]]; then
        fail "install-toolchains.sh not found at $TOOLCHAIN_SCRIPT"
        exit 1
    fi
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" bash "$TOOLCHAIN_SCRIPT"
    else
        bash "$TOOLCHAIN_SCRIPT"
    fi
fi

# ── 4. Runtime directories ────────────────────────────────────────────────────

echo ""
echo "--- runtime directories ---"

# Create directories as the invoking user when possible
OWNER="${SUDO_USER:-root}"

create_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        chown "$OWNER":"$OWNER" "$dir"
        ok "created $dir"
    else
        ok "$dir already exists"
    fi
}

if [[ "$INSTALL_TEAMSERVER" -eq 1 ]]; then
    create_dir "$SCRIPT_DIR/data"
    create_dir "$SCRIPT_DIR/logs"
fi

if [[ "$INSTALL_CLIENT" -eq 1 ]]; then
    create_dir "$SCRIPT_DIR/logs"
fi

# ── 5. Agent Rust toolchains (agents only) ────────────────────────────────────

if [[ "$INSTALL_AGENTS" -eq 1 ]]; then
    echo ""
    echo "--- agent Rust cross-compile targets ---"

    if ! command -v rustup &>/dev/null; then
        fail "rustup not found — install Rust first: https://rustup.rs"
        exit 1
    fi

    # Phantom: statically-linked Linux binaries
    info "Adding Rust target: x86_64-unknown-linux-musl (Phantom x64)"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" rustup target add x86_64-unknown-linux-musl
    else
        rustup target add x86_64-unknown-linux-musl
    fi

    info "Adding Rust target: aarch64-unknown-linux-musl (Phantom arm64)"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" rustup target add aarch64-unknown-linux-musl
    else
        rustup target add aarch64-unknown-linux-musl
    fi

    # musl-tools provides musl-gcc wrapper needed by the musl targets
    apt-get install -y --no-install-recommends musl-tools

    # aarch64 cross-linker
    apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu

    # Specter: Windows PE binaries (uses MinGW linker from --teamserver)
    info "Adding Rust target: x86_64-pc-windows-gnu (Specter x64)"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" rustup target add x86_64-pc-windows-gnu
    else
        rustup target add x86_64-pc-windows-gnu
    fi

    ok "agent Rust targets installed"
    warn "Specter requires MinGW-w64 linker — run --teamserver if not already done."

    # cargo-nextest — faster test runner used by the QA loop
    if command -v cargo-nextest &>/dev/null; then
        ok "cargo-nextest already installed"
    else
        info "Installing cargo-nextest..."
        NEXTEST_USER="${SUDO_USER:-root}"
        NEXTEST_CARGO_BIN="$(eval echo ~$NEXTEST_USER)/.cargo/bin"
        if curl -LsSf https://get.nexte.st/latest/linux | sudo -u "$NEXTEST_USER" tar zxf - -C "$NEXTEST_CARGO_BIN" 2>/dev/null; then
            ok "cargo-nextest installed"
        else
            warn "cargo-nextest install failed — QA loop will fall back to cargo test"
        fi
    fi
fi

# ── 6. Binary checks ──────────────────────────────────────────────────────────

echo ""
echo "--- binaries ---"

check_binary() {
    local name="$1" path="$2"
    if [[ -x "$path" ]]; then
        ok "$name binary found at $path"
    else
        warn "$name binary not found at $path"
        echo "       Build with: cargo build --release -p $name"
    fi
}

[[ "$INSTALL_TEAMSERVER" -eq 1 ]] && check_binary "red-cell"        "$SCRIPT_DIR/target/release/red-cell"
[[ "$INSTALL_CLIENT"     -eq 1 ]] && check_binary "red-cell-client" "$SCRIPT_DIR/target/release/red-cell-client"

# ── 7. Summary ────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}=== Installation complete ===${NC}"
echo ""

if [[ "$INSTALL_TEAMSERVER" -eq 1 ]]; then
    echo "Teamserver:"
    echo "  ./target/release/red-cell --profile profiles/havoc.yaotl"
    echo ""
fi

if [[ "$INSTALL_CLIENT" -eq 1 ]]; then
    echo "Client:"
    echo "  ./target/release/red-cell-client"
    echo ""
fi

if [[ "$INSTALL_AGENTS" -eq 1 ]]; then
    echo "Agent builds:"
    echo "  Phantom:  cd phantom && cargo build --release --target x86_64-unknown-linux-musl"
    echo "  Specter:  cd specter && cargo build --release --target x86_64-pc-windows-gnu"
    echo "  Archon:   cd archon && make   (requires --teamserver for nasm + MinGW)"
    echo ""
fi
