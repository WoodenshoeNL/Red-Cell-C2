#!/bin/bash
# Download and install the musl.cc MinGW-w64 cross-compilers expected by the
# default Havoc-compatible teamserver profile.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="${RED_CELL_DATA_DIR:-$REPO_ROOT/data}"
CACHE_DIR="${RED_CELL_TOOLCHAIN_CACHE_DIR:-${TMPDIR:-/tmp}/red-cell-toolchains}"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail() { echo -e "${RED}[fail]${NC}  $*"; }

require_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "Required tool '$tool' is not installed"
        exit 1
    fi
}

download_file() {
    local url="$1" destination="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error "$url" --output "$destination"
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$destination" "$url"
        return
    fi
    fail "Neither curl nor wget is installed; cannot download toolchains"
    exit 1
}

install_toolchain() {
    local toolchain="$1" archive_name="$2" compiler_path="$3"
    local destination_dir="$DATA_DIR/$toolchain"
    local expected_binary="$destination_dir/bin/$compiler_path"
    local archive_path="$CACHE_DIR/$archive_name"

    if [[ -x "$expected_binary" ]]; then
        ok "$toolchain already installed at $expected_binary"
        return
    fi

    mkdir -p "$DATA_DIR" "$CACHE_DIR"

    if [[ -f "$archive_path" ]]; then
        ok "using cached archive $archive_path"
    else
        local url="https://musl.cc/$archive_name"
        echo "Downloading $url"
        download_file "$url" "$archive_path"
    fi

    local extract_root
    extract_root="$(mktemp -d "${TMPDIR:-/tmp}/red-cell-toolchain.XXXXXX")"

    tar -xzf "$archive_path" -C "$extract_root"

    local extracted_dir="$extract_root/$toolchain"
    if [[ ! -d "$extracted_dir" ]]; then
        rm -rf "$extract_root"
        fail "archive $archive_name did not contain expected directory $toolchain"
        exit 1
    fi

    rm -rf "$destination_dir"
    mv "$extracted_dir" "$destination_dir"
    rm -rf "$extract_root"

    if [[ ! -x "$expected_binary" ]]; then
        fail "installed toolchain is missing expected compiler $expected_binary"
        exit 1
    fi

    ok "installed $toolchain into $destination_dir"
}

require_tool tar

echo "Installing Havoc-compatible MinGW-w64 toolchains into $DATA_DIR"

install_toolchain \
    "x86_64-w64-mingw32-cross" \
    "x86_64-w64-mingw32-cross.tgz" \
    "x86_64-w64-mingw32-gcc"

install_toolchain \
    "i686-w64-mingw32-cross" \
    "i686-w64-mingw32-cross.tgz" \
    "i686-w64-mingw32-gcc"

ok "payload build toolchains ready"
