#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHON_BIN="$(uv python find --system 2>/dev/null || uv python find)"
PYTHON_LIB_DIR="$(dirname "$PYTHON_BIN")/../lib"

export LD_LIBRARY_PATH="$PYTHON_LIB_DIR:${LD_LIBRARY_PATH:-}"

exec "$REPO_ROOT/target/release/red-cell" "$@"
