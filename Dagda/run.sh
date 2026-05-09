#!/usr/bin/env bash
# ============================================================
#  Dagda IDE — Linux / macOS Launcher
#  The All-Father of Polyglot IDEs
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colour output helpers ────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[Dagda]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[Dagda]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# ── Locate Python 3.9+ ───────────────────────────────────────
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major="${ver%%.*}"; minor="${ver##*.}"
        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.9+ not found. Install it and re-run."
    error "  Ubuntu/Debian: sudo apt install python3 python3-tk"
    error "  macOS:         brew install python-tk"
    exit 1
fi

info "Using: $PYTHON ($($PYTHON --version 2>&1))"

# ── Check tkinter ────────────────────────────────────────────
if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
    error "tkinter is not available for $PYTHON."
    warn  "  Ubuntu/Debian: sudo apt install python3-tk"
    warn  "  Fedora/RHEL:   sudo dnf install python3-tkinter"
    warn  "  macOS:         brew install python-tk@3.11  (or matching version)"
    exit 1
fi

# ── Optional: install pygments ───────────────────────────────
if ! "$PYTHON" -c "import pygments" &>/dev/null; then
    warn "pygments not found — attempting install for syntax highlighting..."
    "$PYTHON" -m pip install --quiet pygments || \
        warn "Could not install pygments. Syntax highlighting will be disabled."
fi

# ── Launch ───────────────────────────────────────────────────
info "Starting Dagda IDE..."
exec "$PYTHON" main.py "$@"
