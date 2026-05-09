#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════
#  BeanFeasa — Linux / macOS Launcher
#  Log Analysis & Threat Detection Toolkit
# ═══════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BLUE='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${BLUE}  =============================================${NC}"
echo -e "${BLUE}    BeanFeasa — Log Analysis Toolkit${NC}"
echo -e "${BLUE}  =============================================${NC}"
echo ""

# ── Locate Python 3 ──
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 | awk '{print $2}')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${RED}[ERROR] Python 3.10+ not found.${NC}"
    echo "  Install from https://python.org or your package manager."
    exit 1
fi

PY_VER=$("$PYTHON" --version 2>&1)
echo -e "  ${GREEN}[*]${NC} $PY_VER"
echo -e "  ${GREEN}[*]${NC} Working directory: $SCRIPT_DIR"

# ── Check / install dependencies ──
echo -e "  ${GREEN}[*]${NC} Checking dependencies..."

install_pkg() {
    local pkg="$1"
    local import_name="${2:-$1}"
    if ! "$PYTHON" -c "import $import_name" &>/dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing $pkg..."
        "$PYTHON" -m pip install "$pkg" --quiet --break-system-packages 2>/dev/null \
            || "$PYTHON" -m pip install "$pkg" --quiet --user 2>/dev/null \
            || "$PYTHON" -m pip install "$pkg" --quiet
    fi
}

install_pkg "pyyaml" "yaml"
install_pkg "python-evtx" "Evtx"
install_pkg "minidump" "minidump"

echo -e "  ${GREEN}[*]${NC} Dependencies OK."

# ── macOS: tkinter check ──
if [[ "$(uname)" == "Darwin" ]]; then
    if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
        echo -e "  ${RED}[ERROR] tkinter not available.${NC}"
        echo "  On macOS, install via: brew install python-tk"
        exit 1
    fi
fi

# ── Linux: tkinter check ──
if [[ "$(uname)" == "Linux" ]]; then
    if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
        echo -e "  ${RED}[ERROR] tkinter not available.${NC}"
        echo "  Install via: sudo apt install python3-tk  (Debian/Ubuntu)"
        echo "           or: sudo dnf install python3-tkinter  (Fedora)"
        exit 1
    fi
fi

echo ""
echo -e "  ${GREEN}[*]${NC} Starting BeanFeasa GUI..."
echo -e "${BLUE}  =============================================${NC}"
echo ""

"$PYTHON" main.py "$@"
