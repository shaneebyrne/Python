#!/usr/bin/env bash
# ====================================================
#   Lugh - Cybersecurity Toolkit v3.0
# ====================================================
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "===================================================="
echo "  Lugh - Cybersecurity Toolkit v3.0"
echo "  Email / IDN / Files / Hashes / Logs / Links / Adv"
echo "===================================================="
echo ""

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(sys.version_info.major)")
        if [ "$ver" = "3" ]; then PYTHON="$cmd"; break; fi
    fi
done
if [ -z "$PYTHON" ]; then
    echo "[ERROR] Python 3 not found."
    echo "  macOS:  brew install python3"
    echo "  Ubuntu: sudo apt install python3 python3-tk"
    echo "  Fedora: sudo dnf install python3 python3-tkinter"
    exit 1
fi
echo "  Python: $($PYTHON --version)"

# CLI mode if args passed
if [ $# -gt 0 ]; then
    $PYTHON "$SCRIPT_DIR/lugh.py" "$@"
    exit $?
fi

# GUI mode
if ! $PYTHON -c "import tkinter" 2>/dev/null; then
    echo "[ERROR] tkinter not available."
    echo "  Ubuntu: sudo apt install python3-tk"
    echo "  Fedora: sudo dnf install python3-tkinter"
    echo "  macOS:  brew install python-tk"
    exit 1
fi
[ ! -f "main.py" ] && echo "[ERROR] main.py not found" && exit 1

$PYTHON -c "import customtkinter" 2>/dev/null && echo "  customtkinter: installed" || echo "  customtkinter: not installed"
$PYTHON -c "import yara" 2>/dev/null && echo "  yara-python: installed" || echo "  yara-python: not installed"
$PYTHON -c "import Evtx.Evtx" 2>/dev/null && echo "  python-evtx: installed" || echo "  python-evtx: auto-installs"

echo ""
echo "Launching Lugh..."
$PYTHON main.py
