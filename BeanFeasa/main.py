#!/usr/bin/env python3
"""
BeanFeasa — Log Analysis & Threat Detection Toolkit
=====================================================

A modular, cross-platform Python tool for parsing and analyzing log files
using Sigma-inspired detection rules. Inspired by WithSecure's Chainsaw.

Usage:
    python main.py                      Launch the GUI
    python main.py <file_or_dir>        CLI mode (auto-detected)
    python main.py --help               Show CLI options
    python cli.py <file_or_dir> [opts]  CLI mode directly
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _preflight():
    """Check for required packages."""
    missing = []
    try:
        import yaml
    except ImportError:
        missing.append("pyyaml")

    if missing:
        print(f"[!] Missing required packages: {', '.join(missing)}")
        print(f"    Install with: pip install {' '.join(missing)}")
        print(f"    Or run:       pip install -r requirements.txt")

    try:
        import Evtx
    except ImportError:
        print("[*] python-evtx not installed — EVTX parsing disabled.")
        print("    Install with: pip install python-evtx")

    try:
        from minidump.minidumpfile import MinidumpFile
    except ImportError:
        print("[*] minidump not installed — .dmp crash dump parsing disabled.")
        print("    Install with: pip install minidump")


def launch_gui():
    """Launch the BeanFeasa GUI."""
    _preflight()

    from gui.app import BeanFeasa

    app = BeanFeasa()

    # Center the window on screen
    app.update_idletasks()
    w = app.winfo_width()
    h = app.winfo_height()
    x = (app.winfo_screenwidth() // 2) - (w // 2)
    y = (app.winfo_screenheight() // 2) - (h // 2)
    app.geometry(f"+{x}+{y}")

    app.mainloop()


def main():
    """Route to GUI or CLI based on arguments."""
    # If arguments provided (other than just the script name), use CLI mode
    if len(sys.argv) > 1:
        # Check if the first arg looks like a file/dir or a CLI flag
        arg = sys.argv[1]
        if arg in ("--gui", "-g"):
            # Explicit GUI flag
            sys.argv.pop(1)
            launch_gui()
        elif arg in ("--help", "-h") or os.path.exists(arg) or arg.startswith("-"):
            # Route to CLI
            _preflight()
            from cli import main as cli_main
            cli_main()
        else:
            # Unknown arg — try CLI, it will show its own help/errors
            _preflight()
            from cli import main as cli_main
            cli_main()
    else:
        # No arguments — launch GUI
        launch_gui()


if __name__ == "__main__":
    main()
