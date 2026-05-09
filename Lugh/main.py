#!/usr/bin/env python3
"""
Lugh - Cybersecurity Toolkit v3.0
Tempo Communications IT Department

GUI Mode:   python main.py
CLI Mode:   python lugh.py headers <file.eml> [--all|--hops|--auth|--json|--raw]
            python lugh.py gui

Tabs:
  1. Email Header Analyzer    5. Event Log Parser
  2. Homograph / IDN Detector  6. Malicious Link Analyzer
  3. File Type Checker         7. Advanced Tools
  4. Hash Checker

Requirements:
  REQUIRED:  Python 3.8+ with tkinter
  OPTIONAL:  pip install customtkinter   (modern dark UI)
             pip install yara-python     (YARA rule scanning)
             pip install python-evtx     (.evtx parsing — auto-installs on first use)
"""
import sys
import os

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
os.chdir(_PROJECT_ROOT)

if len(sys.argv) > 1:
    from lugh import main as cli_main
    cli_main()
else:
    from gui.app import PyCyApp
    app = PyCyApp()
    app.run()
