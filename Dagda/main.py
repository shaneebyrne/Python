"""
Dagda IDE — Main entry point.

Usage:
    python main.py
    python -m dagda
"""

import sys
import os

# Ensure the project root is on the Python path when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from dagda.app import DagdaApp


def main():
    root = tk.Tk()
    root.withdraw()  # Hide while initialising to prevent flash
    try:
        _app = DagdaApp(root)
    except Exception as e:
        import traceback
        traceback.print_exc()
        root.destroy()
        sys.exit(1)
    root.deiconify()
    root.mainloop()


if __name__ == "__main__":
    main()
