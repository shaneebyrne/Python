"""
Dagda IDE - File Manager
Open/save files and auto-detect language from extension.
"""

from __future__ import annotations
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional

from .languages import from_extension, get_runner

# ── File-type filter for the open dialog ──────────────────────────────────────
FILETYPES = [
    ("All files",        "*.*"),
    ("Python",           "*.py *.pyw"),
    ("Rust",             "*.rs"),
    ("Java",             "*.java"),
    ("JavaScript",       "*.js *.mjs *.cjs"),
    ("TypeScript",       "*.ts"),
    ("Ruby",             "*.rb"),
    ("PowerShell",       "*.ps1 *.psm1 *.psd1"),
    ("Bash/Shell",       "*.sh"),
    ("Batch",            "*.bat *.cmd"),
    ("C",                "*.c *.h"),
    ("C++",              "*.cpp *.cc *.cxx *.hpp"),
    ("Go",               "*.go"),
    ("Lua",              "*.lua"),
    ("PHP",              "*.php"),
    ("Swift",            "*.swift"),
    ("Kotlin",           "*.kt"),
    ("Perl",             "*.pl *.pm"),
    ("Markdown",         "*.md *.markdown"),
    ("JSON",             "*.json *.jsonc"),
    ("YAML",             "*.yaml *.yml"),
    ("TOML",             "*.toml"),
    ("SQL",              "*.sql"),
    ("HTML",             "*.html *.htm"),
    ("CSS",              "*.css"),
    ("Text",             "*.txt"),
]


def detect_language(filepath: str) -> str:
    """Return the internal language name for a file path."""
    _, ext = os.path.splitext(filepath)
    runner = from_extension(ext)
    return runner.name if runner else "text"


def language_display_name(lang_name: str) -> str:
    runner = get_runner(lang_name)
    return runner.display_name if runner else lang_name.capitalize()


def open_file(parent: tk.Widget, initial_dir: Optional[str] = None) -> Optional[tuple[str, str, str]]:
    """
    Show open dialog. Returns (filepath, content, language_name) or None.
    """
    path = filedialog.askopenfilename(
        parent=parent,
        title="Open File — Dagda",
        filetypes=FILETYPES,
        initialdir=initial_dir or os.path.expanduser("~"),
    )
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        messagebox.showerror("Open Error", f"Could not read file:\n{e}", parent=parent)
        return None
    lang = detect_language(path)
    return path, content, lang


def save_file(
    parent: tk.Widget,
    content: str,
    filepath: Optional[str] = None,
    save_as: bool = False,
) -> Optional[str]:
    """
    Save content to disk. Shows dialog if filepath is None or save_as=True.
    Returns the path saved to, or None on cancel.
    """
    if not filepath or save_as:
        filepath = filedialog.asksaveasfilename(
            parent=parent,
            title="Save File — Dagda",
            filetypes=FILETYPES,
            defaultextension=".py",
        )
        if not filepath:
            return None
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath
    except Exception as e:
        messagebox.showerror("Save Error", f"Could not save file:\n{e}", parent=parent)
        return None


def ask_save_before_close(parent: tk.Widget, name: str) -> str:
    """
    Ask the user whether to save before closing an unsaved tab.
    Returns: "save", "discard", "cancel"
    """
    answer = messagebox.askyesnocancel(
        "Unsaved Changes",
        f"'{name}' has unsaved changes.\nSave before closing?",
        parent=parent,
    )
    if answer is True:
        return "save"
    elif answer is False:
        return "discard"
    else:
        return "cancel"
