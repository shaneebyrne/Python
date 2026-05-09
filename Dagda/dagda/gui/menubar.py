"""
Dagda IDE - Menu Bar
Full application menu: File, Edit, View, Run, Language, Help.
"""

from __future__ import annotations
import tkinter as tk
from typing import Callable, TYPE_CHECKING

from ..theme import MOCHA
from ..languages import all_names, get_runner


def build_menubar(root: tk.Tk, app) -> tk.Menu:
    """Build and return the application menu bar, wiring callbacks to app."""

    col = {
        "bg":     MOCHA["surface0"],
        "fg":     MOCHA["text"],
        "abg":    MOCHA["surface1"],
        "afg":    MOCHA["text"],
        "relief": "flat",
        "bd":     0,
    }

    def menu(parent=None):
        m = tk.Menu(parent or root, tearoff=0,
                    bg=col["bg"], fg=col["fg"],
                    activebackground=col["abg"],
                    activeforeground=col["afg"],
                    relief=col["relief"], borderwidth=1)
        return m

    menubar = menu()

    # ── File ──────────────────────────────────────────────────────────────────
    file_m = menu(menubar)
    file_m.add_command(label="New",             accelerator="Ctrl+N",  command=app.cmd_new)
    file_m.add_command(label="Open…",           accelerator="Ctrl+O",  command=app.cmd_open)
    file_m.add_separator()
    file_m.add_command(label="Save",            accelerator="Ctrl+S",  command=app.cmd_save)
    file_m.add_command(label="Save As…",        accelerator="Ctrl+Shift+S", command=app.cmd_save_as)
    file_m.add_separator()
    file_m.add_command(label="Close Tab",       accelerator="Ctrl+W",  command=app.cmd_close_tab)
    file_m.add_separator()
    file_m.add_command(label="Quit",            accelerator="Ctrl+Q",  command=app.cmd_quit)
    menubar.add_cascade(label="File", menu=file_m)

    # ── Edit ──────────────────────────────────────────────────────────────────
    edit_m = menu(menubar)
    edit_m.add_command(label="Undo",            accelerator="Ctrl+Z",  command=app.cmd_undo)
    edit_m.add_command(label="Redo",            accelerator="Ctrl+Y",  command=app.cmd_redo)
    edit_m.add_separator()
    edit_m.add_command(label="Cut",             accelerator="Ctrl+X",  command=app.cmd_cut)
    edit_m.add_command(label="Copy",            accelerator="Ctrl+C",  command=app.cmd_copy)
    edit_m.add_command(label="Paste",           accelerator="Ctrl+V",  command=app.cmd_paste)
    edit_m.add_separator()
    edit_m.add_command(label="Select All",      accelerator="Ctrl+A",  command=app.cmd_select_all)
    edit_m.add_separator()
    edit_m.add_command(label="Find / Replace",  accelerator="Ctrl+F",  command=app.cmd_find)
    edit_m.add_separator()
    edit_m.add_command(label="Toggle Comment",  accelerator="Ctrl+/",  command=app.cmd_toggle_comment)
    edit_m.add_command(label="Duplicate Line",  accelerator="Ctrl+D",  command=app.cmd_duplicate_line)
    menubar.add_cascade(label="Edit", menu=edit_m)

    # ── View ──────────────────────────────────────────────────────────────────
    view_m = menu(menubar)
    view_m.add_command(label="Increase Font Size", accelerator="Ctrl++", command=app.cmd_font_larger)
    view_m.add_command(label="Decrease Font Size", accelerator="Ctrl+-", command=app.cmd_font_smaller)
    view_m.add_command(label="Reset Font Size",    accelerator="Ctrl+0", command=app.cmd_font_reset)
    view_m.add_separator()
    view_m.add_command(label="Toggle Terminal",    accelerator="Ctrl+`", command=app.cmd_toggle_terminal)
    menubar.add_cascade(label="View", menu=view_m)

    # ── Run ───────────────────────────────────────────────────────────────────
    run_m = menu(menubar)
    run_m.add_command(label="Run File",         accelerator="F5",      command=app.cmd_run)
    run_m.add_command(label="Stop",             accelerator="F6",      command=app.cmd_stop)
    run_m.add_separator()
    run_m.add_command(label="Clear Output",     command=app.cmd_clear_output)
    menubar.add_cascade(label="Run", menu=run_m)

    # ── Language ──────────────────────────────────────────────────────────────
    lang_m = menu(menubar)
    for lang_name in all_names():
        runner = get_runner(lang_name)
        if runner:
            lang_m.add_command(
                label=runner.display_name,
                command=lambda ln=lang_name: app.cmd_set_language(ln)
            )
    menubar.add_cascade(label="Language", menu=lang_m)

    # ── Help ──────────────────────────────────────────────────────────────────
    help_m = menu(menubar)
    help_m.add_command(label="Keyboard Shortcuts", command=app.cmd_show_shortcuts)
    help_m.add_command(label="About Dagda",        command=app.cmd_about)
    menubar.add_cascade(label="Help", menu=help_m)

    root.config(menu=menubar)
    return menubar
