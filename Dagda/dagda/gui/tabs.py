"""
Dagda IDE - Tab Manager
Wraps ttk.Notebook to manage multiple EditorWidget tabs.
Each tab carries its own EditorWidget and file state.
"""

from __future__ import annotations
import os
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from ..editor import EditorWidget
from ..theme import MOCHA


class TabManager(ttk.Notebook):
    """Notebook subclass that manages EditorWidget tabs."""

    def __init__(self, parent, on_tab_change: Callable | None = None, **kwargs):
        super().__init__(parent, **kwargs)
        self._on_tab_change = on_tab_change
        self._tab_count = 0
        self.bind("<<NotebookTabChanged>>", self._tab_changed)
        # Right-click context menu
        self.bind("<Button-3>", self._on_right_click)
        self._menu = self._build_ctx_menu()

    def _build_ctx_menu(self):
        m = tk.Menu(self, tearoff=0,
                    bg=MOCHA["surface0"], fg=MOCHA["text"],
                    activebackground=MOCHA["surface1"],
                    activeforeground=MOCHA["text"],
                    relief="flat", borderwidth=1)
        m.add_command(label="Close Tab",       command=self.close_current)
        m.add_command(label="Close Others",    command=self._close_others)
        m.add_command(label="Close All",       command=self._close_all)
        m.add_separator()
        m.add_command(label="New Tab",         command=self.new_tab)
        return m

    def _on_right_click(self, event):
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    # ── Tab creation / removal ────────────────────────────────────────────────
    def new_tab(self, filepath: Optional[str] = None,
                content: str = "", language: str = "python") -> EditorWidget:
        """Create and return a new EditorWidget tab."""
        self._tab_count += 1
        frame = ttk.Frame(self, style="TFrame")

        editor = EditorWidget(frame)
        editor.pack(fill="both", expand=True)

        label = os.path.basename(filepath) if filepath else f"untitled-{self._tab_count}"
        self.add(frame, text=f"  {label}  ")
        self.select(frame)

        if filepath:
            editor.filepath = filepath
        if content:
            editor.set_content(content)
        editor.language = language
        editor.focus()

        # Store editor reference on the frame for retrieval
        frame._editor = editor  # type: ignore[attr-defined]

        return editor

    def current_editor(self) -> Optional[EditorWidget]:
        tab = self.select()
        if not tab:
            return None
        frame = self.nametowidget(tab)
        return getattr(frame, "_editor", None)

    def all_editors(self) -> list[EditorWidget]:
        eds = []
        for tab in self.tabs():
            frame = self.nametowidget(tab)
            ed = getattr(frame, "_editor", None)
            if ed:
                eds.append(ed)
        return eds

    def close_current(self):
        tab = self.select()
        if tab:
            self.forget(tab)
            if not self.tabs():
                self.new_tab()

    def _close_others(self):
        current = self.select()
        for tab in list(self.tabs()):
            if tab != current:
                self.forget(tab)

    def _close_all(self):
        for tab in list(self.tabs()):
            self.forget(tab)
        self.new_tab()

    def update_tab_title(self, editor: EditorWidget):
        """Refresh the tab label (e.g. after save or modification)."""
        for tab in self.tabs():
            frame = self.nametowidget(tab)
            ed = getattr(frame, "_editor", None)
            if ed is editor:
                name = (
                    os.path.basename(editor.filepath)
                    if editor.filepath else "untitled"
                )
                dot = "● " if editor.modified else "  "
                self.tab(tab, text=f"{dot}{name}  ")
                break

    def _tab_changed(self, event=None):
        if self._on_tab_change:
            ed = self.current_editor()
            self._on_tab_change(ed)
