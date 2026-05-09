"""
Dagda IDE - Status Bar
Shows: language, cursor position, encoding, modification flag, pygments availability.
"""

from __future__ import annotations
import tkinter as tk
from tkinter import ttk

from ..theme import MOCHA, BG_DARK, SUBTEXT


class StatusBar(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, style="Dark.TFrame", **kwargs)

        sep = tk.Frame(self, height=1, bg=MOCHA["surface1"])
        sep.pack(fill="x", side="top")

        inner = ttk.Frame(self, style="Dark.TFrame")
        inner.pack(fill="x", expand=True, padx=4)

        # Left-side items
        self._lang_var   = tk.StringVar(value="Plain Text")
        self._enc_var    = tk.StringVar(value="UTF-8")
        self._mod_var    = tk.StringVar(value="")

        ttk.Label(inner, textvariable=self._lang_var,
                  style="Accent.TLabel").pack(side="left")
        self._vsep(inner)
        ttk.Label(inner, textvariable=self._enc_var,
                  style="Status.TLabel").pack(side="left")
        self._vsep(inner)
        ttk.Label(inner, textvariable=self._mod_var,
                  style="Status.TLabel").pack(side="left")

        # Right-side items
        self._pos_var    = tk.StringVar(value="Ln 1, Col 1")
        self._hint_var   = tk.StringVar(value="")

        ttk.Label(inner, textvariable=self._hint_var,
                  style="Status.TLabel").pack(side="right", padx=(0, 4))
        self._vsep(inner)
        ttk.Label(inner, textvariable=self._pos_var,
                  style="Status.TLabel").pack(side="right")

    def _vsep(self, parent):
        tk.Frame(parent, width=1, bg=MOCHA["surface1"]).pack(
            side="left", fill="y", padx=2, pady=2)

    def set_language(self, name: str):
        self._lang_var.set(name)

    def set_cursor(self, line: int, col: int):
        self._pos_var.set(f"Ln {line}, Col {col}")

    def set_modified(self, modified: bool):
        self._mod_var.set("●  Unsaved" if modified else "")

    def set_encoding(self, enc: str):
        self._enc_var.set(enc)

    def set_hint(self, hint: str):
        self._hint_var.set(hint)
