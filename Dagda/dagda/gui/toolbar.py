"""
Dagda IDE - Toolbar
Run/Stop button + language selector combobox + common file-action buttons.
"""

from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from typing import Callable

from ..theme import MOCHA, BG_DARK, BORDER
from ..languages import all_names, get_runner


class Toolbar(ttk.Frame):
    def __init__(
        self,
        parent,
        on_new:      Callable,
        on_open:     Callable,
        on_save:     Callable,
        on_run:      Callable,
        on_stop:     Callable,
        on_lang_change: Callable[[str], None],
        **kwargs,
    ):
        super().__init__(parent, style="Dark.TFrame", **kwargs)
        self._on_run  = on_run
        self._on_stop = on_stop
        self._on_lang = on_lang_change
        self._build(on_new, on_open, on_save)

    def _build(self, on_new, on_open, on_save):
        # ── Logo / Brand ──────────────────────────────────────────────────────
        ttk.Label(self, text="☘ Dagda ☘", style="Logo.TLabel").pack(side="left")

        sep = tk.Frame(self, width=1, bg=BORDER)
        sep.pack(side="left", fill="y", padx=4, pady=4)

        # ── File buttons ──────────────────────────────────────────────────────
        self._tbtn("New",  "📄", on_new)
        self._tbtn("Open", "📂", on_open)
        self._tbtn("Save", "💾", on_save)

        sep2 = tk.Frame(self, width=1, bg=BORDER)
        sep2.pack(side="left", fill="y", padx=4, pady=4)

        # ── Run / Stop ────────────────────────────────────────────────────────
        self._run_btn = ttk.Button(
            self, text="▶  Run", style="Run.TButton",
            command=self._on_run, width=8,
        )
        self._run_btn.pack(side="left", padx=(0, 3), pady=4)

        self._stop_btn = ttk.Button(
            self, text="■  Stop", style="Stop.TButton",
            command=self._on_stop, width=8,
        )
        self._stop_btn.pack(side="left", padx=(0, 6), pady=4)
        self._stop_btn.state(["disabled"])

        sep3 = tk.Frame(self, width=1, bg=BORDER)
        sep3.pack(side="left", fill="y", padx=4, pady=4)

        # ── Language selector ─────────────────────────────────────────────────
        ttk.Label(self, text="Language:", style="Dark.TLabel").pack(
            side="left", padx=(4, 2))

        # Build display list: "Python", "Rust", …
        runners = {n: get_runner(n) for n in all_names()}
        self._lang_names = {
            r.display_name: n
            for n, r in runners.items()
            if r is not None
        }
        display_names = sorted(self._lang_names.keys())

        self._lang_var = tk.StringVar(value="Python")
        self._lang_cb = ttk.Combobox(
            self,
            textvariable=self._lang_var,
            values=display_names,
            state="readonly",
            width=20,
        )
        self._lang_cb.pack(side="left", padx=2, pady=4)
        self._lang_cb.bind("<<ComboboxSelected>>", self._lang_selected)

    def _tbtn(self, label: str, icon: str, cmd: Callable):
        ttk.Button(self, text=f"{icon} {label}", style="Tool.TButton",
                   command=cmd, width=8).pack(side="left", padx=2, pady=4)

    def _lang_selected(self, event=None):
        display = self._lang_var.get()
        internal = self._lang_names.get(display, "text")
        self._on_lang(internal)

    def set_running(self, running: bool):
        if running:
            self._run_btn.state(["disabled"])
            self._stop_btn.state(["!disabled"])
        else:
            self._run_btn.state(["!disabled"])
            self._stop_btn.state(["disabled"])

    def set_language_display(self, display_name: str):
        """Update the combobox to match a language (e.g. on file open)."""
        if display_name in self._lang_names:
            self._lang_var.set(display_name)

    def get_internal_language(self) -> str:
        display = self._lang_var.get()
        return self._lang_names.get(display, "text")
