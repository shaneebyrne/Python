"""
Dagda IDE - Terminal / Output Panel
Scrollable read-only Text widget that receives streamed output from language runners.
Supports colour-coded tags: stdout, stderr, info, success, error.
"""

from __future__ import annotations
import tkinter as tk
from tkinter import ttk
import queue
import threading
from typing import Callable

from ..theme import MOCHA, BG_DARK, BG_DARKER, TEXT as TEXT_COLOR, SUBTEXT


class TerminalPanel(ttk.Frame):
    """Streams process output with colour tagging and an embedded toolbar."""

    TAGS = {
        "stdout":  {"foreground": MOCHA["text"]},
        "stderr":  {"foreground": MOCHA["red"]},
        "info":    {"foreground": MOCHA["blue"]},
        "success": {"foreground": MOCHA["green"]},
        "error":   {"foreground": MOCHA["red"]},
        "warn":    {"foreground": MOCHA["yellow"]},
        "prompt":  {"foreground": MOCHA["mauve"], "font": ("Segoe UI", 9, "bold")},
    }

    def __init__(self, parent, on_stop_cb: Callable | None = None, **kwargs):
        super().__init__(parent, style="Dark.TFrame", **kwargs)
        self._on_stop = on_stop_cb
        self._queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self._polling = False
        self._build()
        self._configure_tags()

    def _build(self):
        # ── Toolbar ───────────────────────────────────────────────────────────
        toolbar = ttk.Frame(self, style="Dark.TFrame")
        toolbar.pack(fill="x", side="top")

        lbl = ttk.Label(toolbar, text="⚡ Output", style="Accent.TLabel")
        lbl.pack(side="left", padx=(6, 0))

        self._stop_btn = ttk.Button(
            toolbar, text="■ Stop", style="Stop.TButton",
            command=self._on_stop_clicked, width=7
        )
        self._stop_btn.pack(side="left", padx=4, pady=2)
        self._stop_btn.state(["disabled"])

        clear_btn = ttk.Button(
            toolbar, text="⌫ Clear", style="Tool.TButton",
            command=self.clear, width=7
        )
        clear_btn.pack(side="left", padx=2, pady=2)

        # Separator
        sep = tk.Frame(self, height=1, bg=MOCHA["surface1"])
        sep.pack(fill="x")

        # ── Text area ─────────────────────────────────────────────────────────
        frame = ttk.Frame(self, style="Dark.TFrame")
        frame.pack(fill="both", expand=True)

        self._text = tk.Text(
            frame,
            bg=BG_DARKER, fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            relief="flat", bd=0,
            font=("Cascadia Code", 9),
            wrap="word",
            state="disabled",
            padx=8, pady=6,
        )
        vscroll = ttk.Scrollbar(frame, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=vscroll.set)

        self._text.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

    def _configure_tags(self):
        for tag, opts in self.TAGS.items():
            cfg = dict(opts)
            if "font" not in cfg:
                cfg["font"] = ("Cascadia Code", 9)
            self._text.tag_configure(tag, **cfg)

    # ── Public API ────────────────────────────────────────────────────────────
    def write(self, text: str, tag: str = "stdout"):
        """Thread-safe: enqueue a chunk of output."""
        self._queue.put((text, tag))
        if not self._polling:
            self._polling = True
            self._text.after(20, self._poll_queue)

    def clear(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def set_running(self, running: bool):
        if running:
            self._stop_btn.state(["!disabled"])
        else:
            self._stop_btn.state(["disabled"])

    def _on_stop_clicked(self):
        if self._on_stop:
            self._on_stop()

    def _poll_queue(self):
        """Drain the queue and write to the text widget (on the main thread)."""
        count = 0
        self._text.configure(state="normal")
        while not self._queue.empty() and count < 200:
            try:
                text, tag = self._queue.get_nowait()
                self._text.insert("end", text, (tag,))
                count += 1
            except queue.Empty:
                break
        self._text.see("end")
        self._text.configure(state="disabled")

        if not self._queue.empty():
            self._text.after(20, self._poll_queue)
        else:
            self._polling = False

    def print_separator(self, label: str = ""):
        bar = "─" * 60
        if label:
            bar = f"{'─' * 3} {label} {'─' * (55 - len(label))}"
        self.write(bar + "\n", "info")
