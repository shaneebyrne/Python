"""
Dagda IDE - Theme Module
Catppuccin Mocha colour palette and ttk style configuration.
"""

import tkinter as tk
from tkinter import ttk

# ── Catppuccin Mocha palette ──────────────────────────────────────────────────
MOCHA = {
    "base":      "#1e1e2e",
    "mantle":    "#181825",
    "crust":     "#11111b",
    "surface0":  "#313244",
    "surface1":  "#45475a",
    "surface2":  "#585b70",
    "overlay0":  "#6c7086",
    "overlay1":  "#7f849c",
    "overlay2":  "#9399b2",
    "subtext0":  "#a6adc8",
    "subtext1":  "#bac2de",
    "text":      "#cdd6f4",
    "lavender":  "#b4befe",
    "blue":      "#89b4fa",
    "sapphire":  "#74c7ec",
    "sky":       "#89dceb",
    "teal":      "#94e2d5",
    "green":     "#a6e3a1",
    "yellow":    "#f9e2af",
    "peach":     "#fab387",
    "maroon":    "#eba0ac",
    "red":       "#f38ba8",
    "mauve":     "#cba6f7",
    "pink":      "#f5c2e7",
    "flamingo":  "#f2cdcd",
    "rosewater": "#f5e0dc",
}

# Convenient aliases
BG        = MOCHA["base"]
BG_DARK   = MOCHA["mantle"]
BG_DARKER = MOCHA["crust"]
SURFACE   = MOCHA["surface0"]
SURFACE1  = MOCHA["surface1"]
BORDER    = MOCHA["surface1"]
TEXT      = MOCHA["text"]
SUBTEXT   = MOCHA["subtext1"]
ACCENT    = MOCHA["mauve"]
GREEN     = MOCHA["green"]
RED       = MOCHA["red"]
YELLOW    = MOCHA["yellow"]
BLUE      = MOCHA["blue"]

# ── Editor syntax token colours ───────────────────────────────────────────────
SYNTAX = {
    "keyword":     MOCHA["mauve"],
    "builtin":     MOCHA["peach"],
    "string":      MOCHA["green"],
    "string_esc":  MOCHA["teal"],
    "comment":     MOCHA["overlay1"],
    "number":      MOCHA["peach"],
    "operator":    MOCHA["sky"],
    "punctuation": MOCHA["text"],
    "name":        MOCHA["text"],
    "class_name":  MOCHA["yellow"],
    "func_name":   MOCHA["blue"],
    "decorator":   MOCHA["flamingo"],
    "error":       MOCHA["red"],
    "type":        MOCHA["yellow"],
    "constant":    MOCHA["peach"],
    "attribute":   MOCHA["lavender"],
    "namespace":   MOCHA["teal"],
    "preprocessor":MOCHA["pink"],
    "label":       MOCHA["sapphire"],
}


def apply_theme(root: tk.Tk) -> ttk.Style:
    """Apply the Catppuccin Mocha theme to all ttk widgets."""
    style = ttk.Style(root)
    style.theme_use("clam")

    # ── General ───────────────────────────────────────────────────────────────
    style.configure(".",
        background=BG,
        foreground=TEXT,
        fieldbackground=SURFACE,
        bordercolor=BORDER,
        darkcolor=BG_DARK,
        lightcolor=SURFACE,
        troughcolor=BG_DARK,
        selectbackground=SURFACE1,
        selectforeground=TEXT,
        insertcolor=TEXT,
        relief="flat",
        font=("Segoe UI", 10),
    )

    # ── Frame ─────────────────────────────────────────────────────────────────
    style.configure("TFrame", background=BG)
    style.configure("Dark.TFrame", background=BG_DARK)
    style.configure("Surface.TFrame", background=SURFACE)

    # ── Label ─────────────────────────────────────────────────────────────────
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Dark.TLabel", background=BG_DARK, foreground=TEXT)
    style.configure("Status.TLabel",
        background=BG_DARK, foreground=SUBTEXT, font=("Segoe UI", 9), padding=(4, 2))
    style.configure("Accent.TLabel",
        background=BG_DARK, foreground=ACCENT, font=("Segoe UI", 9, "bold"), padding=(4, 2))
    style.configure("Logo.TLabel",
        background=BG_DARK, foreground=ACCENT,
        font=("Segoe UI", 11, "bold"), padding=(8, 4))

    # ── Button ────────────────────────────────────────────────────────────────
    style.configure("TButton",
        background=SURFACE, foreground=TEXT,
        relief="flat", padding=(8, 4), borderwidth=0)
    style.map("TButton",
        background=[("active", SURFACE1), ("pressed", BORDER)],
        foreground=[("active", TEXT)])

    style.configure("Run.TButton",
        background=MOCHA["green"], foreground=MOCHA["base"],
        font=("Segoe UI", 9, "bold"), padding=(10, 4))
    style.map("Run.TButton",
        background=[("active", MOCHA["teal"]), ("pressed", MOCHA["sapphire"])])

    style.configure("Stop.TButton",
        background=MOCHA["red"], foreground=MOCHA["base"],
        font=("Segoe UI", 9, "bold"), padding=(10, 4))
    style.map("Stop.TButton",
        background=[("active", MOCHA["maroon"]), ("pressed", MOCHA["red"])])

    style.configure("Tool.TButton",
        background=BG_DARK, foreground=TEXT,
        relief="flat", padding=(6, 4), borderwidth=0, font=("Segoe UI", 9))
    style.map("Tool.TButton",
        background=[("active", SURFACE), ("pressed", SURFACE1)])

    # ── Notebook (tabs) ───────────────────────────────────────────────────────
    style.configure("TNotebook",
        background=BG_DARK, borderwidth=0, tabmargins=0)
    style.configure("TNotebook.Tab",
        background=BG_DARK, foreground=SUBTEXT,
        padding=(12, 5), borderwidth=0, font=("Segoe UI", 9))
    style.map("TNotebook.Tab",
        background=[("selected", BG), ("active", SURFACE)],
        foreground=[("selected", TEXT), ("active", TEXT)])

    # ── Scrollbar ─────────────────────────────────────────────────────────────
    style.configure("TScrollbar",
        background=SURFACE, troughcolor=BG_DARK,
        arrowcolor=SUBTEXT, borderwidth=0, relief="flat")
    style.map("TScrollbar",
        background=[("active", SURFACE1), ("pressed", BORDER)])

    # ── Combobox ──────────────────────────────────────────────────────────────
    style.configure("TCombobox",
        background=SURFACE, foreground=TEXT,
        fieldbackground=SURFACE, selectbackground=SURFACE1,
        arrowcolor=SUBTEXT, borderwidth=0, relief="flat", padding=(4, 3))
    style.map("TCombobox",
        background=[("active", SURFACE1)],
        fieldbackground=[("readonly", SURFACE)],
        selectbackground=[("readonly", SURFACE)])

    # ── Separator ─────────────────────────────────────────────────────────────
    style.configure("TSeparator", background=BORDER)

    # ── Sash (PanedWindow) ───────────────────────────────────────────────────
    style.configure("TPanedwindow", background=BG_DARK)
    style.configure("Sash", sashrelief="flat", sashthickness=4, background=BORDER)

    return style
