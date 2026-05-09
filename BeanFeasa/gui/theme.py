"""
BeanFeasa GUI Theme — Catppuccin Mocha
"""


class CatppuccinMocha:
    """Catppuccin Mocha color palette."""

    # Base colors
    BASE = "#1e1e2e"
    MANTLE = "#181825"
    CRUST = "#11111b"
    SURFACE0 = "#313244"
    SURFACE1 = "#45475a"
    SURFACE2 = "#585b70"
    OVERLAY0 = "#6c7086"
    OVERLAY1 = "#7f849c"
    OVERLAY2 = "#9399b2"

    # Text
    TEXT = "#cdd6f4"
    SUBTEXT0 = "#a6adc8"
    SUBTEXT1 = "#bac2de"

    # Accents
    ROSEWATER = "#f5e0dc"
    FLAMINGO = "#f2cdcd"
    PINK = "#f5c2e7"
    MAUVE = "#cba6f7"
    RED = "#f38ba8"
    MAROON = "#eba0ac"
    PEACH = "#fab387"
    YELLOW = "#f9e2af"
    GREEN = "#a6e3a1"
    TEAL = "#94e2d5"
    SKY = "#89dceb"
    SAPPHIRE = "#74c7ec"
    BLUE = "#89b4fa"
    LAVENDER = "#b4befe"

    # Semantic aliases
    BG_PRIMARY = BASE
    BG_SECONDARY = MANTLE
    BG_TERTIARY = CRUST
    BG_WIDGET = SURFACE0
    BG_HOVER = SURFACE1
    BG_ACTIVE = SURFACE2
    FG_PRIMARY = TEXT
    FG_SECONDARY = SUBTEXT1
    FG_DIM = SUBTEXT0
    FG_MUTED = OVERLAY1
    ACCENT = BLUE
    ACCENT_ALT = MAUVE
    SUCCESS = GREEN
    WARNING = YELLOW
    ERROR = RED
    INFO = SAPPHIRE
    HIGHLIGHT = PEACH

    # Severity mapping for detections
    SEVERITY = {
        "critical": RED,
        "high": PEACH,
        "medium": YELLOW,
        "low": BLUE,
        "informational": TEAL,
        "info": TEAL,
    }


def apply_theme(root):
    """Apply the Catppuccin Mocha theme to a tkinter root and its ttk styles."""
    import tkinter.ttk as ttk

    C = CatppuccinMocha
    style = ttk.Style(root)

    root.configure(bg=C.BG_PRIMARY)
    root.option_add("*Background", C.BG_PRIMARY)
    root.option_add("*Foreground", C.FG_PRIMARY)
    root.option_add("*Font", ("Consolas", 10))

    # ── ttk Theme ──
    style.theme_use("clam")

    style.configure(".", background=C.BG_PRIMARY, foreground=C.FG_PRIMARY,
                     fieldbackground=C.BG_WIDGET, borderwidth=0,
                     font=("Consolas", 10))

    # Frames
    style.configure("TFrame", background=C.BG_PRIMARY)
    style.configure("Card.TFrame", background=C.BG_SECONDARY)
    style.configure("Header.TFrame", background=C.BG_TERTIARY)

    # Labels
    style.configure("TLabel", background=C.BG_PRIMARY, foreground=C.FG_PRIMARY)
    style.configure("Card.TLabel", background=C.BG_SECONDARY, foreground=C.FG_PRIMARY)
    style.configure("Header.TLabel", background=C.BG_TERTIARY,
                     foreground=C.ACCENT, font=("Consolas", 14, "bold"))
    style.configure("Title.TLabel", background=C.BG_PRIMARY,
                     foreground=C.ACCENT, font=("Consolas", 20, "bold"))
    style.configure("Subtitle.TLabel", background=C.BG_PRIMARY,
                     foreground=C.FG_SECONDARY, font=("Consolas", 10))
    style.configure("Status.TLabel", background=C.BG_TERTIARY,
                     foreground=C.FG_DIM, font=("Consolas", 9))

    # Severity labels
    for sev, color in C.SEVERITY.items():
        style.configure(f"{sev.capitalize()}.TLabel",
                        background=C.BG_SECONDARY, foreground=color,
                        font=("Consolas", 10, "bold"))

    # Buttons
    style.configure("TButton", background=C.BG_WIDGET, foreground=C.FG_PRIMARY,
                     padding=(12, 6), font=("Consolas", 10))
    style.map("TButton",
              background=[("active", C.BG_HOVER), ("pressed", C.BG_ACTIVE)],
              foreground=[("active", C.FG_PRIMARY)])

    style.configure("Accent.TButton", background=C.ACCENT, foreground=C.CRUST,
                     padding=(14, 8), font=("Consolas", 10, "bold"))
    style.map("Accent.TButton",
              background=[("active", C.LAVENDER), ("pressed", C.SAPPHIRE)])

    style.configure("Danger.TButton", background=C.RED, foreground=C.CRUST,
                     padding=(12, 6), font=("Consolas", 10, "bold"))
    style.map("Danger.TButton",
              background=[("active", C.MAROON), ("pressed", C.FLAMINGO)])

    # Entry / Combobox
    style.configure("TEntry", fieldbackground=C.BG_WIDGET, foreground=C.FG_PRIMARY,
                     insertcolor=C.FG_PRIMARY, padding=6)
    style.configure("TCombobox", fieldbackground=C.BG_WIDGET, foreground=C.FG_PRIMARY,
                     padding=4)
    style.map("TCombobox",
              fieldbackground=[("readonly", C.BG_WIDGET)],
              selectbackground=[("readonly", C.BG_WIDGET)])

    # Treeview (results table)
    style.configure("Treeview", background=C.BG_SECONDARY, foreground=C.FG_PRIMARY,
                     fieldbackground=C.BG_SECONDARY, rowheight=26,
                     font=("Consolas", 9))
    style.configure("Treeview.Heading", background=C.SURFACE0, foreground=C.ACCENT,
                     font=("Consolas", 10, "bold"), padding=4)
    style.map("Treeview",
              background=[("selected", C.SURFACE1)],
              foreground=[("selected", C.FG_PRIMARY)])
    style.map("Treeview.Heading",
              background=[("active", C.SURFACE1)])

    # Progressbar
    style.configure("TProgressbar", background=C.ACCENT, troughcolor=C.BG_WIDGET,
                     thickness=8)
    style.configure("Green.Horizontal.TProgressbar",
                     background=C.GREEN, troughcolor=C.BG_WIDGET)

    # Notebook (tabs)
    style.configure("TNotebook", background=C.BG_PRIMARY, borderwidth=0)
    style.configure("TNotebook.Tab", background=C.BG_WIDGET, foreground=C.FG_DIM,
                     padding=(14, 6), font=("Consolas", 10))
    style.map("TNotebook.Tab",
              background=[("selected", C.BG_PRIMARY)],
              foreground=[("selected", C.ACCENT)])

    # Labelframe
    style.configure("TLabelframe", background=C.BG_PRIMARY, foreground=C.FG_DIM,
                     borderwidth=1, relief="solid")
    style.configure("TLabelframe.Label", background=C.BG_PRIMARY,
                     foreground=C.ACCENT_ALT, font=("Consolas", 10, "bold"))

    # Scrollbar
    style.configure("Vertical.TScrollbar", background=C.SURFACE0,
                     troughcolor=C.BG_SECONDARY, arrowcolor=C.FG_DIM)
    style.map("Vertical.TScrollbar",
              background=[("active", C.SURFACE1)])

    # Checkbutton
    style.configure("TCheckbutton", background=C.BG_PRIMARY, foreground=C.FG_PRIMARY)
    style.map("TCheckbutton",
              background=[("active", C.BG_PRIMARY)])

    # Separator
    style.configure("TSeparator", background=C.SURFACE0)

    return style
