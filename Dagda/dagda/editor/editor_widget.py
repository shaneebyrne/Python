"""
Dagda IDE - Editor Widget
A Text widget enhanced with:
  • Synchronised line-number gutter
  • Syntax highlighting (via SyntaxHighlighter)
  • Smart indentation (Tab → spaces, auto-indent)
  • Bracket/quote auto-pairing
  • Find / Replace dialog
"""

from __future__ import annotations
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from ..theme import MOCHA, BG, BG_DARK, SURFACE, TEXT as TEXT_COLOR, SUBTEXT, BORDER
from .syntax import SyntaxHighlighter


# ── Editor constants ──────────────────────────────────────────────────────────
FONT_FAMILY  = "Cascadia Code"  # Falls back to Consolas / Courier New
FONT_SIZE    = 11
TAB_WIDTH    = 4
GUTTER_WIDTH = 52
LINE_COLOR   = MOCHA["surface0"]
GUTTER_FG    = MOCHA["overlay0"]
GUTTER_BG    = MOCHA["mantle"]
CURSOR_LINE  = MOCHA["surface0"]


def _best_font() -> tuple[str, int]:
    import tkinter.font as tkfont
    preferred = ["Cascadia Code", "Cascadia Mono", "Fira Code",
                 "JetBrains Mono", "Consolas", "Courier New", "monospace"]
    available = set(tkfont.families())
    for f in preferred:
        if f in available:
            return (f, FONT_SIZE)
    return ("Courier New", FONT_SIZE)


class LineNumbers(tk.Canvas):
    """Canvas painted with line numbers that tracks a sibling Text widget."""

    def __init__(self, parent, text_widget: tk.Text, **kwargs):
        super().__init__(parent, width=GUTTER_WIDTH,
                         bg=GUTTER_BG, highlightthickness=0, **kwargs)
        self._text = text_widget
        self._font = None  # Set after editor font is chosen
        self.bind("<Button-1>", self._on_click)

    def set_font(self, font):
        self._font = font

    def redraw(self, *_):
        self.delete("all")
        tw = self._text
        i = tw.index("@0,0")
        while True:
            dline = tw.dlineinfo(i)
            if dline is None:
                break
            y = dline[1]
            linenum = str(i).split(".")[0]
            self.create_text(
                GUTTER_WIDTH - 8, y,
                anchor="ne", text=linenum,
                fill=GUTTER_FG, font=self._font,
            )
            i = tw.index(f"{i}+1line")
            if i == tw.index(f"{i}lineend") and tw.compare(i, ">=", "end"):
                break

    def _on_click(self, event):
        """Click on gutter → select that line in the editor."""
        y = event.y
        tw = self._text
        idx = tw.index(f"@0,{y}")
        line = idx.split(".")[0]
        tw.tag_remove("sel", "1.0", "end")
        tw.tag_add("sel", f"{line}.0", f"{line}.end")
        tw.mark_set("insert", f"{line}.0")
        tw.focus_set()


class EditorWidget(ttk.Frame):
    """
    The full editor pane: gutter + text area + scrollbars.
    Public API mirrors a subset of tk.Text.
    """

    # Pairs for auto-close
    _PAIRS = {"(": ")", "[": "]", "{": "}", '"': '"', "'": "'"}

    def __init__(self, parent, **kwargs):
        super().__init__(parent, style="TFrame", **kwargs)
        self._modified = False
        self._filepath: Optional[str] = None
        self._language = "text"

        self._build_ui()
        self._bind_events()

        # Highlighter
        self._highlighter = SyntaxHighlighter(self._text)
        self._highlighter.set_language("text")

        # Initial redraw
        self._text.after(50, self._line_numbers.redraw)

    # ── Build ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        font = _best_font()
        self._font = tk.font.Font(family=font[0], size=font[1])
        self._line_numbers = LineNumbers(self, text_widget=None)  # wired below

        # Scrollbars
        self._vscroll = ttk.Scrollbar(self, orient="vertical")
        self._hscroll = ttk.Scrollbar(self, orient="horizontal")

        # Main text area
        self._text = tk.Text(
            self,
            font=self._font,
            bg=BG, fg=TEXT_COLOR,
            insertbackground=MOCHA["rosewater"],
            selectbackground=MOCHA["surface1"],
            selectforeground=TEXT_COLOR,
            relief="flat", bd=0,
            wrap="none",
            undo=True, maxundo=-1,
            padx=8, pady=4,
            tabs=(self._font.measure(" " * TAB_WIDTH),),
            yscrollcommand=self._on_vscroll,
            xscrollcommand=self._hscroll.set,
        )
        self._line_numbers._text = self._text
        self._line_numbers.set_font(self._font)

        self._vscroll.config(command=self._text.yview)
        self._hscroll.config(command=self._text.xview)

        # Layout
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._line_numbers.grid(row=0, column=0, sticky="ns")

        # Thin separator between gutter and text
        sep = tk.Frame(self, width=1, bg=BORDER)
        sep.grid(row=0, column=0, sticky="nse")

        self._text.grid(row=0, column=1, sticky="nsew")
        self._vscroll.grid(row=0, column=2, sticky="ns")
        self._hscroll.grid(row=1, column=0, columnspan=3, sticky="ew")

        # Current-line highlight tag
        self._text.tag_configure("current_line", background=CURSOR_LINE)
        self._text.tag_configure("find_match",
            background=MOCHA["yellow"], foreground=MOCHA["base"])
        self._text.tag_configure("find_current",
            background=MOCHA["peach"], foreground=MOCHA["base"])

    def _bind_events(self):
        t = self._text
        t.bind("<KeyRelease>", self._on_key_release)
        t.bind("<KeyPress>", self._on_key_press)
        t.bind("<<Modified>>", self._on_modified)
        t.bind("<Configure>", self._line_numbers.redraw)
        t.bind("<FocusIn>", self._highlight_current_line)
        t.bind("<ButtonRelease-1>", self._highlight_current_line)
        t.bind("<Tab>", self._on_tab)
        t.bind("<Return>", self._on_return)
        t.bind("<BackSpace>", self._on_backspace)
        t.bind("<Control-z>", lambda e: (t.edit_undo(), "break"))
        t.bind("<Control-y>", lambda e: (t.edit_redo(), "break"))
        t.bind("<Control-a>", self._select_all)
        t.bind("<Control-d>", self._duplicate_line)
        t.bind("<Control-slash>", self._toggle_comment)
        t.bind("<Control-f>", self._show_find)

    # ── Event handlers ────────────────────────────────────────────────────────
    def _on_vscroll(self, first, last):
        self._vscroll.set(first, last)
        self._line_numbers.redraw()

    def _on_key_release(self, event=None):
        self._line_numbers.redraw()
        self._highlight_current_line()
        # Trigger syntax highlight with debounce
        self._highlighter.schedule_highlight(200)

    def _on_key_press(self, event):
        if event.char in self._PAIRS:
            partner = self._PAIRS[event.char]
            # Don't double-up if next char is already the partner
            pos = self._text.index("insert")
            next_char = self._text.get(pos)
            if event.char != '"' and event.char != "'" or next_char != event.char:
                if next_char != partner:
                    self._text.insert("insert", event.char + partner)
                    self._text.mark_set("insert", f"insert-{len(partner)}c")
                    return "break"

    def _on_modified(self, event=None):
        if self._text.edit_modified():
            self._modified = True
            self._text.edit_modified(False)

    def _highlight_current_line(self, event=None):
        t = self._text
        t.tag_remove("current_line", "1.0", "end")
        line = t.index("insert").split(".")[0]
        t.tag_add("current_line", f"{line}.0", f"{line}.end+1c")

    def _on_tab(self, event):
        t = self._text
        if t.tag_ranges("sel"):
            # Indent selection
            start = int(t.index("sel.first").split(".")[0])
            end   = int(t.index("sel.last").split(".")[0])
            for ln in range(start, end + 1):
                t.insert(f"{ln}.0", " " * TAB_WIDTH)
        else:
            t.insert("insert", " " * TAB_WIDTH)
        return "break"

    def _on_return(self, event):
        """Auto-indent: match indent of current line."""
        t = self._text
        line = t.get("insert linestart", "insert")
        indent = len(line) - len(line.lstrip())
        # Add extra indent after a colon (Python) or opening brace
        stripped = line.rstrip()
        if stripped.endswith((":", "{", "(")):
            indent += TAB_WIDTH
        t.insert("insert", "\n" + " " * indent)
        self._line_numbers.redraw()
        return "break"

    def _on_backspace(self, event):
        """Delete up to TAB_WIDTH spaces if we're on a soft-tab boundary."""
        t = self._text
        if t.tag_ranges("sel"):
            return  # Let default handle selection deletion

        pos = t.index("insert")
        col = int(pos.split(".")[1])
        if col == 0:
            return  # Let default handle newline removal

        # Check if preceding chars are spaces on a tab boundary
        start = f"{pos.split('.')[0]}.0"
        line_to_cursor = t.get(start, pos)
        if line_to_cursor == " " * len(line_to_cursor) and col % TAB_WIDTH == 0:
            t.delete(f"insert-{TAB_WIDTH}c", "insert")
            self._line_numbers.redraw()
            return "break"

    def _select_all(self, event):
        self._text.tag_add("sel", "1.0", "end")
        return "break"

    def _duplicate_line(self, event):
        t = self._text
        line = t.index("insert").split(".")[0]
        content = t.get(f"{line}.0", f"{line}.end")
        t.insert(f"{line}.end", f"\n{content}")
        self._line_numbers.redraw()
        return "break"

    def _toggle_comment(self, event):
        """Toggle line comment using the language's comment character."""
        from ..languages import get_runner
        runner = get_runner(self._language)
        char = (runner.comment_char + " ") if runner else "# "
        if not char.strip():
            return "break"

        t = self._text
        if t.tag_ranges("sel"):
            start_ln = int(t.index("sel.first").split(".")[0])
            end_ln   = int(t.index("sel.last").split(".")[0])
        else:
            start_ln = end_ln = int(t.index("insert").split(".")[0])

        # Detect if already commented
        first_line = t.get(f"{start_ln}.0", f"{start_ln}.end").lstrip()
        is_commented = first_line.startswith(char.strip())

        for ln in range(start_ln, end_ln + 1):
            line_text = t.get(f"{ln}.0", f"{ln}.end")
            if is_commented:
                idx = line_text.find(char.strip())
                if idx >= 0:
                    t.delete(f"{ln}.{idx}", f"{ln}.{idx + len(char)}")
            else:
                t.insert(f"{ln}.0", char)

        return "break"

    # ── Find / Replace ────────────────────────────────────────────────────────
    def _show_find(self, event=None):
        FindReplaceDialog(self, self._text)
        return "break"

    # ── Public API ────────────────────────────────────────────────────────────
    @property
    def text_widget(self) -> tk.Text:
        return self._text

    @property
    def modified(self) -> bool:
        return self._modified

    @modified.setter
    def modified(self, val: bool):
        self._modified = val

    @property
    def filepath(self) -> Optional[str]:
        return self._filepath

    @filepath.setter
    def filepath(self, val: Optional[str]):
        self._filepath = val

    @property
    def language(self) -> str:
        return self._language

    @language.setter
    def language(self, lang: str):
        self._language = lang
        self._highlighter.set_language(lang)

    def get_content(self) -> str:
        return self._text.get("1.0", "end-1c")

    def set_content(self, content: str):
        t = self._text
        t.delete("1.0", "end")
        t.insert("1.0", content)
        t.mark_set("insert", "1.0")
        self._modified = False
        t.edit_reset()
        self._highlighter.highlight_all()
        self._line_numbers.redraw()

    def focus(self):
        self._text.focus_set()

    def get_cursor_pos(self) -> tuple[int, int]:
        pos = self._text.index("insert")
        parts = pos.split(".")
        return int(parts[0]), int(parts[1]) + 1


# ── Find / Replace Dialog ─────────────────────────────────────────────────────

class FindReplaceDialog(tk.Toplevel):
    def __init__(self, editor: EditorWidget, text_widget: tk.Text):
        super().__init__(editor)
        self._text = text_widget
        self._matches: list[str] = []
        self._cur_match = -1

        self.title("Find / Replace")
        self.resizable(False, False)
        self.configure(bg=MOCHA["mantle"])
        self.attributes("-topmost", True)
        self._build()
        self.transient(editor)
        self.grab_set()

    def _build(self):
        pad = {"padx": 8, "pady": 4}

        lbl_bg = MOCHA["mantle"]
        lbl_fg = MOCHA["text"]

        f = tk.Frame(self, bg=lbl_bg, padx=12, pady=10)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Find:", bg=lbl_bg, fg=lbl_fg,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="e", **pad)
        self._find_var = tk.StringVar()
        tk.Entry(f, textvariable=self._find_var,
                 bg=MOCHA["surface0"], fg=MOCHA["text"],
                 insertbackground=MOCHA["text"], relief="flat",
                 font=("Segoe UI", 9), width=28).grid(row=0, column=1, **pad)

        tk.Label(f, text="Replace:", bg=lbl_bg, fg=lbl_fg,
                 font=("Segoe UI", 9)).grid(row=1, column=0, sticky="e", **pad)
        self._replace_var = tk.StringVar()
        tk.Entry(f, textvariable=self._replace_var,
                 bg=MOCHA["surface0"], fg=MOCHA["text"],
                 insertbackground=MOCHA["text"], relief="flat",
                 font=("Segoe UI", 9), width=28).grid(row=1, column=1, **pad)

        self._case_var = tk.BooleanVar(value=False)
        tk.Checkbutton(f, text="Case sensitive",
                       variable=self._case_var,
                       bg=lbl_bg, fg=lbl_fg, selectcolor=MOCHA["surface0"],
                       activebackground=lbl_bg, activeforeground=lbl_fg,
                       font=("Segoe UI", 9)).grid(row=2, column=1, sticky="w")

        btn_frame = tk.Frame(f, bg=lbl_bg)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(8, 0))

        def btn(text, cmd, fg=MOCHA["text"]):
            b = tk.Button(btn_frame, text=text, command=cmd,
                          bg=MOCHA["surface0"], fg=fg,
                          activebackground=MOCHA["surface1"],
                          relief="flat", font=("Segoe UI", 9),
                          padx=8, pady=3)
            b.pack(side="left", padx=3)
            return b

        btn("Find All", self._find_all)
        btn("Find Next", self._find_next)
        btn("Replace", self._replace_one)
        btn("Replace All", self._replace_all)
        btn("Close", self.destroy, fg=MOCHA["red"])

        self._status = tk.Label(f, text="", bg=lbl_bg,
                                fg=MOCHA["overlay1"], font=("Segoe UI", 8))
        self._status.grid(row=4, column=0, columnspan=2)

        self.bind("<Return>", lambda _: self._find_next())
        self.bind("<Escape>", lambda _: self.destroy())

    def _find_all(self, highlight=True):
        t = self._text
        t.tag_remove("find_match", "1.0", "end")
        t.tag_remove("find_current", "1.0", "end")
        self._matches.clear()
        self._cur_match = -1

        needle = self._find_var.get()
        if not needle:
            return

        nocase = not self._case_var.get()
        start = "1.0"
        while True:
            pos = t.search(needle, start, stopindex="end", nocase=nocase)
            if not pos:
                break
            end = f"{pos}+{len(needle)}c"
            t.tag_add("find_match", pos, end)
            self._matches.append(pos)
            start = end

        n = len(self._matches)
        self._status.config(text=f"{n} match{'es' if n != 1 else ''} found")

    def _find_next(self):
        self._find_all(highlight=True)
        if not self._matches:
            return
        self._cur_match = (self._cur_match + 1) % len(self._matches)
        t = self._text
        t.tag_remove("find_current", "1.0", "end")
        pos = self._matches[self._cur_match]
        needle = self._find_var.get()
        end = f"{pos}+{len(needle)}c"
        t.tag_add("find_current", pos, end)
        t.see(pos)
        t.mark_set("insert", pos)

    def _replace_one(self):
        t = self._text
        needle = self._find_var.get()
        if not needle:
            return
        ranges = t.tag_ranges("find_current")
        if ranges:
            t.delete(ranges[0], ranges[1])
            t.insert(ranges[0], self._replace_var.get())
            self._find_next()

    def _replace_all(self):
        self._find_all()
        t = self._text
        needle  = self._find_var.get()
        replace = self._replace_var.get()
        if not needle or not self._matches:
            return
        # Replace in reverse so indices stay valid
        nocase = not self._case_var.get()
        start = "1.0"
        count = 0
        while True:
            pos = t.search(needle, start, stopindex="end", nocase=nocase)
            if not pos:
                break
            end = f"{pos}+{len(needle)}c"
            t.delete(pos, end)
            t.insert(pos, replace)
            start = f"{pos}+{len(replace)}c"
            count += 1
        t.tag_remove("find_match", "1.0", "end")
        t.tag_remove("find_current", "1.0", "end")
        self._status.config(text=f"Replaced {count} occurrence(s)")
