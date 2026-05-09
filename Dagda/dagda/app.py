"""
Dagda IDE - Main Application
Orchestrates all modules: tabs, editor, terminal, toolbar, status bar, file I/O, runner.
"""

from __future__ import annotations
import os
import sys
import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from .theme     import apply_theme, MOCHA
from .gui       import TerminalPanel, StatusBar, Toolbar, TabManager, build_menubar
from .editor    import EditorWidget, HAS_PYGMENTS
from .languages import get_runner, all_names
from .file_manager import (
    open_file, save_file, detect_language, language_display_name,
    ask_save_before_close,
)

APP_NAME    = "Dagda"
APP_VERSION = "1.0.0"
APP_SUBTITLE = "The All-Father of Polyglot IDEs"
ICON_B64 = None   # Set to a base64 ICO if you want a custom icon


class DagdaApp:
    def __init__(self, root: tk.Tk):
        self._root = root
        self._style = apply_theme(root)
        self._setup_window()

        self._current_runner = None   # active LanguageRunner instance
        self._font_size = 11

        # ── Layout ────────────────────────────────────────────────────────────
        self._toolbar = Toolbar(
            root,
            on_new=self.cmd_new,
            on_open=self.cmd_open,
            on_save=self.cmd_save,
            on_run=self.cmd_run,
            on_stop=self.cmd_stop,
            on_lang_change=self.cmd_set_language,
        )
        self._toolbar.pack(fill="x", side="top")

        # Horizontal separator below toolbar
        tk.Frame(root, height=1, bg=MOCHA["surface1"]).pack(fill="x")

        # Vertical paned: editor area (top) + terminal (bottom)
        self._vpane = ttk.PanedWindow(root, orient="vertical")
        self._vpane.pack(fill="both", expand=True)

        # Tab manager (editor area)
        self._tabs = TabManager(
            self._vpane,
            on_tab_change=self._on_tab_changed,
        )
        self._vpane.add(self._tabs, weight=3)

        # Terminal panel
        self._terminal = TerminalPanel(
            self._vpane,
            on_stop_cb=self.cmd_stop,
        )
        self._vpane.add(self._terminal, weight=1)

        # Status bar
        self._status = StatusBar(root)
        self._status.pack(fill="x", side="bottom")

        # Menu bar
        build_menubar(root, self)

        # Keyboard shortcuts
        self._bind_shortcuts()

        # Open a default blank tab
        self._tabs.new_tab(language="python")
        self._sync_status()

        # Pygments warning
        if not HAS_PYGMENTS:
            self._terminal.write(
                "[Dagda] pygments not found — syntax highlighting disabled.\n"
                "        Install with: pip install pygments\n",
                "warn",
            )

        # Welcome message
        self._terminal.write(
            f"⚔  {APP_NAME} IDE v{APP_VERSION}  ─  {APP_SUBTITLE}\n", "success")
        self._terminal.write(
            "    Ready. Open a file or start coding. Press F5 to run.\n\n", "info")

    # ── Window setup ──────────────────────────────────────────────────────────
    def _setup_window(self):
        r = self._root
        r.title(f"{APP_NAME} IDE")
        r.configure(bg=MOCHA["base"])
        r.minsize(800, 500)
        # Centre on screen at 80% size
        sw, sh = r.winfo_screenwidth(), r.winfo_screenheight()
        w, h   = int(sw * 0.80), int(sh * 0.80)
        x, y   = (sw - w) // 2, (sh - h) // 2
        r.geometry(f"{w}x{h}+{x}+{y}")
        r.protocol("WM_DELETE_WINDOW", self.cmd_quit)
        try:
            r.tk.call("wm", "iconphoto", r._w,
                      tk.PhotoImage(data=_DAGDA_ICON_DATA))
        except Exception:
            pass

    def _bind_shortcuts(self):
        r = self._root
        r.bind("<Control-n>", lambda _: self.cmd_new())
        r.bind("<Control-o>", lambda _: self.cmd_open())
        r.bind("<Control-s>", lambda _: self.cmd_save())
        r.bind("<Control-S>", lambda _: self.cmd_save_as())
        r.bind("<Control-w>", lambda _: self.cmd_close_tab())
        r.bind("<Control-q>", lambda _: self.cmd_quit())
        r.bind("<F5>",        lambda _: self.cmd_run())
        r.bind("<F6>",        lambda _: self.cmd_stop())
        r.bind("<Control-grave>", lambda _: self.cmd_toggle_terminal())
        r.bind("<Control-equal>", lambda _: self.cmd_font_larger())
        r.bind("<Control-minus>", lambda _: self.cmd_font_smaller())
        r.bind("<Control-0>",     lambda _: self.cmd_font_reset())

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _current_editor(self) -> Optional[EditorWidget]:
        return self._tabs.current_editor()

    def _on_tab_changed(self, editor: Optional[EditorWidget]):
        self._sync_status(editor)

    def _sync_status(self, editor: Optional[EditorWidget] = None):
        ed = editor or self._current_editor()
        if ed:
            lang = ed.language
            dn   = language_display_name(lang)
            self._status.set_language(dn)
            ln, col = ed.get_cursor_pos()
            self._status.set_cursor(ln, col)
            self._status.set_modified(ed.modified)
        if not HAS_PYGMENTS:
            self._status.set_hint("pygments not installed")

    def _update_status_loop(self):
        """Periodically sync status bar (cursor pos, modified flag)."""
        self._sync_status()
        self._root.after(500, self._update_status_loop)

    # ── File commands ─────────────────────────────────────────────────────────
    def cmd_new(self):
        self._tabs.new_tab(language=self._toolbar.get_internal_language())

    def cmd_open(self):
        result = open_file(self._root)
        if not result:
            return
        filepath, content, lang = result
        ed = self._tabs.new_tab(filepath=filepath, content=content, language=lang)
        ed.modified = False
        self._tabs.update_tab_title(ed)
        # Sync toolbar language
        runner = get_runner(lang)
        if runner:
            self._toolbar.set_language_display(runner.display_name)
        self._sync_status(ed)

    def cmd_save(self):
        ed = self._current_editor()
        if not ed:
            return
        path = save_file(self._root, ed.get_content(), ed.filepath)
        if path:
            ed.filepath = path
            ed.modified = False
            # Update language if extension changed
            lang = detect_language(path)
            ed.language = lang
            self._tabs.update_tab_title(ed)
            self._sync_status(ed)

    def cmd_save_as(self):
        ed = self._current_editor()
        if not ed:
            return
        path = save_file(self._root, ed.get_content(), ed.filepath, save_as=True)
        if path:
            ed.filepath = path
            ed.modified = False
            lang = detect_language(path)
            ed.language = lang
            self._tabs.update_tab_title(ed)
            self._sync_status(ed)

    def cmd_close_tab(self):
        ed = self._current_editor()
        if ed and ed.modified:
            name = os.path.basename(ed.filepath) if ed.filepath else "untitled"
            action = ask_save_before_close(self._root, name)
            if action == "cancel":
                return
            if action == "save":
                self.cmd_save()
        self._tabs.close_current()

    def cmd_quit(self):
        # Check for any unsaved tabs
        for ed in self._tabs.all_editors():
            if ed.modified:
                name = os.path.basename(ed.filepath) if ed.filepath else "untitled"
                action = ask_save_before_close(self._root, name)
                if action == "cancel":
                    return
                if action == "save":
                    path = save_file(self._root, ed.get_content(), ed.filepath)
                    if not path:
                        return
        self._root.destroy()

    # ── Edit commands ─────────────────────────────────────────────────────────
    def _tw(self):
        ed = self._current_editor()
        return ed.text_widget if ed else None

    def cmd_undo(self):
        t = self._tw()
        if t:
            try:
                t.edit_undo()
            except tk.TclError:
                pass

    def cmd_redo(self):
        t = self._tw()
        if t:
            try:
                t.edit_redo()
            except tk.TclError:
                pass

    def cmd_cut(self):
        t = self._tw()
        if t:
            t.event_generate("<<Cut>>")

    def cmd_copy(self):
        t = self._tw()
        if t:
            t.event_generate("<<Copy>>")

    def cmd_paste(self):
        t = self._tw()
        if t:
            t.event_generate("<<Paste>>")

    def cmd_select_all(self):
        t = self._tw()
        if t:
            t.tag_add("sel", "1.0", "end")

    def cmd_find(self):
        ed = self._current_editor()
        if ed:
            ed._show_find()

    def cmd_toggle_comment(self):
        ed = self._current_editor()
        if ed:
            ed._toggle_comment(None)

    def cmd_duplicate_line(self):
        ed = self._current_editor()
        if ed:
            ed._duplicate_line(None)

    # ── View commands ─────────────────────────────────────────────────────────
    def cmd_font_larger(self):
        self._font_size = min(self._font_size + 1, 30)
        self._apply_font_size()

    def cmd_font_smaller(self):
        self._font_size = max(self._font_size - 1, 7)
        self._apply_font_size()

    def cmd_font_reset(self):
        self._font_size = 11
        self._apply_font_size()

    def _apply_font_size(self):
        for ed in self._tabs.all_editors():
            ed._font.configure(size=self._font_size)
            ed._line_numbers.redraw()

    def cmd_toggle_terminal(self):
        # Sash toggle: if pane is very small, restore; else minimise
        panes = self._vpane.panes()
        if len(panes) < 2:
            return
        self._vpane.paneconfig(panes[1],
            height=max(120, self._vpane.winfo_height() // 4))

    # ── Run commands ──────────────────────────────────────────────────────────
    def cmd_run(self):
        ed = self._current_editor()
        if not ed:
            return

        # Must save first
        if not ed.filepath or ed.modified:
            path = save_file(self._root, ed.get_content(), ed.filepath)
            if not path:
                self._terminal.write(
                    "[Dagda] Save cancelled — not running.\n", "warn")
                return
            ed.filepath = path
            ed.modified = False
            lang = detect_language(path)
            ed.language = lang
            self._tabs.update_tab_title(ed)

        lang = ed.language
        runner = get_runner(lang)
        if not runner:
            self._terminal.write(
                f"[Dagda] No runner configured for '{lang}'.\n", "error")
            return

        # Check for languages that can't be run
        try:
            runner.get_run_command(ed.filepath)
        except NotImplementedError as e:
            self._terminal.write(f"[Dagda] {e}\n", "warn")
            return

        self._current_runner = runner
        cwd = os.path.dirname(ed.filepath) or None

        self._terminal.clear()
        self._terminal.print_separator(
            f" {os.path.basename(ed.filepath)} — {language_display_name(lang)} ")
        self._toolbar.set_running(True)
        self._terminal.set_running(True)

        start_time = time.monotonic()

        def done(rc: int):
            elapsed = time.monotonic() - start_time
            tag = "success" if rc == 0 else "error"
            self._terminal.write(
                f"\n[Dagda] Process exited with code {rc}  ({elapsed:.2f}s)\n", tag)
            self._toolbar.set_running(False)
            self._terminal.set_running(False)
            self._current_runner = None

        runner.execute(
            ed.filepath,
            output_cb=self._terminal.write,
            done_cb=done,
            cwd=cwd,
        )

    def cmd_stop(self):
        if self._current_runner:
            self._current_runner.stop()
            self._terminal.write("\n[Dagda] Process stopped by user.\n", "warn")

    def cmd_clear_output(self):
        self._terminal.clear()

    # ── Language commands ─────────────────────────────────────────────────────
    def cmd_set_language(self, lang_name: str):
        ed = self._current_editor()
        if ed:
            ed.language = lang_name
            runner = get_runner(lang_name)
            if runner:
                self._toolbar.set_language_display(runner.display_name)
            self._sync_status(ed)

    # ── Help commands ─────────────────────────────────────────────────────────
    def cmd_show_shortcuts(self):
        shortcuts = [
            ("Ctrl+N",        "New tab"),
            ("Ctrl+O",        "Open file"),
            ("Ctrl+S",        "Save"),
            ("Ctrl+Shift+S",  "Save As"),
            ("Ctrl+W",        "Close tab"),
            ("Ctrl+Q",        "Quit"),
            ("F5",            "Run file"),
            ("F6",            "Stop process"),
            ("Ctrl+Z",        "Undo"),
            ("Ctrl+Y",        "Redo"),
            ("Ctrl+F",        "Find / Replace"),
            ("Ctrl+/",        "Toggle comment"),
            ("Ctrl+D",        "Duplicate line"),
            ("Ctrl+A",        "Select all"),
            ("Tab",           "Indent (4 spaces)"),
            ("Ctrl++/-",      "Font size ±1"),
            ("Ctrl+0",        "Reset font size"),
            ("Ctrl+`",        "Toggle terminal"),
        ]
        win = tk.Toplevel(self._root)
        win.title("Keyboard Shortcuts")
        win.configure(bg=MOCHA["mantle"])
        win.resizable(False, False)
        win.attributes("-topmost", True)

        f = tk.Frame(win, bg=MOCHA["mantle"], padx=20, pady=16)
        f.pack()

        tk.Label(f, text="⚔  Dagda Keyboard Shortcuts",
                 bg=MOCHA["mantle"], fg=MOCHA["mauve"],
                 font=("Segoe UI", 11, "bold")).grid(
                     row=0, column=0, columnspan=2, pady=(0, 12))

        for i, (key, desc) in enumerate(shortcuts, start=1):
            tk.Label(f, text=key, bg=MOCHA["surface0"], fg=MOCHA["yellow"],
                     font=("Cascadia Code", 9), padx=6, pady=2,
                     relief="flat").grid(row=i, column=0, sticky="e", padx=(0, 8), pady=2)
            tk.Label(f, text=desc, bg=MOCHA["mantle"], fg=MOCHA["text"],
                     font=("Segoe UI", 9)).grid(row=i, column=1, sticky="w")

        tk.Button(f, text="Close", command=win.destroy,
                  bg=MOCHA["surface0"], fg=MOCHA["text"],
                  activebackground=MOCHA["surface1"],
                  relief="flat", font=("Segoe UI", 9), padx=10
                  ).grid(row=len(shortcuts)+1, column=0, columnspan=2, pady=(14, 0))

    def cmd_about(self):
        win = tk.Toplevel(self._root)
        win.title(f"About {APP_NAME}")
        win.configure(bg=MOCHA["mantle"])
        win.resizable(False, False)
        win.attributes("-topmost", True)

        f = tk.Frame(win, bg=MOCHA["mantle"], padx=30, pady=24)
        f.pack()

        tk.Label(f, text="⚔", bg=MOCHA["mantle"], fg=MOCHA["mauve"],
                 font=("Segoe UI", 40)).pack()
        tk.Label(f, text="☘ Dagda ☘", bg=MOCHA["mantle"], fg=MOCHA["mauve"],
                 font=("Segoe UI", 22, "bold")).pack()
        tk.Label(f, text=APP_SUBTITLE, bg=MOCHA["mantle"], fg=MOCHA["subtext1"],
                 font=("Segoe UI", 10)).pack(pady=(2, 12))
        tk.Label(f, text=f"Version {APP_VERSION}", bg=MOCHA["mantle"],
                 fg=MOCHA["overlay1"], font=("Segoe UI", 9)).pack()

        langs = ", ".join(
            get_runner(n).display_name
            for n in all_names()
            if get_runner(n)
        )
        tk.Label(f, text=f"Supported: {langs}",
                 bg=MOCHA["mantle"], fg=MOCHA["overlay1"],
                 font=("Segoe UI", 8), wraplength=380, justify="center").pack(pady=(6, 0))

        tk.Label(f, text="Built with Python + tkinter · Catppuccin Mocha theme",
                 bg=MOCHA["mantle"], fg=MOCHA["overlay0"],
                 font=("Segoe UI", 8)).pack(pady=(8, 0))

        tk.Button(f, text="Close", command=win.destroy,
                  bg=MOCHA["surface0"], fg=MOCHA["text"],
                  activebackground=MOCHA["surface1"],
                  relief="flat", font=("Segoe UI", 9), padx=10).pack(pady=(16, 0))


# ── Minimal inline icon (1x1 transparent PNG as GIF placeholder) ──────────────
_DAGDA_ICON_DATA = ""  # If you have a real icon, put base64 here
