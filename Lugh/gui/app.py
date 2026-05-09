"""
Lugh v3.0 - Main Application Class
Assembles all tab mixins into the unified PyCyApp.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext
from config import USE_CTK, ctk, VERSION, APP_TITLE, SUBTITLE

# Engine imports
from engines.email_parser import EmailHeaderParser
from engines.homograph import HomographDetector
from engines.file_checker import FileTypeChecker
from engines.deep_analyzer import DeepAnalyzer
from engines.yara_engine import YaraEngine
from engines.risk_scoring import RiskScoringEngine
from engines.ps_analyzer import PowerShellAnalyzer
from engines.archive_extractor import ArchiveExtractor
from engines.event_log import EventLogParser
from engines.link_analyzer import LinkAnalyzer

# GUI Tab Mixins
from gui.tab_email import EmailTabMixin
from gui.tab_homograph import HomographTabMixin
from gui.tab_filechecker import FileCheckerTabMixin
from gui.tab_hash import HashTabMixin
from gui.tab_eventlog import EventLogTabMixin
from gui.tab_links import LinkTabMixin
from gui.tab_advanced import AdvancedTabMixin


class PyCyApp(EmailTabMixin, HomographTabMixin, FileCheckerTabMixin,
              HashTabMixin, EventLogTabMixin, LinkTabMixin, AdvancedTabMixin):
    """Lugh Cybersecurity Toolkit — main application window."""

    # ── Theme Colors ──
    BG="#0D1117"; BP="#161B22"; BI="#0D1117"
    FT="#C9D1D9"; FD="#8B949E"; FB="#F0F6FC"
    AC="#58A6FF"; GR="#3FB950"; YL="#D29922"; RD="#F85149"
    OR="#DB6D28"; PU="#BC8CFF"; CY="#39D2C0"; BD="#30363D"
    PR="#e94560"; PRH="#ff6b6b"; SB="#555555"

    def __init__(self):
        self.parser = EmailHeaderParser()
        self.detector = HomographDetector()
        self.fchk = FileTypeChecker()
        self.deep = DeepAnalyzer()
        self.yara_eng = YaraEngine()
        self.risk_eng = RiskScoringEngine()
        self.ps_eng = PowerShellAnalyzer()
        self.arc_eng = ArchiveExtractor()
        self.evlog_eng = EventLogParser()
        self.link_eng = LinkAnalyzer()
        self.parsed = None
        self._build()

    def _build(self):
        if USE_CTK:
            self.root = ctk.CTk()
            self.root.configure(fg_color=self.BG)
        else:
            self.root = tk.Tk()
            self.root.configure(bg=self.BG)
        self.root.title(APP_TITLE)
        self.root.geometry("1150x850")
        self.root.minsize(950, 700)
        self._titlebar()
        self._tabs()

    def _titlebar(self):
        if USE_CTK:
            f = ctk.CTkFrame(self.root, fg_color=self.BP, height=56, corner_radius=0)
            f.pack(fill="x"); f.pack_propagate(False)
            ctk.CTkLabel(f, text="\u2694  Lugh",
                         font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
                         text_color=self.AC).pack(side="left", padx=20, pady=8)
            ctk.CTkLabel(f, text=SUBTITLE,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         text_color=self.FD).pack(side="left", padx=10)
            ctk.CTkLabel(f, text=f"v{VERSION}",
                         font=ctk.CTkFont(family="Consolas", size=11),
                         text_color=self.FD).pack(side="right", padx=20)
        else:
            f = tk.Frame(self.root, bg=self.BP, height=56)
            f.pack(fill="x"); f.pack_propagate(False)
            tk.Label(f, text="\u2694  Lugh", font=("Consolas", 18, "bold"),
                     fg=self.AC, bg=self.BP).pack(side="left", padx=20)
            tk.Label(f, text=SUBTITLE, font=("Consolas", 10),
                     fg=self.FD, bg=self.BP).pack(side="left", padx=10)

    def _tabs(self):
        s = ttk.Style(); s.theme_use("default")
        s.configure("TNotebook", background=self.BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=self.BP, foreground=self.FD,
                    padding=[14, 6], font=("Consolas", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", self.BG)],
              foreground=[("selected", self.AC)])
        s.configure("Treeview", background=self.BG, foreground=self.FT,
                    fieldbackground=self.BG, font=("Consolas", 10),
                    rowheight=26, borderwidth=0)
        s.configure("Treeview.Heading", background=self.BP, foreground=self.AC,
                    font=("Consolas", 10, "bold"), borderwidth=0)
        s.map("Treeview", background=[("selected", "#2D1520")],
              foreground=[("selected", self.AC)])

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        mk = self._mf
        self.t_email = mk(); self.t_homo = mk()
        self.t_fc = mk(); self.t_hash = mk()
        self.t_evlog = mk(); self.t_link = mk(); self.t_adv = mk()
        for t, l in [(self.t_email, " \U0001F4E7 Email Headers "),
                     (self.t_homo,  " \U0001F50D Homograph "),
                     (self.t_fc,    " \U0001F4C2 File Checker "),
                     (self.t_hash,  " #\u20E3 Hash Checker "),
                     (self.t_evlog, " \U0001F4DC Event Logs "),
                     (self.t_link,  " \U0001F517 Links "),
                     (self.t_adv,   " \u2699 Advanced ")]:
            self.nb.add(t, text=l)
        # Build all tabs (methods from mixins)
        self._b_email(); self._b_homo(); self._b_fc()
        self._b_hash(); self._b_evlog(); self._b_link(); self._b_adv()

    def _mf(self, parent=None):
        p = parent or self.nb
        if USE_CTK:
            return ctk.CTkFrame(p, fg_color=self.BG, corner_radius=0)
        return tk.Frame(p, bg=self.BG)

    def _mt(self, p, h=10):
        w = scrolledtext.ScrolledText(
            p, wrap="word", height=h, bg=self.BI, fg=self.FT,
            insertbackground=self.FT, font=("Consolas", 10), relief="flat",
            borderwidth=1, highlightbackground=self.BD, highlightthickness=1,
            selectbackground="#3B3050", selectforeground="#FFF")
        self._bind_ctx(w)
        return w

    def _bind_ctx(self, widget):
        """Bind right-click context menu (Cut/Copy/Paste/Select All) to any Text or Entry widget."""
        menu = tk.Menu(widget, tearoff=0, bg=self.BP, fg=self.FT,
                       activebackground="#2D1520", activeforeground=self.AC,
                       font=("Consolas", 10), relief="flat", bd=1)
        is_text = isinstance(widget, (tk.Text, scrolledtext.ScrolledText))
        menu.add_command(label="Cut        Ctrl+X",
            command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy       Ctrl+C",
            command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste      Ctrl+V",
            command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        if is_text:
            menu.add_command(label="Select All  Ctrl+A",
                command=lambda: (widget.tag_add("sel", "1.0", "end-1c"),
                                 widget.mark_set("insert", "end-1c")))
        else:
            menu.add_command(label="Select All  Ctrl+A",
                command=lambda: (widget.select_range(0, tk.END),
                                 widget.icursor(tk.END)))
        menu.add_separator()
        if is_text:
            menu.add_command(label="Clear",
                command=lambda: widget.delete("1.0", "end"))
        else:
            menu.add_command(label="Clear",
                command=lambda: widget.delete(0, tk.END))

        def _show(e):
            try: menu.tk_popup(e.x_root, e.y_root)
            finally: menu.grab_release()

        widget.bind("<Button-3>", _show)
        # Also bind Ctrl+A for Select All (not default in tkinter)
        if is_text:
            widget.bind("<Control-a>", lambda e: (widget.tag_add("sel", "1.0", "end-1c"), "break"))
            widget.bind("<Control-A>", lambda e: (widget.tag_add("sel", "1.0", "end-1c"), "break"))
        else:
            widget.bind("<Control-a>", lambda e: (widget.select_range(0, tk.END), widget.icursor(tk.END), "break"))
            widget.bind("<Control-A>", lambda e: (widget.select_range(0, tk.END), widget.icursor(tk.END), "break"))

    def run(self):
        self.root.mainloop()
