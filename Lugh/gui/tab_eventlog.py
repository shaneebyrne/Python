"""
Lugh v3.0 - Event Log Parser Tab (Mixin)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, csv
from config import USE_CTK, ctk
from pathlib import Path
from datetime import datetime
from engines.event_log import NOTABLE_EVENT_IDS

class EventLogTabMixin:
    """Event Log Parser tab — troublesome event filter."""

    # ══════════════════════════════════════════════════════════════
    # EVENT LOG PARSER TAB
    # ══════════════════════════════════════════════════════════════
    def _b_evlog(self):
        tab = self.t_evlog
        # Header
        if USE_CTK: hdr = ctk.CTkFrame(tab, fg_color=self.BP, corner_radius=8)
        else: hdr = tk.Frame(tab, bg=self.BP, bd=1, relief="flat")
        hdr.pack(fill="x", padx=15, pady=(12,6))
        if USE_CTK:
            ctk.CTkLabel(hdr, text="\U0001F4DC Event Log Parser \u2014 Troublesome Event Filter",
                         font=ctk.CTkFont(family="Consolas",size=14,weight="bold"), text_color=self.AC).pack(anchor="w", padx=15, pady=(12,2))
            ctk.CTkLabel(hdr, text="Load logs \u2192 Analyze \u2192 only security-relevant and error events are shown.",
                         font=ctk.CTkFont(family="Consolas",size=10), text_color=self.FD).pack(anchor="w", padx=15, pady=(0,8))
        else:
            tk.Label(hdr, text="\U0001F4DC Event Log Parser \u2014 Troublesome Event Filter", font=("Consolas",14,"bold"), fg=self.AC, bg=self.BP).pack(anchor="w", padx=15, pady=(12,2))
            tk.Label(hdr, text="Load logs > Analyze > only security-relevant and error events are shown.", font=("Consolas",10), fg=self.FD, bg=self.BP).pack(anchor="w", padx=15, pady=(0,8))
        # File list + buttons
        ff = tk.Frame(hdr, bg=self.BP); ff.pack(fill="x", padx=15, pady=(0,8))
        lf = tk.Frame(ff, bg=self.BP); lf.pack(side="left", fill="both", expand=True)
        self.el_files = tk.Listbox(lf, height=4, font=("Consolas",10), bg=self.BI, fg=self.FT,
                                    selectbackground="#2D1520", selectforeground=self.AC, relief="flat", bd=2)
        el_scr = ttk.Scrollbar(lf, orient="vertical", command=self.el_files.yview)
        self.el_files.configure(yscrollcommand=el_scr.set)
        self.el_files.pack(side="left", fill="both", expand=True)
        el_scr.pack(side="left", fill="y")
        bf = tk.Frame(ff, bg=self.BP); bf.pack(side="right", padx=(10,0))
        if USE_CTK:
            ctk.CTkButton(bf, text="\u2795 Add Files", command=self._el_add, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=32, width=110, corner_radius=6).pack(pady=(0,4))
            ctk.CTkButton(bf, text="\u2796 Remove", command=self._el_remove, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=32, width=110, corner_radius=6).pack(pady=(0,4))
            ctk.CTkButton(bf, text="\U0001F5D1 Clear All", command=self._el_clear_files, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=32, width=110, corner_radius=6).pack()
        else:
            tk.Button(bf, text="\u2795 Add Files", command=self._el_add, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(pady=(0,4), fill="x")
            tk.Button(bf, text="\u2796 Remove", command=self._el_remove, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(pady=(0,4), fill="x")
            tk.Button(bf, text="Clear All", command=self._el_clear_files, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(fill="x")
        # Action row: Analyze + CSV + Stop + Clear
        af = tk.Frame(hdr, bg=self.BP); af.pack(fill="x", padx=15, pady=(0,12))
        if USE_CTK:
            ctk.CTkButton(af, text="\u26A1 Analyze", command=self._el_analyze, font=ctk.CTkFont(family="Consolas",size=13,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=38, width=120, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(af, text="\U0001F4BE Export CSV", command=self._el_export, font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.GR, hover_color="#2EA043", height=38, width=120, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(af, text="\u23F9 Stop", command=lambda:self.evlog_eng.stop(), font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.RD, hover_color="#DA3633", height=38, width=70, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(af, text="\U0001F5D1 Clear", command=self._el_clear_results, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=38, width=80, corner_radius=6).pack(side="left")
        else:
            tk.Button(af, text="\u26A1 Analyze", command=self._el_analyze, font=("Consolas",12,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=14, pady=6).pack(side="left", padx=(0,8))
            tk.Button(af, text="Export CSV", command=self._el_export, font=("Consolas",11), bg=self.GR, fg="#FFF",
                      relief="flat", padx=12, pady=6).pack(side="left", padx=(0,8))
            tk.Button(af, text="Stop", command=lambda:self.evlog_eng.stop(), font=("Consolas",10), bg=self.RD, fg="#FFF",
                      relief="flat", padx=8, pady=6).pack(side="left", padx=(0,8))
            tk.Button(af, text="Clear", command=self._el_clear_results, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=6).pack(side="left")
        # Progress
        self.el_pv = tk.StringVar(value="Add log files and hit Analyze. Only troublesome events will appear.")
        tk.Label(tab, textvariable=self.el_pv, font=("Consolas",10), fg=self.FD, bg=self.BG).pack(fill="x", padx=15, pady=(4,2))
        # Single treeview — only flagged events go here
        cols = ("Severity","EventID","Time","Source File","Provider","Computer","Description","Message")
        self.el_tree = ttk.Treeview(tab, columns=cols, show="headings", height=20)
        for c in cols: self.el_tree.heading(c, text=c)
        self.el_tree.column("Severity", width=80, anchor="center"); self.el_tree.column("EventID", width=65, anchor="center")
        self.el_tree.column("Time", width=170); self.el_tree.column("Source File", width=110)
        self.el_tree.column("Provider", width=180); self.el_tree.column("Computer", width=100)
        self.el_tree.column("Description", width=200); self.el_tree.column("Message", width=300)
        el_tscr = ttk.Scrollbar(tab, orient="vertical", command=self.el_tree.yview)
        self.el_tree.configure(yscrollcommand=el_tscr.set)
        self.el_tree.pack(side="left", fill="both", expand=True, padx=(15,0), pady=(0,12))
        el_tscr.pack(side="right", fill="y", padx=(0,15), pady=(0,12))
        self.el_tree.tag_configure("CRITICAL", foreground="#FF0040")
        self.el_tree.tag_configure("WARNING", foreground=self.YL)
        self.el_tree.tag_configure("INFO", foreground=self.CY)
        self.el_flagged = []  # store flagged event dicts for CSV export

    def _el_add(self):
        files = filedialog.askopenfilenames(title="Add Event Log Files",
            filetypes=[("Event Logs","*.evtx *.csv *.xml *.log *.txt"),("EVTX","*.evtx"),
                       ("CSV","*.csv"),("XML","*.xml"),("Log","*.log *.txt"),("All","*.*")])
        for f in files:
            # Avoid duplicates
            existing = list(self.el_files.get(0, tk.END))
            if f not in existing:
                self.el_files.insert(tk.END, f)

    def _el_remove(self):
        sel = self.el_files.curselection()
        for i in reversed(sel):
            self.el_files.delete(i)

    def _el_clear_files(self):
        self.el_files.delete(0, tk.END)

    def _el_analyze(self):
        files = list(self.el_files.get(0, tk.END))
        if not files: messagebox.showwarning("No Files","Add event log files first."); return
        self.evlog_eng.reset()
        for i in self.el_tree.get_children(): self.el_tree.delete(i)
        self.el_flagged = []
        self.el_pv.set("Parsing logs...")

        def prog(count, fname):
            self.root.after(0, lambda: self.el_pv.set(f"Parsing {Path(fname).name}: {count} events..."))

        def run():
            for fp in files:
                if self.evlog_eng.stop_requested: break
                self.root.after(0, lambda f=fp: self.el_pv.set(f"Parsing {Path(f).name}..."))
                self.evlog_eng.parse_file(fp, prog_cb=prog)
            self.root.after(0, self._el_display)

        threading.Thread(target=run, daemon=True).start()

    def _el_display(self):
        """Iterate through ALL parsed events. Pull out only troublesome ones. Display them."""
        for i in self.el_tree.get_children(): self.el_tree.delete(i)
        self.el_flagged = []
        total = len(self.evlog_eng.events)
        for ev in self.evlog_eng.events:
            eid_raw = ev.get("event_id","").strip()
            desc = ""; sev = ""; flagged = False
            # 1) Check if Event ID is in the notable lookup table
            try:
                eid_int = int(eid_raw)
                if eid_int in NOTABLE_EVENT_IDS:
                    n = NOTABLE_EVENT_IDS[eid_int]
                    desc = n[1]; sev = n[2]; flagged = True
            except (ValueError, TypeError): pass
            # 2) Check level for Critical / Error
            lv = ev.get("level","").lower().strip()
            if "critical" in lv:
                if not flagged: desc = "Critical-level event"; sev = "CRITICAL"
                flagged = True
            elif "error" in lv:
                if not flagged: desc = "Error-level event"; sev = "WARNING"
                flagged = True
            # 3) Check keywords for Audit Failure (Security logs mark these as
            #    "Information" level but "Audit Failure" in keywords)
            kw = ev.get("keywords","").lower().strip()
            if "audit failure" in kw or "failure" in kw:
                if not flagged: desc = "Audit Failure"; sev = "WARNING"
                flagged = True
            # 4) Check Warning level
            if "warning" in lv:
                if not flagged: desc = "Warning-level event"; sev = "WARNING"
                flagged = True
            if not flagged:
                continue  # skip normal events
            row = {"severity":sev, "event_id":eid_raw, "time":ev.get("time",""),
                   "source_file":ev.get("source_file",""), "provider":ev.get("provider",""),
                   "computer":ev.get("computer",""), "description":desc,
                   "message":ev.get("message","")[:300], "level":ev.get("level",""),
                   "keywords":ev.get("keywords",""), "channel":ev.get("channel","")}
            self.el_flagged.append(row)
            self.el_tree.insert("","end", values=(
                sev, eid_raw, ev.get("time",""), Path(ev.get("source_file","")).name,
                ev.get("provider",""), ev.get("computer",""), desc,
                ev.get("message","")[:120]
            ), tags=(sev,))
        # Status message with diagnostics
        errs = len(self.evlog_eng.errors)
        files_parsed = len(set(ev.get("source_file","") for ev in self.evlog_eng.events))
        msg = f"\u26A0 {len(self.el_flagged):,} troublesome events from {total:,} total ({files_parsed} file(s) parsed)"
        if errs:
            msg += f" | {errs} parse error(s)"
            err_msgs = "; ".join(f"{e.get('file','')}: {e.get('error','')}" for e in self.evlog_eng.errors[:3])
            msg += f": {err_msgs}"
        if total > 0 and len(self.el_flagged) == 0:
            # Show a sample event so user can see what was parsed
            sample = self.evlog_eng.events[0]
            msg += f" | Sample: level='{sample.get('level','')}' eid='{sample.get('event_id','')}' kw='{sample.get('keywords','')}'"
        self.el_pv.set(msg)

    def _el_export(self):
        """Export exactly what's on screen — the flagged events — to CSV."""
        if not self.el_flagged:
            messagebox.showwarning("No Data","No troublesome events to export. Run Analyze first."); return
        fp = filedialog.asksaveasfilename(title="Export Troublesome Events to CSV", defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile=f"troublesome_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not fp: return
        with open(fp, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["Severity","Event ID","Time","Source File","Provider",
                         "Level","Keywords","Channel","Computer","Description","Message"])
            for r in self.el_flagged:
                w.writerow([r["severity"],r["event_id"],r["time"],r["source_file"],
                            r["provider"],r["level"],r.get("keywords",""),r["channel"],
                            r["computer"],r["description"],r["message"]])
        messagebox.showinfo("Exported",f"CSV saved:\n{fp}\n\n{len(self.el_flagged):,} troublesome events exported.")

    def _el_clear_results(self):
        self.evlog_eng.reset()
        for i in self.el_tree.get_children(): self.el_tree.delete(i)
        self.el_flagged = []
        self.el_pv.set("Add log files and hit Analyze. Only troublesome events will appear.")

