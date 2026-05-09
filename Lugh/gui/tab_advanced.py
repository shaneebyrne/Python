"""
Lugh v3.0 - Advanced Tools Tab (Mixin)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, os
from config import USE_CTK, ctk
from pathlib import Path
from datetime import datetime
from engines.yara_engine import YARA_TEMPLATES

class AdvancedTabMixin:
    """Advanced Tools tab: Deep Analyzer, YARA, Risk Scoring, PS Analyzer, Archive Extractor."""

    # ══════════════════════════════════════════════════════════════
    # ADVANCED TOOLS TAB
    # ══════════════════════════════════════════════════════════════
    def _b_adv(self):
        tab = self.t_adv
        # Top bar with module selector
        if USE_CTK: top = ctk.CTkFrame(tab, fg_color=self.BP, corner_radius=8)
        else: top = tk.Frame(tab, bg=self.BP, bd=1, relief="flat")
        top.pack(fill="x", padx=15, pady=(12,6))
        if USE_CTK:
            ctk.CTkLabel(top, text="\u2699 Advanced Tools", font=ctk.CTkFont(family="Consolas",size=14,weight="bold"),
                         text_color=self.AC).pack(side="left", padx=15, pady=12)
        else:
            tk.Label(top, text="\u2699 Advanced Tools", font=("Consolas",14,"bold"), fg=self.AC, bg=self.BP).pack(side="left", padx=15, pady=12)
        sf = tk.Frame(top, bg=self.BP); sf.pack(side="left", fill="x", expand=True, padx=10, pady=8)
        tk.Label(sf, text="Module:", font=("Consolas",11), fg=self.FT, bg=self.BP).pack(side="left", padx=(0,8))
        self.adv_sel = ttk.Combobox(sf, values=["Deep Analyzer (Windows)","YARA Engine Integration",
                                                  "Weighted Risk Scoring","PowerShell Static Analyzer","Archive Extractor"],
                                     state="readonly", font=("Consolas",11), width=30)
        self.adv_sel.set("Deep Analyzer (Windows)")
        self.adv_sel.pack(side="left")
        self.adv_sel.bind("<<ComboboxSelected>>", self._adv_switch)
        # Container for module panels
        self.adv_container = tk.Frame(tab, bg=self.BG)
        self.adv_container.pack(fill="both", expand=True, padx=15, pady=(6,12))
        # Build all panels
        self._adv_panels = {}
        self._b_adv_deep(); self._b_adv_yara(); self._b_adv_risk()
        self._b_adv_ps(); self._b_adv_arc()
        # Show first panel
        self._adv_show("Deep Analyzer (Windows)")

    def _adv_switch(self, e=None):
        self._adv_show(self.adv_sel.get())

    def _adv_show(self, name):
        for n, f in self._adv_panels.items():
            if n == name: f.pack(fill="both", expand=True)
            else: f.pack_forget()

    # ── Deep Analyzer Panel ──
    def _b_adv_deep(self):
        fr = tk.Frame(self.adv_container, bg=self.BG)
        self._adv_panels["Deep Analyzer (Windows)"] = fr
        # Controls
        cf = tk.Frame(fr, bg=self.BP); cf.pack(fill="x", pady=(0,6))
        tk.Label(cf, text="File:", font=("Consolas",11), fg=self.FT, bg=self.BP).pack(side="left", padx=(10,5), pady=8)
        self.da_path = tk.Entry(cf, font=("Consolas",11), bg=self.BI, fg=self.FT, insertbackground=self.FT, relief="flat", bd=2)
        self.da_path.pack(side="left", fill="x", expand=True, padx=(0,8), pady=8)
        self._bind_ctx(self.da_path)
        if USE_CTK:
            ctk.CTkButton(cf, text="Browse", command=self._da_browse, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=34, width=90, corner_radius=6).pack(side="left", padx=(0,5), pady=8)
            ctk.CTkButton(cf, text="\U0001F52C Analyze", command=self._da_run, font=ctk.CTkFont(family="Consolas",size=12,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=34, width=110, corner_radius=6).pack(side="left", padx=(0,10), pady=8)
        else:
            tk.Button(cf, text="Browse", command=self._da_browse, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(side="left", padx=(0,5), pady=8)
            tk.Button(cf, text="\U0001F52C Analyze", command=self._da_run, font=("Consolas",11,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=12, pady=4).pack(side="left", padx=(0,10), pady=8)
        # Results notebook
        self.da_nb = ttk.Notebook(fr); self.da_nb.pack(fill="both", expand=True)
        f_ov = tk.Frame(self.da_nb, bg=self.BG); f_pe = tk.Frame(self.da_nb, bg=self.BG)
        f_str = tk.Frame(self.da_nb, bg=self.BG); f_sus = tk.Frame(self.da_nb, bg=self.BG)
        self.da_nb.add(f_ov, text=" Overview "); self.da_nb.add(f_pe, text=" PE Info ")
        self.da_nb.add(f_str, text=" Strings "); self.da_nb.add(f_sus, text=" Suspicious ")
        self.da_ov = self._mt(f_ov, 25); self.da_ov.pack(fill="both", expand=True, padx=5, pady=5)
        self.da_pe = self._mt(f_pe, 25); self.da_pe.pack(fill="both", expand=True, padx=5, pady=5)
        self.da_str = self._mt(f_str, 25); self.da_str.pack(fill="both", expand=True, padx=5, pady=5)
        self.da_sus = self._mt(f_sus, 25); self.da_sus.pack(fill="both", expand=True, padx=5, pady=5)

    def _da_browse(self):
        fp = filedialog.askopenfilename(title="Select File to Analyze")
        if fp:
            if USE_CTK: self.da_path.delete(0,"end"); self.da_path.insert(0,fp)
            else: self.da_path.delete(0,tk.END); self.da_path.insert(0,fp)

    def _da_run(self):
        fp = self.da_path.get().strip()
        if not fp: messagebox.showwarning("No File","Select a file first."); return
        if not Path(fp).exists(): messagebox.showerror("Not Found",f"File not found:\n{fp}"); return
        def run():
            r = self.deep.analyze(fp)
            self.root.after(0, self._da_display, r)
        threading.Thread(target=run, daemon=True).start()

    def _da_display(self, r):
        # Overview
        o = self.da_ov; o.delete("1.0","end")
        L = ["="*60,"  DEEP ANALYSIS OVERVIEW","="*60,"",
             f"  File:     {r['filename']}",f"  Path:     {r['filepath']}",
             f"  Size:     {r['size']:,} bytes ({r['size']/1024:.1f} KB)","",
             "\u2500"*40,"  HASHES","\u2500"*40]
        for algo, h in r["hashes"].items(): L.append(f"  {algo:<8}{h}")
        L += ["",f"  Entropy:  {r['entropy']:.4f} / 8.0"]
        if r["entropy"] > 7.0: L.append("  \u26A0 HIGH ENTROPY - possible packing/encryption")
        elif r["entropy"] > 6.5: L.append("  \u26A0 Elevated entropy - may be compressed")
        L += ["",f"  PE File:  {'Yes' if r['is_pe'] else 'No'}"]
        if r.get("error"): L.append(f"\n  ERROR: {r['error']}")
        L += ["",f"  Suspicious APIs:     {len(r['suspicious_apis'])}",
              f"  Suspicious Strings:  {len(r['suspicious_strings'])}"]
        sec = r.get("section_entropy", [])
        if sec:
            L += ["","\u2500"*40,"  SECTION ENTROPY","\u2500"*40,
                  f"  {'Name':<12}{'VSize':>10}{'RawSize':>10}{'Entropy':>10}"]
            for s in sec:
                flag = " \u25C0 HIGH" if s["entropy"] > 7.0 else ""
                L.append(f"  {s['name']:<12}{s['virtual_size']:>10,}{s['raw_size']:>10,}{s['entropy']:>10.4f}{flag}")
        L += ["","="*60]
        o.insert("1.0", "\n".join(L))
        # PE Info
        p = self.da_pe; p.delete("1.0","end")
        pe = r.get("pe_info",{})
        if r["is_pe"] and pe:
            PL = ["="*60,"  PE HEADER DETAILS","="*60,""]
            for k, v in pe.items():
                if k == "characteristics":
                    PL.append(f"  {k:<22}{', '.join(v)}")
                else:
                    PL.append(f"  {k:<22}{v}")
            PL += ["","="*60]
            p.insert("1.0","\n".join(PL))
        else:
            p.insert("1.0","  Not a PE file or PE headers could not be parsed.")
        # Strings
        s = self.da_str; s.delete("1.0","end")
        strs = r.get("strings",[])
        SL = ["="*60,f"  EXTRACTED STRINGS ({len(strs)} total)","="*60,""]
        for i, st in enumerate(strs[:2000]):
            SL.append(f"  {i+1:>5}  {st[:120]}")
        if len(strs) > 2000: SL.append(f"\n  ... {len(strs)-2000} more strings truncated ...")
        s.insert("1.0","\n".join(SL))
        # Suspicious
        u = self.da_sus; u.delete("1.0","end")
        UL = ["="*60,"  SUSPICIOUS INDICATORS","="*60,""]
        apis = r.get("suspicious_apis",[])
        if apis:
            UL += ["\u2500"*40,"  SUSPICIOUS APIs FOUND","\u2500"*40]
            for a in sorted(set(apis)): UL.append(f"  \u26A0 {a}")
        else:
            UL.append("  No suspicious API imports found.")
        ss = r.get("suspicious_strings",[])
        if ss:
            UL += ["","\u2500"*40,"  SUSPICIOUS STRINGS/PATTERNS","\u2500"*40]
            for s in ss: UL.append(f"  [{s['type']:<22}] {s['value'][:80]}")
        else:
            UL += ["","  No suspicious string patterns found."]
        UL += ["","="*60]
        u.insert("1.0","\n".join(UL))

    # ── YARA Engine Panel ──
    def _b_adv_yara(self):
        fr = tk.Frame(self.adv_container, bg=self.BG)
        self._adv_panels["YARA Engine Integration"] = fr
        # Top row: template selector + load/compile buttons
        tf = tk.Frame(fr, bg=self.BP); tf.pack(fill="x", pady=(0,4))
        tk.Label(tf, text="Template:", font=("Consolas",10), fg=self.FT, bg=self.BP).pack(side="left", padx=(10,5), pady=6)
        self.yr_tmpl = ttk.Combobox(tf, values=list(YARA_TEMPLATES.keys()), state="readonly",
                                     font=("Consolas",10), width=22)
        self.yr_tmpl.set("Empty Template"); self.yr_tmpl.pack(side="left", padx=(0,5), pady=6)
        if USE_CTK:
            ctk.CTkButton(tf, text="Load Template", command=self._yr_load_tmpl, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=30, width=110, corner_radius=6).pack(side="left", padx=(0,5), pady=6)
            ctk.CTkButton(tf, text="\U0001F4C2 Load .yar", command=self._yr_load_file, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=30, width=100, corner_radius=6).pack(side="left", padx=(0,5), pady=6)
            ctk.CTkButton(tf, text="\u2705 Compile", command=self._yr_compile, font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=30, width=100, corner_radius=6).pack(side="left", padx=(0,5), pady=6)
        else:
            tk.Button(tf, text="Load Template", command=self._yr_load_tmpl, font=("Consolas",9), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=3).pack(side="left", padx=(0,5), pady=6)
            tk.Button(tf, text="Load .yar", command=self._yr_load_file, font=("Consolas",9), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=3).pack(side="left", padx=(0,5), pady=6)
            tk.Button(tf, text="\u2705 Compile", command=self._yr_compile, font=("Consolas",10,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=10, pady=3).pack(side="left", padx=(0,5), pady=6)
        self.yr_status = tk.Label(tf, text="", font=("Consolas",10), fg=self.FD, bg=self.BP)
        self.yr_status.pack(side="right", padx=10, pady=6)
        # Rule editor (top half)
        ef = tk.LabelFrame(fr, text=" YARA Rule Editor ", font=("Consolas",10,"bold"), fg=self.AC,
                           bg=self.BG, bd=1, relief="flat")
        ef.pack(fill="both", expand=True, pady=(0,4))
        self.yr_editor = self._mt(ef, 12); self.yr_editor.pack(fill="both", expand=True, padx=5, pady=5)
        self.yr_editor.insert("1.0", YARA_TEMPLATES["Empty Template"])
        # Scan controls
        sf = tk.Frame(fr, bg=self.BP); sf.pack(fill="x", pady=(0,4))
        tk.Label(sf, text="Scan:", font=("Consolas",10), fg=self.FT, bg=self.BP).pack(side="left", padx=(10,5), pady=6)
        self.yr_path = tk.Entry(sf, font=("Consolas",10), bg=self.BI, fg=self.FT, insertbackground=self.FT, relief="flat", bd=2)
        self.yr_path.pack(side="left", fill="x", expand=True, padx=(0,5), pady=6)
        self._bind_ctx(self.yr_path)
        if USE_CTK:
            ctk.CTkButton(sf, text="File", command=self._yr_browse_file, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=28, width=60, corner_radius=6).pack(side="left", padx=(0,3), pady=6)
            ctk.CTkButton(sf, text="Folder", command=self._yr_browse_dir, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=28, width=70, corner_radius=6).pack(side="left", padx=(0,5), pady=6)
            ctk.CTkButton(sf, text="\U0001F52C Scan", command=self._yr_scan, font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=28, width=90, corner_radius=6).pack(side="left", padx=(0,10), pady=6)
        else:
            tk.Button(sf, text="File", command=self._yr_browse_file, font=("Consolas",9), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=2).pack(side="left", padx=(0,3), pady=6)
            tk.Button(sf, text="Folder", command=self._yr_browse_dir, font=("Consolas",9), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=2).pack(side="left", padx=(0,5), pady=6)
            tk.Button(sf, text="\U0001F52C Scan", command=self._yr_scan, font=("Consolas",10,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=10, pady=2).pack(side="left", padx=(0,10), pady=6)
        # Results (bottom half)
        rf = tk.LabelFrame(fr, text=" Scan Results ", font=("Consolas",10,"bold"), fg=self.AC,
                           bg=self.BG, bd=1, relief="flat")
        rf.pack(fill="both", expand=True, pady=(0,0))
        self.yr_results = self._mt(rf, 10); self.yr_results.pack(fill="both", expand=True, padx=5, pady=5)
        for tg, cl in [("rule",self.AC),("match",self.GR),("warn",self.YL),("err",self.RD),("dim",self.FD),("sep",self.BD)]:
            self.yr_results.tag_configure(tg, foreground=cl,
                font=("Consolas",11 if tg=="rule" else 10, "bold" if tg in ("rule","err") else ""))

    def _yr_load_tmpl(self):
        name = self.yr_tmpl.get()
        if name in YARA_TEMPLATES:
            self.yr_editor.delete("1.0","end"); self.yr_editor.insert("1.0", YARA_TEMPLATES[name])

    def _yr_load_file(self):
        fp = filedialog.askopenfilename(title="Load YARA Rule File", filetypes=[("YARA","*.yar *.yara"),("All","*.*")])
        if fp:
            with open(fp,'r',encoding='utf-8',errors='replace') as f:
                self.yr_editor.delete("1.0","end"); self.yr_editor.insert("1.0",f.read())

    def _yr_compile(self):
        src = self.yr_editor.get("1.0","end-1c").strip()
        if not src: messagebox.showwarning("Empty","Write or load a YARA rule first."); return
        if self.yara_eng.compile_source(src):
            self.yr_status.configure(text="\u2705 Compiled OK", fg=self.GR)
        else:
            self.yr_status.configure(text=f"\u274C {self.yara_eng.last_error[:60]}", fg=self.RD)

    def _yr_browse_file(self):
        fp = filedialog.askopenfilename(title="Select File to Scan")
        if fp:
            if USE_CTK: self.yr_path.delete(0,"end"); self.yr_path.insert(0,fp)
            else: self.yr_path.delete(0,tk.END); self.yr_path.insert(0,fp)

    def _yr_browse_dir(self):
        d = filedialog.askdirectory(title="Select Folder to Scan")
        if d:
            if USE_CTK: self.yr_path.delete(0,"end"); self.yr_path.insert(0,d)
            else: self.yr_path.delete(0,tk.END); self.yr_path.insert(0,d)

    def _yr_scan(self):
        if not self.yara_eng.compiled:
            messagebox.showwarning("Not Compiled","Compile a rule first."); return
        fp = self.yr_path.get().strip()
        if not fp: messagebox.showwarning("No Target","Select a file or folder to scan."); return
        p = Path(fp)
        if not p.exists(): messagebox.showerror("Not Found", f"Path not found:\n{fp}"); return
        out = self.yr_results; out.delete("1.0","end")
        out.insert("end","Scanning...\n","dim")
        def run():
            if p.is_file():
                matches = self.yara_eng.scan_file(str(p))
                res = [{"file":str(p),"matches":matches}] if matches else []
            else:
                res = self.yara_eng.scan_dir(str(p))
            self.root.after(0, self._yr_display, res)
        threading.Thread(target=run, daemon=True).start()

    def _yr_display(self, results):
        out = self.yr_results; out.delete("1.0","end")
        if not results:
            out.insert("end","  No matches found.\n","dim"); return
        total_matches = sum(len(r["matches"]) for r in results)
        out.insert("end",f"  \u2550"*50+"\n","sep")
        out.insert("end",f"  YARA SCAN RESULTS: {total_matches} match(es) in {len(results)} file(s)\n","rule")
        out.insert("end",f"  \u2550"*50+"\n\n","sep")
        for fr in results:
            out.insert("end",f"  FILE: {fr['file']}\n","match")
            for m in fr["matches"]:
                out.insert("end",f"    \u2500 Rule: {m['rule']}\n","rule")
                if m.get("tags"): out.insert("end",f"      Tags: {', '.join(m['tags'])}\n","dim")
                if m.get("meta"):
                    for mk, mv in m["meta"].items(): out.insert("end",f"      {mk}: {mv}\n","dim")
                if m.get("strings"):
                    out.insert("end",f"      Matched strings:\n","warn")
                    for s in m["strings"][:50]:
                        out.insert("end",f"        0x{s['offset']:08X}  {s['identifier']:<20}  {s['data'][:40]}\n","dim")
                    if len(m["strings"]) > 50:
                        out.insert("end",f"        ... {len(m['strings'])-50} more\n","dim")
            out.insert("end","\n","dim")

    # ── Weighted Risk Scoring Panel ──
    def _b_adv_risk(self):
        fr = tk.Frame(self.adv_container, bg=self.BG)
        self._adv_panels["Weighted Risk Scoring"] = fr
        # Two-pane layout: left = indicator checklist, right = results
        pw = tk.PanedWindow(fr, orient="horizontal", bg=self.BD, sashwidth=4, sashrelief="flat")
        pw.pack(fill="both", expand=True)
        # Left pane: indicators
        left = tk.Frame(pw, bg=self.BG); pw.add(left, width=500)
        lh = tk.Frame(left, bg=self.BP); lh.pack(fill="x")
        tk.Label(lh, text="Risk Indicators", font=("Consolas",12,"bold"), fg=self.AC, bg=self.BP).pack(side="left", padx=10, pady=8)
        if USE_CTK:
            ctk.CTkButton(lh, text="\u26A1 Calculate", command=self._rs_calc, font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=30, width=110, corner_radius=6).pack(side="right", padx=5, pady=6)
            ctk.CTkButton(lh, text="Reset", command=self._rs_reset, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=30, width=70, corner_radius=6).pack(side="right", padx=(0,5), pady=6)
            ctk.CTkButton(lh, text="\U0001F4BE Export", command=self._rs_export, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=30, width=80, corner_radius=6).pack(side="right", padx=(0,5), pady=6)
        else:
            tk.Button(lh, text="\u26A1 Calculate", command=self._rs_calc, font=("Consolas",10,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=10, pady=4).pack(side="right", padx=5, pady=6)
            tk.Button(lh, text="Reset", command=self._rs_reset, font=("Consolas",9), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=4).pack(side="right", padx=(0,5), pady=6)
            tk.Button(lh, text="Export", command=self._rs_export, font=("Consolas",9), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=4).pack(side="right", padx=(0,5), pady=6)
        # Scrollable checklist
        canvas = tk.Canvas(left, bg=self.BG, highlightthickness=0)
        vsb = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        self.rs_inner = tk.Frame(canvas, bg=self.BG)
        self.rs_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.rs_inner, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True); vsb.pack(side="right", fill="y")
        # Build checkboxes grouped by category
        self.rs_vars = {}
        last_cat = ""
        for ind in self.risk_eng.indicators:
            if ind["category"] != last_cat:
                last_cat = ind["category"]
                cf = tk.Frame(self.rs_inner, bg=self.BG)
                cf.pack(fill="x", padx=5, pady=(8,2))
                tk.Label(cf, text=f"\u25B6 {last_cat}", font=("Consolas",11,"bold"), fg=self.PU, bg=self.BG).pack(anchor="w")
            rf = tk.Frame(self.rs_inner, bg=self.BG); rf.pack(fill="x", padx=15, pady=1)
            var = tk.BooleanVar(value=False)
            self.rs_vars[ind["id"]] = var
            cb = tk.Checkbutton(rf, text=f"{ind['name']}  (w={ind['weight']})", variable=var,
                                bg=self.BG, fg=self.FT, selectcolor=self.BP, activebackground=self.BG,
                                activeforeground=self.FT, font=("Consolas",10), anchor="w")
            cb.pack(side="left", fill="x", expand=True)
            tk.Label(rf, text=ind["desc"], font=("Consolas",9), fg=self.FD, bg=self.BG).pack(side="right", padx=(10,5))
        # Right pane: results display
        right = tk.Frame(pw, bg=self.BG); pw.add(right, width=450)
        self.rs_out = self._mt(right, 30)
        self.rs_out.pack(fill="both", expand=True, padx=5, pady=5)
        for tg, cl in [("hdr",self.AC),("safe",self.GR),("warn",self.YL),("danger",self.RD),
                        ("crit","#FF0040"),("info",self.FT),("dim",self.FD),("sep",self.BD),
                        ("purple",self.PU),("orange",self.OR)]:
            self.rs_out.tag_configure(tg, foreground=cl,
                font=("Consolas",11 if tg in ("hdr","crit") else 10, "bold" if tg in ("hdr","safe","warn","danger","crit") else ""))
        # Initial message
        self.rs_out.insert("1.0","  Check indicators on the left, then click Calculate.\n\n"
                           "  Each indicator has a weight. The total score is compared\n"
                           "  against the max possible to determine risk level:\n\n"
                           "    0-19%   = LOW\n    20-44%  = MEDIUM\n    45-69%  = HIGH\n    70-100% = CRITICAL\n","dim")

    def _rs_calc(self):
        # Sync checkboxes -> engine
        for ind_id, var in self.rs_vars.items():
            self.risk_eng.set_active(ind_id, var.get())
        result = self.risk_eng.calculate()
        o = self.rs_out; o.delete("1.0","end")
        # Score header
        o.insert("end","="*50+"\n","sep")
        o.insert("end","  WEIGHTED RISK SCORE\n","hdr")
        o.insert("end","="*50+"\n\n","sep")
        # Level display
        lv = result["level"]
        lv_tag = {"NONE":"dim","LOW":"safe","MEDIUM":"warn","HIGH":"orange","CRITICAL":"crit"}.get(lv,"info")
        # Score bar
        pct = result["pct"]
        filled = int(pct / 100 * 30); empty = 30 - filled
        bar = "\u2588" * filled + "\u2591" * empty
        o.insert("end", f"  {bar}  {pct}%\n\n", lv_tag)
        o.insert("end", f"  Risk Level:  ", "info")
        o.insert("end", f"{lv}\n", lv_tag)
        o.insert("end", f"  Score:       {result['score']} / {result['max_possible']}\n\n", "info")
        if not result["active"]:
            o.insert("end","  No indicators selected.\n","dim"); return
        # Breakdown by category
        o.insert("end","\u2500"*50+"\n","sep")
        o.insert("end","  BREAKDOWN BY CATEGORY\n","hdr")
        o.insert("end","\u2500"*50+"\n\n","sep")
        for cat, data in result["breakdown"].items():
            o.insert("end", f"  \u25B6 {cat}", "purple")
            o.insert("end", f"  (subtotal: {data['subtotal']})\n", "dim")
            for item in data["items"]:
                o.insert("end", f"    \u2022 {item['name']:<30} weight: {item['weight']}\n", "info")
            o.insert("end","\n","dim")
        # Recommendations
        o.insert("end","\u2500"*50+"\n","sep")
        o.insert("end","  ASSESSMENT\n","hdr")
        o.insert("end","\u2500"*50+"\n\n","sep")
        if lv == "CRITICAL":
            o.insert("end","  \U0001F6A8 CRITICAL RISK - Immediate action required.\n","crit")
            o.insert("end","  \u2022 Isolate affected systems from network\n","danger")
            o.insert("end","  \u2022 Preserve evidence for forensic analysis\n","danger")
            o.insert("end","  \u2022 Engage incident response team\n","danger")
            o.insert("end","  \u2022 Notify security leadership\n","danger")
        elif lv == "HIGH":
            o.insert("end","  \u26A0 HIGH RISK - Priority investigation needed.\n","orange")
            o.insert("end","  \u2022 Deep-dive analysis on flagged indicators\n","warn")
            o.insert("end","  \u2022 Check threat intel for related IOCs\n","warn")
            o.insert("end","  \u2022 Consider containment measures\n","warn")
        elif lv == "MEDIUM":
            o.insert("end","  \u26A0 MEDIUM RISK - Further analysis recommended.\n","warn")
            o.insert("end","  \u2022 Investigate flagged indicators individually\n","info")
            o.insert("end","  \u2022 Monitor for escalation\n","info")
        elif lv == "LOW":
            o.insert("end","  \u2705 LOW RISK - Minimal concern.\n","safe")
            o.insert("end","  \u2022 Log findings for baseline\n","info")
            o.insert("end","  \u2022 Continue standard monitoring\n","info")
        else:
            o.insert("end","  No active indicators.\n","dim")
        o.insert("end","\n"+"="*50+"\n","sep")

    def _rs_reset(self):
        for var in self.rs_vars.values(): var.set(False)
        self.risk_eng.reset()
        self.rs_out.delete("1.0","end")
        self.rs_out.insert("1.0","  All indicators cleared.\n","dim")

    def _rs_export(self):
        for ind_id, var in self.rs_vars.items():
            self.risk_eng.set_active(ind_id, var.get())
        result = self.risk_eng.calculate()
        fp = filedialog.asksaveasfilename(title="Export Risk Report", defaultextension=".json",
            filetypes=[("JSON","*.json"),("CSV","*.csv")],
            initialfile=f"risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not fp: return
        if fp.endswith('.csv'):
            with open(fp,'w',newline='',encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["Category","Indicator","Weight","Active","Description"])
                for ind in self.risk_eng.indicators:
                    w.writerow([ind["category"],ind["name"],ind["weight"],ind["active"],ind["desc"]])
                w.writerow([])
                w.writerow(["Score",result["score"],"Max",result["max_possible"],"Pct",result["pct"],"Level",result["level"]])
        else:
            export = {"timestamp":datetime.now().isoformat(),"score":result["score"],"max_possible":result["max_possible"],
                      "percentage":result["pct"],"risk_level":result["level"],
                      "active_indicators":[{"name":i["name"],"category":i["category"],"weight":i["weight"]} for i in result["active"]]}
            with open(fp,'w',encoding='utf-8') as f: json.dump(export, f, indent=2)
        messagebox.showinfo("Exported", f"Report saved:\n{fp}")

    # ── PowerShell Static Analyzer Panel ──
    def _b_adv_ps(self):
        fr = tk.Frame(self.adv_container, bg=self.BG)
        self._adv_panels["PowerShell Static Analyzer"] = fr
        # Controls
        cf = tk.Frame(fr, bg=self.BP); cf.pack(fill="x", pady=(0,4))
        tk.Label(cf, text="Source:", font=("Consolas",11), fg=self.FT, bg=self.BP).pack(side="left", padx=(10,5), pady=8)
        if USE_CTK:
            ctk.CTkButton(cf, text="\U0001F4C2 Load .ps1", command=self._ps_load, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=34, width=110, corner_radius=6).pack(side="left", padx=(0,5), pady=8)
            ctk.CTkButton(cf, text="\U0001F52C Analyze", command=self._ps_run, font=ctk.CTkFont(family="Consolas",size=12,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=34, width=110, corner_radius=6).pack(side="left", padx=(0,5), pady=8)
            ctk.CTkButton(cf, text="\U0001F5D1 Clear", command=self._ps_clr, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=34, width=80, corner_radius=6).pack(side="left", padx=(0,5), pady=8)
        else:
            tk.Button(cf, text="Load .ps1", command=self._ps_load, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(side="left", padx=(0,5), pady=8)
            tk.Button(cf, text="\U0001F52C Analyze", command=self._ps_run, font=("Consolas",11,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=12, pady=4).pack(side="left", padx=(0,5), pady=8)
            tk.Button(cf, text="Clear", command=self._ps_clr, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(side="left", padx=(0,5), pady=8)
        self.ps_file_lbl = tk.Label(cf, text="(paste code below or load a file)", font=("Consolas",9), fg=self.FD, bg=self.BP)
        self.ps_file_lbl.pack(side="left", padx=10, pady=8)
        # Code editor (top half)
        ef = tk.LabelFrame(fr, text=" PowerShell Source ", font=("Consolas",10,"bold"), fg=self.AC,
                           bg=self.BG, bd=1, relief="flat")
        ef.pack(fill="both", expand=True, pady=(0,4))
        self.ps_editor = self._mt(ef, 10); self.ps_editor.pack(fill="both", expand=True, padx=5, pady=5)
        # Results (bottom half)
        self.ps_nb = ttk.Notebook(fr); self.ps_nb.pack(fill="both", expand=True)
        f_ov = tk.Frame(self.ps_nb, bg=self.BG); f_ob = tk.Frame(self.ps_nb, bg=self.BG)
        f_cmd = tk.Frame(self.ps_nb, bg=self.BG); f_dp = tk.Frame(self.ps_nb, bg=self.BG)
        self.ps_nb.add(f_ov, text=" Overview "); self.ps_nb.add(f_ob, text=" Obfuscation ")
        self.ps_nb.add(f_cmd, text=" Cmdlets "); self.ps_nb.add(f_dp, text=" Danger Patterns ")
        self.ps_ov = self._mt(f_ov, 10); self.ps_ov.pack(fill="both", expand=True, padx=5, pady=5)
        self.ps_ob = self._mt(f_ob, 10); self.ps_ob.pack(fill="both", expand=True, padx=5, pady=5)
        self.ps_cmd = self._mt(f_cmd, 10); self.ps_cmd.pack(fill="both", expand=True, padx=5, pady=5)
        self.ps_dp = self._mt(f_dp, 10); self.ps_dp.pack(fill="both", expand=True, padx=5, pady=5)
        # Tag colors for results
        for widget in [self.ps_ov, self.ps_ob, self.ps_cmd, self.ps_dp]:
            for tg, cl in [("hdr",self.AC),("safe",self.GR),("warn",self.YL),("danger",self.RD),
                            ("crit","#FF0040"),("info",self.FT),("dim",self.FD),("sep",self.BD),("orange",self.OR)]:
                widget.tag_configure(tg, foreground=cl,
                    font=("Consolas",11 if tg in ("hdr","crit") else 10, "bold" if tg in ("hdr","safe","warn","danger","crit") else ""))

    def _ps_load(self):
        fp = filedialog.askopenfilename(title="Load PowerShell Script",
            filetypes=[("PowerShell","*.ps1 *.psm1 *.psd1"),("All","*.*")])
        if fp:
            with open(fp,'r',encoding='utf-8',errors='replace') as f:
                self.ps_editor.delete("1.0","end"); self.ps_editor.insert("1.0",f.read())
            self.ps_file_lbl.configure(text=Path(fp).name)

    def _ps_run(self):
        content = self.ps_editor.get("1.0","end-1c").strip()
        if not content: messagebox.showwarning("Empty","Paste PowerShell code or load a .ps1 file."); return
        fname = self.ps_file_lbl.cget("text") or "<input>"
        r = self.ps_eng.analyze(content, fname)
        self._ps_display(r)

    def _ps_display(self, r):
        # Overview
        o = self.ps_ov; o.delete("1.0","end")
        lv = r["risk_level"]
        lv_tag = {"CLEAN":"safe","LOW":"safe","MEDIUM":"warn","HIGH":"orange","CRITICAL":"crit"}.get(lv,"info")
        o.insert("end","="*55+"\n","sep")
        o.insert("end","  POWERSHELL STATIC ANALYSIS\n","hdr")
        o.insert("end","="*55+"\n\n","sep")
        o.insert("end",f"  File:       {r['filename']}\n","info")
        o.insert("end",f"  Lines:      {r['lines']}\n","info")
        o.insert("end",f"  Size:       {r['size']:,} bytes\n\n","info")
        o.insert("end",f"  Risk Level: ",  "info")
        o.insert("end",f"{lv}\n",lv_tag)
        o.insert("end",f"  Score:      {r['score']} / 100\n\n","info")
        # Summary counts
        o.insert("end","\u2500"*45+"\n","sep")
        o.insert("end",f"  Obfuscation Indicators:  {len(r['obfuscation'])}\n", "warn" if r["obfuscation"] else "dim")
        o.insert("end",f"  Suspicious Cmdlets:      {len(r['suspicious_cmdlets'])}\n", "warn" if r["suspicious_cmdlets"] else "dim")
        o.insert("end",f"  Danger Patterns:         {len(r['danger_patterns'])}\n", "danger" if r["danger_patterns"] else "dim")
        o.insert("end",f"  Functions Defined:       {len(r['functions'])}\n","info")
        o.insert("end",f"  Variables:               {len(r['variables'])}\n","info")
        o.insert("end",f"  Comments:                {len(r['comments'])}\n\n","info")
        if r["functions"]:
            o.insert("end","\u2500"*45+"\n","sep")
            o.insert("end","  FUNCTIONS\n","hdr")
            for fn in r["functions"]: o.insert("end",f"    \u2022 {fn}\n","info")
        if r.get("error"): o.insert("end",f"\n  ERROR: {r['error']}\n","danger")
        o.insert("end","\n"+"="*55+"\n","sep")
        # Obfuscation tab
        ob = self.ps_ob; ob.delete("1.0","end")
        if r["obfuscation"]:
            ob.insert("end","="*55+"\n","sep"); ob.insert("end","  OBFUSCATION INDICATORS\n","hdr"); ob.insert("end","="*55+"\n\n","sep")
            for item in r["obfuscation"]:
                ob.insert("end",f"  \u26A0 {item['pattern']}", "warn")
                ob.insert("end",f"  ({item['count']} occurrence{'s' if item['count']>1 else ''})\n","dim")
                for s in item.get("samples",[]): ob.insert("end",f"    \u2192 {s}\n","dim")
                ob.insert("end","\n","dim")
        else:
            ob.insert("end","  \u2705 No obfuscation indicators found.\n","safe")
        # Cmdlets tab
        cm = self.ps_cmd; cm.delete("1.0","end")
        if r["suspicious_cmdlets"]:
            cm.insert("end","="*55+"\n","sep"); cm.insert("end","  SUSPICIOUS CMDLETS / APIs\n","hdr"); cm.insert("end","="*55+"\n\n","sep")
            for item in r["suspicious_cmdlets"]:
                cm.insert("end",f"  \u26A0 {item['cmdlet']}", "warn")
                if item.get("alias"): cm.insert("end",f"  (alias: {item['alias']})","dim")
                cm.insert("end","\n","dim")
                cm.insert("end",f"    {item['description']}\n\n","dim")
        else:
            cm.insert("end","  \u2705 No suspicious cmdlets found.\n","safe")
        # Danger patterns tab
        dp = self.ps_dp; dp.delete("1.0","end")
        if r["danger_patterns"]:
            dp.insert("end","="*55+"\n","sep"); dp.insert("end","  DANGER PATTERNS\n","crit"); dp.insert("end","="*55+"\n\n","sep")
            for item in r["danger_patterns"]:
                dp.insert("end",f"  \U0001F6A8 {item['pattern']}", "danger")
                dp.insert("end",f"  ({item['count']}x)\n","dim")
                for s in item.get("samples",[]):
                    dp.insert("end",f"    \u2192 {str(s)[:80]}\n","dim")
                dp.insert("end","\n","dim")
        else:
            dp.insert("end","  \u2705 No danger patterns found.\n","safe")

    def _ps_clr(self):
        self.ps_editor.delete("1.0","end")
        for w in [self.ps_ov, self.ps_ob, self.ps_cmd, self.ps_dp]: w.delete("1.0","end")
        self.ps_file_lbl.configure(text="(paste code below or load a file)")

    # ── Archive Extractor Panel ──
    def _b_adv_arc(self):
        fr = tk.Frame(self.adv_container, bg=self.BG)
        self._adv_panels["Archive Extractor"] = fr
        # Controls
        cf = tk.Frame(fr, bg=self.BP); cf.pack(fill="x", pady=(0,4))
        tk.Label(cf, text="Archive:", font=("Consolas",11), fg=self.FT, bg=self.BP).pack(side="left", padx=(10,5), pady=8)
        self.ae_path = tk.Entry(cf, font=("Consolas",11), bg=self.BI, fg=self.FT, insertbackground=self.FT, relief="flat", bd=2)
        self.ae_path.pack(side="left", fill="x", expand=True, padx=(0,5), pady=8)
        self._bind_ctx(self.ae_path)
        if USE_CTK:
            ctk.CTkButton(cf, text="Browse", command=self._ae_browse, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=34, width=80, corner_radius=6).pack(side="left", padx=(0,5), pady=8)
        else:
            tk.Button(cf, text="Browse", command=self._ae_browse, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(side="left", padx=(0,5), pady=8)
        # Output dir row
        of = tk.Frame(fr, bg=self.BP); of.pack(fill="x", pady=(0,4))
        tk.Label(of, text="Output:", font=("Consolas",11), fg=self.FT, bg=self.BP).pack(side="left", padx=(10,5), pady=8)
        self.ae_out = tk.Entry(of, font=("Consolas",11), bg=self.BI, fg=self.FT, insertbackground=self.FT, relief="flat", bd=2)
        self.ae_out.pack(side="left", fill="x", expand=True, padx=(0,5), pady=8)
        self._bind_ctx(self.ae_out)
        if USE_CTK:
            ctk.CTkButton(of, text="Browse", command=self._ae_bout, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=34, width=80, corner_radius=6).pack(side="left", padx=(0,5), pady=8)
        else:
            tk.Button(of, text="Browse", command=self._ae_bout, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=4).pack(side="left", padx=(0,5), pady=8)
        # Options row
        bf = tk.Frame(fr, bg=self.BP); bf.pack(fill="x", pady=(0,6))
        self.ae_rec = tk.BooleanVar(value=True)
        tk.Checkbutton(bf, text="Recursive (extract nested archives)", variable=self.ae_rec,
                       bg=self.BP, fg=self.FT, selectcolor=self.BG, activebackground=self.BP,
                       activeforeground=self.FT, font=("Consolas",10)).pack(side="left", padx=(10,15), pady=6)
        tk.Label(bf, text="Max depth:", font=("Consolas",10), fg=self.FD, bg=self.BP).pack(side="left", padx=(0,5), pady=6)
        self.ae_depth = tk.Spinbox(bf, from_=1, to=20, width=4, font=("Consolas",10), bg=self.BI, fg=self.FT,
                                   buttonbackground=self.BP, relief="flat", bd=2)
        self.ae_depth.delete(0,tk.END); self.ae_depth.insert(0,"10")
        self.ae_depth.pack(side="left", padx=(0,15), pady=6)
        if USE_CTK:
            ctk.CTkButton(bf, text="\U0001F4E6 Extract", command=self._ae_run, font=ctk.CTkFont(family="Consolas",size=12,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=34, width=110, corner_radius=6).pack(side="left", padx=(0,8), pady=6)
            ctk.CTkButton(bf, text="\u23F9 Stop", command=lambda:self.arc_eng.stop(), font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.RD, hover_color="#DA3633", height=34, width=70, corner_radius=6).pack(side="left", padx=(0,8), pady=6)
            ctk.CTkButton(bf, text="\U0001F5D1 Clear", command=self._ae_clr, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=34, width=70, corner_radius=6).pack(side="left", pady=6)
        else:
            tk.Button(bf, text="\U0001F4E6 Extract", command=self._ae_run, font=("Consolas",11,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=12, pady=4).pack(side="left", padx=(0,8), pady=6)
            tk.Button(bf, text="Stop", command=lambda:self.arc_eng.stop(), font=("Consolas",10), bg=self.RD, fg="#FFF",
                      relief="flat", padx=8, pady=4).pack(side="left", padx=(0,8), pady=6)
            tk.Button(bf, text="Clear", command=self._ae_clr, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=8, pady=4).pack(side="left", pady=6)
        # Progress
        self.ae_pv = tk.StringVar(value="")
        tk.Label(fr, textvariable=self.ae_pv, font=("Consolas",10), fg=self.FD, bg=self.BG).pack(fill="x", padx=10, pady=(0,2))
        # Results treeview
        self.ae_nb = ttk.Notebook(fr); self.ae_nb.pack(fill="both", expand=True)
        f_files = tk.Frame(self.ae_nb, bg=self.BG); f_stats = tk.Frame(self.ae_nb, bg=self.BG)
        self.ae_nb.add(f_files, text=" Extracted Files "); self.ae_nb.add(f_stats, text=" Summary ")
        cols = ("File","Source","Size","Depth","Status")
        self.ae_tree = ttk.Treeview(f_files, columns=cols, show="headings", height=18)
        for c in cols: self.ae_tree.heading(c, text=c)
        self.ae_tree.column("File", width=280); self.ae_tree.column("Source", width=280)
        self.ae_tree.column("Size", width=90, anchor="e"); self.ae_tree.column("Depth", width=60, anchor="center")
        self.ae_tree.column("Status", width=80, anchor="center")
        scr = ttk.Scrollbar(f_files, orient="vertical", command=self.ae_tree.yview)
        self.ae_tree.configure(yscrollcommand=scr.set)
        self.ae_tree.pack(side="left", fill="both", expand=True, padx=(5,0), pady=5)
        scr.pack(side="right", fill="y", padx=(0,5), pady=5)
        self.ae_tree.tag_configure("error", foreground=self.RD)
        self.ae_tree.tag_configure("nested", foreground=self.CY)
        self.ae_stats_t = self._mt(f_stats, 15); self.ae_stats_t.pack(fill="both", expand=True, padx=5, pady=5)

    def _ae_browse(self):
        fp = filedialog.askopenfilename(title="Select Archive",
            filetypes=[("Archives","*.zip *.tar *.tar.gz *.tgz *.tar.bz2 *.tar.xz *.gz *.bz2 *.xz"),("All","*.*")])
        if fp:
            if USE_CTK: self.ae_path.delete(0,"end"); self.ae_path.insert(0,fp)
            else: self.ae_path.delete(0,tk.END); self.ae_path.insert(0,fp)
            # Auto-fill output dir
            out = str(Path(fp).parent / (Path(fp).stem + "_extracted"))
            if USE_CTK: self.ae_out.delete(0,"end"); self.ae_out.insert(0,out)
            else: self.ae_out.delete(0,tk.END); self.ae_out.insert(0,out)

    def _ae_bout(self):
        d = filedialog.askdirectory(title="Select Output Directory")
        if d:
            if USE_CTK: self.ae_out.delete(0,"end"); self.ae_out.insert(0,d)
            else: self.ae_out.delete(0,tk.END); self.ae_out.insert(0,d)

    def _ae_run(self):
        arc = self.ae_path.get().strip()
        out = self.ae_out.get().strip()
        if not arc: messagebox.showwarning("No Archive","Select an archive file."); return
        if not out: messagebox.showwarning("No Output","Select an output directory."); return
        if not Path(arc).exists(): messagebox.showerror("Not Found",f"Archive not found:\n{arc}"); return
        # Clear tree
        for i in self.ae_tree.get_children(): self.ae_tree.delete(i)
        self.ae_stats_t.delete("1.0","end")
        try: self.arc_eng.max_depth = int(self.ae_depth.get())
        except: self.arc_eng.max_depth = 10
        def prog(count): self.root.after(0, lambda: self.ae_pv.set(f"Extracted: {count} items..."))
        def run():
            results = self.arc_eng.extract(arc, out, recursive=self.ae_rec.get(), prog_cb=prog)
            self.root.after(0, self._ae_display, results)
        threading.Thread(target=run, daemon=True).start()

    def _ae_display(self, results):
        for i in self.ae_tree.get_children(): self.ae_tree.delete(i)
        for r in results:
            sz = f"{r.get('size',0):,}" if r.get("size") else ""
            tags = ()
            if r.get("status") == "error": tags = ("error",)
            elif r.get("depth",0) > 0: tags = ("nested",)
            src = Path(r.get("source","")).name if r.get("source") else ""
            self.ae_tree.insert("","end", values=(r.get("file",""), src, sz,
                                                   r.get("depth",0), r.get("status","")), tags=tags)
        # Stats
        st = self.arc_eng.stats()
        self.ae_pv.set(f"Done: {st['extracted']} extracted | {st['errors']} errors | depth {st['max_depth']}")
        s = self.ae_stats_t; s.delete("1.0","end")
        L = ["="*50,"  EXTRACTION SUMMARY","="*50,"",
             f"  Total Items:    {st['total']}",f"  Extracted OK:   {st['extracted']}",
             f"  Errors:         {st['errors']}",f"  Skipped:        {st['skipped']}",
             f"  Max Depth:      {st['max_depth']}",""]
        if st["extracted"] > 0:
            outdir = self.ae_out.get().strip()
            L += ["\u2500"*40,f"  Output: {outdir}",""]
        # List nested extractions
        nested = [r for r in results if r.get("depth",0) > 0 and r.get("status")=="ok"]
        if nested:
            L += ["\u2500"*40,"  NESTED ARCHIVES EXTRACTED","\u2500"*40]
            for r in nested:
                L.append(f"  depth {r['depth']}: {r.get('file','')} (from {Path(r.get('source','')).name})")
        L += ["","="*50]
        s.insert("1.0","\n".join(L))

    def _ae_clr(self):
        for i in self.ae_tree.get_children(): self.ae_tree.delete(i)
        self.ae_stats_t.delete("1.0","end")
        if USE_CTK: self.ae_path.delete(0,"end"); self.ae_out.delete(0,"end")
        else: self.ae_path.delete(0,tk.END); self.ae_out.delete(0,tk.END)
        self.ae_pv.set("")

    def run(self): self.root.mainloop()
