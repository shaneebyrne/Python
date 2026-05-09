"""
Lugh v3.0 - Malicious Link Analyzer Tab (Mixin)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
from config import USE_CTK, ctk
from pathlib import Path
from datetime import datetime

class LinkTabMixin:
    """Malicious Link Analyzer tab."""

    # ══════════════════════════════════════════════════════════════
    # MALICIOUS LINK ANALYZER TAB
    # ══════════════════════════════════════════════════════════════
    def _b_link(self):
        tab = self.t_link
        # Header
        if USE_CTK: hdr = ctk.CTkFrame(tab, fg_color=self.BP, corner_radius=8)
        else: hdr = tk.Frame(tab, bg=self.BP, bd=1, relief="flat")
        hdr.pack(fill="x", padx=15, pady=(12,6))
        if USE_CTK:
            ctk.CTkLabel(hdr, text="\U0001F517 Malicious Link Analyzer",
                         font=ctk.CTkFont(family="Consolas",size=14,weight="bold"), text_color=self.AC).pack(anchor="w", padx=15, pady=(12,2))
            ctk.CTkLabel(hdr, text="Paste URLs, email body, or HTML. Extracts and analyzes all links for malicious indicators.",
                         font=ctk.CTkFont(family="Consolas",size=10), text_color=self.FD).pack(anchor="w", padx=15, pady=(0,8))
        else:
            tk.Label(hdr, text="\U0001F517 Malicious Link Analyzer", font=("Consolas",14,"bold"), fg=self.AC, bg=self.BP).pack(anchor="w", padx=15, pady=(12,2))
            tk.Label(hdr, text="Paste URLs, email body, or HTML. Extracts and analyzes all links.", font=("Consolas",10), fg=self.FD, bg=self.BP).pack(anchor="w", padx=15, pady=(0,8))
        # Input area
        inf = tk.LabelFrame(tab, text=" Paste URLs or content containing links ", font=("Consolas",10,"bold"),
                            fg=self.AC, bg=self.BG, bd=1, relief="flat")
        inf.pack(fill="x", padx=15, pady=(0,4))
        self.lk_input = self._mt(inf, 5); self.lk_input.pack(fill="x", expand=False, padx=5, pady=5)
        # Buttons
        bf = tk.Frame(tab, bg=self.BG); bf.pack(fill="x", padx=15, pady=(0,6))
        if USE_CTK:
            ctk.CTkButton(bf, text="\U0001F52C Analyze Links", command=self._lk_analyze, font=ctk.CTkFont(family="Consolas",size=13,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=38, width=150, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(bf, text="\U0001F4BE CSV", command=self._lk_csv, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=38, width=70, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(bf, text="Defang All", command=self._lk_defang, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.OR, hover_color="#E3751C", height=38, width=100, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(bf, text="\U0001F5D1 Clear", command=self._lk_clear, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1,
                          height=38, width=70, corner_radius=6).pack(side="left")
        else:
            tk.Button(bf, text="\U0001F52C Analyze Links", command=self._lk_analyze, font=("Consolas",12,"bold"), bg="#e94560", fg="#FFF",
                      relief="flat", padx=14, pady=6).pack(side="left", padx=(0,8))
            tk.Button(bf, text="CSV", command=self._lk_csv, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=6).pack(side="left", padx=(0,8))
            tk.Button(bf, text="Defang All", command=self._lk_defang, font=("Consolas",10), bg=self.OR, fg="#FFF",
                      relief="flat", padx=10, pady=6).pack(side="left", padx=(0,8))
            tk.Button(bf, text="Clear", command=self._lk_clear, font=("Consolas",10), bg=self.BP, fg=self.FT,
                      relief="flat", padx=10, pady=6).pack(side="left")
        self.lk_pv = tk.StringVar(value="")
        tk.Label(tab, textvariable=self.lk_pv, font=("Consolas",10), fg=self.FD, bg=self.BG).pack(fill="x", padx=15, pady=(0,2))
        # Results: sub-notebook
        self.lk_nb = ttk.Notebook(tab); self.lk_nb.pack(fill="both", expand=True, padx=15, pady=(0,12))
        f_table = tk.Frame(self.lk_nb, bg=self.BG); f_detail = tk.Frame(self.lk_nb, bg=self.BG)
        self.lk_nb.add(f_table, text=" Results "); self.lk_nb.add(f_detail, text=" Detail ")
        # Results treeview
        cols = ("Risk","Score","Domain","URL","Flags")
        self.lk_tree = ttk.Treeview(f_table, columns=cols, show="headings", height=14)
        for c in cols: self.lk_tree.heading(c, text=c)
        self.lk_tree.column("Risk", width=80, anchor="center"); self.lk_tree.column("Score", width=55, anchor="center")
        self.lk_tree.column("Domain", width=200); self.lk_tree.column("URL", width=400)
        self.lk_tree.column("Flags", width=350)
        lk_scr = ttk.Scrollbar(f_table, orient="vertical", command=self.lk_tree.yview)
        self.lk_tree.configure(yscrollcommand=lk_scr.set)
        self.lk_tree.pack(side="left", fill="both", expand=True, padx=(5,0), pady=5)
        lk_scr.pack(side="right", fill="y", padx=(0,5), pady=5)
        self.lk_tree.tag_configure("CRITICAL", foreground="#FF0040")
        self.lk_tree.tag_configure("HIGH", foreground=self.RD)
        self.lk_tree.tag_configure("MEDIUM", foreground=self.YL)
        self.lk_tree.tag_configure("LOW", foreground=self.FT)
        self.lk_tree.tag_configure("SAFE", foreground=self.GR)
        self.lk_tree.bind("<<TreeviewSelect>>", self._lk_sel)
        # Detail view
        self.lk_detail = self._mt(f_detail, 20)
        self.lk_detail.pack(fill="both", expand=True, padx=5, pady=5)
        for tg, cl in [("hdr",self.AC),("safe",self.GR),("warn",self.YL),("danger",self.RD),
                        ("crit","#FF0040"),("info",self.FT),("dim",self.FD),("sep",self.BD),("orange",self.OR)]:
            self.lk_detail.tag_configure(tg, foreground=cl,
                font=("Consolas",11 if tg in ("hdr","crit") else 10, "bold" if tg in ("hdr","safe","warn","danger","crit") else ""))
        self.lk_results = []

    def _lk_analyze(self):
        text = self.lk_input.get("1.0","end-1c").strip()
        if not text: messagebox.showwarning("No Input","Paste URLs or content containing links."); return
        for i in self.lk_tree.get_children(): self.lk_tree.delete(i)
        self.lk_detail.delete("1.0","end")
        self.lk_results = self.link_eng.analyze_bulk(text)
        if not self.lk_results:
            self.lk_pv.set("No URLs found in input."); return
        # Sort by risk score descending
        self.lk_results.sort(key=lambda r: r["risk_score"], reverse=True)
        for r in self.lk_results:
            flags_str = ", ".join(f[0] for f in r["flags"]) if r["flags"] else "None"
            self.lk_tree.insert("","end", values=(
                r["risk_level"], r["risk_score"], r["domain"], r["url"][:120], flags_str
            ), tags=(r["risk_level"],))
        bad = sum(1 for r in self.lk_results if r["risk_level"] in ("HIGH","CRITICAL"))
        med = sum(1 for r in self.lk_results if r["risk_level"] == "MEDIUM")
        safe = sum(1 for r in self.lk_results if r["risk_level"] in ("SAFE","LOW"))
        self.lk_pv.set(f"Analyzed {len(self.lk_results)} links: {bad} high/critical, {med} medium, {safe} safe/low")

    def _lk_sel(self, e):
        sel = self.lk_tree.selection()
        if not sel: return
        idx = self.lk_tree.index(sel[0])
        if idx >= len(self.lk_results): return
        r = self.lk_results[idx]
        d = self.lk_detail; d.delete("1.0","end")
        lv_tag = {"SAFE":"safe","LOW":"safe","MEDIUM":"warn","HIGH":"danger","CRITICAL":"crit"}.get(r["risk_level"],"info")
        d.insert("end","="*55+"\n","sep")
        d.insert("end","  LINK ANALYSIS\n","hdr")
        d.insert("end","="*55+"\n\n","sep")
        d.insert("end","  URL:       ","info"); d.insert("end",f"{r['url']}\n","dim")
        d.insert("end","  Domain:    ","info"); d.insert("end",f"{r['domain']}\n","dim")
        d.insert("end","  TLD:       ","info"); d.insert("end",f"{r['tld']}\n","dim")
        d.insert("end","  Defanged:  ","info"); d.insert("end",f"{r['defanged']}\n\n","dim")
        d.insert("end","  Risk:      ","info"); d.insert("end",f"{r['risk_level']}",lv_tag)
        d.insert("end",f"  (score: {r['risk_score']}/100)\n\n","dim")
        if r["flags"]:
            d.insert("end","\u2500"*45+"\n","sep")
            d.insert("end","  FLAGS\n","hdr")
            d.insert("end","\u2500"*45+"\n\n","sep")
            for flag_name, severity, desc in r["flags"]:
                sv_tag = {"HIGH":"danger","MEDIUM":"warn","LOW":"dim","CRITICAL":"crit"}.get(severity,"info")
                d.insert("end",f"  [{severity}] ","" if severity == "LOW" else sv_tag)
                d.insert("end",f"{flag_name}\n","info")
                d.insert("end",f"         {desc}\n\n","dim")
        else:
            d.insert("end","  \u2705 No suspicious indicators found.\n\n","safe")
        d.insert("end","="*55+"\n","sep")

    def _lk_defang(self):
        if not self.lk_results: messagebox.showwarning("No Data","Analyze links first."); return
        lines = [r["defanged"] for r in self.lk_results]
        text = "\n".join(lines)
        try: self.root.clipboard_clear(); self.root.clipboard_append(text)
        except: pass
        self.lk_pv.set(f"Copied {len(lines)} defanged URLs to clipboard.")

    def _lk_csv(self):
        if not self.lk_results: messagebox.showwarning("No Data","Analyze links first."); return
        fp = filedialog.asksaveasfilename(title="Export Link Analysis", defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile=f"link_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not fp: return
        with open(fp, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["URL","Defanged","Domain","TLD","Risk Level","Risk Score","Flags","Flag Details"])
            for r in self.lk_results:
                flags = "; ".join(f[0] for f in r["flags"])
                details = "; ".join(f"{f[0]}: {f[2]}" for f in r["flags"])
                w.writerow([r["url"],r["defanged"],r["domain"],r["tld"],
                            r["risk_level"],r["risk_score"],flags,details])
        messagebox.showinfo("Exported",f"CSV saved: {fp}\n{len(self.lk_results)} links exported.")

    def _lk_clear(self):
        self.lk_input.delete("1.0","end")
        self.lk_detail.delete("1.0","end")
        for i in self.lk_tree.get_children(): self.lk_tree.delete(i)
        self.lk_results = []; self.lk_pv.set("")

