"""
Lugh v3.0 - Email Header Analyzer Tab (Mixin)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from config import USE_CTK, ctk
from pathlib import Path
from datetime import datetime
import json

SCL_DESC = {"-1":"Safe sender bypass","0":"Clean","1":"Very low","5":"Spam","6":"Spam",
            "7":"High Confidence Spam","8":"High Confidence Spam","9":"High Confidence Spam"}
SFV_DESC = {"BLK":"Blocked sender","NSPM":"Not Spam","SFE":"Safe sender","SKA":"Allow policy",
            "SKB":"Block policy","SKN":"Pre-filter: clean","SKQ":"From quarantine","SPM":"Spam"}

class EmailTabMixin:
    """Email Header Analyzer tab: builder + actions."""

    # EMAIL HEADERS TAB (consolidated)
    # ══════════════════════════════════════════════════════════════
    def _b_email(self):
        tab = self.t_email
        # Top bar with section selector
        if USE_CTK: top = ctk.CTkFrame(tab, fg_color=self.BP, corner_radius=8)
        else: top = tk.Frame(tab, bg=self.BP, bd=1, relief="flat")
        top.pack(fill="x", padx=15, pady=(10,6))
        if USE_CTK:
            ctk.CTkLabel(top, text="\U0001F4E7 Email Header Analyzer",
                         font=ctk.CTkFont(family="Consolas",size=14,weight="bold"), text_color=self.AC).pack(side="left", padx=15, pady=10)
        else:
            tk.Label(top, text="\U0001F4E7 Email Header Analyzer", font=("Consolas",14,"bold"),
                     fg=self.AC, bg=self.BP).pack(side="left", padx=15, pady=10)
        sf = tk.Frame(top, bg=self.BP); sf.pack(side="left", fill="x", expand=True, padx=10, pady=8)
        tk.Label(sf, text="Section:", font=("Consolas",11), fg=self.FT, bg=self.BP).pack(side="left", padx=(0,8))
        self.em_sel = ttk.Combobox(sf, values=["\U0001F4E5 Input","\U0001F4CB Summary",
            "\U0001F500 Hops","\U0001F510 Auth","\U0001F6E1 Anti-Spam","\U0001F4D1 Other","{ } Raw"],
            state="readonly", font=("Consolas",11), width=20)
        self.em_sel.set("\U0001F4E5 Input"); self.em_sel.pack(side="left")
        self.em_sel.bind("<<ComboboxSelected>>", self._em_switch)
        # Container for section panels
        self.em_container = tk.Frame(tab, bg=self.BG)
        self.em_container.pack(fill="both", expand=True, padx=0, pady=(0,0))
        self._em_panels = {}
        # Create sub-frames for each section
        self.t_in = tk.Frame(self.em_container, bg=self.BG)
        self.t_sum = tk.Frame(self.em_container, bg=self.BG)
        self.t_hop = tk.Frame(self.em_container, bg=self.BG)
        self.t_auth = tk.Frame(self.em_container, bg=self.BG)
        self.t_spam = tk.Frame(self.em_container, bg=self.BG)
        self.t_oth = tk.Frame(self.em_container, bg=self.BG)
        self.t_raw = tk.Frame(self.em_container, bg=self.BG)
        self._em_panels["\U0001F4E5 Input"] = self.t_in
        self._em_panels["\U0001F4CB Summary"] = self.t_sum
        self._em_panels["\U0001F500 Hops"] = self.t_hop
        self._em_panels["\U0001F510 Auth"] = self.t_auth
        self._em_panels["\U0001F6E1 Anti-Spam"] = self.t_spam
        self._em_panels["\U0001F4D1 Other"] = self.t_oth
        self._em_panels["{ } Raw"] = self.t_raw
        # Build each section's content
        self._b_input(); self._b_sum(); self._b_hop(); self._b_auth()
        self._b_spam(); self._b_oth(); self._b_raw()
        # Show Input by default
        self._em_show("\U0001F4E5 Input")

    def _em_switch(self, e=None):
        self._em_show(self.em_sel.get())

    def _em_show(self, name):
        for n, f in self._em_panels.items():
            if n == name: f.pack(fill="both", expand=True)
            else: f.pack_forget()

    # ── Input Section ──
    def _b_input(self):
        t=self.t_in
        if USE_CTK:
            ctk.CTkLabel(t,text="Paste Email Headers Below",font=ctk.CTkFont(family="Consolas",size=14,weight="bold"),
                         text_color=self.FB).pack(pady=(15,5),padx=20,anchor="w")
            ctk.CTkLabel(t,text="Outlook: message \u2192 File \u2192 Properties \u2192 Internet Headers",
                         font=ctk.CTkFont(family="Consolas",size=10),text_color=self.FD).pack(pady=(0,8),padx=20,anchor="w")
        else:
            tk.Label(t,text="Paste Email Headers Below",font=("Consolas",14,"bold"),fg=self.FB,bg=self.BG).pack(pady=(15,5),padx=20,anchor="w")
            tk.Label(t,text="Outlook: message > File > Properties > Internet Headers",font=("Consolas",10),fg=self.FD,bg=self.BG).pack(pady=(0,8),padx=20,anchor="w")
        # Pack buttons FIRST at bottom so they're always visible even when resized
        bf=tk.Frame(t,bg=self.BG); bf.pack(side="bottom",fill="x",padx=20,pady=(0,15))
        if USE_CTK:
            ctk.CTkButton(bf,text="\u26A1 Analyze",command=self._do_analyze,font=ctk.CTkFont(family="Consolas",size=13,weight="bold"),
                          fg_color="#e94560",hover_color="#ff6b6b",height=40,corner_radius=6).pack(side="left",padx=(0,10))
            ctk.CTkButton(bf,text="\U0001F4C2 Load",command=self._load_file,font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=40,corner_radius=6).pack(side="left",padx=(0,10))
            ctk.CTkButton(bf,text="\U0001F5D1 Clear",command=lambda:self.inp.delete("1.0","end"),font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=40,corner_radius=6).pack(side="left")
            ctk.CTkButton(bf,text="\U0001F4BE Export",command=self._export_json,font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=40,corner_radius=6).pack(side="right")
        else:
            tk.Button(bf,text="\u26A1 Analyze",command=self._do_analyze,font=("Consolas",12,"bold"),bg="#e94560",fg="#FFF",relief="flat",padx=15,pady=8).pack(side="left",padx=(0,10))
            tk.Button(bf,text="Load",command=self._load_file,font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=12,pady=8).pack(side="left",padx=(0,10))
            tk.Button(bf,text="Clear",command=lambda:self.inp.delete("1.0","end"),font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=12,pady=8).pack(side="left")
            tk.Button(bf,text="Export",command=self._export_json,font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=12,pady=8).pack(side="right")
        # Text widget fills remaining space above buttons
        self.inp=self._mt(t,22); self.inp.pack(fill="both",expand=True,padx=20,pady=(0,10))

    # ── Summary / Auth / Anti-Spam / Other / Raw Sections ──
    def _b_sum(self):
        self.sum_t=self._mt(self.t_sum,30); self.sum_t.pack(fill="both",expand=True,padx=20,pady=15)

    def _b_hop(self):
        cols=("Hop","From","By","Protocol","Time","Delay")
        self.hop_tree=ttk.Treeview(self.t_hop,columns=cols,show="headings",height=15)
        for c in cols: self.hop_tree.heading(c,text=c)
        self.hop_tree.column("Hop",width=50,anchor="center"); self.hop_tree.column("From",width=250)
        self.hop_tree.column("By",width=250); self.hop_tree.column("Protocol",width=100,anchor="center")
        self.hop_tree.column("Time",width=200); self.hop_tree.column("Delay",width=80,anchor="center")
        sc=ttk.Scrollbar(self.t_hop,orient="vertical",command=self.hop_tree.yview)
        self.hop_tree.configure(yscrollcommand=sc.set)
        self.hop_tree.pack(side="left",fill="both",expand=True,padx=(20,0),pady=15)
        sc.pack(side="right",fill="y",padx=(0,20),pady=15)
        self.hop_det=self._mt(self.t_hop,6); self.hop_det.pack(fill="x",padx=20,pady=(0,15),side="bottom")
        self.hop_tree.bind("<<TreeviewSelect>>",self._hop_sel)

    def _b_auth(self):
        self.auth_t=self._mt(self.t_auth,30); self.auth_t.pack(fill="both",expand=True,padx=20,pady=15)

    def _b_spam(self):
        self.spam_t=self._mt(self.t_spam,30); self.spam_t.pack(fill="both",expand=True,padx=20,pady=15)

    def _b_oth(self):
        self.oth_t=self._mt(self.t_oth,30); self.oth_t.pack(fill="both",expand=True,padx=20,pady=15)

    def _b_raw(self):
        self.raw_t=self._mt(self.t_raw,30); self.raw_t.pack(fill="both",expand=True,padx=20,pady=15)

    # ── Homograph Tab ──
    def _b_homo(self):
        tab=self.t_homo
        if USE_CTK: inf=ctk.CTkFrame(tab,fg_color=self.BP,corner_radius=8)
        else: inf=tk.Frame(tab,bg=self.BP,bd=1,relief="flat")
        inf.pack(fill="x",padx=15,pady=(12,6))
        if USE_CTK:
            ctk.CTkLabel(inf,text="\U0001F50D Homograph / IDN Detector",font=ctk.CTkFont(family="Consolas",size=14,weight="bold"),
                         text_color=self.AC).pack(anchor="w",padx=15,pady=(12,2))
            ctk.CTkLabel(inf,text="Check URLs, domains, or text for deceptive Unicode characters.",
                         font=ctk.CTkFont(family="Consolas",size=10),text_color=self.FD).pack(anchor="w",padx=15,pady=(0,8))
        else:
            tk.Label(inf,text="\U0001F50D Homograph / IDN Detector",font=("Consolas",14,"bold"),fg=self.AC,bg=self.BP).pack(anchor="w",padx=15,pady=(12,2))
            tk.Label(inf,text="Check URLs, domains, or text for deceptive Unicode characters.",font=("Consolas",10),fg=self.FD,bg=self.BP).pack(anchor="w",padx=15,pady=(0,8))
        ef=tk.Frame(inf,bg=self.BP); ef.pack(fill="x",padx=15,pady=(0,12))
        if USE_CTK:
            self.h_in=ctk.CTkEntry(ef,placeholder_text="e.g. \u0430pple.com or p\u0430ypal.com",font=ctk.CTkFont(family="Consolas",size=13),
                                   fg_color=self.BI,text_color=self.FT,border_color=self.BD,height=40,corner_radius=6)
            self.h_in.pack(side="left",fill="x",expand=True,padx=(0,10)); self.h_in.bind("<Return>",lambda e:self._do_homo())
            ctk.CTkButton(ef,text="\U0001F52C Scan",command=self._do_homo,font=ctk.CTkFont(family="Consolas",size=13,weight="bold"),
                          fg_color="#e94560",hover_color="#ff6b6b",height=40,width=120,corner_radius=6).pack(side="left",padx=(0,5))
            ctk.CTkButton(ef,text="\u26A0 Examples",command=self._do_homo_ex,font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.OR,hover_color="#E3751C",height=40,width=130,corner_radius=6).pack(side="left",padx=(0,5))
            ctk.CTkButton(ef,text="Clear",command=self._homo_clr,font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BG,hover_color="#21262D",border_color=self.BD,border_width=1,height=40,width=70,corner_radius=6).pack(side="left")
        else:
            self.h_in=tk.Entry(ef,font=("Consolas",13),bg=self.BI,fg=self.FT,insertbackground=self.FT,relief="flat",bd=2)
            self.h_in.pack(side="left",fill="x",expand=True,padx=(0,10)); self.h_in.bind("<Return>",lambda e:self._do_homo())
            tk.Button(ef,text="Scan",command=self._do_homo,font=("Consolas",12,"bold"),bg="#e94560",fg="#FFF",relief="flat",padx=12,pady=6).pack(side="left",padx=(0,5))
            tk.Button(ef,text="Examples",command=self._do_homo_ex,font=("Consolas",10),bg=self.OR,fg="#FFF",relief="flat",padx=10,pady=6).pack(side="left",padx=(0,5))
            tk.Button(ef,text="Clear",command=self._homo_clr,font=("Consolas",10),bg=self.BG,fg=self.FT,relief="flat",padx=10,pady=6).pack(side="left")
        self._bind_ctx(self.h_in)
        self.rbf=tk.Frame(tab,bg=self.BG,height=45); self.rbf.pack(fill="x",padx=15,pady=(4,4)); self.rbf.pack_propagate(False)
        self.rlbl=tk.Label(self.rbf,text="",font=("Consolas",13,"bold"),bg=self.BG,fg=self.FD); self.rlbl.pack(fill="both",expand=True)
        self.h_out=self._mt(tab,25); self.h_out.pack(fill="both",expand=True,padx=15,pady=(0,12))
        for tg,cl in [("hdr",self.AC),("safe",self.GR),("warn",self.YL),("danger",self.RD),
                       ("crit",self.RD),("info",self.FT),("dim",self.FD),("cyan",self.CY),
                       ("purple",self.PU),("orange",self.OR),("sep",self.BD)]:
            self.h_out.tag_configure(tg,foreground=cl,
                font=("Consolas",11 if tg in ("hdr","crit") else 10,"bold" if tg in ("hdr","safe","warn","danger","crit") else ""))

    # ── File Checker Tab ──
    def _b_fc(self):
        tab=self.t_fc
        if USE_CTK: ctrl=ctk.CTkFrame(tab,fg_color=self.BP,corner_radius=8)
        else: ctrl=tk.Frame(tab,bg=self.BP,bd=1,relief="flat")
        ctrl.pack(fill="x",padx=15,pady=(12,6))
        if USE_CTK:
            ctk.CTkLabel(ctrl,text="\U0001F4C2 File Type Checker \u2014 Magic Number Scanner",
                         font=ctk.CTkFont(family="Consolas",size=14,weight="bold"),text_color=self.AC).pack(anchor="w",padx=15,pady=(12,2))
            ctk.CTkLabel(ctrl,text="Scan files/folders to detect true types by binary signatures.\nFinds extension mismatches (EXE disguised as JPG, etc.)",
                         font=ctk.CTkFont(family="Consolas",size=10),text_color=self.FD,justify="left").pack(anchor="w",padx=15,pady=(0,8))
        else:
            tk.Label(ctrl,text="\U0001F4C2 File Type Checker",font=("Consolas",14,"bold"),fg=self.AC,bg=self.BP).pack(anchor="w",padx=15,pady=(12,2))
            tk.Label(ctrl,text="Scan files/folders to detect true types. Finds extension mismatches.",font=("Consolas",10),fg=self.FD,bg=self.BP).pack(anchor="w",padx=15,pady=(0,8))
        pf=tk.Frame(ctrl,bg=self.BP); pf.pack(fill="x",padx=15,pady=(0,6))
        if USE_CTK:
            self.fc_p=ctk.CTkEntry(pf,placeholder_text="Select file or folder...",font=ctk.CTkFont(family="Consolas",size=12),
                                   fg_color=self.BI,text_color=self.FT,border_color=self.BD,height=38,corner_radius=6)
            self.fc_p.pack(side="left",fill="x",expand=True,padx=(0,8))
            ctk.CTkButton(pf,text="\U0001F4C1 Folder",command=self._fc_bdir,font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=38,width=100,corner_radius=6).pack(side="left",padx=(0,5))
            ctk.CTkButton(pf,text="\U0001F4C4 File",command=self._fc_bfile,font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=38,width=90,corner_radius=6).pack(side="left")
        else:
            self.fc_p=tk.Entry(pf,font=("Consolas",12),bg=self.BI,fg=self.FT,insertbackground=self.FT,relief="flat",bd=2)
            self.fc_p.pack(side="left",fill="x",expand=True,padx=(0,8))
            tk.Button(pf,text="Folder",command=self._fc_bdir,font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=12,pady=6).pack(side="left",padx=(0,5))
            tk.Button(pf,text="File",command=self._fc_bfile,font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=12,pady=6).pack(side="left")
        self._bind_ctx(self.fc_p)
        of=tk.Frame(ctrl,bg=self.BP); of.pack(fill="x",padx=15,pady=(0,12))
        self.fc_rec=tk.BooleanVar(value=True)
        tk.Checkbutton(of,text="Recursive",variable=self.fc_rec,bg=self.BP,fg=self.FT,selectcolor=self.BG,
                       activebackground=self.BP,activeforeground=self.FT,font=("Consolas",10)).pack(side="left",padx=(0,15))
        if USE_CTK:
            ctk.CTkButton(of,text="\U0001F52C Scan",command=self._fc_scan,font=ctk.CTkFont(family="Consolas",size=13,weight="bold"),
                          fg_color="#e94560",hover_color="#ff6b6b",height=38,width=120,corner_radius=6).pack(side="left",padx=(0,10))
            ctk.CTkButton(of,text="\u23F9 Stop",command=lambda:self.fchk.stop(),font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.RD,hover_color="#DA3633",height=38,width=80,corner_radius=6).pack(side="left",padx=(0,10))
            ctk.CTkButton(of,text="\U0001F4BE CSV",command=self._fc_csv,font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=38,width=80,corner_radius=6).pack(side="left",padx=(0,10))
            ctk.CTkButton(of,text="\U0001F5D1 Clear",command=self._fc_clr,font=ctk.CTkFont(family="Consolas",size=12),
                          fg_color=self.BP,hover_color="#21262D",border_color=self.BD,border_width=1,height=38,width=80,corner_radius=6).pack(side="left")
        else:
            tk.Button(of,text="Scan",command=self._fc_scan,font=("Consolas",12,"bold"),bg="#e94560",fg="#FFF",relief="flat",padx=12,pady=6).pack(side="left",padx=(0,10))
            tk.Button(of,text="Stop",command=lambda:self.fchk.stop(),font=("Consolas",11),bg=self.RD,fg="#FFF",relief="flat",padx=10,pady=6).pack(side="left",padx=(0,10))
            tk.Button(of,text="CSV",command=self._fc_csv,font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=10,pady=6).pack(side="left",padx=(0,10))
            tk.Button(of,text="Clear",command=self._fc_clr,font=("Consolas",11),bg=self.BP,fg=self.FT,relief="flat",padx=10,pady=6).pack(side="left")
        self.fc_pv=tk.StringVar(value="")
        tk.Label(tab,textvariable=self.fc_pv,font=("Consolas",10),fg=self.FD,bg=self.BG).pack(fill="x",padx=15,pady=(0,2))
        self.fc_nb=ttk.Notebook(tab); self.fc_nb.pack(fill="both",expand=True,padx=15,pady=(0,12))
        self.fc_ta=self._mf(); self.fc_ts=self._mf(); self.fc_tst=self._mf(); self.fc_td=self._mf()
        self.fc_nb.add(self.fc_ta,text=" All Results "); self.fc_nb.add(self.fc_ts,text=" \u26A0 Suspicious ")
        self.fc_nb.add(self.fc_tst,text=" Stats "); self.fc_nb.add(self.fc_td,text=" Detail ")
        # All tree
        ca=("File","Ext","Type","Category","Match","Severity")
        self.fc_all=ttk.Treeview(self.fc_ta,columns=ca,show="headings",height=18)
        for c in ca: self.fc_all.heading(c,text=c)
        self.fc_all.column("File",width=300); self.fc_all.column("Ext",width=60,anchor="center")
        self.fc_all.column("Type",width=220); self.fc_all.column("Category",width=120,anchor="center")
        self.fc_all.column("Match",width=60,anchor="center"); self.fc_all.column("Severity",width=80,anchor="center")
        s1=ttk.Scrollbar(self.fc_ta,orient="vertical",command=self.fc_all.yview); self.fc_all.configure(yscrollcommand=s1.set)
        self.fc_all.pack(side="left",fill="both",expand=True,padx=(5,0),pady=5); s1.pack(side="right",fill="y",padx=(0,5),pady=5)
        self.fc_all.bind("<<TreeviewSelect>>",self._fc_sel)
        # Suspicious tree
        cs=("File","Ext","True Type","Severity","Description")
        self.fc_sus=ttk.Treeview(self.fc_ts,columns=cs,show="headings",height=18)
        for c in cs: self.fc_sus.heading(c,text=c)
        self.fc_sus.column("File",width=250); self.fc_sus.column("Ext",width=60,anchor="center")
        self.fc_sus.column("True Type",width=200); self.fc_sus.column("Severity",width=80,anchor="center")
        self.fc_sus.column("Description",width=300)
        s2=ttk.Scrollbar(self.fc_ts,orient="vertical",command=self.fc_sus.yview); self.fc_sus.configure(yscrollcommand=s2.set)
        self.fc_sus.pack(side="left",fill="both",expand=True,padx=(5,0),pady=5); s2.pack(side="right",fill="y",padx=(0,5),pady=5)
        for sv in ["Critical","High","Medium","Low"]:
            cl = {self.RD:"Critical",self.OR:"High",self.YL:"Medium",self.FD:"Low"}
            self.fc_sus.tag_configure(sv,foreground={v:k for k,v in cl.items()}.get(sv,self.FD))
        self.fc_sus.tag_configure("Critical",foreground=self.RD)
        self.fc_sus.tag_configure("High",foreground=self.OR)
        self.fc_sus.tag_configure("Medium",foreground=self.YL)
        self.fc_sus.tag_configure("Low",foreground=self.FD)
        # Stats & Detail
        self.fc_st_t=self._mt(self.fc_tst,20); self.fc_st_t.pack(fill="both",expand=True,padx=5,pady=5)
        self.fc_dt_t=self._mt(self.fc_td,20); self.fc_dt_t.pack(fill="both",expand=True,padx=5,pady=5)

    # ══════════════════════════════════════════════════════════════
    # HEADER ACTIONS
    # ══════════════════════════════════════════════════════════════
    def _do_analyze(self):
        raw=self.inp.get("1.0","end-1c").strip()
        if not raw: messagebox.showwarning("No Input","Paste headers first."); return
        try:
            self.parsed=self.parser.parse(raw)
            self._p_sum(); self._p_hop(); self._p_auth(); self._p_spam(); self._p_oth(); self._p_raw()
            self.nb.select(self.t_email)
            self.em_sel.set("\U0001F4CB Summary"); self._em_show("\U0001F4CB Summary")
        except Exception as e: messagebox.showerror("Error",str(e))

    def _p_sum(self):
        self.sum_t.delete("1.0","end"); p=self.parsed
        L=["\u2550"*70,"  EMAIL SUMMARY","\u2550"*70,""]
        for k,v in p.summary.items():
            if v: L.append(f"  {k:.<20s} {v}")
        L+=[""," \u2500"*35,f"  Total Hops: {len(p.received_hops)}"]
        if p.received_hops:
            td=sum(h.delay_seconds for h in p.received_hops if h.delay_seconds>0)
            if td: L.append(f"  Transit: {td:.0f}s ({td/60:.1f}m)")
        a=p.authentication; L+=["","\u2500"*35,"  AUTH STATUS","\u2500"*35]
        for nm,vl in [("SPF",a.spf_result),("DKIM",a.dkim_result),("DMARC",a.dmarc_result),("CompAuth",a.compauth_result)]:
            if vl:
                ic="\u2705" if vl.lower()=="pass" else "\u274C"
                L.append(f"  {nm}:{' '*(9-len(nm))}{ic} {vl.upper()}")
        L+=["","\u2550"*70]; self.sum_t.insert("1.0","\n".join(L))

    def _p_hop(self):
        for i in self.hop_tree.get_children(): self.hop_tree.delete(i)
        for h in self.parsed.received_hops:
            ts=h.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z") if h.timestamp else "N/A"
            tg=("slow",) if h.delay_seconds>60 else ("medium",) if h.delay_seconds>10 else ()
            self.hop_tree.insert("","end",values=(h.hop_number,h.from_host or "(local)",h.by_host,h.with_protocol,ts,h.delay or "-"),tags=tg)
        self.hop_tree.tag_configure("slow",foreground=self.RD); self.hop_tree.tag_configure("medium",foreground=self.YL)

    def _hop_sel(self,e):
        sel=self.hop_tree.selection()
        if not sel: return
        idx=self.hop_tree.index(sel[0])
        if idx<len(self.parsed.received_hops):
            h=self.parsed.received_hops[idx]; self.hop_det.delete("1.0","end")
            self.hop_det.insert("1.0",f"Raw Received (Hop #{h.hop_number}):\n\n{h.raw_header}")

    def _p_auth(self):
        self.auth_t.delete("1.0","end"); a=self.parsed.authentication
        L=["="*60,"EMAIL AUTHENTICATION RESULTS","="*60,""]
        # SPF
        L+=[ "\u2500"*40,"SPF (Sender Policy Framework)","\u2500"*40]
        if a.spf_result:
            ic="\u2705" if a.spf_result.lower() in ("pass","passed") else "\u26A0\uFE0F" if a.spf_result.lower() in ("softfail","neutral","none") else "\u274C"
            L.append(f"Result:  {ic} {a.spf_result.upper()}")
            L.append(f"Details: {a.spf_details or 'N/A'}")
        else: L.append("Result:  Not present")
        L+=["","  \u2500"*40,"DKIM (DomainKeys Identified Mail)","\u2500"*40]
        if a.dkim_result:
            ic="\u2705" if a.dkim_result.lower() in ("pass","passed") else "\u26A0\uFE0F" if a.dkim_result.lower() in ("softfail","neutral","none") else "\u274C"
            L.append(f"Result:  {ic} {a.dkim_result.upper()}")
            L.append(f"Details: {a.dkim_details or 'N/A'}")
        else: L.append("Result:  Not present")
        L+=["","\u2500"*40,"DMARC (Domain-based Message Authentication)","\u2500"*40]
        if a.dmarc_result:
            ic="\u2705" if a.dmarc_result.lower() in ("pass","passed") else "\u26A0\uFE0F" if a.dmarc_result.lower() in ("softfail","neutral","none") else "\u274C"
            L.append(f"Result:  {ic} {a.dmarc_result.upper()}")
            L.append(f"Details: {a.dmarc_details or 'N/A'}")
        else: L.append("Result:  Not present")
        if a.compauth_result:
            L+=["","\u2500"*40,"Composite Authentication (Microsoft)","\u2500"*40]
            ic="\u2705" if a.compauth_result.lower() in ("pass","passed") else "\u274C"
            L.append(f"Result:  {ic} {a.compauth_result.upper()}")
            if a.compauth_reason: L.append(f"Reason:  {a.compauth_reason}")
        if a.arc_result:
            L+=["","\u2500"*40,"ARC (Authenticated Received Chain)","\u2500"*40]
            ic="\u2705" if a.arc_result.lower() in ("pass","passed") else "\u274C"
            L.append(f"Result:  {ic} {a.arc_result.upper()}")
        L+=["","\u2550"*60]; self.auth_t.insert("1.0","\n".join(L))

    def _p_spam(self):
        self.spam_t.delete("1.0","end"); a=self.parsed.antispam
        L=["\u2550"*70,"  ANTI-SPAM","\u2550"*70,"","  -- SCL --"]
        if a.scl: L.append(f"    SCL={a.scl} -> {SCL_DESC.get(a.scl,'Unknown')}")
        else: L.append("    Not present")
        L+=["","  -- SFV --"]
        if a.sfv: L.append(f"    SFV={a.sfv} -> {SFV_DESC.get(a.sfv,'Unknown')}")
        else: L.append("    Not present")
        L+=["","  -- Other --"]
        for nm,vl in [("BCL",a.bcl),("CIP",a.cip),("CTRY",a.country),("H",a.h_value),("PTR",a.ptr)]:
            if vl: L.append(f"    {nm}: {vl}")
        if self.parsed.forefront_antispam:
            L+=["","  -- Forefront --"]
            for k,v in self.parsed.forefront_antispam.items(): L.append(f"    {k}: {v}")
        L+=["","\u2550"*70]; self.spam_t.insert("1.0","\n".join(L))

    def _p_oth(self):
        self.oth_t.delete("1.0","end")
        L=["\u2550"*70,"  OTHER HEADERS","\u2550"*70,""]
        if self.parsed.other_headers:
            for k,v in self.parsed.other_headers.items(): L+=[f"  {k}:",f"    {v}",""]
        else: L.append("  None found.")
        self.oth_t.insert("1.0","\n".join(L))

    def _p_raw(self):
        self.raw_t.delete("1.0","end")
        if not self.parsed: return
        d={"summary":self.parsed.summary,
           "hops":[{"hop":h.hop_number,"from":h.from_host,"by":h.by_host,"protocol":h.with_protocol,
                    "time":h.timestamp.isoformat() if h.timestamp else None,"delay":h.delay,
                    "delay_s":h.delay_seconds} for h in self.parsed.received_hops],
           "auth":{k:getattr(self.parsed.authentication,k) for k in ["spf_result","dkim_result","dmarc_result","compauth_result","arc_result"]},
           "antispam":{k:getattr(self.parsed.antispam,k) for k in ["scl","bcl","sfv","cat","cip","country"]},
           "other":self.parsed.other_headers}
        self.raw_t.insert("1.0",json.dumps(d,indent=2,default=str))

    def _load_file(self):
        fp=filedialog.askopenfilename(title="Open Headers",filetypes=[("Text","*.txt"),("Email","*.eml"),("All","*.*")])
        if fp:
            with open(fp,'r',encoding='utf-8',errors='replace') as f: self.inp.delete("1.0","end"); self.inp.insert("1.0",f.read())

    def _export_json(self):
        if not self.parsed: messagebox.showwarning("No Data","Analyze first."); return
        fp=filedialog.asksaveasfilename(title="Export",defaultextension=".json",filetypes=[("JSON","*.json")])
        if fp:
            raw=self.raw_t.get("1.0","end-1c"); j=raw.find('{')
            if j!=-1:
                with open(fp,'w') as f: json.dump(json.loads(raw[j:]),f,indent=2)
                messagebox.showinfo("Done",f"Saved: {fp}")

