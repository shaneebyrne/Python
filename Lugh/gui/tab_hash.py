"""
Lugh v3.0 - Hash Checker Tab (Mixin)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib, os, threading
from config import USE_CTK, ctk
from pathlib import Path
from datetime import datetime
import csv

class HashTabMixin:
    """Hash Checker tab."""

    # ══════════════════════════════════════════════════════════════
    # HASH CHECKER TAB
    # ══════════════════════════════════════════════════════════════
    def _b_hash(self):
        tab = self.t_hash
        # Header
        if USE_CTK: hdr = ctk.CTkFrame(tab, fg_color=self.BP, corner_radius=8)
        else: hdr = tk.Frame(tab, bg=self.BP, bd=1, relief="flat")
        hdr.pack(fill="x", padx=15, pady=(12,6))
        if USE_CTK:
            ctk.CTkLabel(hdr, text="#\u20E3 Hash Checker \u2014 MD5 / SHA1 / SHA256",
                         font=ctk.CTkFont(family="Consolas",size=14,weight="bold"), text_color=self.AC).pack(anchor="w", padx=15, pady=(12,2))
            ctk.CTkLabel(hdr, text="Hash files or entire directories. Compare against known hash values.",
                         font=ctk.CTkFont(family="Consolas",size=10), text_color=self.FD).pack(anchor="w", padx=15, pady=(0,8))
        else:
            tk.Label(hdr, text="#\u20E3 Hash Checker", font=("Consolas",14,"bold"), fg=self.AC, bg=self.BP).pack(anchor="w", padx=15, pady=(12,2))
            tk.Label(hdr, text="Hash files or directories. Compare against known values.", font=("Consolas",10), fg=self.FD, bg=self.BP).pack(anchor="w", padx=15, pady=(0,8))
        # Path row
        pf = tk.Frame(hdr, bg=self.BP); pf.pack(fill="x", padx=15, pady=(0,6))
        if USE_CTK:
            self.hc_path = ctk.CTkEntry(pf, placeholder_text="Select file or folder...", font=ctk.CTkFont(family="Consolas",size=12),
                                        fg_color=self.BI, text_color=self.FT, border_color=self.BD, height=38, corner_radius=6)
            self.hc_path.pack(side="left", fill="x", expand=True, padx=(0,8))
            ctk.CTkButton(pf, text="\U0001F4C1 Folder", command=self._hc_bdir, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1, height=38, width=100, corner_radius=6).pack(side="left", padx=(0,5))
            ctk.CTkButton(pf, text="\U0001F4C4 File", command=self._hc_bfile, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1, height=38, width=80, corner_radius=6).pack(side="left")
        else:
            self.hc_path = tk.Entry(pf, font=("Consolas",12), bg=self.BI, fg=self.FT, insertbackground=self.FT, relief="flat", bd=2)
            self.hc_path.pack(side="left", fill="x", expand=True, padx=(0,8))
            tk.Button(pf, text="Folder", command=self._hc_bdir, font=("Consolas",10), bg=self.BP, fg=self.FT, relief="flat", padx=10, pady=5).pack(side="left", padx=(0,5))
            tk.Button(pf, text="File", command=self._hc_bfile, font=("Consolas",10), bg=self.BP, fg=self.FT, relief="flat", padx=10, pady=5).pack(side="left")
        self._bind_ctx(self.hc_path)
        # Options + buttons row
        of = tk.Frame(hdr, bg=self.BP); of.pack(fill="x", padx=15, pady=(0,12))
        self.hc_rec = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="Recursive", variable=self.hc_rec, bg=self.BP, fg=self.FT, selectcolor=self.BG,
                       activebackground=self.BP, activeforeground=self.FT, font=("Consolas",10)).pack(side="left", padx=(0,15))
        self.hc_md5 = tk.BooleanVar(value=True); self.hc_sha1 = tk.BooleanVar(value=True); self.hc_sha256 = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="MD5", variable=self.hc_md5, bg=self.BP, fg=self.FT, selectcolor=self.BG,
                       activebackground=self.BP, activeforeground=self.FT, font=("Consolas",10)).pack(side="left", padx=(0,8))
        tk.Checkbutton(of, text="SHA1", variable=self.hc_sha1, bg=self.BP, fg=self.FT, selectcolor=self.BG,
                       activebackground=self.BP, activeforeground=self.FT, font=("Consolas",10)).pack(side="left", padx=(0,8))
        tk.Checkbutton(of, text="SHA256", variable=self.hc_sha256, bg=self.BP, fg=self.FT, selectcolor=self.BG,
                       activebackground=self.BP, activeforeground=self.FT, font=("Consolas",10)).pack(side="left", padx=(0,15))
        if USE_CTK:
            ctk.CTkButton(of, text="\U0001F52C Hash", command=self._hc_scan, font=ctk.CTkFont(family="Consolas",size=12,weight="bold"),
                          fg_color="#e94560", hover_color="#ff6b6b", height=36, width=110, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(of, text="\U0001F4BE CSV", command=self._hc_csv, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1, height=36, width=80, corner_radius=6).pack(side="left", padx=(0,8))
            ctk.CTkButton(of, text="\U0001F5D1 Clear", command=self._hc_clr, font=ctk.CTkFont(family="Consolas",size=11),
                          fg_color=self.BP, hover_color="#21262D", border_color=self.BD, border_width=1, height=36, width=80, corner_radius=6).pack(side="left")
        else:
            tk.Button(of, text="\U0001F52C Hash", command=self._hc_scan, font=("Consolas",11,"bold"), bg="#e94560", fg="#FFF", relief="flat", padx=12, pady=5).pack(side="left", padx=(0,8))
            tk.Button(of, text="CSV", command=self._hc_csv, font=("Consolas",10), bg=self.BP, fg=self.FT, relief="flat", padx=10, pady=5).pack(side="left", padx=(0,8))
            tk.Button(of, text="Clear", command=self._hc_clr, font=("Consolas",10), bg=self.BP, fg=self.FT, relief="flat", padx=10, pady=5).pack(side="left")
        # Compare hash
        cmpf = tk.Frame(hdr, bg=self.BP); cmpf.pack(fill="x", padx=15, pady=(0,10))
        tk.Label(cmpf, text="Compare:", font=("Consolas",10), fg=self.FD, bg=self.BP).pack(side="left", padx=(0,5))
        self.hc_cmp = tk.Entry(cmpf, font=("Consolas",10), bg=self.BI, fg=self.YL, insertbackground=self.FT, relief="flat", bd=2)
        self.hc_cmp.pack(side="left", fill="x", expand=True, padx=(0,8))
        self._bind_ctx(self.hc_cmp)
        if USE_CTK:
            ctk.CTkButton(cmpf, text="Find Match", command=self._hc_find, font=ctk.CTkFont(family="Consolas",size=10),
                          fg_color=self.OR, hover_color="#E3751C", height=30, width=100, corner_radius=6).pack(side="left")
        else:
            tk.Button(cmpf, text="Find Match", command=self._hc_find, font=("Consolas",9), bg=self.OR, fg="#FFF", relief="flat", padx=8, pady=3).pack(side="left")
        # Progress
        self.hc_pv = tk.StringVar(value="")
        tk.Label(tab, textvariable=self.hc_pv, font=("Consolas",10), fg=self.FD, bg=self.BG).pack(fill="x", padx=15, pady=(0,2))
        # Results treeview
        cols = ("File","Size","MD5","SHA1","SHA256")
        self.hc_tree = ttk.Treeview(tab, columns=cols, show="headings", height=20)
        for c in cols: self.hc_tree.heading(c, text=c)
        self.hc_tree.column("File", width=250); self.hc_tree.column("Size", width=80, anchor="e")
        self.hc_tree.column("MD5", width=260); self.hc_tree.column("SHA1", width=320); self.hc_tree.column("SHA256", width=450)
        scr = ttk.Scrollbar(tab, orient="vertical", command=self.hc_tree.yview)
        self.hc_tree.configure(yscrollcommand=scr.set)
        self.hc_tree.pack(side="left", fill="both", expand=True, padx=(15,0), pady=(0,12))
        scr.pack(side="right", fill="y", padx=(0,15), pady=(0,12))
        self.hc_tree.tag_configure("match", foreground=self.GR)
        self.hc_tree.bind("<<TreeviewSelect>>", self._hc_sel)
        self.hc_data = []  # store raw results

    def _hc_bdir(self):
        d = filedialog.askdirectory(title="Select Folder")
        if d:
            if USE_CTK: self.hc_path.delete(0,"end"); self.hc_path.insert(0,d)
            else: self.hc_path.delete(0,tk.END); self.hc_path.insert(0,d)

    def _hc_bfile(self):
        f = filedialog.askopenfilename(title="Select File")
        if f:
            if USE_CTK: self.hc_path.delete(0,"end"); self.hc_path.insert(0,f)
            else: self.hc_path.delete(0,tk.END); self.hc_path.insert(0,f)

    def _hc_hash_file(self, fp):
        r = {"filepath":str(fp),"filename":fp.name,"size":0,"md5":"","sha1":"","sha256":"","error":None}
        try:
            r["size"] = fp.stat().st_size
            data = fp.read_bytes()
            if self.hc_md5.get(): r["md5"] = hashlib.md5(data).hexdigest()
            if self.hc_sha1.get(): r["sha1"] = hashlib.sha1(data).hexdigest()
            if self.hc_sha256.get(): r["sha256"] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            r["error"] = str(e)
        return r

    def _hc_scan(self):
        ps = self.hc_path.get().strip()
        if not ps: messagebox.showwarning("No Path","Select a file or folder."); return
        p = Path(ps)
        if not p.exists(): messagebox.showerror("Not Found",f"Path not found:\n{ps}"); return
        # Clear
        for i in self.hc_tree.get_children(): self.hc_tree.delete(i)
        self.hc_data = []
        def add(r):
            sz = f"{r['size']:,}" if r.get('size') else "err"
            self.hc_tree.insert("","end", values=(r["filename"],sz,r.get("md5",""),r.get("sha1",""),r.get("sha256","")))
            self.hc_data.append(r)
        def prog(c,t): self.hc_pv.set(f"Hashing: {c}/{t}...")
        def run():
            if p.is_file():
                r = self._hc_hash_file(p)
                self.root.after(0, add, r)
                self.root.after(0, lambda: self.hc_pv.set(f"Done: 1 file"))
            else:
                files = []
                if self.hc_rec.get():
                    for root, _, fns in os.walk(p):
                        for fn in fns: files.append(Path(root)/fn)
                else:
                    files = [f for f in p.iterdir() if f.is_file()]
                for i, fp in enumerate(files):
                    r = self._hc_hash_file(fp)
                    self.root.after(0, add, r)
                    if (i+1) % 10 == 0: self.root.after(0, prog, i+1, len(files))
                self.root.after(0, lambda: self.hc_pv.set(f"Done: {len(files)} files hashed"))
        threading.Thread(target=run, daemon=True).start()

    def _hc_sel(self, e):
        sel = self.hc_tree.selection()
        if not sel: return
        idx = self.hc_tree.index(sel[0])
        if idx < len(self.hc_data):
            r = self.hc_data[idx]
            lines = [f"File:   {r['filename']}",f"Path:   {r['filepath']}",f"Size:   {r.get('size',0):,} bytes"]
            if r.get("md5"): lines.append(f"MD5:    {r['md5']}")
            if r.get("sha1"): lines.append(f"SHA1:   {r['sha1']}")
            if r.get("sha256"): lines.append(f"SHA256: {r['sha256']}")
            if r.get("error"): lines.append(f"Error:  {r['error']}")
            # Copy to clipboard on select
            clip = "\n".join(lines)
            try: self.root.clipboard_clear(); self.root.clipboard_append(clip)
            except: pass

    def _hc_find(self):
        target = self.hc_cmp.get().strip().lower()
        if not target: messagebox.showwarning("No Hash","Enter a hash value to compare."); return
        if not self.hc_data: messagebox.showwarning("No Data","Run a hash scan first."); return
        # Clear existing tags
        for item in self.hc_tree.get_children(): self.hc_tree.item(item, tags=())
        found = 0
        for i, r in enumerate(self.hc_data):
            match = False
            if r.get("md5","").lower() == target: match = True
            elif r.get("sha1","").lower() == target: match = True
            elif r.get("sha256","").lower() == target: match = True
            if match:
                item_id = self.hc_tree.get_children()[i]
                self.hc_tree.item(item_id, tags=("match",))
                self.hc_tree.see(item_id)
                found += 1
        if found: self.hc_pv.set(f"\u2705 {found} file(s) matched!")
        else: self.hc_pv.set(f"\u274C No matches for: {target[:20]}...")

    def _hc_csv(self):
        if not self.hc_data: messagebox.showwarning("No Data","Run a scan first."); return
        fp = filedialog.asksaveasfilename(title="Export Hashes", defaultextension=".csv",
            filetypes=[("CSV","*.csv")], initialfile=f"hashes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if fp:
            with open(fp,'w',newline='',encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["File","Path","Size","MD5","SHA1","SHA256","Error"])
                for r in self.hc_data:
                    w.writerow([r.get("filename",""),r.get("filepath",""),r.get("size",0),
                                r.get("md5",""),r.get("sha1",""),r.get("sha256",""),r.get("error","")])
            messagebox.showinfo("Done",f"CSV saved: {fp}")

    def _hc_clr(self):
        for i in self.hc_tree.get_children(): self.hc_tree.delete(i)
        self.hc_data = []
        if USE_CTK: self.hc_path.delete(0,"end"); self.hc_cmp.delete(0,"end")
        else: self.hc_path.delete(0,tk.END); self.hc_cmp.delete(0,tk.END)
        self.hc_pv.set("")

