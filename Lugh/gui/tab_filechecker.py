"""
Lugh v3.0 - File Type Checker Tab (Mixin)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from config import USE_CTK, ctk
from pathlib import Path
from datetime import datetime
import csv

class FileCheckerTabMixin:
    """File Type Checker tab."""

    # ══════════════════════════════════════════════════════════════
    # FILE CHECKER ACTIONS
    # ══════════════════════════════════════════════════════════════
    def _fc_bdir(self):
        d=filedialog.askdirectory(title="Select Folder")
        if d:
            if USE_CTK: self.fc_p.delete(0,"end"); self.fc_p.insert(0,d)
            else: self.fc_p.delete(0,tk.END); self.fc_p.insert(0,d)

    def _fc_bfile(self):
        f=filedialog.askopenfilename(title="Select File")
        if f:
            if USE_CTK: self.fc_p.delete(0,"end"); self.fc_p.insert(0,f)
            else: self.fc_p.delete(0,tk.END); self.fc_p.insert(0,f)

    def _fc_scan(self):
        ps=self.fc_p.get().strip()
        if not ps: messagebox.showwarning("No Path","Select file/folder first."); return
        p=Path(ps)
        if not p.exists(): messagebox.showerror("Not Found",f"Path not found:\n{ps}"); return
        self._fc_clr_results(); self.fchk=FileTypeChecker()
        def prog(c,t): self.fc_pv.set(f"Scanning: {c}/{t}...")
        def run():
            if p.is_file():
                r=self.fchk.identify(p); self.fchk.results.append(r)
                self.root.after(0,self._fc_add,r)
                self.root.after(0,lambda:self.fc_pv.set("Done: 1 file"))
            else:
                self.fchk.scan_dir(p,recursive=self.fc_rec.get(),
                    prog_cb=lambda c,t:self.root.after(0,prog,c,t),
                    file_cb=lambda r:self.root.after(0,self._fc_add,r))
                st=self.fchk.stats()
                self.root.after(0,lambda:self.fc_pv.set(f"Done: {st['total']} files | {st['identified']} identified | {st['mismatched']} mismatched | {st['errors']} errors"))
            self.root.after(0,self._fc_stats)
        threading.Thread(target=run,daemon=True).start()

    def _fc_add(self, r):
        mi="\u2705" if r.get('extension_match',True) else "\u274C"
        self.fc_all.insert("","end",values=(r.get('filename',''),r.get('extension',''),r.get('type_name','Unknown'),
                                             r.get('category','Unknown'),mi,r.get('mismatch_severity','')))
        if not r.get('extension_match',True):
            sv=r.get('mismatch_severity','Low')
            self.fc_sus.insert("","end",values=(r.get('filename',''),r.get('extension',''),r.get('type_name',''),
                                                sv,r.get('mismatch_description','')),tags=(sv,))

    def _fc_sel(self, e):
        sel=self.fc_all.selection()
        if not sel: return
        idx=self.fc_all.index(sel[0])
        if idx<len(self.fchk.results):
            r=self.fchk.results[idx]; self.fc_dt_t.delete("1.0","end")
            L=["\u2550"*60,"  FILE DETAIL","\u2550"*60,"",
               f"  File:      {r.get('filename','')}",f"  Path:      {r.get('filepath','')}",
               f"  Extension: {r.get('extension','')}",f"  Size:      {r.get('size',0):,} bytes",
               f"  Type:      {r.get('type_name','Unknown')}",f"  Category:  {r.get('category','Unknown')}",
               f"  Identified:{r.get('identified',False)}",
               f"  Match:     {'Yes' if r.get('extension_match',True) else 'NO - MISMATCH'}"]
            if r.get('mismatch_severity'):
                L+=[f"  Severity:  {r['mismatch_severity']}",f"  Issue:     {r.get('mismatch_description','')}"]
            if r.get('error'): L.append(f"  Error:     {r['error']}")
            L+=["","\u2500"*60,"  HEADER HEX (first 32 bytes):","\u2500"*60]
            hx=r.get('header_hex','')
            for i in range(0,len(hx),32):
                ch=hx[i:i+32]; sp=' '.join(ch[j:j+2] for j in range(0,len(ch),2))
                L.append(f"  {i//2:04X}: {sp}")
            L+=["","\u2550"*60]; self.fc_dt_t.insert("1.0","\n".join(L))
            self.fc_nb.select(self.fc_td)

    def _fc_stats(self):
        st=self.fchk.stats(); self.fc_st_t.delete("1.0","end")
        L=["\u2550"*60,"  SCAN STATISTICS","\u2550"*60,"",
           f"  Total:      {st['total']}",f"  Identified: {st['identified']}",
           f"  Mismatched: {st['mismatched']}",f"  Errors:     {st['errors']}"]
        if st['severities']:
            L+=["","  -- Severity Breakdown --"]
            for sv in ["Critical","High","Medium","Low"]:
                if sv in st['severities']: L.append(f"    {sv}: {st['severities'][sv]}")
        if st['categories']:
            L+=["","  -- Categories --"]
            for c,n in sorted(st['categories'].items(),key=lambda x:-x[1]):
                L.append(f"    {c:<25}{n:>5}  {chr(9608)*min(n,40)}")
        L+=["","\u2550"*60]; self.fc_st_t.insert("1.0","\n".join(L))

    def _fc_csv(self):
        if not self.fchk.results: messagebox.showwarning("No Data","Run a scan first."); return
        fp=filedialog.asksaveasfilename(title="Export",defaultextension=".csv",
            filetypes=[("CSV","*.csv")],initialfile=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if fp:
            with open(fp,'w',newline='',encoding='utf-8') as f:
                w=csv.writer(f)
                w.writerow(["File","Path","Ext","Size","Type","Category","Match","Severity","Description","Error"])
                for r in self.fchk.results:
                    w.writerow([r.get('filename',''),r.get('filepath',''),r.get('extension',''),
                                r.get('size',0),r.get('type_name',''),r.get('category',''),
                                r.get('extension_match',True),r.get('mismatch_severity',''),
                                r.get('mismatch_description',''),r.get('error','')])
            messagebox.showinfo("Done",f"CSV saved: {fp}")

    def _fc_clr(self):
        self._fc_clr_results()
        if USE_CTK: self.fc_p.delete(0,"end")
        else: self.fc_p.delete(0,tk.END)
        self.fc_pv.set("")

    def _fc_clr_results(self):
        for i in self.fc_all.get_children(): self.fc_all.delete(i)
        for i in self.fc_sus.get_children(): self.fc_sus.delete(i)
        self.fc_st_t.delete("1.0","end"); self.fc_dt_t.delete("1.0","end")

