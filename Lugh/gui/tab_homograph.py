"""
Lugh v3.0 - Homograph Detector Tab (Mixin)
"""
import tkinter as tk
from tkinter import messagebox
from config import USE_CTK, ctk
from engines.homograph import HomographDetector

class HomographTabMixin:
    """Homograph / IDN Attack Detector tab."""

    # ══════════════════════════════════════════════════════════════
    # HOMOGRAPH ACTIONS
    # ══════════════════════════════════════════════════════════════
    def _do_homo(self):
        t=self.h_in.get().strip()
        if not t: messagebox.showwarning("No Input","Enter URL/domain/text."); return
        self._show_homo(self.detector.analyze_text(t))

    def _show_homo(self, r):
        o=self.h_out; o.delete("1.0","end"); risk=r["risk_level"]
        bn={"SAFE":(self.GR,self.BG,"\u2705 SAFE"),"MEDIUM":(self.YL,self.BG,"\u26A0\uFE0F MEDIUM RISK"),
            "HIGH":(self.OR,self.BG,"\U0001F536 HIGH RISK"),"CRITICAL":("#FFF",self.RD,"\U0001F6A8 CRITICAL")}
        fg,bg,msg=bn.get(risk,(self.FT,self.BG,""))
        self.rlbl.configure(text=msg,fg=fg,bg=bg); self.rbf.configure(bg=bg)
        o.insert("end","INPUT\n","hdr"); o.insert("end",f"  {r['input']}\n\n","info")
        if r["clean_text"]!=r["input"]:
            o.insert("end","DECODED AS\n","hdr"); o.insert("end",f"  {r['clean_text']}\n\n","cyan")
        if r.get("punycode"): o.insert("end","PUNYCODE\n","hdr"); o.insert("end",f"  {r['punycode']}\n\n","purple")
        if r.get("deceptive_target"):
            o.insert("end","\u26A0 IMPERSONATES: ","crit"); o.insert("end",f"{r['deceptive_target']}\n\n","danger")
        o.insert("end","SCRIPTS\n","hdr")
        for s in sorted(r["scripts_detected"]):
            o.insert("end",f"  \u2022 {s}\n","danger" if s not in ("LATIN","COMMON") else "safe")
        if r["mixed_script"]: o.insert("end","\n  \u26A0 MIXED SCRIPT \u2014 strong attack indicator\n","danger")
        o.insert("end","\n","info")
        fnd=[f for f in r["findings"] if f["type"]=="CONFUSABLE"]
        if fnd:
            o.insert("end","\u2500"*70+"\n","sep"); o.insert("end","CONFUSABLE CHARS\n","hdr")
            o.insert("end",f"  {'Pos':<5}{'Char':<6}{'U+':<12}{'Like':<8}{'Script':<18}Desc\n","dim")
            o.insert("end","  "+"\u2500"*64+"\n","sep")
            for f in fnd:
                o.insert("end",f"  {f['position']:<5}{f['character']!r:<6}{f['unicode']:<12}'{f['looks_like']}'{'':.<5}{f['script']:<18}{f['description']}\n","orange")
            o.insert("end","\n","info")
        o.insert("end","\u2500"*70+"\n","sep"); o.insert("end","CHAR MAP\n","hdr")
        o.insert("end",f"  {'Pos':<5}{'Char':<6}{'U+':<12}{'Script':<20}Name\n","dim")
        o.insert("end","  "+"\u2500"*60+"\n","sep")
        for ca in r["char_analysis"]:
            tg="orange" if ca["is_suspicious"] else "dim"
            cd=repr(ca["character"]) if ord(ca["character"])>127 else f"'{ca['character']}'"
            mk=" \u25C0" if ca["is_suspicious"] else ""
            o.insert("end",f"  {ca['position']:<5}{cd:<6}{ca['unicode']:<12}{ca['script']:<20}{ca['name']}{mk}\n",tg)

    def _do_homo_ex(self):
        t=self.h_in.get().strip()
        if not t:
            t="google.com"
            if USE_CTK: self.h_in.delete(0,"end"); self.h_in.insert(0,t)
            else: self.h_in.delete(0,tk.END); self.h_in.insert(0,t)
        ex=self.detector.generate_examples(t)
        o=self.h_out; o.delete("1.0","end")
        self.rlbl.configure(text=f"\u26A0\uFE0F Examples for: {t}",fg=self.YL,bg=self.BG)
        o.insert("end",f"HOMOGRAPH SPOOFS: {t}\n","hdr"); o.insert("end","\u2500"*70+"\n\n","sep")
        if not ex: o.insert("end","  No Cyrillic substitutions possible.\n","dim"); return
        o.insert("end",f"  {'#':<4}{'Spoofed':<35}{'Pos':<8}{'Orig':<8}{'Replace':<20}Unicode\n","dim")
        for i,e in enumerate(ex,1):
            o.insert("end",f"  {i:<4}{e['spoofed']:<35}{e['position']:<8}'{e['original_char']}'{'':.<5}'{e['replaced_with']}' {e['description']:<18}{e['unicode']}\n","orange")
        o.insert("end","\n\u2500"*35+"\n","sep"); o.insert("end","DEFENSES\n","hdr")
        for tip in ["Check URLs carefully \u2014 hover before clicking","Look for punycode (xn--) in browser bar",
                     "Bookmark sensitive sites","Enable IDN display in browser","Deploy mixed-script email gateway rules"]:
            o.insert("end",f"  \u2022 {tip}\n","info")

    def _homo_clr(self):
        if USE_CTK: self.h_in.delete(0,"end")
        else: self.h_in.delete(0,tk.END)
        self.h_out.delete("1.0","end"); self.rlbl.configure(text="",bg=self.BG); self.rbf.configure(bg=self.BG)

