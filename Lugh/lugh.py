#!/usr/bin/env python3
"""
Lugh v3.0 - Command Line Interface

Usage:
    lugh headers <file.eml>              Analyze email headers, print summary
    lugh headers <file.eml> --hops       Show received hop chain with delays
    lugh headers <file.eml> --auth       Show SPF/DKIM/DMARC authentication
    lugh headers <file.eml> --all        Full analysis (summary + hops + auth + anti-spam)
    lugh headers <file.eml> --json       Output parsed results as JSON
    lugh headers <file.eml> --raw        Dump raw headers only
    lugh headers <dir/> --batch          Analyze all .eml/.msg/.txt files in directory
    lugh gui                             Launch the GUI
    lugh --help                          Show this help

Examples:
    lugh headers suspicious.eml --all
    lugh headers C:\\Cases\\phish.eml --auth --json
    lugh headers inbox/ --batch
    lugh gui
"""
import sys
import os
import json
from pathlib import Path

# Ensure project root is on path
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from engines.email_parser import EmailHeaderParser


def _extract_headers(filepath):
    """Read a file and extract the header block (everything before the first blank line)."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    for sep in ['\r\n\r\n', '\n\n']:
        if sep in content:
            return content.split(sep, 1)[0]
    return content


def _format_summary(parsed, filepath=""):
    lines = []
    lines.append("  " + "=" * 62)
    lines.append("  \u2694 LUGH \u2014 Email Header Analysis")
    if filepath:
        lines.append(f"  File: {filepath}")
    lines.append("  " + "=" * 62)
    lines.append("")
    s = parsed.summary
    for label, key in [("From","From"),("To","To"),("Subject","Subject"),
                        ("Date","Date"),("Message-ID","Message-ID"),
                        ("Return-Path","Return-Path"),("Reply-To","Reply-To")]:
        val = s.get(key, "") or s.get(key.lower(), "")
        if val:
            lines.append(f"  {label:<14} {val}")
    lines.append("")
    return "\n".join(lines)


def _format_hops(parsed):
    lines = []
    lines.append("  RECEIVED HOPS")
    lines.append("  " + "\u2500" * 60)
    hops = parsed.received_hops
    if not hops:
        lines.append("  No Received headers found.")
        return "\n".join(lines)
    for h in hops:
        lines.append(f"  Hop {h.hop_number}:")
        if h.from_host:     lines.append(f"    From:     {h.from_host}")
        if h.by_host:       lines.append(f"    By:       {h.by_host}")
        if h.with_protocol: lines.append(f"    Protocol: {h.with_protocol}")
        if h.timestamp:     lines.append(f"    Time:     {h.timestamp}")
        if h.delay:         lines.append(f"    Delay:    {h.delay}")
        lines.append("")
    return "\n".join(lines)


def _format_auth(parsed):
    lines = []
    lines.append("  AUTHENTICATION")
    lines.append("  " + "\u2500" * 60)
    a = parsed.authentication
    checks = [
        ("SPF",   a.spf_result,   a.spf_details),
        ("DKIM",  a.dkim_result,  a.dkim_details),
        ("DMARC", a.dmarc_result, a.dmarc_details),
    ]
    if a.compauth_result:
        checks.append(("CompAuth", a.compauth_result, a.compauth_reason))
    if a.arc_result:
        checks.append(("ARC", a.arc_result, ""))
    found = False
    for method, result, details in checks:
        if result:
            found = True
            status = result.upper()
            icon = "\u2705" if status == "PASS" else "\u274C" if status in ("FAIL","SOFTFAIL") else "\u26A0"
            det = f"  ({details})" if details else ""
            lines.append(f"  {icon} {method:<10} {status:<10}{det}")
    if not found:
        lines.append("  No authentication results found.")
    lines.append("")
    return "\n".join(lines)


def _format_antispam(parsed):
    lines = []
    lines.append("  ANTI-SPAM")
    lines.append("  " + "\u2500" * 60)
    a = parsed.antispam
    SCL_DESC = {"-1":"Safe sender","0":"Clean","1":"Very low","5":"Spam",
                "6":"Spam","7":"HCSpam","8":"HCSpam","9":"HCSpam"}
    SFV_DESC = {"BLK":"Blocked","NSPM":"Not Spam","SFE":"Safe sender",
                "SKA":"Allow","SKB":"Block","SKN":"Clean","SPM":"Spam"}
    found = False
    if a.scl: lines.append(f"  SCL:  {a.scl} \u2192 {SCL_DESC.get(a.scl, 'Unknown')}"); found = True
    if a.bcl: lines.append(f"  BCL:  {a.bcl}"); found = True
    if a.sfv: lines.append(f"  SFV:  {a.sfv} \u2192 {SFV_DESC.get(a.sfv, 'Unknown')}"); found = True
    if a.pcl: lines.append(f"  PCL:  {a.pcl}"); found = True
    if a.source_ip: lines.append(f"  IP:   {a.source_ip}"); found = True
    if a.country: lines.append(f"  Geo:  {a.country}"); found = True
    if not found:
        lines.append("  No anti-spam headers found.")
    lines.append("")
    return "\n".join(lines)


def _parsed_to_dict(parsed):
    d = {"summary": parsed.summary, "hops": [], "authentication": {}, "antispam": {}, "other_headers": parsed.other_headers}
    for h in parsed.received_hops:
        d["hops"].append({"hop":h.hop_number, "from":h.from_host, "by":h.by_host,
            "protocol":h.with_protocol, "time":str(h.timestamp) if h.timestamp else "",
            "delay":h.delay or ""})
    a = parsed.authentication
    d["authentication"] = {"spf":a.spf_result,"spf_details":a.spf_details,
        "dkim":a.dkim_result,"dkim_details":a.dkim_details,
        "dmarc":a.dmarc_result,"dmarc_details":a.dmarc_details,
        "compauth":a.compauth_result,"arc":a.arc_result}
    s = parsed.antispam
    d["antispam"] = {"scl":s.scl,"bcl":s.bcl,"sfv":s.sfv,"pcl":s.pcl,
        "source_ip":s.source_ip,"country":s.country}
    return d


def analyze_file(filepath, flags):
    fp = Path(filepath)
    if not fp.exists():
        print(f"  \u274C File not found: {filepath}", file=sys.stderr)
        return False

    raw = _extract_headers(filepath)
    if not raw.strip():
        print(f"  \u274C Empty file: {filepath}", file=sys.stderr)
        return False

    parser = EmailHeaderParser()
    parsed = parser.parse(raw)

    if "--json" in flags:
        d = _parsed_to_dict(parsed)
        d["source_file"] = str(fp.name)
        print(json.dumps(d, indent=2, default=str))
        return True

    if "--raw" in flags:
        print(raw)
        return True

    show_all = "--all" in flags
    show_hops = "--hops" in flags or show_all
    show_auth = "--auth" in flags or show_all
    show_spam = "--spam" in flags or show_all

    if not (show_hops or show_auth or show_spam):
        show_all = True; show_hops = show_auth = show_spam = True

    print(_format_summary(parsed, str(fp)))
    if show_hops: print(_format_hops(parsed))
    if show_auth: print(_format_auth(parsed))
    if show_spam: print(_format_antispam(parsed))

    # Verdict
    a = parsed.authentication
    auth_pass = sum(1 for r in [a.spf_result,a.dkim_result,a.dmarc_result] if r and r.lower()=="pass")
    auth_fail = sum(1 for r in [a.spf_result,a.dkim_result,a.dmarc_result] if r and r.lower() in ("fail","softfail"))
    hop_count = len(parsed.received_hops)
    print(f"  \u2500\u2500 {hop_count} hops | Auth: {auth_pass} pass, {auth_fail} fail | ", end="")
    if auth_fail > 0: print("\u274C SUSPICIOUS")
    elif auth_pass >= 2: print("\u2705 CLEAN")
    else: print("\u26A0 INCONCLUSIVE")
    print()
    return True


def batch_analyze(directory, flags):
    dp = Path(directory)
    if not dp.is_dir():
        print(f"  \u274C Not a directory: {directory}", file=sys.stderr)
        return
    files = []
    for pat in ["*.eml","*.msg","*.txt","*.headers"]:
        files.extend(dp.glob(pat))
    files = sorted(set(files))
    if not files:
        print(f"  No .eml/.msg/.txt/.headers files found in {directory}")
        return
    print(f"  \u2694 Lugh batch analysis: {len(files)} files in {directory}")
    print("  " + "=" * 62)
    print()
    for fp in files:
        analyze_file(str(fp), flags)
        print()


def show_help():
    print(__doc__)


def main():
    args = sys.argv[1:]
    if not args or "--help" in args or "-h" in args:
        show_help()
        return
    cmd = args[0].lower()
    if cmd == "gui":
        os.chdir(_ROOT)
        from gui.app import PyCyApp
        PyCyApp().run()
        return
    if cmd in ("headers","header","analyze","eml"):
        if len(args) < 2:
            print("  Usage: lugh headers <file.eml> [--all|--hops|--auth|--json|--raw|--batch]")
            return
        target = args[1]
        flags = [a.lower() for a in args[2:]]
        if "--batch" in flags: batch_analyze(target, flags)
        else: analyze_file(target, flags)
        return
    if os.path.isfile(cmd) or cmd.endswith(('.eml','.msg','.txt','.headers')):
        analyze_file(cmd, [a.lower() for a in args[1:]])
        return
    print(f"  Unknown command: {cmd}")
    show_help()


if __name__ == "__main__":
    main()
