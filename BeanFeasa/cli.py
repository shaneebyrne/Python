#!/usr/bin/env python3
"""
BeanFeasa — CLI Mode.

Run BeanFeasa from the command line without the GUI. Useful for:
  - Batch processing multiple log directories
  - Scheduled analysis via Task Scheduler / cron
  - Integration into other scripts and pipelines
  - Remote/headless systems without a display

Usage:
    python cli.py <input_path> [options]

Examples:
    python cli.py C:\\Logs\\Security.evtx
    python cli.py /var/log/ --recursive --output report.csv
    python cli.py C:\\Logs\\ -r -o results.csv --rules C:\\MyRules\\
    python cli.py logs/ --full-report --no-color
"""

import sys
import os
import argparse
import time
from pathlib import Path
from datetime import datetime

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.registry import parse_file, get_parser_name, get_supported_extensions
from parsers.supplemental import resolve_hostname
from analyzers.rule_loader import load_rules
from analyzers.detection_engine import DetectionEngine
from analyzers.correlation_engine import CorrelationEngine
from analyzers.anomaly_detector import AnomalyDetector
from analyzers.remediation_kb import RemediationKB
from exporters.csv_exporter import (
    export_detections, export_events, export_incidents,
    export_anomalies, export_full_report,
)
from utils.platform_utils import discover_log_files, format_file_size, is_event_log
from utils.device_context import detect_profile, get_suppressed_rules
from parsers.storage_parser import parse_largest_files_csv
from analyzers.storage_analyzer import StorageAnalyzer
from analyzers.baseline_model import BaselineModel
from analyzers.supplemental_analyzers import SupplementalAnalyzerSuite, SupplementalFinding
from exporters.csv_exporter import export_storage_findings


# ── ANSI colors (disabled with --no-color) ──

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

NO_COLOR = Colors()
for attr in dir(NO_COLOR):
    if attr.isupper():
        setattr(NO_COLOR, attr, "")


def main():
    parser = argparse.ArgumentParser(
        description="BeanFeasa CLI — Log Analysis & Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s Security.evtx
  %(prog)s C:\\Logs\\ -r -o report.csv
  %(prog)s /var/log/ --full-report --rules /etc/beanfeasa/rules/
  %(prog)s logs/ --events-only -o parsed_events.csv
        """,
    )

    parser.add_argument(
        "input", nargs="+",
        help="Log file(s) or directory to analyze",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output CSV path (default: beanfeasa_report_<timestamp>.csv)",
    )
    parser.add_argument(
        "-r", "--recursive", action="store_true", default=True,
        help="Recursively scan directories (default: True)",
    )
    parser.add_argument(
        "--rules", default=None,
        help="Custom rules directory (default: built-in rules/)",
    )
    parser.add_argument(
        "--full-report", action="store_true",
        help="Export combined report (incidents + anomalies + detections)",
    )
    parser.add_argument(
        "--events-only", action="store_true",
        help="Export all parsed events without rule matching",
    )
    parser.add_argument(
        "--no-correlate", action="store_true",
        help="Skip correlation engine",
    )
    parser.add_argument(
        "--no-anomaly", action="store_true",
        help="Skip anomaly detection",
    )
    parser.add_argument(
        "--storage", default=None, metavar="LARGESTFILES_CSV",
        help="Path to a LargestFiles CSV from Get-LargestFiles.ps1. "
             "Runs disk space analysis and adds findings to the report.",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output (only show summary)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed per-file and per-detection output",
    )

    args = parser.parse_args()
    C = NO_COLOR if args.no_color else Colors()

    # ── Banner ──
    if not args.quiet:
        print(f"\n{C.CYAN}{C.BOLD}  BeanFeasa — CLI Log Analysis{C.RESET}")
        print(f"{C.DIM}  {'═' * 40}{C.RESET}\n")

    # ── Resolve input files ──
    log_files = []
    supported = get_supported_extensions()

    for input_path in args.input:
        p = Path(input_path)
        if p.is_file():
            if p.suffix.lower() in supported:
                log_files.append(str(p))
            else:
                print(f"{C.YELLOW}  [!] Unsupported: {p.name}{C.RESET}")
        elif p.is_dir():
            found = discover_log_files(str(p), recursive=args.recursive)
            log_files.extend(found)
            if not args.quiet:
                print(f"{C.DIM}  Scanned {p}: {len(found)} file(s){C.RESET}")
        else:
            print(f"{C.RED}  [!] Not found: {input_path}{C.RESET}")

    if not log_files:
        print(f"{C.RED}  [!] No supported log files found.{C.RESET}")
        sys.exit(1)

    if not args.quiet:
        total_size = sum(Path(f).stat().st_size for f in log_files)
        print(f"{C.GREEN}  [*] {len(log_files)} file(s) to analyze ({format_file_size(total_size)}){C.RESET}")

    # ── Load rules ──
    app_dir = Path(__file__).resolve().parent
    rules_dir = args.rules or str(app_dir / "rules")

    rules, rule_errors = load_rules(rules_dir)
    if rule_errors and args.verbose:
        for err in rule_errors:
            print(f"{C.YELLOW}  [!] Rule: {err}{C.RESET}")

    if not args.quiet:
        print(f"{C.GREEN}  [*] {len(rules)} detection rules loaded from {rules_dir}{C.RESET}")

    # ── Device context detection ──
    seen_dirs = set()
    for f in log_files:
        parent = str(Path(f).parent)
        if parent not in seen_dirs:
            seen_dirs.add(parent)
            profile = detect_profile(parent)
            if profile.hostname:
                suppressed = get_suppressed_rules(profile)
                if suppressed:
                    rules = [r for r in rules if r.id not in suppressed]
                    if not args.quiet:
                        print(f"{C.GREEN}  [*] Device: {profile.summary()}{C.RESET}")
                        print(f"{C.DIM}  Suppressed {len(suppressed)} rules for device context{C.RESET}")
                break

    # ── Phase 1a: Parse all event files ──
    start_time = time.time()
    all_events = []
    all_detections = []
    _file_events: dict[str, list] = {}   # filepath → events (for detection pass)

    for i, filepath in enumerate(log_files):
        fname = Path(filepath).name
        if not args.quiet and not args.verbose:
            print(f"\r{C.DIM}  Parsing [{i+1}/{len(log_files)}] {fname}...{C.RESET}", end="", flush=True)

        events, errors = parse_file(filepath)
        if args.verbose:
            print(f"  [{i+1}/{len(log_files)}] {fname}: {len(events)} events", end="")
            if errors:
                print(f" {C.YELLOW}({len(errors)} errors){C.RESET}")
            else:
                print()

        # Only event log files contribute to analysis
        if not is_event_log(filepath):
            if args.verbose:
                print(f"    {C.DIM}(inventory/config — excluded from analysis){C.RESET}")
            continue

        all_events.extend(events)
        _file_events[filepath] = events

    if not args.quiet:
        print(f"\r{C.GREEN}  [*] Parsed {len(all_events):,} events from {len(log_files)} files{C.RESET}" + " " * 30)

    # ── Supplemental file analysis ──
    # Auto-discovers Hotfixes.csv, InstalledApps.csv, Services.csv, RunningProcesses.csv
    # in the same directories as the analyzed log files.
    supplemental_findings: list[SupplementalFinding] = []
    if not args.events_only:
        _supp_suite = SupplementalAnalyzerSuite()
        _seen_folders: set[str] = set()
        for _lf in log_files:
            _folder = str(Path(_lf).parent)
            if _folder not in _seen_folders:
                _seen_folders.add(_folder)
                _supp_findings = _supp_suite.analyze_folder(_folder)
                supplemental_findings.extend(_supp_findings)
        if supplemental_findings and not args.quiet:
            print(f"\n{C.CYAN}  Supplemental findings:{C.RESET}")
            for _sf in supplemental_findings:
                color = {"critical": C.RED, "high": C.YELLOW,
                         "medium": C.MAGENTA, "low": C.DIM}.get(_sf.severity, "")
                print(f"    {color}[{_sf.severity.upper():>8s}]{C.RESET} {_sf.title}")

    # ── Phase 1b: Build baseline model from full event set ──
    _baseline = BaselineModel()
    if all_events and not args.events_only:
        if not args.quiet:
            print(f"{C.DIM}  Building baseline frequency model...{C.RESET}", end="", flush=True)
        _baseline.build(all_events)
        bstats = _baseline.get_stats()
        if not args.quiet:
            print(f"\r{C.DIM}  Baseline: {bstats['baseline_pairs']} routine patterns, "                  f"{bstats['signal_pairs']} signal patterns{C.RESET}" + " " * 10)

    # ── Phase 1c: Run detection with baseline-aware engine ──
    if not args.events_only:
        engine = DetectionEngine(rules, baseline=_baseline)
        for filepath, events in _file_events.items():
            dets = engine.analyze(events, filepath)
            all_detections.extend(dets)
            if args.verbose and dets:
                print(f"    {C.MAGENTA}→ {len(dets)} detection(s) in {Path(filepath).name}{C.RESET}")
    else:
        engine = DetectionEngine(rules)

    # ── Hostname resolution from supplemental files ──
    resolved_hostname = ""
    seen_dirs = set()
    for f in log_files:
        parent = str(Path(f).parent)
        if parent not in seen_dirs:
            seen_dirs.add(parent)
            h = resolve_hostname(parent)
            if h:
                resolved_hostname = h
                break
    if resolved_hostname:
        backfilled = 0
        for evt in all_events:
            if not evt.computer or evt.computer == "unknown":
                evt.computer = resolved_hostname
                backfilled += 1
        if not args.quiet and backfilled:
            print(f"{C.GREEN}  [*] Resolved hostname: {resolved_hostname} (backfilled {backfilled} events){C.RESET}")

    # ── Phase 2: Correlation ──
    incidents = []
    if not args.no_correlate and not args.events_only:
        if not args.quiet:
            print(f"{C.DIM}  Running correlation engine...{C.RESET}")
        correlator = CorrelationEngine()
        incidents = correlator.correlate(all_events)
        if not args.quiet:
            print(f"{C.GREEN}  [*] {len(incidents)} correlated incident(s){C.RESET}")

    # ── Phase 3: Anomaly detection ──
    anomalies = []
    if not args.no_anomaly and not args.events_only:
        if not args.quiet:
            print(f"{C.DIM}  Running anomaly detector...{C.RESET}")
        detector = AnomalyDetector()
        anomalies = detector.analyze(all_events)
        if not args.quiet:
            print(f"{C.GREEN}  [*] {len(anomalies)} anomalie(s) detected{C.RESET}")

    elapsed = time.time() - start_time

    # ── Summary ──
    print(f"\n{C.CYAN}{C.BOLD}  Results{C.RESET}")
    print(f"{C.DIM}  {'─' * 40}{C.RESET}")

    if not args.events_only:
        summary = engine.get_summary()
        sev_display = {"critical": C.RED, "high": C.MAGENTA, "medium": C.YELLOW, "low": C.BLUE}

        raw = summary.get('detections_raw', summary['total_detections'])
        deduped = summary['total_detections']
        suppressed = summary.get('baseline_suppressed', 0)
        print(f"  Events scanned:      {C.BOLD}{summary['events_scanned']:,}{C.RESET}")
        print(f"  Detections (raw):    {C.BOLD}{raw:,}{C.RESET}")
        print(f"  After dedup:         {C.BOLD}{deduped:,}{C.RESET}" +
              (f"  {C.DIM}(-{raw - deduped} merged){C.RESET}" if raw > deduped else ""))
        if suppressed:
            print(f"  Baseline-suppressed: {C.DIM}{suppressed:,} weak-rule hits downgraded{C.RESET}")
        strength = summary.get('by_strength', {})
        if strength:
            print(f"  {C.DIM}Rule strength: "                  f"strong={strength.get('strong',0)} "                  f"medium={strength.get('medium',0)} "                  f"weak={strength.get('weak',0)}{C.RESET}")
        print(f"  Correlated incidents:{C.BOLD} {len(incidents):,}{C.RESET}")
        print(f"  Anomalies:           {C.BOLD}{len(anomalies):,}{C.RESET}")
        print(f"  Elapsed:             {elapsed:.2f}s")

        if summary["by_severity"]:
            print(f"\n  {C.DIM}Detections by severity:{C.RESET}")
            for sev in ("critical", "high", "medium", "low", "informational"):
                count = summary["by_severity"].get(sev, 0)
                if count > 0:
                    color = sev_display.get(sev, "")
                    print(f"    {color}{sev.upper():15s}{C.RESET} {count:,}")

        # Show top incidents
        if incidents:
            print(f"\n  {C.DIM}Correlated incidents:{C.RESET}")
            for inc in incidents[:10]:
                color = sev_display.get(inc.severity, "")
                print(f"    {color}[{inc.severity.upper():>8s}]{C.RESET} {inc.title}")
                print(f"             {C.DIM}{inc.computer} | {inc.event_count} events | {inc.first_seen}{C.RESET}")
                if args.verbose and inc.root_cause:
                    print(f"             {C.YELLOW}Cause: {inc.root_cause[:80]}{C.RESET}")

        # Show top anomalies
        if anomalies:
            print(f"\n  {C.DIM}Top anomalies:{C.RESET}")
            for anom in anomalies[:10]:
                print(f"    [{anom.score:.2f}] {anom.title}")
                if args.verbose:
                    print(f"           {C.DIM}{anom.recommendation[:80]}{C.RESET}")

    # ── Export ──
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or f"beanfeasa_report_{ts}.csv"

    if args.events_only:
        ok, msg = export_events(all_events, output_path)
    elif args.full_report:
        ok, msg = export_full_report(all_detections, incidents, anomalies, output_path,
                                        storage_findings=storage_findings_raw,
                                        supplemental_findings=supplemental_findings,
                                        supplemental_findings=supplemental_findings)
    else:
        ok, msg = export_detections(all_detections, output_path)

    print(f"\n  {C.GREEN if ok else C.RED}{'✓' if ok else '✗'} {msg}{C.RESET}")

    # Export incidents separately if full report
    if incidents and not args.full_report:
        inc_path = output_path.replace(".csv", "_incidents.csv")
        ok2, msg2 = export_incidents(incidents, inc_path)
        print(f"  {C.GREEN if ok2 else C.RED}{'✓' if ok2 else '✗'} {msg2}{C.RESET}")

    if anomalies and not args.full_report:
        anom_path = output_path.replace(".csv", "_anomalies.csv")
        ok3, msg3 = export_anomalies(anomalies, anom_path)
        print(f"  {C.GREEN if ok3 else C.RED}{'✓' if ok3 else '✗'} {msg3}{C.RESET}")

    print()

    # Exit code: 0 = clean, 1 = critical findings, 2 = high findings
    if any(d.severity == "critical" for d in all_detections) or \
       any(i.severity == "critical" for i in incidents):
        sys.exit(1)
    elif any(d.severity == "high" for d in all_detections) or \
         any(i.severity == "high" for i in incidents):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
