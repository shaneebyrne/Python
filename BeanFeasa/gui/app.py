"""
BeanFeasa — Main GUI Application.

Cross-platform tkinter GUI for log analysis with Catppuccin Mocha theme.
"""

import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox

from gui.theme import CatppuccinMocha as C, apply_theme
from utils.platform_utils import (
    get_platform, select_log_files, select_log_directory,
    select_output_file, select_rules_directory, discover_log_files,
    get_file_info, is_event_log,
)
from parsers.registry import parse_file, get_parser_name
from parsers.supplemental import resolve_hostname
from utils.device_context import detect_profile, get_suppressed_rules, DeviceProfile
from analyzers.rule_loader import load_rules, DetectionRule
from analyzers.detection_engine import DetectionEngine, Detection
from analyzers.baseline_model import BaselineModel
from analyzers.correlation_engine import CorrelationEngine, CorrelatedIncident
from analyzers.anomaly_detector import AnomalyDetector, Anomaly
from analyzers.remediation_kb import RemediationKB
from exporters.csv_exporter import (
    export_detections, export_events, export_incidents,
    export_anomalies, export_full_report,
)


# ── Resolve the bundled rules directory ──
APP_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = str(APP_DIR / "rules")


class BeanFeasa(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.title("BeanFeasa — Log Analysis Toolkit")
        self.geometry("1280x820")
        self.minsize(960, 640)

        # State
        self.log_files: list[str] = []
        self.rules: list[DetectionRule] = []
        self.detections: list[Detection] = []
        self.incidents: list[CorrelatedIncident] = []
        self.anomalies: list[Anomaly] = []
        self.all_events = []
        self.rules_dir: str = DEFAULT_RULES_DIR
        self.is_running = False
        self.remediation_kb = RemediationKB()

        # Theme
        apply_theme(self)
        self.configure(bg=C.BG_PRIMARY)

        self._build_ui()
        self._load_default_rules()
        self._log(f"Platform: {get_platform().upper()}")
        self._log(f"Rules directory: {self.rules_dir}")
        self._log("Ready. Add log files or a directory to begin.")

    # ────────────────────────────────────────────
    #  UI CONSTRUCTION
    # ────────────────────────────────────────────

    def _build_ui(self):
        """Assemble the entire GUI layout."""
        # ── Top Banner ──
        banner = ttk.Frame(self, style="Header.TFrame")
        banner.pack(fill="x", padx=0, pady=0)

        banner_inner = ttk.Frame(banner, style="Header.TFrame")
        banner_inner.pack(fill="x", padx=16, pady=10)

        ttk.Label(
            banner_inner, text="⛓  BeanFeasa",
            style="Header.TLabel",
            font=("Consolas", 18, "bold"),
        ).pack(side="left")

        ttk.Label(
            banner_inner,
            text="Log Analysis & Threat Detection",
            font=("Consolas", 10),
            foreground=C.FG_DIM,
            background=C.BG_TERTIARY,
        ).pack(side="left", padx=(12, 0))

        self.platform_label = ttk.Label(
            banner_inner,
            text=f" {get_platform().upper()} ",
            font=("Consolas", 9, "bold"),
            foreground=C.CRUST,
            background=C.MAUVE,
        )
        self.platform_label.pack(side="right")

        # ── Main content area: left panel + right panel ──
        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=12, pady=(8, 0))
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        # ── LEFT PANEL: Controls ──
        left = ttk.Frame(main, width=340)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_propagate(False)

        self._build_input_section(left)
        self._build_rules_section(left)
        self._build_actions_section(left)

        # ── RIGHT PANEL: Tabs (Results, Log, Stats) ──
        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky="nsew")

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        self._build_results_tab()
        self._build_incidents_tab()
        self._build_anomalies_tab()
        self._build_log_tab()
        self._build_stats_tab()

        # ── Bottom Status Bar ──
        self._build_status_bar()

    def _build_input_section(self, parent):
        """Input files section."""
        frame = ttk.LabelFrame(parent, text="  INPUT  ", padding=10)
        frame.pack(fill="x", padx=4, pady=(4, 6))

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x", pady=(0, 6))

        ttk.Button(btn_row, text="+ Files", command=self._add_files).pack(
            side="left", padx=(0, 4))
        ttk.Button(btn_row, text="+ Directory", command=self._add_directory).pack(
            side="left", padx=(0, 4))
        ttk.Button(btn_row, text="Clear", command=self._clear_files,
                    style="Danger.TButton").pack(side="right")

        # File list
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True)

        self.file_listbox = tk.Listbox(
            list_frame, height=8,
            bg=C.BG_WIDGET, fg=C.FG_PRIMARY,
            selectbackground=C.SURFACE1, selectforeground=C.FG_PRIMARY,
            font=("Consolas", 9), borderwidth=0, highlightthickness=0,
            activestyle="none",
        )
        list_sb = ttk.Scrollbar(list_frame, orient="vertical",
                                command=self.file_listbox.yview)
        self.file_listbox.configure(yscrollcommand=list_sb.set)
        self.file_listbox.pack(side="left", fill="both", expand=True)
        list_sb.pack(side="right", fill="y")

        self.file_count_label = ttk.Label(
            frame, text="0 files loaded", foreground=C.FG_DIM,
            font=("Consolas", 9),
        )
        self.file_count_label.pack(anchor="w", pady=(4, 0))

    def _build_rules_section(self, parent):
        """Rules configuration section."""
        frame = ttk.LabelFrame(parent, text="  RULES  ", padding=10)
        frame.pack(fill="x", padx=4, pady=(0, 6))

        self.rules_label = ttk.Label(
            frame, text=f"Loaded: 0 rules",
            foreground=C.FG_DIM, font=("Consolas", 9),
        )
        self.rules_label.pack(anchor="w", pady=(0, 6))

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="Load Custom Rules",
                    command=self._load_custom_rules).pack(side="left", padx=(0, 4))
        ttk.Button(btn_row, text="Reload Built-in",
                    command=self._load_default_rules).pack(side="left")

    def _build_actions_section(self, parent):
        """Analysis action buttons and progress."""
        frame = ttk.LabelFrame(parent, text="  ANALYZE  ", padding=10)
        frame.pack(fill="x", padx=4, pady=(0, 6))

        # Options
        self.opt_frame = ttk.Frame(frame)
        self.opt_frame.pack(fill="x", pady=(0, 8))

        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            self.opt_frame, text="Recursive directory scan",
            variable=self.recursive_var,
        ).pack(anchor="w")

        self.include_raw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self.opt_frame, text="Include raw data in export",
            variable=self.include_raw_var,
        ).pack(anchor="w")

        # Buttons
        self.analyze_btn = ttk.Button(
            frame, text="▶  Run Analysis", style="Accent.TButton",
            command=self._start_analysis,
        )
        self.analyze_btn.pack(fill="x", pady=(0, 6))

        self.export_btn = ttk.Button(
            frame, text="💾  Export Results to CSV",
            command=self._export_results,
        )
        self.export_btn.pack(fill="x", pady=(0, 4))

        self.export_events_btn = ttk.Button(
            frame, text="📋  Export All Events (no rules)",
            command=self._export_all_events,
        )
        self.export_events_btn.pack(fill="x", pady=(0, 4))

        self.export_full_btn = ttk.Button(
            frame, text="📊  Export Full Report",
            command=self._export_full_report,
        )
        self.export_full_btn.pack(fill="x")

        # Progress
        self.progress = ttk.Progressbar(
            frame, mode="determinate",
            style="Green.Horizontal.TProgressbar",
        )
        self.progress.pack(fill="x", pady=(8, 2))

        self.progress_label = ttk.Label(
            frame, text="", foreground=C.FG_DIM, font=("Consolas", 9),
        )
        self.progress_label.pack(anchor="w")

    def _build_results_tab(self):
        """Results treeview tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Results  ")

        # Severity filter bar
        filter_bar = ttk.Frame(tab)
        filter_bar.pack(fill="x", padx=4, pady=4)

        ttk.Label(filter_bar, text="Filter:", foreground=C.FG_DIM,
                   font=("Consolas", 9)).pack(side="left", padx=(0, 6))

        self.filter_var = tk.StringVar(value="All")
        for sev in ("All", "Critical", "High", "Medium", "Low", "Info"):
            ttk.Radiobutton(
                filter_bar, text=sev, variable=self.filter_var, value=sev,
                command=self._apply_filter,
            ).pack(side="left", padx=2)

        self.result_count_label = ttk.Label(
            filter_bar, text="0 detections", foreground=C.FG_DIM,
            font=("Consolas", 9, "bold"),
        )
        self.result_count_label.pack(side="right")

        # Treeview
        columns = (
            "severity", "rule_title", "timestamp", "event_id",
            "source", "computer", "message",
        )
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.results_tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse",
        )

        col_widths = {
            "severity": 80, "rule_title": 220, "timestamp": 175,
            "event_id": 70, "source": 140, "computer": 120, "message": 400,
        }
        for col in columns:
            self.results_tree.heading(col, text=col.replace("_", " ").title(),
                                      command=lambda c=col: self._sort_results(c))
            self.results_tree.column(col, width=col_widths.get(col, 120), minwidth=60)

        tree_sb_y = ttk.Scrollbar(tree_frame, orient="vertical",
                                   command=self.results_tree.yview)
        tree_sb_x = ttk.Scrollbar(tree_frame, orient="horizontal",
                                   command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=tree_sb_y.set,
                                     xscrollcommand=tree_sb_x.set)

        self.results_tree.grid(row=0, column=0, sticky="nsew")
        tree_sb_y.grid(row=0, column=1, sticky="ns")
        tree_sb_x.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # Bind double-click to show detail
        self.results_tree.bind("<Double-1>", self._show_detail)

    def _build_incidents_tab(self):
        """Correlated incidents tab — multi-event chains and root cause analysis."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Incidents  ")

        # Header bar
        header = ttk.Frame(tab)
        header.pack(fill="x", padx=4, pady=4)
        self.incident_count_label = ttk.Label(
            header, text="0 correlated incidents", foreground=C.FG_DIM,
            font=("Consolas", 9, "bold"),
        )
        self.incident_count_label.pack(side="right")
        ttk.Label(header, text="Multi-event patterns with root cause & remediation",
                   foreground=C.FG_DIM, font=("Consolas", 9)).pack(side="left")

        # Treeview
        columns = ("severity", "title", "category", "computer",
                    "first_seen", "event_count", "confidence")
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.incidents_tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse",
        )
        col_widths = {
            "severity": 80, "title": 280, "category": 90, "computer": 130,
            "first_seen": 175, "event_count": 80, "confidence": 80,
        }
        for col in columns:
            self.incidents_tree.heading(col, text=col.replace("_", " ").title())
            self.incidents_tree.column(col, width=col_widths.get(col, 100), minwidth=60)

        tree_sb = ttk.Scrollbar(tree_frame, orient="vertical",
                                 command=self.incidents_tree.yview)
        self.incidents_tree.configure(yscrollcommand=tree_sb.set)
        self.incidents_tree.grid(row=0, column=0, sticky="nsew")
        tree_sb.grid(row=0, column=1, sticky="ns")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.incidents_tree.bind("<Double-1>", self._show_incident_detail)

    def _build_anomalies_tab(self):
        """Statistical anomalies tab — data-driven findings."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Anomalies  ")

        # Header bar
        header = ttk.Frame(tab)
        header.pack(fill="x", padx=4, pady=4)
        self.anomaly_count_label = ttk.Label(
            header, text="0 anomalies", foreground=C.FG_DIM,
            font=("Consolas", 9, "bold"),
        )
        self.anomaly_count_label.pack(side="right")
        ttk.Label(header, text="Statistical outliers — no rules required",
                   foreground=C.FG_DIM, font=("Consolas", 9)).pack(side="left")

        # Treeview
        columns = ("score", "anomaly_type", "severity", "title",
                    "computer", "event_count", "first_seen")
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.anomalies_tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse",
        )
        col_widths = {
            "score": 60, "anomaly_type": 90, "severity": 80, "title": 320,
            "computer": 130, "event_count": 80, "first_seen": 175,
        }
        for col in columns:
            self.anomalies_tree.heading(col, text=col.replace("_", " ").title())
            self.anomalies_tree.column(col, width=col_widths.get(col, 100), minwidth=60)

        tree_sb = ttk.Scrollbar(tree_frame, orient="vertical",
                                 command=self.anomalies_tree.yview)
        self.anomalies_tree.configure(yscrollcommand=tree_sb.set)
        self.anomalies_tree.grid(row=0, column=0, sticky="nsew")
        tree_sb.grid(row=0, column=1, sticky="ns")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.anomalies_tree.bind("<Double-1>", self._show_anomaly_detail)

    def _build_log_tab(self):
        """Activity log tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Activity Log  ")

        self.log_text = tk.Text(
            tab, wrap="word", state="disabled",
            bg=C.BG_SECONDARY, fg=C.FG_PRIMARY,
            font=("Consolas", 9), borderwidth=0,
            insertbackground=C.FG_PRIMARY,
            selectbackground=C.SURFACE1,
            padx=10, pady=8,
        )
        log_sb = ttk.Scrollbar(tab, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_sb.pack(side="right", fill="y")

        # Color tags for the log
        self.log_text.tag_configure("info", foreground=C.SAPPHIRE)
        self.log_text.tag_configure("success", foreground=C.GREEN)
        self.log_text.tag_configure("warning", foreground=C.YELLOW)
        self.log_text.tag_configure("error", foreground=C.RED)
        self.log_text.tag_configure("dim", foreground=C.FG_DIM)
        self.log_text.tag_configure("accent", foreground=C.PEACH)

    def _build_stats_tab(self):
        """Statistics / summary tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Statistics  ")

        self.stats_text = tk.Text(
            tab, wrap="word", state="disabled",
            bg=C.BG_SECONDARY, fg=C.FG_PRIMARY,
            font=("Consolas", 10), borderwidth=0,
            insertbackground=C.FG_PRIMARY,
            padx=14, pady=10,
        )
        self.stats_text.pack(fill="both", expand=True)

        self.stats_text.tag_configure("header", foreground=C.ACCENT,
                                       font=("Consolas", 13, "bold"))
        self.stats_text.tag_configure("subheader", foreground=C.MAUVE,
                                       font=("Consolas", 11, "bold"))
        self.stats_text.tag_configure("critical", foreground=C.RED,
                                       font=("Consolas", 10, "bold"))
        self.stats_text.tag_configure("high", foreground=C.PEACH,
                                       font=("Consolas", 10, "bold"))
        self.stats_text.tag_configure("medium", foreground=C.YELLOW,
                                       font=("Consolas", 10))
        self.stats_text.tag_configure("low", foreground=C.BLUE,
                                       font=("Consolas", 10))
        self.stats_text.tag_configure("info", foreground=C.TEAL,
                                       font=("Consolas", 10))
        self.stats_text.tag_configure("value", foreground=C.FG_PRIMARY,
                                       font=("Consolas", 10, "bold"))

    def _build_status_bar(self):
        """Bottom status bar."""
        bar = ttk.Frame(self, style="Header.TFrame")
        bar.pack(fill="x", side="bottom")

        inner = ttk.Frame(bar, style="Header.TFrame")
        inner.pack(fill="x", padx=12, pady=4)

        self.status_label = ttk.Label(
            inner, text="Idle", style="Status.TLabel",
        )
        self.status_label.pack(side="left")

        self.detection_count_label = ttk.Label(
            inner, text="", style="Status.TLabel",
        )
        self.detection_count_label.pack(side="right")

    # ────────────────────────────────────────────
    #  FILE MANAGEMENT
    # ────────────────────────────────────────────

    def _add_files(self):
        """Open file picker dialog for log files."""
        files = select_log_files(self)
        if files:
            added = 0
            for f in files:
                if f not in self.log_files:
                    self.log_files.append(f)
                    info = get_file_info(f)
                    parser = get_parser_name(f)
                    self.file_listbox.insert(
                        "end",
                        f"  [{parser.upper():4s}] {info['name']}  ({info['size_human']})"
                    )
                    added += 1
            self._update_file_count()
            self._log(f"Added {added} file(s).", "success")

    def _add_directory(self):
        """Open directory picker dialog."""
        directory = select_log_directory(self)
        if directory:
            self._log(f"Scanning: {directory}...")
            files = discover_log_files(directory, recursive=self.recursive_var.get())
            added = 0
            for f in files:
                if f not in self.log_files:
                    self.log_files.append(f)
                    info = get_file_info(f)
                    parser = get_parser_name(f)
                    self.file_listbox.insert(
                        "end",
                        f"  [{parser.upper():4s}] {info['name']}  ({info['size_human']})"
                    )
                    added += 1
            self._update_file_count()
            self._log(f"Found {added} supported file(s) in {directory}.", "success")

    def _clear_files(self):
        """Clear the file list."""
        self.log_files.clear()
        self.file_listbox.delete(0, "end")
        self._update_file_count()
        self._log("File list cleared.", "dim")

    def _update_file_count(self):
        count = len(self.log_files)
        self.file_count_label.configure(text=f"{count} file(s) loaded")

    # ────────────────────────────────────────────
    #  RULES MANAGEMENT
    # ────────────────────────────────────────────

    def _load_default_rules(self):
        """Load built-in rules from the rules/ directory."""
        self._load_rules_from(DEFAULT_RULES_DIR, "built-in")

    def _load_custom_rules(self):
        """Open directory picker for custom rules."""
        directory = select_rules_directory(self)
        if directory:
            self._load_rules_from(directory, "custom")

    def _load_rules_from(self, directory: str, label: str):
        """Load rules from a given directory."""
        rules, errors = load_rules(directory)
        if errors:
            for err in errors:
                self._log(f"Rule load error: {err}", "warning")

        self.rules = rules
        self.rules_dir = directory
        self.rules_label.configure(
            text=f"Loaded: {len(rules)} {label} rules",
            foreground=C.GREEN if rules else C.WARNING,
        )
        self._log(f"Loaded {len(rules)} {label} detection rule(s).", "info")

    # ────────────────────────────────────────────
    #  ANALYSIS
    # ────────────────────────────────────────────

    def _start_analysis(self):
        """Launch the analysis in a background thread."""
        if self.is_running:
            return
        if not self.log_files:
            messagebox.showwarning("No Input", "Add log files or a directory first.")
            return
        if not self.rules:
            messagebox.showwarning("No Rules", "Load detection rules before analysis.")
            return

        self.is_running = True
        self.analyze_btn.configure(state="disabled")
        self.detections.clear()
        self.incidents.clear()
        self.anomalies.clear()
        self.all_events.clear()
        self._clear_results_tree()
        self._clear_tree(self.incidents_tree)
        self._clear_tree(self.anomalies_tree)

        thread = threading.Thread(target=self._run_analysis, daemon=True)
        thread.start()

    def _run_analysis(self):
        """Worker thread: parse all files, run detection, correlation, and anomaly detection."""
        total_files = len(self.log_files)
        all_detections = []
        all_events = []          # Events from event log files ONLY
        context_events = []      # Events from all files (for hostname etc.)

        start_time = time.time()
        self._update_status("Parsing files...")

        # ── Phase 0: Resolve hostname + device context ──
        resolved_hostname = ""
        device_profile = DeviceProfile()
        seen_dirs = set()
        for f in self.log_files:
            parent = str(Path(f).parent)
            if parent not in seen_dirs:
                seen_dirs.add(parent)
                h = resolve_hostname(parent)
                if h and not resolved_hostname:
                    resolved_hostname = h
                # Detect device profile
                dp = detect_profile(parent)
                if dp.hostname:
                    device_profile = dp

        if resolved_hostname:
            self._log(f"Resolved hostname: {resolved_hostname}", "info")
        if device_profile.hostname:
            self._log(f"Device profile: {device_profile.summary()}", "info")

        # Filter rules based on device context
        suppressed_ids = get_suppressed_rules(device_profile)
        active_rules = [r for r in self.rules if r.id not in suppressed_ids]
        if suppressed_ids:
            self._log(f"Suppressed {len(self.rules) - len(active_rules)} rules for device context.", "dim")

        correlator = CorrelationEngine()
        anomaly_detector = AnomalyDetector()
        _file_events: dict[str, list] = {}   # for detection pass

        # ── Phase 1a: Parse all files ──
        for file_idx, filepath in enumerate(self.log_files):
            fname = Path(filepath).name
            self._log(f"[{file_idx + 1}/{total_files}] Parsing: {fname}...")
            self._update_progress(file_idx, total_files + 3,
                                   f"File {file_idx + 1}/{total_files}: {fname}")

            events, parse_errors = parse_file(filepath)
            for err in parse_errors:
                self._log(f"  ⚠ {err}", "warning")

            if not events:
                self._log(f"  No events parsed from {fname}.", "dim")
                continue

            self._log(f"  Parsed {len(events)} events.", "dim")

            if not is_event_log(filepath):
                self._log(f"  ⊘ Skipping analysis (inventory/config file).", "dim")
                context_events.extend(events)
                continue

            all_events.extend(events)
            _file_events[filepath] = events

        inventory_count = len(context_events)
        if inventory_count:
            self._log(f"Excluded {inventory_count} inventory/config events from analysis.", "dim")

        # ── Phase 1b: Build baseline model ──
        self._update_status("Building baseline model...")
        self._update_progress(total_files, total_files + 3, "Building baseline frequency model...")
        self._log("Building baseline frequency model...", "info")
        _baseline = BaselineModel()
        _baseline.build(all_events)
        bstats = _baseline.get_stats()
        self._log(
            f"  Baseline: {bstats['baseline_pairs']} routine patterns, "            f"{bstats['signal_pairs']} signal patterns.", "dim"
        )

        # ── Phase 1c: Run detection with baseline-aware engine ──
        self._update_status("Detecting...")
        self._update_progress(total_files + 1, total_files + 3, "Rule-based detection...")
        engine = DetectionEngine(active_rules, baseline=_baseline)

        for file_idx, (filepath, events) in enumerate(_file_events.items()):
            fname = Path(filepath).name

            def progress_cb(current, total_ev, _fi=file_idx, _fn=fname):
                self._update_progress(
                    _fi * 1000 + int(current / max(total_ev, 1) * 1000),
                    (total_files + 3) * 1000,
                    f"Detecting {_fn}: {current}/{total_ev}",
                )

            file_detections = engine.analyze(events, filepath, callback=progress_cb)
            all_detections.extend(file_detections)

            if file_detections:
                self._log(f"  🔍 {len(file_detections)} detection(s) in {fname}", "accent")

        # ── Hostname backfill ──
        if resolved_hostname:
            backfilled = 0
            for evt in all_events:
                if not evt.computer or evt.computer == "unknown":
                    evt.computer = resolved_hostname
                    backfilled += 1
            if backfilled:
                self._log(f"Backfilled hostname '{resolved_hostname}' on {backfilled} events.", "dim")

        # ── Phase 2: Correlation engine ──
        self._update_status("Correlating incidents...")
        self._update_progress(total_files, total_files + 2, "Correlating multi-event incidents...")
        self._log("Running correlation engine...", "info")

        incidents = correlator.correlate(all_events)
        if incidents:
            self._log(f"  🔗 {len(incidents)} correlated incident(s) found.", "accent")
        else:
            self._log("  No correlated incidents found.", "dim")

        # ── Phase 3: Anomaly detection ──
        self._update_status("Detecting anomalies...")
        self._update_progress(total_files + 1, total_files + 2, "Statistical anomaly detection...")
        self._log("Running anomaly detector...", "info")

        anomalies = anomaly_detector.analyze(all_events)
        if anomalies:
            self._log(f"  📈 {len(anomalies)} statistical anomalie(s) found.", "accent")
        else:
            self._log("  No statistical anomalies found.", "dim")

        elapsed = time.time() - start_time

        # Store results
        self.detections = all_detections
        self.incidents = incidents
        self.anomalies = anomalies
        self.all_events = all_events

        # Build combined summary
        summary = engine.get_summary()
        summary["correlation"] = correlator.get_summary()
        summary["anomalies"] = anomaly_detector.get_summary()

        # Update UI on main thread
        self.after(0, self._analysis_complete, summary, elapsed)

    def _analysis_complete(self, summary: dict, elapsed: float):
        """Called on main thread when analysis finishes."""
        self.is_running = False
        self.analyze_btn.configure(state="normal")
        self._update_progress(100, 100, "Complete")

        # Populate all result tabs
        self._populate_results()
        self._populate_incidents()
        self._populate_anomalies()
        self._populate_stats(summary, elapsed)

        det = summary["total_detections"]
        inc = summary["correlation"]["total_incidents"]
        anom = summary["anomalies"]["total_anomalies"]
        self._log(
            f"Analysis complete: {det} detections, {inc} incidents, "
            f"{anom} anomalies across {summary['events_scanned']} events "
            f"in {elapsed:.2f}s.",
            "success",
        )
        self._update_status(f"Done — {det} detections, {inc} incidents, {anom} anomalies")
        self.detection_count_label.configure(
            text=f"Events: {summary['events_scanned']}  |  Det: {det}  |  Inc: {inc}  |  Anom: {anom}"
        )
        self.notebook.select(0)  # Switch to Results tab

    # ────────────────────────────────────────────
    #  RESULTS DISPLAY
    # ────────────────────────────────────────────

    def _populate_results(self):
        """Fill the results treeview with detection data."""
        self._clear_results_tree()
        for det in self.detections:
            self.results_tree.insert("", "end", values=(
                det.severity.upper(),
                det.rule_title,
                det.timestamp,
                det.event_id,
                det.source,
                det.computer,
                det.message[:200],
            ), tags=(det.severity,))

        # Color rows by severity
        for sev, color in C.SEVERITY.items():
            self.results_tree.tag_configure(sev, foreground=color)

        self.result_count_label.configure(text=f"{len(self.detections)} detections")

    def _clear_results_tree(self):
        """Remove all items from the results treeview."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

    def _clear_tree(self, tree):
        """Remove all items from any treeview."""
        for item in tree.get_children():
            tree.delete(item)

    # ── Incidents display ──

    def _populate_incidents(self):
        """Fill the incidents treeview."""
        self._clear_tree(self.incidents_tree)
        for inc in self.incidents:
            self.incidents_tree.insert("", "end", values=(
                inc.severity.upper(),
                inc.title,
                inc.category,
                inc.computer,
                inc.first_seen,
                inc.event_count,
                inc.confidence,
            ), tags=(inc.severity,))

        for sev, color in C.SEVERITY.items():
            self.incidents_tree.tag_configure(sev, foreground=color)
        self.incident_count_label.configure(text=f"{len(self.incidents)} correlated incidents")

    def _show_incident_detail(self, event):
        """Show full incident detail with root cause and remediation."""
        sel = self.incidents_tree.selection()
        if not sel:
            return
        idx = self.incidents_tree.index(sel[0])
        if idx >= len(self.incidents):
            return

        inc = self.incidents[idx]
        win = tk.Toplevel(self)
        win.title(f"Incident — {inc.title}")
        win.geometry("780x600")
        win.configure(bg=C.BG_PRIMARY)

        text = tk.Text(win, wrap="word", bg=C.BG_SECONDARY, fg=C.FG_PRIMARY,
                       font=("Consolas", 10), borderwidth=0, padx=14, pady=10)
        text.pack(fill="both", expand=True, padx=8, pady=8)

        text.tag_configure("label", foreground=C.ACCENT, font=("Consolas", 10, "bold"))
        text.tag_configure("section", foreground=C.MAUVE, font=("Consolas", 11, "bold"))
        sev_color = C.SEVERITY.get(inc.severity, C.FG_PRIMARY)
        text.tag_configure("severity", foreground=sev_color, font=("Consolas", 10, "bold"))
        text.tag_configure("step", foreground=C.GREEN, font=("Consolas", 10))

        text.insert("end", f"{inc.title}\n", "section")
        text.insert("end", f"{'═' * 60}\n\n")

        text.insert("end", "Severity: ", "label")
        text.insert("end", f"{inc.severity.upper()}\n", "severity")
        text.insert("end", "Category: ", "label")
        text.insert("end", f"{inc.category}\n")
        text.insert("end", "Computer: ", "label")
        text.insert("end", f"{inc.computer}\n")
        text.insert("end", "Time Range: ", "label")
        text.insert("end", f"{inc.first_seen} → {inc.last_seen}\n")
        text.insert("end", "Events: ", "label")
        text.insert("end", f"{inc.event_count}  (Confidence: {inc.confidence})\n")
        text.insert("end", "Incident ID: ", "label")
        text.insert("end", f"{inc.incident_id}\n")

        text.insert("end", "\nDescription\n", "section")
        text.insert("end", f"{inc.description}\n")

        text.insert("end", "\nRoot Cause\n", "section")
        text.insert("end", f"{inc.root_cause}\n")

        if inc.remediation:
            text.insert("end", "\nRemediation Steps\n", "section")
            for i, step in enumerate(inc.remediation, 1):
                text.insert("end", f"  {i}. ", "step")
                text.insert("end", f"{step}\n")

        # KB lookup for related events
        if inc.events:
            text.insert("end", "\nRelated Events\n", "section")
            for evt in inc.events[:10]:
                text.insert("end", f"  [{evt.event_id:>5s}] ", "label")
                text.insert("end", f"{evt.source} — {(evt.message or '')[:100]}\n")

                # KB enrichment
                kb_results = self.remediation_kb.lookup_event(evt)
                if kb_results:
                    kb = kb_results[0]
                    text.insert("end", f"         KB: {kb.title}\n", "step")

        text.configure(state="disabled")

    # ── Anomalies display ──

    def _populate_anomalies(self):
        """Fill the anomalies treeview."""
        self._clear_tree(self.anomalies_tree)
        for anom in self.anomalies:
            self.anomalies_tree.insert("", "end", values=(
                f"{anom.score:.2f}",
                anom.anomaly_type,
                anom.severity.upper(),
                anom.title,
                anom.computer,
                anom.event_count,
                anom.first_seen,
            ), tags=(anom.severity,))

        for sev, color in C.SEVERITY.items():
            self.anomalies_tree.tag_configure(sev, foreground=color)
        self.anomaly_count_label.configure(text=f"{len(self.anomalies)} anomalies")

    def _show_anomaly_detail(self, event):
        """Show anomaly detail popup."""
        sel = self.anomalies_tree.selection()
        if not sel:
            return
        idx = self.anomalies_tree.index(sel[0])
        if idx >= len(self.anomalies):
            return

        anom = self.anomalies[idx]
        win = tk.Toplevel(self)
        win.title(f"Anomaly — {anom.title}")
        win.geometry("720x440")
        win.configure(bg=C.BG_PRIMARY)

        text = tk.Text(win, wrap="word", bg=C.BG_SECONDARY, fg=C.FG_PRIMARY,
                       font=("Consolas", 10), borderwidth=0, padx=14, pady=10)
        text.pack(fill="both", expand=True, padx=8, pady=8)

        text.tag_configure("label", foreground=C.ACCENT, font=("Consolas", 10, "bold"))
        text.tag_configure("section", foreground=C.MAUVE, font=("Consolas", 11, "bold"))
        text.tag_configure("rec", foreground=C.GREEN, font=("Consolas", 10))
        sev_color = C.SEVERITY.get(anom.severity, C.FG_PRIMARY)
        text.tag_configure("severity", foreground=sev_color, font=("Consolas", 10, "bold"))

        text.insert("end", f"{anom.title}\n", "section")
        text.insert("end", f"{'═' * 60}\n\n")

        for lbl, val in [
            ("Type", anom.anomaly_type),
            ("Severity", anom.severity.upper()),
            ("Score", f"{anom.score:.2f}"),
            ("Computer", anom.computer),
            ("Time", f"{anom.first_seen} → {anom.last_seen}"),
            ("Event Count", str(anom.event_count)),
            ("ID", anom.anomaly_id),
        ]:
            tag = "severity" if lbl == "Severity" else None
            text.insert("end", f"{lbl}: ", "label")
            text.insert("end", f"{val}\n", tag)

        text.insert("end", "\nDescription\n", "section")
        text.insert("end", f"{anom.description}\n")

        text.insert("end", "\nEvidence\n", "section")
        text.insert("end", f"{anom.evidence}\n")

        text.insert("end", "\nRecommendation\n", "section")
        text.insert("end", f"{anom.recommendation}\n", "rec")

        text.configure(state="disabled")

    def _apply_filter(self):
        """Filter results by severity."""
        filt = self.filter_var.get().lower()
        self._clear_results_tree()

        for det in self.detections:
            if filt == "all" or det.severity == filt or \
               (filt == "info" and det.severity == "informational"):
                self.results_tree.insert("", "end", values=(
                    det.severity.upper(),
                    det.rule_title,
                    det.timestamp,
                    det.event_id,
                    det.source,
                    det.computer,
                    det.message[:200],
                ), tags=(det.severity,))

        for sev, color in C.SEVERITY.items():
            self.results_tree.tag_configure(sev, foreground=color)

        visible = len(self.results_tree.get_children())
        self.result_count_label.configure(text=f"{visible} detections (filtered)")

    def _sort_results(self, column):
        """Sort the results tree by a column."""
        data = []
        for child in self.results_tree.get_children():
            data.append((self.results_tree.set(child, column), child))
        data.sort(key=lambda t: t[0])

        for idx, (_, child) in enumerate(data):
            self.results_tree.move(child, "", idx)

    def _show_detail(self, event):
        """Show full detail of a detection in a popup."""
        selection = self.results_tree.selection()
        if not selection:
            return

        item = selection[0]
        idx = self.results_tree.index(item)
        if idx >= len(self.detections):
            return

        det = self.detections[idx]
        detail_win = tk.Toplevel(self)
        detail_win.title(f"Detection Detail — {det.rule_title}")
        detail_win.geometry("720x520")
        detail_win.configure(bg=C.BG_PRIMARY)

        text = tk.Text(
            detail_win, wrap="word",
            bg=C.BG_SECONDARY, fg=C.FG_PRIMARY,
            font=("Consolas", 10), borderwidth=0,
            padx=14, pady=10,
        )
        text.pack(fill="both", expand=True, padx=8, pady=8)

        text.tag_configure("label", foreground=C.ACCENT, font=("Consolas", 10, "bold"))
        text.tag_configure("value", foreground=C.FG_PRIMARY)
        sev_color = C.SEVERITY.get(det.severity, C.FG_PRIMARY)
        text.tag_configure("severity", foreground=sev_color, font=("Consolas", 10, "bold"))

        fields = [
            ("Rule", det.rule_title),
            ("Rule ID", det.rule_id),
            ("Severity", det.severity.upper()),
            ("Timestamp", det.timestamp),
            ("Event ID", det.event_id),
            ("Source", det.source),
            ("Computer", det.computer),
            ("Channel", det.channel),
            ("Level", det.level),
            ("Tags", det.tags),
            ("Matched Fields", det.matched_fields),
            ("Source File", det.source_file),
            ("Message", det.message),
        ]

        for label, value in fields:
            tag = "severity" if label == "Severity" else "value"
            text.insert("end", f"{label}: ", "label")
            text.insert("end", f"{value}\n", tag)

        if det.raw_data:
            text.insert("end", "\n─── Raw Data ───\n", "label")
            text.insert("end", det.raw_data, "value")

        # KB enrichment — lookup remediation advice
        text.tag_configure("section", foreground=C.MAUVE, font=("Consolas", 11, "bold"))
        text.tag_configure("step", foreground=C.GREEN, font=("Consolas", 10))
        text.tag_configure("cause", foreground=C.YELLOW, font=("Consolas", 10))

        kb_results = self.remediation_kb.lookup(
            event_id=det.event_id, source=det.source, message=det.message,
        )
        if kb_results:
            kb = kb_results[0]
            text.insert("end", "\n\n─── Remediation Knowledge Base ───\n", "section")
            text.insert("end", f"\n{kb.title}\n", "label")
            if kb.what_it_means:
                text.insert("end", f"\nWhat it means:\n", "label")
                text.insert("end", f"  {kb.what_it_means}\n")
            if kb.likely_cause:
                text.insert("end", f"\nLikely causes:\n", "label")
                for cause in kb.likely_cause:
                    text.insert("end", f"  • {cause}\n", "cause")
            if kb.remediation:
                text.insert("end", f"\nRemediation steps:\n", "label")
                for i, step in enumerate(kb.remediation, 1):
                    text.insert("end", f"  {i}. ", "step")
                    text.insert("end", f"{step}\n")

        text.configure(state="disabled")

    def _populate_stats(self, summary: dict, elapsed: float):
        """Fill the statistics tab with all analysis results."""
        w = self.stats_text
        w.configure(state="normal")
        w.delete("1.0", "end")

        corr = summary.get("correlation", {})
        anom = summary.get("anomalies", {})

        w.insert("end", "ANALYSIS SUMMARY\n", "header")
        w.insert("end", "═" * 60 + "\n\n")

        w.insert("end", "Overview\n", "subheader")
        w.insert("end", f"  Events scanned:      ", "value")
        w.insert("end", f"{summary['events_scanned']:,}\n")
        w.insert("end", f"  Rule detections:     ", "value")
        w.insert("end", f"{summary['total_detections']:,}\n")
        w.insert("end", f"  Correlated incidents:", "value")
        w.insert("end", f" {corr.get('total_incidents', 0):,}\n")
        w.insert("end", f"  Statistical anomalies:", "value")
        w.insert("end", f"{anom.get('total_anomalies', 0):,}\n")
        w.insert("end", f"  Rules loaded:        ", "value")
        w.insert("end", f"{summary['rules_loaded']:,}\n")
        w.insert("end", f"  Event chains:        ", "value")
        w.insert("end", f"{corr.get('chains_evaluated', 0):,}\n")
        w.insert("end", f"  Files analyzed:      ", "value")
        w.insert("end", f"{len(self.log_files):,}\n")
        w.insert("end", f"  Elapsed time:        ", "value")
        w.insert("end", f"{elapsed:.2f}s\n")

        if summary["events_scanned"] > 0:
            rate = summary["events_scanned"] / max(elapsed, 0.001)
            w.insert("end", f"  Throughput:          ", "value")
            w.insert("end", f"{rate:,.0f} events/sec\n")

        # Rule detections by severity
        w.insert("end", "\nRule Detections by Severity\n", "subheader")
        for sev in ("critical", "high", "medium", "low", "informational"):
            count = summary["by_severity"].get(sev, 0)
            if count > 0:
                tag = sev if sev in ("critical", "high", "medium", "low") else "info"
                w.insert("end", f"  {sev.upper():15s} ", tag)
                w.insert("end", f"{count:,}\n", "value")
        if not summary["by_severity"]:
            w.insert("end", "  (none)\n", "info")

        # Top rules
        w.insert("end", "\nTop Rule Detections\n", "subheader")
        sorted_rules = sorted(summary["by_rule"].items(), key=lambda x: -x[1])
        for rule_name, count in sorted_rules[:15]:
            w.insert("end", f"  {count:>5,}  ", "value")
            w.insert("end", f"{rule_name}\n")
        if not sorted_rules:
            w.insert("end", "  (none)\n", "info")

        # Correlated incidents
        if corr.get("total_incidents", 0) > 0:
            w.insert("end", "\nCorrelated Incidents\n", "subheader")
            for sev in ("critical", "high", "medium", "low"):
                count = corr.get("by_severity", {}).get(sev, 0)
                if count > 0:
                    tag = sev if sev in ("critical", "high", "medium", "low") else "info"
                    w.insert("end", f"  {sev.upper():15s} ", tag)
                    w.insert("end", f"{count:,}\n", "value")

            w.insert("end", "\n  By Category:\n")
            for cat, count in sorted(corr.get("by_category", {}).items(), key=lambda x: -x[1]):
                w.insert("end", f"    {cat:15s} {count:,}\n")

        # Anomalies
        if anom.get("total_anomalies", 0) > 0:
            w.insert("end", "\nStatistical Anomalies\n", "subheader")
            for atype, count in sorted(anom.get("by_type", {}).items(), key=lambda x: -x[1]):
                w.insert("end", f"  {atype:15s} ", "info")
                w.insert("end", f"{count:,}\n", "value")

        w.configure(state="disabled")

    # ────────────────────────────────────────────
    #  EXPORT
    # ────────────────────────────────────────────

    def _export_results(self):
        """Export detection results to CSV via native save dialog."""
        if not self.detections:
            messagebox.showinfo("No Results", "Run an analysis first.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = select_output_file(self, f"beanfeasa_detections_{ts}.csv")
        if not output_path:
            return

        if not self.include_raw_var.get():
            for det in self.detections:
                det.raw_data = ""

        success, msg = export_detections(self.detections, output_path)
        if success:
            self._log(f"✓ {msg}", "success")
            messagebox.showinfo("Export Complete", msg)
        else:
            self._log(f"✗ {msg}", "error")
            messagebox.showerror("Export Failed", msg)

    def _export_all_events(self):
        """Export all parsed events (no rule matching) to CSV."""
        if not self.all_events:
            messagebox.showinfo("No Events", "Run an analysis first to parse events.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = select_output_file(self, f"beanfeasa_events_{ts}.csv")
        if not output_path:
            return

        success, msg = export_events(self.all_events, output_path)
        if success:
            self._log(f"✓ {msg}", "success")
            messagebox.showinfo("Export Complete", msg)
        else:
            self._log(f"✗ {msg}", "error")
            messagebox.showerror("Export Failed", msg)

    def _export_full_report(self):
        """Export combined report — incidents, anomalies, and detections."""
        if not self.detections and not self.incidents and not self.anomalies:
            messagebox.showinfo("No Data", "Run an analysis first.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = select_output_file(self, f"beanfeasa_full_report_{ts}.csv")
        if not output_path:
            return

        success, msg = export_full_report(
            self.detections, self.incidents, self.anomalies, output_path,
        )
        if success:
            self._log(f"✓ {msg}", "success")
            messagebox.showinfo("Export Complete", msg)
        else:
            self._log(f"✗ {msg}", "error")
            messagebox.showerror("Export Failed", msg)

    # ────────────────────────────────────────────
    #  LOGGING / STATUS HELPERS
    # ────────────────────────────────────────────

    def _log(self, message: str, tag: str = ""):
        """Append a message to the activity log (thread-safe)."""
        def _write():
            self.log_text.configure(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert("end", f"[{ts}] ", "dim")
            self.log_text.insert("end", f"{message}\n", tag)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        if threading.current_thread() is threading.main_thread():
            _write()
        else:
            self.after(0, _write)

    def _update_status(self, text: str):
        """Update the status bar text (thread-safe)."""
        def _write():
            self.status_label.configure(text=text)
        if threading.current_thread() is threading.main_thread():
            _write()
        else:
            self.after(0, _write)

    def _update_progress(self, current: int, total: int, text: str = ""):
        """Update the progress bar and label (thread-safe)."""
        def _write():
            pct = (current / max(total, 1)) * 100
            self.progress["value"] = pct
            if text:
                self.progress_label.configure(text=text)
        if threading.current_thread() is threading.main_thread():
            _write()
        else:
            self.after(0, _write)
