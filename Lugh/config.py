"""
Lugh v3.0 - Configuration & Shared Imports
"""
import re, os, sys, csv, unicodedata, json, string, threading
import struct, math, hashlib, subprocess, io, tempfile
import zipfile, tarfile, gzip, bz2, lzma
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from pathlib import Path

# ── Optional: CustomTkinter for modern dark UI ──
try:
    import customtkinter as ctk; USE_CTK = True
except ImportError:
    USE_CTK = False; ctk = None

# ── Optional: yara-python ──
try:
    import yara; HAS_YARA = True
except ImportError:
    HAS_YARA = False; yara = None

# ── Theme Colors ──
COLORS = {
    "BG": "#0D1117",   # Background
    "BP": "#161B22",   # Panel
    "BI": "#1C2128",   # Input fields
    "BD": "#30363D",   # Borders
    "FT": "#E6EDF3",   # Text
    "FD": "#8B949E",   # Dim text
    "AC": "#e94560",   # Accent (crimson)
    "GR": "#238636",   # Green
    "RD": "#DA3633",   # Red
    "YL": "#D29922",   # Yellow
    "OR": "#F0883E",   # Orange
    "CY": "#58A6FF",   # Cyan
}

VERSION = "3.0"
APP_TITLE = f"Lugh \u2014 Cybersecurity Toolkit v{VERSION}"
SUBTITLE = "Email \u2022 IDN \u2022 Files \u2022 Hashes \u2022 Logs \u2022 Links \u2022 Advanced"
