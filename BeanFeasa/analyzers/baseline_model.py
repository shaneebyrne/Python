"""
BeanFeasa — Baseline Model.

Scans the full event dataset before any rule matching and builds a
frequency profile of what is *normal* for this specific machine and
log collection. The detection engine consults this model to suppress
or downgrade findings that represent routine, high-volume, evenly-
distributed activity rather than genuine anomalies.

─────────────────────────────────────────────────────────────────
WHY THIS EXISTS
─────────────────────────────────────────────────────────────────
Without a baseline, every occurrence of a broad keyword rule fires
regardless of whether it represents something unusual. If Event 7034
(service crash) fires 300 times uniformly spread across 30 days on a
machine, it is that machine's normal — not an incident. If it fires
6 times in 10 minutes after a GPO change, that IS an incident.

The baseline model distinguishes these cases by:
  1. Counting occurrences of each (source, event_id) pair.
  2. Computing hourly distribution and its coefficient of variation (CV).
  3. Classifying each pair as BASELINE (high-volume, low-CV) or SIGNAL.

─────────────────────────────────────────────────────────────────
SUPPRESSION LOGIC (used by detection engine)
─────────────────────────────────────────────────────────────────
A detection is suppressed / downgraded when ALL of the following hold:
  a) The triggering event's (source, event_id) is classified BASELINE.
  b) The firing rule is "weak" (single-field evidence — message-only).
  c) The event is not part of a burst (detected separately by anomaly
     detector) — bursts of baseline events ARE worth reporting.

Strong rules (multi-field compound evidence) are NEVER suppressed by
baseline, because they express a specific condition, not just a keyword.

─────────────────────────────────────────────────────────────────
PARAMETERS
─────────────────────────────────────────────────────────────────
baseline_min_count : int
    Minimum occurrences for a (source, event_id) pair to be considered
    for baseline classification (default 20). Below this, there is
    insufficient data to determine normality.

baseline_max_cv : float
    Maximum coefficient of variation (std / mean) of the hourly event
    distribution for a pair to be classified as BASELINE (default 1.5).
    CV < 1.5 means the events are spread fairly evenly over time.
    A value of 0 would mean perfectly uniform; 1.5 allows for moderate
    fluctuation while still distinguishing from spiky/bursty patterns.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from datetime import datetime
from parsers.base import ParsedEvent


class BaselineModel:
    """Pre-analysis event frequency profiler."""

    def __init__(
        self,
        baseline_min_count: int = 20,
        baseline_max_cv: float = 1.5,
    ):
        self.baseline_min_count = baseline_min_count
        self.baseline_max_cv = baseline_max_cv

        # (source_lower, event_id) → total count
        self._counts: dict[tuple[str, str], int] = defaultdict(int)

        # (source_lower, event_id) → list of hour buckets (int)
        self._hourly: dict[tuple[str, str], list[int]] = defaultdict(list)

        # Pre-computed classification: key → True if BASELINE
        self._baseline_cache: dict[tuple[str, str], bool] = {}

        self._built = False

    # ── Public API ────────────────────────────────────────────

    def build(self, events: list[ParsedEvent]) -> None:
        """
        Scan events and compute the baseline profile.
        Call this once before any rule matching begins.
        """
        self._counts.clear()
        self._hourly.clear()
        self._baseline_cache.clear()
        self._built = False

        for evt in events:
            key = (
                (evt.source or "").lower().strip(),
                str(evt.event_id or "").strip(),
            )
            self._counts[key] += 1

            ts = self._parse_hour(evt.timestamp)
            if ts is not None:
                self._hourly[key].append(ts)

        # Compute baseline classification for all keys
        for key, count in self._counts.items():
            self._baseline_cache[key] = self._is_baseline(key, count)

        self._built = True

    def is_baseline_event(self, source: str, event_id: str) -> bool:
        """
        Return True if this (source, event_id) pair is classified as
        baseline activity for this dataset.
        """
        if not self._built:
            return False
        key = (source.lower().strip(), str(event_id).strip())
        return self._baseline_cache.get(key, False)

    def get_event_count(self, source: str, event_id: str) -> int:
        """Return total occurrence count for a (source, event_id) pair."""
        key = (source.lower().strip(), str(event_id).strip())
        return self._counts.get(key, 0)

    def get_stats(self) -> dict:
        """Return a summary of the baseline model for logging."""
        if not self._built:
            return {"status": "not built"}
        total_pairs = len(self._counts)
        baseline_pairs = sum(1 for v in self._baseline_cache.values() if v)
        return {
            "status": "built",
            "unique_source_event_pairs": total_pairs,
            "baseline_pairs": baseline_pairs,
            "signal_pairs": total_pairs - baseline_pairs,
            "baseline_min_count": self.baseline_min_count,
            "baseline_max_cv": self.baseline_max_cv,
        }

    # ── Internal ──────────────────────────────────────────────

    def _is_baseline(self, key: tuple[str, str], count: int) -> bool:
        """
        Classify a (source, event_id) pair as BASELINE or SIGNAL.

        Conditions for BASELINE:
          1. count >= baseline_min_count (enough data to judge)
          2. CV of hourly distribution <= baseline_max_cv (evenly spread)
        """
        if count < self.baseline_min_count:
            return False

        hours = self._hourly.get(key, [])
        if len(hours) < 2:
            # All events in a single hour — could be a burst, not baseline
            return False

        # Build hourly bucket counts
        bucket_counts: dict[int, int] = defaultdict(int)
        for h in hours:
            bucket_counts[h] += 1

        counts_per_hour = list(bucket_counts.values())
        if len(counts_per_hour) < 2:
            return False

        mean = statistics.mean(counts_per_hour)
        if mean == 0:
            return False

        try:
            stdev = statistics.stdev(counts_per_hour)
        except statistics.StatisticsError:
            return False

        cv = stdev / mean
        return cv <= self.baseline_max_cv

    @staticmethod
    def _parse_hour(ts_str: str) -> int | None:
        """
        Parse a timestamp and return an integer hour bucket
        (days_since_epoch * 24 + hour_of_day) for distribution analysis.
        """
        if not ts_str:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M %p",
        ):
            try:
                dt = datetime.strptime(ts_str[:26], fmt)
                # Convert to a monotonic hour bucket
                epoch = datetime(1970, 1, 1)
                delta = dt - epoch
                return int(delta.total_seconds() // 3600)
            except (ValueError, OSError):
                continue
        return None
