"""
BeanFeasa — Anomaly Detector.

Statistical analysis of event patterns to surface anomalies WITHOUT
predefined rules. This catches what rules can't — things you haven't
seen before.

Detection methods:
  1. Frequency spike — Event ID count deviates from baseline
  2. New source — A provider/source appears that hasn't been seen before
  3. Burst detection — Concentrated cluster of errors in a short window
  4. Severity escalation — Shift from info/warning to error/critical
  5. Rare event — Event ID seen fewer than N times globally
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math
from parsers.base import ParsedEvent


@dataclass
class Anomaly:
    """A detected statistical anomaly."""
    anomaly_id: str
    anomaly_type: str           # spike, new_source, burst, escalation, rare
    title: str
    severity: str
    description: str
    evidence: str               # What triggered the detection
    computer: str = ""
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    score: float = 0.0          # 0.0–1.0 confidence score
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "computer": self.computer,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "score": f"{self.score:.2f}",
            "recommendation": self.recommendation,
        }

    @staticmethod
    def csv_headers() -> list[str]:
        return [
            "anomaly_id", "anomaly_type", "title", "severity",
            "description", "evidence", "computer", "first_seen",
            "last_seen", "event_count", "score", "recommendation",
        ]


class AnomalyDetector:
    """
    Statistical anomaly detector for parsed log events.

    Operates without rules — purely data-driven detection.
    """

    def __init__(
        self,
        burst_window_minutes: int = 5,
        burst_threshold: int = 10,
        rare_threshold: int = 3,
        spike_stddev_multiplier: float = 2.5,
    ):
        self.burst_window_minutes = burst_window_minutes
        self.burst_threshold = burst_threshold
        self.rare_threshold = rare_threshold
        self.spike_stddev = spike_stddev_multiplier
        self._anomaly_counter = 0
        self.anomalies: list[Anomaly] = []

    def analyze(
        self,
        events: list[ParsedEvent],
        callback=None,
    ) -> list[Anomaly]:
        """
        Run all anomaly detectors on a set of events.

        Returns a list of Anomaly findings.
        """
        self.anomalies = []
        if not events:
            return []

        total_steps = 9
        step = 0

        # 1. Error/warning burst detection
        self._detect_bursts(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 2. Frequency spike detection (per Event ID per machine)
        self._detect_frequency_spikes(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 3. Rare event detection
        self._detect_rare_events(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 4. Severity escalation detection
        self._detect_severity_escalation(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 5. New / unusual source detection
        self._detect_unusual_sources(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 6. Chronic application crash detection (MISS-02/03)
        self._detect_chronic_crashes(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 7. Service install + fail loop detection (MISS-04)
        self._detect_service_install_loops(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 8. MSI installer failure loop detection (MISS-05)
        self._detect_msi_failure_loops(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # 9. Periodic crash pattern detection (post USVIS-952KC14)
        self._detect_crash_periodicity(events)
        step += 1
        if callback:
            callback(step, total_steps)

        # Sort by score descending
        self.anomalies.sort(key=lambda a: -a.score)

        return self.anomalies

    # ────────────────────────────────────────────
    #  BURST DETECTION
    # ────────────────────────────────────────────

    def _detect_bursts(self, events: list[ParsedEvent]):
        """
        Detect concentrated clusters of error/warning events in
        short time windows. A burst of 10+ errors in 5 minutes
        is almost always worth investigating.
        """
        # Filter to errors and warnings only
        error_levels = {"error", "critical", "warning", "2", "3", "1"}
        error_events = [
            e for e in events
            if (e.level or "").lower() in error_levels
        ]

        if len(error_events) < self.burst_threshold:
            return

        # Group by computer
        by_computer = defaultdict(list)
        for evt in error_events:
            by_computer[evt.computer or "unknown"].append(evt)

        for computer, comp_events in by_computer.items():
            # Sort by time and use sliding window
            timed = []
            for evt in comp_events:
                ts = self._parse_ts(evt.timestamp)
                if ts:
                    timed.append((ts, evt))
            timed.sort(key=lambda x: x[0])

            if len(timed) < self.burst_threshold:
                continue

            # Sliding window — with storm deduplication.
            # A sliding window over a sustained storm produces one ANOM per minute.
            # Instead: track the peak window within each distinct burst episode.
            # A new episode begins when the gap between consecutive errors
            # exceeds the burst_window, or the dominant source changes.
            window = timedelta(minutes=self.burst_window_minutes)
            cooldown = timedelta(minutes=self.burst_window_minutes)
            i = 0
            last_emitted: datetime | None = None  # end-time of last emitted burst

            # Collect all qualifying windows first, then emit peak per episode
            peak_windows: list[tuple[int, int, int]] = []  # (count, start_idx, end_idx)

            for j in range(len(timed)):
                while timed[j][0] - timed[i][0] > window:
                    i += 1
                count = j - i + 1
                if count >= self.burst_threshold:
                    peak_windows.append((count, i, j))

            # Group peak_windows into episodes: new episode if gap > cooldown
            episodes: list[list[tuple]] = []
            current_episode: list[tuple] = []
            for pw in peak_windows:
                if not current_episode:
                    current_episode.append(pw)
                else:
                    prev_end = timed[current_episode[-1][2]][0]
                    this_start = timed[pw[1]][0]
                    if this_start - prev_end <= cooldown:
                        current_episode.append(pw)
                    else:
                        episodes.append(current_episode)
                        current_episode = [pw]
            if current_episode:
                episodes.append(current_episode)

            # Emit one ANOM per episode using the peak window
            for episode in episodes:
                peak = max(episode, key=lambda x: x[0])
                count, si, ei = peak
                window_events = [t[1] for t in timed[si:ei + 1]]
                episode_start = timed[episode[0][1]][0]
                episode_end   = timed[episode[-1][2]][0]
                total_in_episode = episode[-1][2] - episode[0][1] + 1

                sources   = Counter(e.source for e in window_events if e.source)
                event_ids = Counter(e.event_id for e in window_events if e.event_id)
                top_source = sources.most_common(1)[0] if sources else ("unknown", 0)
                top_eid    = event_ids.most_common(1)[0] if event_ids else ("N/A", 0)
                score = min(1.0, count / (self.burst_threshold * 3))

                # Build a human-readable duration string
                duration_s = int((episode_end - episode_start).total_seconds())
                if duration_s >= 3600:
                    dur_str = f"{duration_s // 3600}h {(duration_s % 3600) // 60}m"
                elif duration_s >= 60:
                    dur_str = f"{duration_s // 60}m {duration_s % 60}s"
                else:
                    dur_str = f"{duration_s}s"

                self._anomaly_counter += 1
                self.anomalies.append(Anomaly(
                    anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                    anomaly_type="burst",
                    title=f"Error Burst: {count} events in {self.burst_window_minutes} min (storm duration: {dur_str})",
                    severity="high" if count >= self.burst_threshold * 2 else "medium",
                    description=(
                        f"Peak: {count} error/warning events in {self.burst_window_minutes} min. "
                        f"Storm total: {total_in_episode} events over {dur_str}. "
                        f"Top source: {top_source[0]} ({top_source[1]}x). "
                        f"Top Event ID: {top_eid[0]} ({top_eid[1]}x)."
                    ),
                    evidence=(
                        f"Storm: {episode_start.isoformat()} → {episode_end.isoformat()} "
                        f"| Peak window: {timed[si][0].isoformat()} → {timed[ei][0].isoformat()}"
                    ),
                    computer=computer,
                    first_seen=episode_start.isoformat(),
                    last_seen=episode_end.isoformat(),
                    event_count=total_in_episode,
                    score=score,
                    recommendation=(
                        f"Investigate the concentration of {top_source[0]} errors. "
                        f"Check Event ID {top_eid[0]} for recurring failures. "
                        f"This burst pattern often indicates a cascading failure."
                    ),
                ))

    # ────────────────────────────────────────────
    #  FREQUENCY SPIKE DETECTION
    # ────────────────────────────────────────────

    def _detect_frequency_spikes(self, events: list[ParsedEvent]):
        """
        Detect Event IDs that appear far more frequently than their
        baseline rate. Uses standard deviation to find outliers.
        """
        # Bucket events into hourly bins per Event ID
        hourly: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for evt in events:
            if not evt.event_id or not evt.timestamp:
                continue
            ts = self._parse_ts(evt.timestamp)
            if ts:
                hour_key = ts.strftime("%Y-%m-%d %H:00")
                hourly[evt.event_id][hour_key] += 1

        for event_id, hour_counts in hourly.items():
            if len(hour_counts) < 3:
                continue  # Need enough data points

            counts = list(hour_counts.values())
            mean = sum(counts) / len(counts)
            if mean < 1:
                continue

            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            stddev = math.sqrt(variance) if variance > 0 else 0

            if stddev < 1:
                continue

            threshold = mean + (self.spike_stddev * stddev)

            for hour, count in hour_counts.items():
                if count > threshold and count > 5:
                    deviation = (count - mean) / stddev if stddev > 0 else 0
                    score = min(1.0, deviation / 5.0)

                    self._anomaly_counter += 1
                    self.anomalies.append(Anomaly(
                        anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                        anomaly_type="spike",
                        title=f"Frequency Spike: Event {event_id} ({count}x in 1 hour)",
                        severity="medium",
                        description=(
                            f"Event ID {event_id} appeared {count} times during {hour}, "
                            f"which is {deviation:.1f} standard deviations above the "
                            f"baseline average of {mean:.1f}/hour."
                        ),
                        evidence=f"Baseline: {mean:.1f}/hr, Stddev: {stddev:.1f}, Observed: {count}",
                        first_seen=hour,
                        last_seen=hour,
                        event_count=count,
                        score=score,
                        recommendation=(
                            f"Event ID {event_id} is firing abnormally often. "
                            f"Check if a new condition (hardware fault, config change, "
                            f"attack) is triggering this spike."
                        ),
                    ))

    # ────────────────────────────────────────────
    #  RARE EVENT DETECTION
    # ────────────────────────────────────────────

    def _detect_rare_events(self, events: list[ParsedEvent]):
        """
        Flag events that appear very infrequently. Rare events in
        error/critical logs are often the most diagnostic.
        """
        error_levels = {"error", "critical", "1", "2"}

        # Count Event ID occurrences (errors only)
        id_counts = Counter()
        id_examples = {}
        for evt in events:
            if (evt.level or "").lower() in error_levels and evt.event_id:
                id_counts[evt.event_id] += 1
                if evt.event_id not in id_examples:
                    id_examples[evt.event_id] = evt

        for event_id, count in id_counts.items():
            if count <= self.rare_threshold:
                example = id_examples[event_id]
                score = 1.0 - (count / (self.rare_threshold + 1))

                self._anomaly_counter += 1
                self.anomalies.append(Anomaly(
                    anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                    anomaly_type="rare",
                    title=f"Rare Error: Event {event_id} from {example.source}",
                    severity="medium",
                    description=(
                        f"Error Event ID {event_id} ({example.source}) appeared only "
                        f"{count} time(s). Rare errors are often the most diagnostic — "
                        f"they may indicate a unique failure condition."
                    ),
                    evidence=f"Message: {(example.message or '')[:200]}",
                    computer=example.computer or "",
                    first_seen=example.timestamp or "",
                    event_count=count,
                    score=score,
                    recommendation=(
                        f"Research Event ID {event_id} from source '{example.source}'. "
                        f"Rare error events often pinpoint the exact root cause of an issue."
                    ),
                ))

    # ────────────────────────────────────────────
    #  SEVERITY ESCALATION
    # ────────────────────────────────────────────

    def _detect_severity_escalation(self, events: list[ParsedEvent]):
        """
        Detect patterns where a source shifts from producing mostly
        informational events to producing errors/criticals.
        """
        # Group by source and track severity distribution
        source_severity: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for evt in events:
            if evt.source:
                level = (evt.level or "information").lower()
                # Normalize
                if level in ("1", "critical"):
                    level = "critical"
                elif level in ("2", "error"):
                    level = "error"
                elif level in ("3", "warning"):
                    level = "warning"
                else:
                    level = "info"
                source_severity[evt.source][level] += 1

        for source, levels in source_severity.items():
            total = sum(levels.values())
            if total < 10:
                continue  # Not enough data

            error_count = levels.get("error", 0) + levels.get("critical", 0)
            error_ratio = error_count / total

            # If more than 50% of events from this source are errors
            if error_ratio > 0.5 and error_count >= 5:
                score = min(1.0, error_ratio)
                crit_count = levels.get("critical", 0)
                sev = "high" if crit_count > 0 else "medium"

                self._anomaly_counter += 1
                self.anomalies.append(Anomaly(
                    anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                    anomaly_type="escalation",
                    title=f"High Error Rate: {source} ({error_ratio:.0%} errors)",
                    severity=sev,
                    description=(
                        f"Source '{source}' is producing {error_ratio:.0%} error/critical "
                        f"events ({error_count} of {total} total). This indicates the "
                        f"component is in a degraded or failing state."
                    ),
                    evidence=(
                        f"Critical: {levels.get('critical', 0)}, "
                        f"Error: {levels.get('error', 0)}, "
                        f"Warning: {levels.get('warning', 0)}, "
                        f"Info: {levels.get('info', 0)}"
                    ),
                    event_count=error_count,
                    score=score,
                    recommendation=(
                        f"The '{source}' component is generating a majority of errors. "
                        f"Check its service status, configuration, dependencies, and "
                        f"recent changes. This is often a leading indicator of failure."
                    ),
                ))

    # ────────────────────────────────────────────
    #  UNUSUAL SOURCE DETECTION
    # ────────────────────────────────────────────

    def _detect_unusual_sources(self, events: list[ParsedEvent]):
        """
        Flag sources that appear very infrequently — they may be
        new, unexpected, or indicating an unusual condition.
        """
        source_counts = Counter(e.source for e in events if e.source)
        total_events = len(events)

        if not source_counts or total_events < 50:
            return

        # Sources that appear in < 0.5% of events
        threshold = max(2, total_events * 0.005)

        for source, count in source_counts.items():
            if count <= threshold and count <= 5:
                # Is it an error-producing source?
                error_levels = {"error", "critical", "1", "2"}
                source_events = [e for e in events if e.source == source]
                has_errors = any(
                    (e.level or "").lower() in error_levels for e in source_events
                )

                if has_errors:
                    score = 0.6  # Moderate confidence

                    self._anomaly_counter += 1
                    self.anomalies.append(Anomaly(
                        anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                        anomaly_type="new_source",
                        title=f"Unusual Error Source: {source} ({count} events)",
                        severity="low",
                        description=(
                            f"Source '{source}' produced only {count} events out of "
                            f"{total_events} total, and includes errors. Unusual sources "
                            f"with errors warrant investigation."
                        ),
                        evidence=f"Example: {source_events[0].message[:200] if source_events else 'N/A'}",
                        computer=source_events[0].computer if source_events else "",
                        event_count=count,
                        score=score,
                        recommendation=(
                            f"Investigate the '{source}' event source. It may be a newly "
                            f"installed component, a rarely-triggered subsystem, or an "
                            f"indicator of an unusual condition."
                        ),
                    ))

    # ────────────────────────────────────────────
    #  CHRONIC APPLICATION CRASH DETECTION
    #  (MISS-02/03 from evaluation)
    # ────────────────────────────────────────────

    def _detect_chronic_crashes(self, events: list[ParsedEvent]):
        """
        Detect processes that crash repeatedly across the log window.
        A process crashing 3+ times with a consistent fault pattern
        is a chronic stability issue, not a one-time error.
        """
        # Count crashes per process from Application Error 1000
        crash_data: dict[str, dict] = {}  # process_name → {count, first, last, codes, computer}

        for evt in events:
            if str(evt.event_id) != "1000":
                continue
            if "Application Error" not in (evt.source or ""):
                continue

            msg = (evt.message or "").lower()

            # Extract faulting application name from message
            app_name = ""
            for prefix in ("faulting application name:", "application name:"):
                if prefix in msg:
                    start = msg.index(prefix) + len(prefix)
                    rest = msg[start:].strip()
                    app_name = rest.split(",")[0].split()[0].strip()
                    break

            if not app_name:
                continue

            if app_name not in crash_data:
                crash_data[app_name] = {
                    "count": 0, "first": evt.timestamp, "last": evt.timestamp,
                    "codes": set(), "computer": evt.computer or "",
                }

            crash_data[app_name]["count"] += 1
            crash_data[app_name]["last"] = evt.timestamp

            # Extract exception code
            for prefix in ("exception code:", "exception:"):
                if prefix in msg:
                    start = msg.index(prefix) + len(prefix)
                    code = msg[start:].strip().split(",")[0].split()[0].strip()
                    if code:
                        crash_data[app_name]["codes"].add(code)

        # Flag processes with 3+ crashes
        for app_name, data in crash_data.items():
            if data["count"] >= 3:
                codes_str = ", ".join(sorted(data["codes"])) if data["codes"] else "unknown"
                score = min(1.0, data["count"] / 10.0)

                self._anomaly_counter += 1
                self.anomalies.append(Anomaly(
                    anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                    anomaly_type="chronic_crash",
                    title=f"Chronic Application Instability: {app_name} ({data['count']} crashes)",
                    severity="high" if data["count"] >= 10 else "medium",
                    description=(
                        f"{app_name} has crashed {data['count']} times across the log window. "
                        f"Exception codes: {codes_str}. A process crashing this frequently indicates "
                        f"a broken component that needs repair, update, or reinstallation."
                    ),
                    evidence=f"Crashes: {data['count']}, Exception codes: {codes_str}",
                    computer=data["computer"],
                    first_seen=data["first"],
                    last_seen=data["last"],
                    event_count=data["count"],
                    score=score,
                    recommendation=(
                        f"1. Check if {app_name} has available updates. "
                        f"2. Check AV/EDR quarantine for false-positived DLLs. "
                        f"3. Reinstall the parent application. "
                        f"4. If CLR exception (0xe0434352): check .NET Framework health."
                    ),
                ))

    # ────────────────────────────────────────────
    #  SERVICE INSTALL + FAIL LOOP DETECTION
    #  (MISS-04 from evaluation)
    # ────────────────────────────────────────────

    def _detect_service_install_loops(self, events: list[ParsedEvent]):
        """
        Detect services that are repeatedly installed (7045) then
        immediately fail to start (7000). Indicates a broken driver
        deployment or service configuration loop.
        """
        # Track 7045 (install) and 7000 (fail) per service name
        installs: dict[str, int] = Counter()
        failures: dict[str, int] = Counter()
        service_info: dict[str, dict] = {}

        for evt in events:
            if "Service Control Manager" not in (evt.source or ""):
                continue

            msg = evt.message or ""
            eid = str(evt.event_id)

            # Extract service name from message
            svc_name = ""
            msg_lower = msg.lower()
            for prefix in ("the ", "a service was installed"):
                if prefix in msg_lower:
                    # Try to extract the service name — typically first quoted or named item
                    for word in msg.split():
                        if len(word) > 3 and word[0].isupper():
                            svc_name = word.rstrip(".,;:")
                            break
                    break

            # Fallback: use first significant word
            if not svc_name:
                words = [w for w in msg.split() if len(w) > 4 and w[0].isupper()]
                if words:
                    svc_name = words[0].rstrip(".,;:")

            if not svc_name:
                continue

            if eid == "7045":
                installs[svc_name] += 1
            elif eid == "7000":
                failures[svc_name] += 1

            if svc_name not in service_info:
                service_info[svc_name] = {
                    "first": evt.timestamp, "last": evt.timestamp,
                    "computer": evt.computer or "",
                }
            service_info[svc_name]["last"] = evt.timestamp

        # Find services with both install and failure counts >= 2
        for svc_name in set(installs.keys()) & set(failures.keys()):
            i_count = installs[svc_name]
            f_count = failures[svc_name]

            if i_count >= 2 and f_count >= 2:
                info = service_info.get(svc_name, {})
                total = i_count + f_count
                score = min(1.0, total / 10.0)

                self._anomaly_counter += 1
                self.anomalies.append(Anomaly(
                    anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                    anomaly_type="service_loop",
                    title=f"Service Install Loop: {svc_name} (installed {i_count}x, failed {f_count}x)",
                    severity="medium",
                    description=(
                        f"Service '{svc_name}' was installed {i_count} times and failed "
                        f"to start {f_count} times. This pattern indicates a driver or "
                        f"service deployment that is repeatedly registering a service "
                        f"whose binary does not exist at the target path."
                    ),
                    evidence=f"Event 7045 count: {i_count}, Event 7000 count: {f_count}",
                    computer=info.get("computer", ""),
                    first_seen=info.get("first", ""),
                    last_seen=info.get("last", ""),
                    event_count=total,
                    score=score,
                    recommendation=(
                        f"1. Check the service binary path: 'sc qc {svc_name}'. "
                        f"2. Verify the binary exists at the configured path. "
                        f"3. If a driver: check if the .sys file is present in System32\\drivers. "
                        f"4. Identify what automation is deploying this service and fix or disable it."
                    ),
                ))

    # ────────────────────────────────────────────
    #  MSI INSTALLER FAILURE LOOP DETECTION
    #  (MISS-05 from evaluation)
    # ────────────────────────────────────────────

    def _detect_msi_failure_loops(self, events: list[ParsedEvent]):
        """
        Detect MSI installer operations that fail repeatedly for
        the same product. 5+ failures indicates a permanently broken
        installer state that will not self-heal.

        CRITICAL: Event 1035 with "status: 0" is a SUCCESSFUL
        reconfiguration and MUST be excluded. Only non-zero statuses
        are actual failures.
        """
        # Track MsiInstaller failures per product
        msi_failures: dict[str, dict] = {}

        for evt in events:
            if "MsiInstaller" not in (evt.source or ""):
                continue
            if str(evt.event_id) not in ("1035", "11724", "1023"):
                continue

            msg = evt.message or ""
            msg_lower = msg.lower()

            # CRITICAL FIX: Skip successful reconfigurations (status: 0)
            # Event 1035 with "error status: 0" or "status: 0" is a SUCCESS
            if "status: 0" in msg_lower or "status:0" in msg_lower:
                continue

            # Skip Event 1033 entirely — it's "product installed successfully"
            if str(evt.event_id) == "1033":
                continue

            # Try to extract product name
            product = ""
            for prefix in ("product:", "product name:", "windows installer reconfigured the product."):
                if prefix in msg_lower:
                    start = msg_lower.index(prefix) + len(prefix)
                    rest = msg[start:].strip()
                    product = rest.split(".")[0].split(",")[0].strip()
                    break

            if not product:
                product = msg[:60].strip()

            key = product[:50]

            if key not in msi_failures:
                msi_failures[key] = {
                    "count": 0, "product": product,
                    "first": evt.timestamp, "last": evt.timestamp,
                    "computer": evt.computer or "",
                    "statuses": set(),
                }

            msi_failures[key]["count"] += 1
            msi_failures[key]["last"] = evt.timestamp

            # Extract error status
            for code in ("1603", "1618", "1625", "1602", "1612"):
                if code in msg:
                    msi_failures[key]["statuses"].add(code)

        # Flag products with 5+ failures
        for key, data in msi_failures.items():
            if data["count"] >= 5:
                statuses = ", ".join(sorted(data["statuses"])) if data["statuses"] else "unknown"
                score = min(1.0, data["count"] / 20.0)

                self._anomaly_counter += 1
                self.anomalies.append(Anomaly(
                    anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                    anomaly_type="msi_loop",
                    title=f"MSI Installer Failure Loop: {data['product'][:50]} ({data['count']}x)",
                    severity="medium",
                    description=(
                        f"The Windows Installer for '{data['product'][:60]}' has failed "
                        f"{data['count']} times. Error status codes: {statuses}. "
                        f"This indicates a permanently broken installer state that "
                        f"fires on every boot's MSI reconfiguration sweep."
                    ),
                    evidence=f"Failures: {data['count']}, Error statuses: {statuses}",
                    computer=data["computer"],
                    first_seen=data["first"],
                    last_seen=data["last"],
                    event_count=data["count"],
                    score=score,
                    recommendation=(
                        f"1. Try repair install: msiexec /fa <product.msi>. "
                        f"2. If 1603: run as admin, check disk space, close conflicting apps. "
                        f"3. Clean uninstall and reinstall the product. "
                        f"4. Check the MSI log: msiexec /i <product.msi> /l*v install.log. "
                        f"5. If enterprise-managed: check SCCM/Intune deployment status."
                    ),
                ))

    # ────────────────────────────────────────────
    #  PERIODIC CRASH DETECTION
    #  (post USVIS-952KC14 — temporal-crash-001)
    # ────────────────────────────────────────────

    def _detect_crash_periodicity(self, events: list[ParsedEvent]):
        """
        Detect crash events that occur at a regular interval.

        In USVIS-952KC14, lsass crashed at 9 PM, 1 AM, 5 AM, 9 AM, 1 PM —
        a perfect 4-hour cycle matching Kerberos TGT renewal (240 min default).
        A rule that detects this pattern immediately suggests a scheduled or
        timer-driven trigger without requiring manual timestamp arithmetic.

        Fires when 3+ consecutive inter-event deltas cluster within ±10% of
        their median value, and the interval falls within 5 min–24 h.
        Also matches against known timer intervals (Kerberos, GP refresh, etc.).
        """
        import statistics

        CRASH_EVENT_IDS = {"1000", "41", "1074"}
        MIN_INTERVAL_SEC = 300.0      # 5 minutes
        MAX_INTERVAL_SEC = 86400.0    # 24 hours
        TOLERANCE = 0.10              # ±10%
        MIN_EVENTS = 3

        KNOWN_TIMERS = {
            15:   "Short-cycle watchdog or background task (15 min)",
            30:   "Group Policy background refresh (30 min — workstation default)",
            60:   "Kerberos service-ticket renewal (60 min default)",
            90:   "Group Policy background refresh (90 min — server default)",
            120:  "Kerberos TGT renewal (2 h)",
            240:  "Kerberos TGT renewal (4 h — common GPO setting)",
            480:  "Kerberos TGT renewal (8 h)",
            600:  "Kerberos TGT renewal (10 h — extended session)",
            720:  "Twice-daily scheduled task (12 h)",
            1440: "Daily scheduled task (24 h)",
        }

        # Collect crash event timestamps
        timed: list[tuple[datetime, ParsedEvent]] = []
        for evt in events:
            if str(evt.event_id) not in CRASH_EVENT_IDS:
                continue
            ts = self._parse_ts(evt.timestamp)
            if ts:
                timed.append((ts, evt))

        if len(timed) < MIN_EVENTS:
            return

        timed.sort(key=lambda x: x[0])

        # Group by faulting process for per-process analysis
        def get_proc(evt: ParsedEvent) -> str:
            msg = (evt.message or "").lower()
            for prefix in ("faulting application name:", "application name:"):
                if prefix in msg:
                    start = msg.index(prefix) + len(prefix)
                    return msg[start:].strip().split(",")[0].split()[0].strip()
            return ""

        groups: dict[str, list[tuple[datetime, ParsedEvent]]] = {"__all__": timed}
        for ts, evt in timed:
            proc = get_proc(evt)
            if proc:
                groups.setdefault(proc, []).append((ts, evt))

        seen_intervals: set[int] = set()

        for group_name, group in groups.items():
            if len(group) < MIN_EVENTS:
                continue

            timestamps = [t for t, _ in group]
            deltas = [
                (timestamps[i+1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            valid = [d for d in deltas if MIN_INTERVAL_SEC <= d <= MAX_INTERVAL_SEC]

            if len(valid) < MIN_EVENTS - 1:
                continue

            median = statistics.median(valid)
            tol = median * TOLERANCE
            cluster = [d for d in valid if abs(d - median) <= tol]

            if len(cluster) < MIN_EVENTS - 1:
                continue

            pct = len(cluster) / len(valid) if valid else 0
            if pct < 0.60:
                continue

            confidence = "high" if pct >= 0.80 else "medium"
            interval_min = round(median / 60.0, 1)
            interval_min_int = round(interval_min)

            # Deduplicate — don't emit the same interval twice
            if interval_min_int in seen_intervals:
                continue
            seen_intervals.add(interval_min_int)

            # Match known timers (±5 min tolerance)
            known_match = ""
            for known_min, label in KNOWN_TIMERS.items():
                if abs(interval_min - known_min) <= 5:
                    known_match = label
                    break

            # Most common faulting process
            proc_counts: dict[str, int] = {}
            for _, evt in group:
                p = get_proc(evt) or "unknown"
                proc_counts[p] = proc_counts.get(p, 0) + 1
            top_proc = max(proc_counts, key=lambda k: proc_counts[k])

            score = min(1.0, pct)
            self._anomaly_counter += 1
            self.anomalies.append(Anomaly(
                anomaly_id=f"ANOM-{self._anomaly_counter:04d}",
                anomaly_type="periodic_crash",
                title=f"Periodic Crash Pattern: {interval_min} min interval ({len(group)} events)",
                severity="high",
                description=(
                    f"Crash events are occurring at a regular interval of "
                    f"~{interval_min} minutes ({len(group)} events, "
                    f"{pct:.0%} of inter-event deltas cluster within ±10% of median). "
                    f"Most common faulting process: {top_proc}. "
                    + (f"Matches known timer: {known_match}." if known_match else
                       "Interval does not match a common known timer — investigate "
                       "scheduled tasks and service watchdog timers.")
                ),
                evidence=(
                    f"Median interval: {median:.0f}s ({interval_min} min), "
                    f"Cluster: {len(cluster)}/{len(valid)} deltas, "
                    f"Confidence: {confidence}"
                    + (f", Timer: {known_match}" if known_match else "")
                ),
                computer=group[0][1].computer or "",
                first_seen=timestamps[0].isoformat(),
                last_seen=timestamps[-1].isoformat(),
                event_count=len(group),
                score=score,
                recommendation=(
                    f"A {interval_min}-minute crash interval strongly suggests a timer-driven "
                    f"trigger. "
                    + (f"{known_match} — " if known_match else "")
                    + "Investigate: (1) Kerberos ticket lifetime policy "
                    f"(MaxTicketAge / MaxServiceAge in Default Domain Policy), "
                    "(2) scheduled tasks matching this interval "
                    "('schtasks /query /fo LIST /v'), "
                    "(3) Security log Events 4768/4769 for Kerberos renewal failures."
                ),
            ))

    # ────────────────────────────────────────────
    #  HELPERS
    # ────────────────────────────────────────────

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime | None:
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
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_str[:26], fmt)
            except ValueError:
                continue
        return None

    def get_summary(self) -> dict:
        by_type = Counter(a.anomaly_type for a in self.anomalies)
        by_severity = Counter(a.severity for a in self.anomalies)
        return {
            "total_anomalies": len(self.anomalies),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
        }
