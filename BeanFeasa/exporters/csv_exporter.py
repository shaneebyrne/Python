"""
BeanFeasa — CSV Exporter.

v2 fixes (post USVIS-JQD1SQ3 evaluation):
  - export_full_report: switched from csv.writer with QUOTE_MINIMAL to
    csv.DictWriter with QUOTE_ALL. Message and raw_data fields contain
    embedded newlines and commas that QUOTE_MINIMAL did not reliably quote,
    causing 81% of rule detection rows to have column-shifted output.
  - Newline sanitization: embedded \r\n in message fields are replaced with
    a space before writing so the CSV row count stays correct.
  - Added export_storage_findings() for the new storage analysis engine.
"""

import csv
from pathlib import Path
from analyzers.detection_engine import Detection
from analyzers.correlation_engine import CorrelatedIncident
from analyzers.anomaly_detector import Anomaly
from parsers.base import ParsedEvent


def _sanitize(value: str, max_len: int = 2000) -> str:
    """Normalize a field value for CSV output — truncate and remove bare newlines."""
    if value is None:
        return ""
    s = str(value)[:max_len]
    # Replace embedded newlines with visible placeholder so row count is preserved
    s = s.replace("\r\n", " ↵ ").replace("\r", " ↵ ").replace("\n", " ↵ ")
    return s


def _write_section(writer, headers: list[str], rows: list[dict], label: str):
    """Write a labelled section into a combined report file."""
    writer.writerow({h: f"=== {label} ===" if h == headers[0] else "" for h in headers})
    writer.writerow({h: h for h in headers})
    for row in rows:
        sanitized = {k: _sanitize(str(v)) for k, v in row.items() if k in headers}
        writer.writerow(sanitized)
    writer.writerow({h: "" for h in headers})


def export_detections(detections: list[Detection], output_path: str) -> tuple[bool, str]:
    if not detections:
        return False, "No detections to export."
    try:
        headers = Detection.csv_headers()
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=headers, extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            for det in detections:
                row = {k: _sanitize(str(v)) for k, v in det.to_dict().items()}
                writer.writerow(row)
        return True, f"Exported {len(detections)} detections to {output_path}"
    except Exception as exc:
        return False, f"Export failed: {exc}"


def export_events(events: list[ParsedEvent], output_path: str) -> tuple[bool, str]:
    if not events:
        return False, "No events to export."
    try:
        headers = ["timestamp", "source", "event_id", "level", "channel", "computer", "message"]
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=headers, extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            for evt in events:
                row = evt.to_dict()
                row.pop("raw_data", None)
                row.pop("metadata", None)
                writer.writerow({k: _sanitize(str(v)) for k, v in row.items() if k in headers})
        return True, f"Exported {len(events)} events to {output_path}"
    except Exception as exc:
        return False, f"Export failed: {exc}"


def export_incidents(incidents: list[CorrelatedIncident], output_path: str) -> tuple[bool, str]:
    if not incidents:
        return False, "No incidents to export."
    try:
        headers = CorrelatedIncident.csv_headers()
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=headers, extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            for inc in incidents:
                row = {k: _sanitize(str(v)) for k, v in inc.to_dict().items()}
                writer.writerow(row)
        return True, f"Exported {len(incidents)} incidents to {output_path}"
    except Exception as exc:
        return False, f"Export failed: {exc}"


def export_anomalies(anomalies: list[Anomaly], output_path: str) -> tuple[bool, str]:
    if not anomalies:
        return False, "No anomalies to export."
    try:
        headers = Anomaly.csv_headers()
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=headers, extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            for anom in anomalies:
                row = {k: _sanitize(str(v)) for k, v in anom.to_dict().items()}
                writer.writerow(row)
        return True, f"Exported {len(anomalies)} anomalies to {output_path}"
    except Exception as exc:
        return False, f"Export failed: {exc}"


def export_storage_findings(findings: list[dict], output_path: str) -> tuple[bool, str]:
    """Export storage analysis findings to CSV."""
    if not findings:
        return False, "No storage findings to export."
    try:
        headers = [
            "priority", "action", "category", "size_gb", "size_mb",
            "file_name", "full_path", "directory", "last_modified",
            "reason", "recommendation",
        ]
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=headers, extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            for finding in findings:
                row = {k: _sanitize(str(finding.get(k, ""))) for k in headers}
                writer.writerow(row)
        return True, f"Exported {len(findings)} storage findings to {output_path}"
    except Exception as exc:
        return False, f"Export failed: {exc}"


def export_full_report(
    detections: list[Detection],
    incidents: list[CorrelatedIncident],
    anomalies: list[Anomaly],
    output_path: str,
    storage_findings: list[dict] | None = None,
    supplemental_findings: list | None = None,
) -> tuple[bool, str]:
    """
    Export a combined report to a single CSV with section headers.

    v2: Uses QUOTE_ALL and field sanitization throughout.
    Adds optional storage_findings section.
    """
    try:
        # Use the widest header set across all section types so every row
        # has the same column count — this prevents column-shifting in Excel.
        det_headers    = Detection.csv_headers()
        inc_headers    = CorrelatedIncident.csv_headers()
        anom_headers   = Anomaly.csv_headers()
        stor_headers   = [
            "priority", "action", "category", "size_gb", "size_mb",
            "file_name", "full_path", "directory", "last_modified",
            "reason", "recommendation",
        ]

        # Master header: union of all headers, detection headers first
        seen = set()
        master_headers: list[str] = []
        for h in det_headers + inc_headers + anom_headers + stor_headers:
            if h not in seen:
                seen.add(h)
                master_headers.append(h)

        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=master_headers, extrasaction="ignore",
                quoting=csv.QUOTE_ALL, restval="",
            )
            writer.writeheader()

            def section_row(label: str) -> dict:
                row = {h: "" for h in master_headers}
                row[master_headers[0]] = f"=== {label} ==="
                return row

            # Section 1: Correlated Incidents
            writer.writerow(section_row("CORRELATED INCIDENTS"))
            for inc in incidents:
                writer.writerow({k: _sanitize(str(v)) for k, v in inc.to_dict().items()})
            writer.writerow({h: "" for h in master_headers})

            # Section 2: Statistical Anomalies
            writer.writerow(section_row("STATISTICAL ANOMALIES"))
            for anom in anomalies:
                writer.writerow({k: _sanitize(str(v)) for k, v in anom.to_dict().items()})
            writer.writerow({h: "" for h in master_headers})

            # Section 3: Storage Analysis (if present)
            if storage_findings:
                writer.writerow(section_row("STORAGE ANALYSIS"))
                for sf in storage_findings:
                    writer.writerow({k: _sanitize(str(sf.get(k, ""))) for k in master_headers})
                writer.writerow({h: "" for h in master_headers})

            # Section 4: Supplemental Findings (Hotfixes, EOL software, AV conflicts)
            if supplemental_findings:
                writer.writerow(section_row("SUPPLEMENTAL ANALYSIS"))
                for sf in supplemental_findings:
                    d = sf.to_dict() if hasattr(sf, 'to_dict') else sf
                    writer.writerow({k: _sanitize(str(d.get(k, ""))) for k in master_headers})
                writer.writerow({h: "" for h in master_headers})

            # Section 5: Rule-Based Detections
            writer.writerow(section_row("RULE-BASED DETECTIONS"))
            for det in detections:
                writer.writerow({k: _sanitize(str(v)) for k, v in det.to_dict().items()})

        total = len(detections) + len(incidents) + len(anomalies) + len(storage_findings or []) + len(supplemental_findings or [])
        return True, f"Exported full report ({total} findings) to {output_path}"
    except Exception as exc:
        return False, f"Export failed: {exc}"
