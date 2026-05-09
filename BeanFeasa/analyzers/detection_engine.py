"""
BeanFeasa — Detection Engine v4.

v4: Named-group evaluation to fix the win-security-007 catastrophic regression.

v3 changes preserved:
  - Rule strength classification
  - Baseline-aware suppression  
  - Post-analysis deduplication

v4 new:
  - _evaluate_rule now handles DetectionRule.is_grouped properly:
    * For grouped rules: evaluate each ConditionGroup as AND of its conditions,
      combine groups per group_logic (OR or AND), exclude if any exclude group matches.
    * For flat rules: unchanged from v3 (backward compat).
  - _classify_rule_strength updated to inspect group conditions for anchor fields.
"""

import re
import hashlib
from dataclasses import dataclass, field
from parsers.base import ParsedEvent
from analyzers.rule_loader import DetectionRule, DetectionCondition, ConditionGroup

try:
    from analyzers.baseline_model import BaselineModel
    _HAS_BASELINE = True
except ImportError:
    _HAS_BASELINE = False

STRENGTH_STRONG = "strong"
STRENGTH_MEDIUM = "medium"
STRENGTH_WEAK   = "weak"
_ANCHOR_FIELDS  = {"event_id", "source", "channel", "computer"}
_CONTENT_FIELDS = {"message", "level"}
_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


@dataclass
class Detection:
    timestamp: str
    rule_id: str
    rule_title: str
    severity: str
    source_file: str
    event_id: str
    source: str
    computer: str
    channel: str
    level: str
    message: str
    matched_fields: str
    tags: str
    raw_data: str = ""
    rule_strength: str = ""
    baseline_suppressed: bool = False
    also_matched: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp, "rule_id": self.rule_id,
            "rule_title": self.rule_title, "severity": self.severity,
            "source_file": self.source_file, "event_id": self.event_id,
            "source": self.source, "computer": self.computer,
            "channel": self.channel, "level": self.level,
            "message": self.message, "matched_fields": self.matched_fields,
            "tags": self.tags, "raw_data": self.raw_data,
            "rule_strength": self.rule_strength, "also_matched": self.also_matched,
        }

    @staticmethod
    def csv_headers() -> list[str]:
        return [
            "timestamp", "rule_id", "rule_title", "severity",
            "source_file", "event_id", "source", "computer",
            "channel", "level", "message", "matched_fields",
            "tags", "raw_data", "rule_strength", "also_matched",
        ]


def _classify_rule_strength(rule: DetectionRule) -> str:
    """Classify rule strength based on which field types its conditions span."""
    all_conds = list(rule.conditions)
    for g in rule.groups:
        all_conds.extend(g.conditions)

    anchor_fields: set[str] = set()
    content_fields: set[str] = set()
    for cond in all_conds:
        if cond.field in _ANCHOR_FIELDS:
            anchor_fields.add(cond.field)
        elif cond.field in _CONTENT_FIELDS:
            content_fields.add(cond.field)

    if len(anchor_fields) >= 2:
        return STRENGTH_STRONG
    if len(anchor_fields) >= 1 and len(content_fields) >= 1:
        return STRENGTH_STRONG
    if "event_id" in anchor_fields or "source" in anchor_fields:
        return STRENGTH_MEDIUM
    return STRENGTH_WEAK


def _downgrade_severity(severity: str) -> str:
    idx = _SEV_ORDER.index(severity) if severity in _SEV_ORDER else 2
    return _SEV_ORDER[min(idx + 1, len(_SEV_ORDER) - 1)]


def _event_fingerprint(event) -> str:
    raw = f"{event.timestamp}|{event.source}|{event.event_id}|{event.computer}"
    return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()


class DetectionEngine:
    def __init__(
        self,
        rules: list[DetectionRule] | None = None,
        baseline: "BaselineModel | None" = None,
    ):
        self.rules = [r for r in (rules or []) if r.enabled]
        self.baseline = baseline
        self._rule_strength: dict[str, str] = {
            r.id: _classify_rule_strength(r) for r in self.rules
        }
        self.stats = {
            "events_scanned": 0, "detections_raw": 0,
            "detections_after_dedup": 0, "baseline_suppressed": 0,
            "by_severity": {}, "by_rule": {},
            "by_strength": {STRENGTH_STRONG: 0, STRENGTH_MEDIUM: 0, STRENGTH_WEAK: 0},
        }

    def analyze(
        self,
        events: list[ParsedEvent],
        source_file: str = "",
        callback=None,
    ) -> list[Detection]:
        raw_detections: list[Detection] = []
        total = len(events)

        for i, event in enumerate(events):
            self.stats["events_scanned"] += 1

            for rule in self.rules:
                matched, matched_fields = self._evaluate_rule(rule, event)
                if not matched:
                    continue

                strength = self._rule_strength.get(rule.id, STRENGTH_WEAK)
                severity = rule.severity
                suppressed = False

                if self.baseline and self.baseline._built:
                    is_baseline = self.baseline.is_baseline_event(
                        event.source or "", event.event_id or ""
                    )
                    if is_baseline:
                        if strength == STRENGTH_WEAK:
                            severity = _downgrade_severity(severity)
                            suppressed = True
                            self.stats["baseline_suppressed"] += 1
                            matched_fields.append("⬇baseline")
                        elif strength == STRENGTH_MEDIUM:
                            matched_fields.append("~baseline")

                raw_detections.append(Detection(
                    timestamp=event.timestamp,
                    rule_id=rule.id, rule_title=rule.title,
                    severity=severity, source_file=source_file,
                    event_id=event.event_id, source=event.source,
                    computer=event.computer, channel=event.channel,
                    level=event.level, message=event.message[:1000],
                    matched_fields=", ".join(matched_fields),
                    tags=", ".join(rule.tags), raw_data=event.raw_data[:500],
                    rule_strength=strength, baseline_suppressed=suppressed,
                ))
                self.stats["detections_raw"] += 1
                self.stats["by_strength"][strength] = (
                    self.stats["by_strength"].get(strength, 0) + 1
                )

            if callback and (i % 100 == 0 or i == total - 1):
                callback(i + 1, total)

        deduplicated = self._deduplicate(raw_detections)
        self.stats["detections_after_dedup"] = len(deduplicated)
        for det in deduplicated:
            self.stats["by_severity"][det.severity] = (
                self.stats["by_severity"].get(det.severity, 0) + 1
            )
            self.stats["by_rule"][det.rule_title] = (
                self.stats["by_rule"].get(det.rule_title, 0) + 1
            )
        return deduplicated

    def _evaluate_rule(
        self, rule: DetectionRule, event: ParsedEvent
    ) -> tuple[bool, list[str]]:
        if rule.is_grouped:
            return self._evaluate_grouped_rule(rule, event)
        else:
            return self._evaluate_flat_rule(rule, event)

    def _evaluate_grouped_rule(
        self, rule: DetectionRule, event: ParsedEvent
    ) -> tuple[bool, list[str]]:
        """
        Evaluate a multi-group rule.

        Exclusion groups: if any condition in ANY exclude group matches → suppress.
        Selection groups: evaluated per group_logic (OR or AND).
          OR: rule fires if ANY selection group fully matches (all its conds match).
          AND: rule fires if ALL selection groups fully match.
        """
        # Exclusion check first
        for group in rule.groups:
            if not group.is_exclude:
                continue
            for cond in group.conditions:
                if self._eval_cond(cond, event):
                    return False, []

        selection_groups = [g for g in rule.groups if not g.is_exclude]
        if not selection_groups:
            return False, []

        matched_fields: list[str] = []

        if rule.group_logic == "or":
            # Fire if ANY selection group fully matches
            for group in selection_groups:
                group_hits = [
                    f"{c.field}:{c.modifier}"
                    for c in group.conditions
                    if self._eval_cond(c, event)
                ]
                if len(group_hits) == len(group.conditions) and group.conditions:
                    matched_fields.extend(group_hits)
                    return True, matched_fields
            return False, []
        else:
            # Fire if ALL selection groups fully match
            for group in selection_groups:
                group_hits = [
                    f"{c.field}:{c.modifier}"
                    for c in group.conditions
                    if self._eval_cond(c, event)
                ]
                if len(group_hits) < len(group.conditions):
                    return False, []
                matched_fields.extend(group_hits)
            return (True, matched_fields) if matched_fields else (False, [])

    def _evaluate_flat_rule(
        self, rule: DetectionRule, event: ParsedEvent
    ) -> tuple[bool, list[str]]:
        for excl in rule.exclude_conditions:
            if self._eval_cond(excl, event):
                return False, []

        matched_fields = [
            f"{c.field}:{c.modifier}"
            for c in rule.conditions
            if self._eval_cond(c, event)
        ]

        if rule.condition_logic == "and":
            success = len(matched_fields) == len(rule.conditions)
        else:
            success = len(matched_fields) > 0

        return (success, matched_fields) if success else (False, [])

    def _eval_cond(self, cond: DetectionCondition, event: ParsedEvent) -> bool:
        field_value = getattr(event, cond.field, None)
        if field_value is None:
            field_value = event.metadata.get(cond.field, "")
        field_value = str(field_value).lower()

        if cond.modifier == "exists":
            return bool(field_value)

        for pattern in cond.values:
            p = str(pattern).lower()
            if cond.modifier == "contains" and p in field_value:
                return True
            elif cond.modifier == "equals" and field_value == p:
                return True
            elif cond.modifier == "startswith" and field_value.startswith(p):
                return True
            elif cond.modifier == "endswith" and field_value.endswith(p):
                return True
            elif cond.modifier == "regex":
                try:
                    if re.search(pattern, field_value, re.IGNORECASE):
                        return True
                except re.error:
                    pass
        return False

    def _deduplicate(self, detections: list[Detection]) -> list[Detection]:
        if not detections:
            return []
        groups: dict[str, list[Detection]] = {}
        order: list[str] = []
        for det in detections:
            fp = _event_fingerprint(
                _FakeEvent(det.timestamp, det.source, det.event_id, det.computer)
            )
            if fp not in groups:
                groups[fp] = []
                order.append(fp)
            groups[fp].append(det)

        result: list[Detection] = []
        for fp in order:
            group = groups[fp]
            if len(group) == 1:
                result.append(group[0])
                continue
            group.sort(
                key=lambda d: _SEV_ORDER.index(d.severity)
                if d.severity in _SEV_ORDER else 99
            )
            primary = group[0]
            others = group[1:]
            also = [f"{d.rule_id}({d.severity})" for d in others if d.rule_id != primary.rule_id]
            primary.also_matched = "; ".join(also)
            result.append(primary)
        return result

    def get_summary(self) -> dict:
        return {
            "events_scanned": self.stats["events_scanned"],
            "detections_raw": self.stats["detections_raw"],
            "total_detections": self.stats["detections_after_dedup"],
            "baseline_suppressed": self.stats["baseline_suppressed"],
            "by_severity": dict(self.stats["by_severity"]),
            "by_rule": dict(self.stats["by_rule"]),
            "by_strength": dict(self.stats["by_strength"]),
            "rules_loaded": len(self.rules),
        }


class _FakeEvent:
    __slots__ = ("timestamp", "source", "event_id", "computer")
    def __init__(self, ts, src, eid, comp):
        self.timestamp = ts; self.source = src
        self.event_id = eid; self.computer = comp
