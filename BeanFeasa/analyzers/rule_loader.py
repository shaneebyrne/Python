"""
BeanFeasa — Detection Rule Loader v3.

v3: Proper named-group condition evaluation.

PREVIOUS BUG (caused win-security-007 catastrophic regression):
  When a rule used named detection groups (e.g. log_cleared, system_log_cleared)
  with an OR condition between them, the loader flattened ALL conditions into
  one list and set condition_logic="or". This meant ANY single condition from
  ANY group — including broad ones like source="Microsoft-Windows-Security-Auditing"
  — could trigger the rule alone, generating hundreds of false positives.

FIX:
  Named groups are now stored as separate condition sets (ConditionGroup objects).
  Each group is evaluated as AND of its conditions.
  The condition string determines how groups are combined:
    - OR between groups: rule fires if ANY group fully matches
    - AND between groups: rule fires if ALL non-exclude groups fully match
  Exclusion groups (after 'not' in condition string) suppress the rule if
  any of their conditions match the event.

  Single-block rules (condition: selection) work exactly as before.
"""

import re
from pathlib import Path
from dataclasses import dataclass, field

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class DetectionCondition:
    field: str
    values: list[str] = field(default_factory=list)
    modifier: str = "contains"


@dataclass
class ConditionGroup:
    """A named detection block — all conditions within are AND'd."""
    name: str
    conditions: list[DetectionCondition] = field(default_factory=list)
    is_exclude: bool = False


@dataclass
class DetectionRule:
    id: str
    title: str
    description: str = ""
    severity: str = "medium"
    author: str = ""
    tags: list[str] = field(default_factory=list)
    # Flat conditions (single-group rules — backward compat)
    conditions: list[DetectionCondition] = field(default_factory=list)
    exclude_conditions: list[DetectionCondition] = field(default_factory=list)
    condition_logic: str = "and"
    # Named groups (multi-group rules)
    groups: list[ConditionGroup] = field(default_factory=list)
    group_logic: str = "or"   # "or" = any group matches; "and" = all groups must match
    enabled: bool = True

    @property
    def is_grouped(self) -> bool:
        return len(self.groups) > 0

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.title} ({self.id})"


def load_rules(rules_dir: str) -> tuple[list[DetectionRule], list[str]]:
    if yaml is None:
        return [], ["PyYAML not installed."]
    rules, errors = [], []
    for fpath in sorted(Path(rules_dir).glob("**/*.y*ml")):
        if fpath.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            raw = fpath.read_text(encoding="utf-8", errors="replace")
            for doc in yaml.safe_load_all(raw):
                if not isinstance(doc, dict):
                    continue
                try:
                    rule = _build_rule(doc, fpath.stem)
                    if rule:
                        rules.append(rule)
                except Exception as exc:
                    errors.append(f"{fpath.name}: {exc}")
        except Exception as exc:
            errors.append(f"{fpath.name}: {exc}")
    return rules, errors


def _build_rule(doc: dict, fallback_id: str) -> DetectionRule | None:
    title = doc.get("title", "")
    if not title:
        return None

    rule = DetectionRule(
        id=str(doc.get("id", fallback_id)),
        title=title,
        description=doc.get("description", ""),
        severity=doc.get("level", doc.get("severity", "medium")).lower(),
        author=doc.get("author", ""),
        tags=doc.get("tags", []) if isinstance(doc.get("tags"), list) else [doc.get("tags", "")],
        enabled=doc.get("enabled", True),
    )

    detection = doc.get("detection", {})
    if not detection:
        return None

    cond_str = str(detection.get("condition", "selection")).lower().strip()

    # Identify all named blocks (excluding meta-keys)
    named_blocks = {k: v for k, v in detection.items()
                    if k not in ("condition", "timeframe") and isinstance(v, dict)}

    # Identify exclusion block names from "not <name>" in condition string
    exclude_names: set[str] = set(re.findall(r'\bnot\s+(\w+)', cond_str))
    for key in named_blocks:
        if str(key).lower().startswith("filter"):
            exclude_names.add(key.lower())

    # Single unnamed selection block → flat rule (backward compat)
    if len(named_blocks) <= 1:
        rule.conditions, rule.exclude_conditions = _parse_flat(detection, cond_str)
        rule.condition_logic = "or" if (" or " in cond_str) else "and"
        if not rule.conditions:
            return None
        return rule

    # Multi-group rule → evaluate groups as units
    selection_names = [k for k in named_blocks if k.lower() not in exclude_names]
    # Determine group logic: AND between groups if "and" links them and no "or" between selection blocks
    # E.g. "A and B" → AND; "(A or B) and not filter" → OR
    group_logic = "or"
    # Strip out the "and not ..." part, then check remaining tokens
    stripped = re.sub(r'\band\s+not\s+\w+', '', cond_str)
    stripped = re.sub(r'\(|\)', '', stripped).strip()
    # If only "and" connects the non-exclude names and no "or" appears → AND logic
    if " or " not in stripped and " and " in stripped:
        group_logic = "and"
    elif " or " not in stripped and " and " not in stripped:
        group_logic = "and"  # Single group or simple condition

    rule.group_logic = group_logic

    for block_name, block_val in named_blocks.items():
        is_excl = block_name.lower() in exclude_names
        group = ConditionGroup(name=block_name, is_exclude=is_excl)
        if isinstance(block_val, dict):
            for fld, match_val in block_val.items():
                cond = _parse_condition(fld, match_val)
                if cond:
                    group.conditions.append(cond)
        rule.groups.append(group)

    # Validate at least one non-exclude group with conditions
    sel_groups = [g for g in rule.groups if not g.is_exclude and g.conditions]
    if not sel_groups:
        return None

    # Also populate flat conditions from selection groups (for strength classifier compat)
    for g in sel_groups:
        rule.conditions.extend(g.conditions)
    for g in rule.groups:
        if g.is_exclude:
            rule.exclude_conditions.extend(g.conditions)

    return rule


def _parse_flat(detection: dict, cond_str: str) -> tuple[list, list]:
    conditions, exclude_conditions = [], []
    exclude_names = set(re.findall(r'\bnot\s+(\w+)', cond_str))
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        is_excl = key.lower() in exclude_names or str(key).lower().startswith("filter")
        if isinstance(value, dict):
            for fld, match_val in value.items():
                cond = _parse_condition(fld, match_val)
                if cond:
                    (exclude_conditions if is_excl else conditions).append(cond)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for fld, match_val in item.items():
                        cond = _parse_condition(fld, match_val)
                        if cond:
                            (exclude_conditions if is_excl else conditions).append(cond)
    return conditions, exclude_conditions


def _parse_condition(field_spec: str, match_value) -> DetectionCondition | None:
    parts = str(field_spec).split("|")
    fld = parts[0].strip().lower()
    modifier = parts[1].strip().lower() if len(parts) > 1 else "contains"

    aliases = {
        "eventid": "event_id", "provider": "source", "sourcename": "source",
        "providername": "source", "hostname": "computer", "computername": "computer",
        "logname": "channel", "msg": "message",
        "entrytype": "level", "leveldisplayname": "level",
        "timegenerated": "timestamp", "timecreated": "timestamp",
    }
    fld = aliases.get(fld, fld)

    values = [str(v) for v in match_value] if isinstance(match_value, list) else [str(match_value)]
    if modifier not in {"contains", "equals", "startswith", "endswith", "regex", "exists"}:
        modifier = "contains"

    return DetectionCondition(field=fld, values=values, modifier=modifier)
