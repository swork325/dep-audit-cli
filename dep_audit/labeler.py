"""Attach custom labels to dependencies based on name patterns."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

# LabelMap: {label: [package_name_pattern, ...]}
LabelMap = Dict[str, List[str]]

_DEFAULT_PATH = Path(".dep_labels.json")


def load_label_map(path: Path = _DEFAULT_PATH) -> LabelMap:
    """Load label map from JSON file. Returns empty dict if missing or invalid."""
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if isinstance(v, list)}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_label_map(label_map: LabelMap, path: Path = _DEFAULT_PATH) -> None:
    """Persist label map to JSON file."""
    path.write_text(json.dumps(label_map, indent=2))


def labels_for_dep(dep: ResolvedDep, label_map: LabelMap) -> List[str]:
    """Return all labels that match the given dependency."""
    name = dep.name.lower()
    return [
        label
        for label, patterns in label_map.items()
        if any(name == p.lower() for p in patterns)
    ]


def label_report(
    report: AuditReport, label_map: LabelMap
) -> Dict[str, List[ResolvedDep]]:
    """Return a mapping of label -> deps across the full report."""
    result: Dict[str, List[ResolvedDep]] = {}
    for file_audit in report.files:
        for dep in file_audit.deps:
            for label in labels_for_dep(dep, label_map):
                result.setdefault(label, []).append(dep)
    return result


def filter_by_label(
    report: AuditReport, label: str, label_map: LabelMap
) -> List[ResolvedDep]:
    """Return all deps in the report that carry the given label."""
    labeled = label_report(report, label_map)
    return labeled.get(label, [])
