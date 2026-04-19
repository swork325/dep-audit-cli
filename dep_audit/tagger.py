"""Tag dependencies with custom labels for grouping and reporting."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit

# tag map: package_name (lower) -> list of tags
TagMap = Dict[str, List[str]]


def load_tag_map(path: str | Path) -> TagMap:
    """Load tag definitions from a JSON file. Returns empty dict on missing/invalid."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            return {}
        return {k.lower(): list(v) for k, v in data.items() if isinstance(v, list)}
    except (json.JSONDecodeError, TypeError):
        return {}


def save_tag_map(tag_map: TagMap, path: str | Path) -> None:
    """Persist a tag map to disk as JSON."""
    Path(path).write_text(json.dumps(tag_map, indent=2))


def tags_for_dep(dep: ResolvedDep, tag_map: TagMap) -> List[str]:
    """Return tags assigned to a dependency, or empty list."""
    return tag_map.get(dep.name.lower(), [])


def tag_report(report: AuditReport, tag_map: TagMap) -> Dict[str, List[ResolvedDep]]:
    """Return a mapping of tag -> deps that carry that tag across the whole report."""
    result: Dict[str, List[ResolvedDep]] = {}
    for file_audit in report.files:
        for dep in file_audit.deps:
            for tag in tags_for_dep(dep, tag_map):
                result.setdefault(tag, []).append(dep)
    return result


def filter_by_tag(report: AuditReport, tag: str, tag_map: TagMap) -> AuditReport:
    """Return a new AuditReport containing only deps that have the given tag."""
    filtered: List[FileAudit] = []
    for file_audit in report.files:
        kept = [d for d in file_audit.deps if tag in tags_for_dep(d, tag_map)]
        if kept:
            filtered.append(FileAudit(path=file_audit.path, deps=kept))
    return AuditReport(files=filtered)
