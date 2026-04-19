"""Compare two AuditReports and produce a human-readable change summary."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class DepChange:
    package: str
    old_version: str | None
    new_version: str | None
    change_type: str  # 'added' | 'removed' | 'upgraded' | 'downgraded' | 'unchanged'


@dataclass
class ComparisonResult:
    added: List[DepChange] = field(default_factory=list)
    removed: List[DepChange] = field(default_factory=list)
    upgraded: List[DepChange] = field(default_factory=list)
    downgraded: List[DepChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.upgraded or self.downgraded)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.upgraded) + len(self.downgraded)


def _dep_map(report: AuditReport) -> Dict[str, ResolvedDep]:
    """Flatten all deps across files into a name -> dep mapping."""
    result: Dict[str, ResolvedDep] = {}
    for fa in report.files:
        for dep in fa.deps:
            result[dep.name.lower()] = dep
    return result


def _parse_version(v: str | None) -> Tuple[int, ...]:
    if not v:
        return (0,)
    try:
        return tuple(int(x) for x in v.split(".") if x.isdigit())
    except Exception:
        return (0,)


def compare_reports(old: AuditReport, new: AuditReport) -> ComparisonResult:
    """Compare two audit reports and classify per-package version changes."""
    old_map = _dep_map(old)
    new_map = _dep_map(new)

    result = ComparisonResult()

    all_keys = set(old_map) | set(new_map)
    for key in sorted(all_keys):
        if key not in old_map:
            d = new_map[key]
            result.added.append(DepChange(d.name, None, d.version, "added"))
        elif key not in new_map:
            d = old_map[key]
            result.removed.append(DepChange(d.name, d.version, None, "removed"))
        else:
            old_dep = old_map[key]
            new_dep = new_map[key]
            if old_dep.version == new_dep.version:
                continue
            ov = _parse_version(old_dep.version)
            nv = _parse_version(new_dep.version)
            if nv > ov:
                result.upgraded.append(DepChange(new_dep.name, old_dep.version, new_dep.version, "upgraded"))
            else:
                result.downgraded.append(DepChange(new_dep.name, old_dep.version, new_dep.version, "downgraded"))

    return result
