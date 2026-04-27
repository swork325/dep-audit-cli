"""Dependency heatmap: rank files by their aggregate risk exposure."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability

_SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5,
}
_OUTDATED_WEIGHT = 3


@dataclass
class HeatmapEntry:
    path: str
    score: int
    outdated_count: int
    vuln_count: int

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "score": self.score,
            "outdated_count": self.outdated_count,
            "vuln_count": self.vuln_count,
        }


@dataclass
class Heatmap:
    entries: List[HeatmapEntry] = field(default_factory=list)

    @property
    def hottest(self) -> HeatmapEntry | None:
        return self.entries[0] if self.entries else None

    @property
    def total_score(self) -> int:
        return sum(e.score for e in self.entries)


def _score_file(fa: FileAudit) -> HeatmapEntry:
    score = 0
    outdated_count = 0
    vuln_count = 0
    for dep in fa.deps:
        if dep.is_outdated:
            score += _OUTDATED_WEIGHT
            outdated_count += 1
        for v in dep.vulns:
            weight = _SEVERITY_WEIGHT.get(v.severity.lower(), 5)
            score += weight
            vuln_count += 1
    return HeatmapEntry(
        path=fa.path,
        score=score,
        outdated_count=outdated_count,
        vuln_count=vuln_count,
    )


def build_heatmap(report: AuditReport) -> Heatmap:
    """Build a heatmap from an audit report, sorted hottest-first."""
    entries = [_score_file(fa) for fa in report.files]
    entries.sort(key=lambda e: e.score, reverse=True)
    return Heatmap(entries=entries)
