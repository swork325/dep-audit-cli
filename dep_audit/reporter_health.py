"""Health score computation for the overall audit report."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability

_SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5}
_OUTDATED_PENALTY = 8
_MAX_SCORE = 100


@dataclass
class HealthScore:
    score: int  # 0-100, higher is healthier
    total_deps: int
    outdated_count: int
    vuln_count: int
    penalty: int
    grade: str = field(init=False)

    def __post_init__(self) -> None:
        self.grade = _letter_grade(self.score)


def _letter_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _vuln_penalty(vulns: List[Vulnerability]) -> int:
    return sum(_SEVERITY_WEIGHTS.get(v.severity.lower(), 5) for v in vulns)


def compute_health(report: AuditReport) -> HealthScore:
    """Return a HealthScore for the given AuditReport."""
    all_deps: List[ResolvedDep] = [
        dep for fa in report.files for dep in fa.deps
    ]
    total = len(all_deps)
    if total == 0:
        return HealthScore(
            score=_MAX_SCORE,
            total_deps=0,
            outdated_count=0,
            vuln_count=0,
            penalty=0,
        )

    outdated = [d for d in all_deps if d.is_outdated]
    all_vulns: List[Vulnerability] = [
        v for d in all_deps for v in (d.vulns or [])
    ]

    penalty = len(outdated) * _OUTDATED_PENALTY + _vuln_penalty(all_vulns)
    # Scale penalty relative to total deps so large projects aren't unfairly punished
    scaled = int(penalty / max(total, 1))
    score = max(0, _MAX_SCORE - scaled)

    return HealthScore(
        score=score,
        total_deps=total,
        outdated_count=len(outdated),
        vuln_count=len(all_vulns),
        penalty=penalty,
    )
