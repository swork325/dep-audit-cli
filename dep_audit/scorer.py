"""Dependency risk scorer — assigns a numeric risk score to each resolved dep."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport

# Weights
_OUTDATED_SCORE = 30
_VULN_BASE = 40
_SEVERITY_BONUS = {"critical": 30, "high": 20, "medium": 10, "low": 5}


@dataclass
class ScoredDep:
    dep: ResolvedDep
    score: int
    reasons: List[str]


def score_dep(dep: ResolvedDep) -> ScoredDep:
    """Return a ScoredDep with a risk score in [0, 100]."""
    total = 0
    reasons: List[str] = []

    if dep.is_outdated:
        total += _OUTDATED_SCORE
        reasons.append("outdated")

    for vuln in dep.vulnerabilities:
        total += _VULN_BASE
        severity = (vuln.severity or "").lower()
        bonus = _SEVERITY_BONUS.get(severity, 0)
        total += bonus
        reasons.append(f"vuln:{vuln.vuln_id}({severity})")

    return ScoredDep(dep=dep, score=min(total, 100), reasons=reasons)


@dataclass
class ScoredReport:
    scored: List[ScoredDep]

    def top(self, n: int = 10) -> List[ScoredDep]:
        return sorted(self.scored, key=lambda s: s.score, reverse=True)[:n]

    def above(self, threshold: int) -> List[ScoredDep]:
        return [s for s in self.scored if s.score >= threshold]


def score_report(report: AuditReport) -> ScoredReport:
    """Score every dep across all files in an AuditReport."""
    scored: List[ScoredDep] = []
    for file_audit in report.files:
        for dep in file_audit.deps:
            scored.append(score_dep(dep))
    return ScoredReport(scored=scored)
