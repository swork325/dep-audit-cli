"""Classify dependencies into risk tiers based on their audit state."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


class RiskTier(str, Enum):
    CRITICAL = "critical"   # vulnerable with high/critical severity
    HIGH = "high"           # vulnerable with medium severity OR outdated + any vuln
    MEDIUM = "medium"       # outdated only
    LOW = "low"             # unpinned but otherwise clean
    CLEAN = "clean"         # no issues detected


@dataclass
class ClassifiedDep:
    dep: ResolvedDep
    tier: RiskTier
    reasons: List[str] = field(default_factory=list)


@dataclass
class ClassificationReport:
    tiers: Dict[RiskTier, List[ClassifiedDep]] = field(default_factory=dict)

    def by_tier(self, tier: RiskTier) -> List[ClassifiedDep]:
        return self.tiers.get(tier, [])

    def total(self) -> int:
        return sum(len(v) for v in self.tiers.values())

    def critical_count(self) -> int:
        return len(self.by_tier(RiskTier.CRITICAL))


_HIGH_SEVERITIES = {"critical", "high"}
_MEDIUM_SEVERITIES = {"medium"}


def _classify_dep(dep: ResolvedDep) -> ClassifiedDep:
    reasons: List[str] = []
    vulns = dep.vulnerabilities or []
    severities = {v.severity.lower() for v in vulns if v.severity}

    if vulns and (severities & _HIGH_SEVERITIES):
        reasons.append("vulnerable (high/critical severity)")
        if dep.is_outdated:
            reasons.append("outdated")
        return ClassifiedDep(dep=dep, tier=RiskTier.CRITICAL, reasons=reasons)

    if vulns:
        reasons.append("vulnerable (medium severity)")
        if dep.is_outdated:
            reasons.append("outdated")
        return ClassifiedDep(dep=dep, tier=RiskTier.HIGH, reasons=reasons)

    if dep.is_outdated:
        reasons.append("outdated")
        return ClassifiedDep(dep=dep, tier=RiskTier.MEDIUM, reasons=reasons)

    if dep.installed_version and "==" not in (dep.raw_line or ""):
        reasons.append("unpinned")
        return ClassifiedDep(dep=dep, tier=RiskTier.LOW, reasons=reasons)

    return ClassifiedDep(dep=dep, tier=RiskTier.CLEAN, reasons=["no issues"])


def classify_report(report: AuditReport) -> ClassificationReport:
    """Classify every dependency in *report* into a RiskTier."""
    buckets: Dict[RiskTier, List[ClassifiedDep]] = {t: [] for t in RiskTier}
    for file_audit in report.files:
        for dep in file_audit.deps:
            classified = _classify_dep(dep)
            buckets[classified.tier].append(classified)
    return ClassificationReport(tiers=buckets)
