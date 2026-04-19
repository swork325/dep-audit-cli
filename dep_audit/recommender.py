"""Suggest replacement or upgrade actions for problematic dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class Recommendation:
    package: str
    current_version: Optional[str]
    latest_version: Optional[str]
    action: str  # "upgrade", "review_vulns", "upgrade_and_review"
    reason: str
    vuln_ids: List[str] = field(default_factory=list)


def _action(dep: ResolvedDep) -> str:
    outdated = dep.latest_version and dep.current_version != dep.latest_version
    vulnerable = bool(dep.vulns)
    if outdated and vulnerable:
        return "upgrade_and_review"
    if vulnerable:
        return "review_vulns"
    return "upgrade"


def _reason(dep: ResolvedDep) -> str:
    parts: List[str] = []
    if dep.latest_version and dep.current_version != dep.latest_version:
        parts.append(
            f"newer version available ({dep.current_version} -> {dep.latest_version})"
        )
    if dep.vulns:
        ids = ", ".join(v.vuln_id for v in dep.vulns)
        parts.append(f"known vulnerabilities: {ids}")
    return "; ".join(parts) if parts else "no issues"


def recommend_for_dep(dep: ResolvedDep) -> Optional[Recommendation]:
    """Return a Recommendation if the dep needs attention, else None."""
    outdated = dep.latest_version and dep.current_version != dep.latest_version
    if not outdated and not dep.vulns:
        return None
    return Recommendation(
        package=dep.name,
        current_version=dep.current_version,
        latest_version=dep.latest_version,
        action=_action(dep),
        reason=_reason(dep),
        vuln_ids=[v.vuln_id for v in dep.vulns],
    )


def build_recommendations(report: AuditReport) -> List[Recommendation]:
    """Collect recommendations for all deps across all files in a report."""
    seen: dict[str, Recommendation] = {}
    for file_audit in report.files:
        for dep in file_audit.deps:
            rec = recommend_for_dep(dep)
            if rec and rec.package not in seen:
                seen[rec.package] = rec
    return sorted(seen.values(), key=lambda r: r.package.lower())
