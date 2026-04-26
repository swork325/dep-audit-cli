"""Risk matrix: cross-reference outdated status and vulnerability severity
into a 2-D risk cell for each dependency."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep

# Axes
OUTDATED_LEVELS = ("current", "outdated")
VULN_LEVELS = ("none", "low", "medium", "high", "critical")

# Cell label: (outdated_level, vuln_level) -> risk label
_CELL_LABEL: Dict[tuple, str] = {
    ("current", "none"): "ok",
    ("current", "low"): "low",
    ("current", "medium"): "medium",
    ("current", "high"): "high",
    ("current", "critical"): "critical",
    ("outdated", "none"): "low",
    ("outdated", "low"): "medium",
    ("outdated", "medium"): "high",
    ("outdated", "high"): "critical",
    ("outdated", "critical"): "critical",
}


@dataclass
class RiskCell:
    package: str
    outdated_level: str
    vuln_level: str
    risk: str
    source_files: List[str] = field(default_factory=list)


@dataclass
class RiskMatrix:
    cells: List[RiskCell] = field(default_factory=list)

    def by_risk(self, risk: str) -> List[RiskCell]:
        return [c for c in self.cells if c.risk == risk]

    def critical(self) -> List[RiskCell]:
        return self.by_risk("critical")

    def total(self) -> int:
        return len(self.cells)


def _highest_severity(dep: ResolvedDep) -> str:
    if not dep.vulns:
        return "none"
    order = ["none", "low", "medium", "high", "critical"]
    best = "none"
    for v in dep.vulns:
        sev = (v.severity or "none").lower()
        if sev not in order:
            sev = "none"
        if order.index(sev) > order.index(best):
            best = sev
    return best


def build_risk_matrix(report: AuditReport) -> RiskMatrix:
    """Aggregate all deps across all files into a RiskMatrix."""
    # package -> {outdated_level, vuln_level, files}
    seen: Dict[str, dict] = {}
    order = ["none", "low", "medium", "high", "critical"]

    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            ol = "outdated" if dep.is_outdated else "current"
            vl = _highest_severity(dep)
            if key not in seen:
                seen[key] = {"name": dep.name, "ol": ol, "vl": vl, "files": []}
            else:
                # escalate
                if ol == "outdated":
                    seen[key]["ol"] = "outdated"
                if order.index(vl) > order.index(seen[key]["vl"]):
                    seen[key]["vl"] = vl
            if fa.path not in seen[key]["files"]:
                seen[key]["files"].append(fa.path)

    cells = []
    for info in seen.values():
        risk = _CELL_LABEL.get((info["ol"], info["vl"]), "ok")
        cells.append(RiskCell(
            package=info["name"],
            outdated_level=info["ol"],
            vuln_level=info["vl"],
            risk=risk,
            source_files=info["files"],
        ))

    cells.sort(key=lambda c: (["ok", "low", "medium", "high", "critical"].index(c.risk)), reverse=True)
    return RiskMatrix(cells=cells)
