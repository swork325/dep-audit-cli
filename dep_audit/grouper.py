"""Group audit report results by various dimensions."""
from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


@dataclass
class GroupedReport:
    by_package: Dict[str, List[FileAudit]] = field(default_factory=dict)
    by_severity: Dict[str, List[ResolvedDep]] = field(default_factory=dict)
    by_file: Dict[str, FileAudit] = field(default_factory=dict)


def group_by_package(report: AuditReport) -> Dict[str, List[FileAudit]]:
    """Map package name -> list of FileAudits that contain it."""
    mapping: Dict[str, List[FileAudit]] = defaultdict(list)
    for fa in report.files:
        for dep in fa.deps:
            mapping[dep.name].append(fa)
    return dict(mapping)


def group_by_severity(report: AuditReport) -> Dict[str, List[ResolvedDep]]:
    """Map severity label -> deps that have vulnerabilities at that severity."""
    mapping: Dict[str, List[ResolvedDep]] = defaultdict(list)
    for fa in report.files:
        for dep in fa.deps:
            if dep.vulns:
                for v in dep.vulns:
                    sev = (v.severity or "UNKNOWN").upper()
                    mapping[sev].append(dep)
                    break  # one entry per dep per severity bucket
    return dict(mapping)


def group_by_file(report: AuditReport) -> Dict[str, FileAudit]:
    """Map file path -> FileAudit."""
    return {fa.path: fa for fa in report.files}


def group_report(report: AuditReport) -> GroupedReport:
    return GroupedReport(
        by_package=group_by_package(report),
        by_severity=group_by_severity(report),
        by_file=group_by_file(report),
    )
