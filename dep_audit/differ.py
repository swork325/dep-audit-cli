"""Diff two audit reports to surface newly introduced issues."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from dep_audit.auditor import AuditReport,from dep_audit.resolver import ResolvedDep


@dataclass
class DepDiff:
    package: str
    file_path: str
    kind: str  # 'new_outdated' | 'new_vulnerable' | 'resolved'
    detail: str = ""


@dataclass
class ReportDiff:
    new_issues: List[DepDiff] = field(default_factory=list)
    resolved_issues: List[DepDiff] = field(default_factory=list)

    @property
    def has_new_issues(self) -> bool:
        return bool(self.new_issues)

    @property
    def total_changes(self) -> int:
        return len(self.new_issues) + len(self.resolved_issues)


def _dep_keys(file_audit: FileAudit) -> dict:
    """Return mapping of (package, kind) -> detail for a FileAudit."""
    keys: dict = {}
    for dep in file_audit.deps:
        if dep.is_outdated:
            keys[(dep.name, "outdated")] = f"{dep.current} -> {dep.latest}"
        for vuln in dep.vulns:
            keys[(dep.name, f"vuln:{vuln.vuln_id}")] = vuln.summary
    return keys


def diff_reports(before: AuditReport, after: AuditReport) -> ReportDiff:
    """Compare two AuditReports and return newly introduced or resolved issues."""
    before_map: dict = {}
    for fa in before.files:
        before_map[fa.path] = _dep_keys(fa)

    after_map: dict = {}
    for fa in after.files:
        after_map[fa.path] = _dep_keys(fa)

    result = ReportDiff()

    all_paths = set(before_map) | set(after_map)
    for path in all_paths:
        before_keys = before_map.get(path, {})
        after_keys = after_map.get(path, {})

        for key, detail in after_keys.items():
            if key not in before_keys:
                pkg, kind = key[0], key[1]
                result.new_issues.append(DepDiff(package=pkg, file_path=path, kind=kind, detail=detail))

        for key, detail in before_keys.items():
            if key not in after_keys:
                pkg, kind = key[0], key[1]
                result.resolved_issues.append(DepDiff(package=pkg, file_path=path, kind=kind, detail=detail))

    return result
