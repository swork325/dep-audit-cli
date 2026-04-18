"""Aggregate audit results into a summary report with statistics."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from dep_audit.auditor import AuditReport, FileAudit


@dataclass
class SummaryStats:
    total_files: int = 0
    files_with_issues: int = 0
    total_deps: int = 0
    outdated_count: int = 0
    vulnerable_count: int = 0
    unique_vulnerabilities: int = 0

    @property
    def clean_files(self) -> int:
        return self.total_files - self.files_with_issues

    @property
    def issue_rate(self) -> float:
        if self.total_files == 0:
            return 0.0
        return round(self.files_with_issues / self.total_files * 100, 1)


@dataclass
class ProjectSummary:
    stats: SummaryStats
    report: AuditReport
    top_issues: List[str] = field(default_factory=list)


def compute_stats(report: AuditReport) -> SummaryStats:
    stats = SummaryStats()
    stats.total_files = len(report.file_audits)
    stats.total_deps = report.total_deps

    vuln_ids: set[str] = set()

    for fa in report.file_audits:
        if fa.has_issues:
            stats.files_with_issues += 1
        for dep in fa.deps:
            if dep.latest and dep.installed != dep.latest:
                stats.outdated_count += 1
            for v in dep.vulns:
                stats.vulnerable_count += 1
                if v.vuln_id:
                    vuln_ids.add(v.vuln_id)

    stats.unique_vulnerabilities = len(vuln_ids)
    return stats


def build_top_issues(report: AuditReport, limit: int = 5) -> list[str]:
    issues: list[str] = []
    for fa in report.file_audits:
        for dep in fa.deps:
            for v in dep.vulns:
                msg = f"{dep.name}: {v.description or v.vuln_id}"
                if msg not in issues:
                    issues.append(msg)
                if len(issues) >= limit:
                    return issues
    return issues


def summarize(report: AuditReport) -> ProjectSummary:
    stats = compute_stats(report)
    top = build_top_issues(report)
    return ProjectSummary(stats=stats, report=report, top_issues=top)
