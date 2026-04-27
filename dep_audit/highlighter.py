"""Highlight newly introduced issues by comparing against a known-good baseline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class HighlightedDep:
    dep: ResolvedDep
    is_new_issue: bool


@dataclass
class HighlightReport:
    file_path: str
    deps: List[HighlightedDep] = field(default_factory=list)

    @property
    def new_issues(self) -> List[HighlightedDep]:
        return [h for h in self.deps if h.is_new_issue]

    @property
    def has_new_issues(self) -> bool:
        return bool(self.new_issues)


def _baseline_keys(report: AuditReport) -> set:
    """Return a set of (file_path, package, installed_version) for all deps in report."""
    keys: set = set()
    for fa in report.files:
        for dep in fa.deps:
            keys.add((fa.file_path, dep.package.lower(), dep.installed_version))
    return keys


def highlight_new_issues(
    current: AuditReport,
    baseline: Optional[AuditReport],
) -> List[HighlightReport]:
    """Return per-file highlight reports marking deps that are new issues.

    A dep is considered a *new issue* when it has an outdated or vulnerable flag
    and was NOT present (same file + package + version) in the baseline.
    """
    baseline_keys = _baseline_keys(baseline) if baseline is not None else set()

    results: List[HighlightReport] = []
    for fa in current.files:
        hr = HighlightReport(file_path=fa.file_path)
        for dep in fa.deps:
            is_issue = dep.is_outdated or bool(dep.vulnerabilities)
            key = (fa.file_path, dep.package.lower(), dep.installed_version)
            is_new = is_issue and key not in baseline_keys
            hr.deps.append(HighlightedDep(dep=dep, is_new_issue=is_new))
        results.append(hr)
    return results


def total_new_issues(highlight_reports: List[HighlightReport]) -> int:
    return sum(len(hr.new_issues) for hr in highlight_reports)
