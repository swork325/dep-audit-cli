"""Combines finder and resolver to produce an audit report for one or more project roots."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dep_audit.finder import find_dependency_files
from dep_audit.resolver import ResolvedDep, resolve_dependencies


@dataclass
class FileAudit:
    """Audit results for a single dependency file."""

    path: Path
    dependencies: List[ResolvedDep] = field(default_factory=list)

    @property
    def outdated(self) -> List[ResolvedDep]:
        return [d for d in self.dependencies if d.outdated]

    @property
    def has_issues(self) -> bool:
        return bool(self.outdated)


@dataclass
class AuditReport:
    """Aggregated audit report across all scanned files."""

    root: Path
    file_audits: List[FileAudit] = field(default_factory=list)

    @property
    def total_deps(self) -> int:
        return sum(len(fa.dependencies) for fa in self.file_audits)

    @property
    def total_outdated(self) -> int:
        return sum(len(fa.outdated) for fa in self.file_audits)

    @property
    def files_with_issues(self) -> List[FileAudit]:
        return [fa for fa in self.file_audits if fa.has_issues]


def audit_project(root: str | Path, *, timeout: int = 10) -> AuditReport:
    """Scan *root* for dependency files and resolve each one.

    Args:
        root: Directory to scan recursively.
        timeout: HTTP timeout forwarded to the resolver.

    Returns:
        An :class:`AuditReport` with results for every discovered file.
    """
    root = Path(root)
    report = AuditReport(root=root)

    for dep_file in find_dependency_files(root):
        resolved = resolve_dependencies(dep_file, timeout=timeout)
        report.file_audits.append(FileAudit(path=dep_file, dependencies=resolved))

    return report
