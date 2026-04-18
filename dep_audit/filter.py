"""Filtering utilities to narrow audit results by severity, package name, or file path."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import List, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


@dataclass
class FilterConfig:
    only_outdated: bool = False
    only_vulnerable: bool = False
    min_severity: Optional[str] = None  # "low", "medium", "high", "critical"
    package_glob: Optional[str] = None  # e.g. "django*"
    path_glob: Optional[str] = None  # e.g. "**/dev*"


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _dep_matches(dep: ResolvedDep, cfg: FilterConfig) -> bool:
    if cfg.only_outdated and not dep.is_outdated:
        return False
    if cfg.only_vulnerable and not dep.vulns:
        return False
    if cfg.package_glob and not fnmatch(dep.name.lower(), cfg.package_glob.lower()):
        return False
    if cfg.min_severity:
        min_rank = _SEVERITY_RANK.get(cfg.min_severity.lower(), 0)
        sev_ranks = [
            _SEVERITY_RANK.get((v.severity or "").lower(), 0) for v in (dep.vulns or [])
        ]
        if not any(r >= min_rank for r in sev_ranks):
            return False
    return True


def filter_report(report: AuditReport, cfg: FilterConfig) -> AuditReport:
    """Return a new AuditReport containing only deps that match *cfg*."""
    filtered_files: List[FileAudit] = []
    for fa in report.files:
        if cfg.path_glob and not fnmatch(str(fa.path), cfg.path_glob):
            continue
        matching = [d for d in fa.deps if _dep_matches(d, cfg)]
        if matching:
            filtered_files.append(FileAudit(path=fa.path, deps=matching))
    return AuditReport(files=filtered_files)
