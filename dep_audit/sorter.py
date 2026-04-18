"""Sort AuditReport dependencies by various criteria."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, List

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep

SortKey = Literal["name", "severity", "outdated", "file"]


@dataclass
class SortConfig:
    key: SortKey = "name"
    reverse: bool = False


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4, "": 4}


def _dep_severity(dep: ResolvedDep) -> int:
    if not dep.vulns:
        return _SEVERITY_ORDER[None]
    best = min(
        _SEVERITY_ORDER.get((v.severity or "").lower(), 4) for v in dep.vulns
    )
    return best


def _sort_deps(deps: List[ResolvedDep], cfg: SortConfig) -> List[ResolvedDep]:
    if cfg.key == "name":
        key_fn = lambda d: d.name.lower()
    elif cfg.key == "severity":
        key_fn = _dep_severity
    elif cfg.key == "outdated":
        key_fn = lambda d: (not d.is_outdated, d.name.lower())
    else:
        key_fn = lambda d: d.name.lower()
    return sorted(deps, key=key_fn, reverse=cfg.reverse)


def sort_report(report: AuditReport, cfg: SortConfig) -> AuditReport:
    """Return a new AuditReport with deps sorted within each FileAudit."""
    sorted_files: List[FileAudit] = []
    for fa in report.files:
        sorted_deps = _sort_deps(list(fa.deps), cfg)
        sorted_files.append(
            FileAudit(path=fa.path, deps=sorted_deps)
        )
    if cfg.key == "file":
        sorted_files = sorted(
            sorted_files,
            key=lambda f: str(f.path).lower(),
            reverse=cfg.reverse,
        )
    return AuditReport(files=sorted_files)
