"""Watchlist: flag specific packages for priority attention."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep

DEFAULT_WATCHLIST_FILE = ".dep-watchlist.json"


def load_watchlist(path: str = DEFAULT_WATCHLIST_FILE) -> List[str]:
    """Return normalised package names from the watchlist file."""
    try:
        data = json.loads(Path(path).read_text())
        if isinstance(data, list):
            return [str(p).lower() for p in data]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return []


def save_watchlist(packages: List[str], path: str = DEFAULT_WATCHLIST_FILE) -> None:
    """Persist a list of package names to the watchlist file."""
    Path(path).write_text(json.dumps(sorted({p.lower() for p in packages}), indent=2))


def is_watched(dep: ResolvedDep, watchlist: List[str]) -> bool:
    """Return True if the dep's package name is on the watchlist."""
    return dep.name.lower() in watchlist


def flag_watched_deps(dep: ResolvedDep, watchlist: List[str]) -> ResolvedDep:
    """Return the dep unchanged; caller uses is_watched to annotate."""
    return dep


def filter_by_watchlist(report: AuditReport, watchlist: List[str]) -> AuditReport:
    """Return a new AuditReport containing only watchlisted deps."""
    filtered: List[FileAudit] = []
    for fa in report.files:
        deps = [d for d in fa.deps if is_watched(d, watchlist)]
        if deps:
            filtered.append(FileAudit(path=fa.path, deps=deps))
    return AuditReport(files=filtered)
