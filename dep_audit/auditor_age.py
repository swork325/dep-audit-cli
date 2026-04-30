"""Compute age-based risk for each dependency using PyPI release dates."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_OLD_THRESHOLD_DAYS = 365 * 3  # 3 years


@dataclass
class AgeEntry:
    name: str
    version: str
    release_date: Optional[datetime]
    age_days: Optional[int]
    is_old: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "release_date": self.release_date.isoformat() if self.release_date else None,
            "age_days": self.age_days,
            "is_old": self.is_old,
        }


@dataclass
class AgeReport:
    entries: List[AgeEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def old_count(self) -> int:
        return sum(1 for e in self.entries if e.is_old)

    def find(self, name: str) -> Optional[AgeEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None


def _fetch_release_date(
    dep: ResolvedDep,
    session: Optional[requests.Session] = None,
) -> Optional[datetime]:
    sess = session or requests.Session()
    try:
        resp = sess.get(_PYPI_URL.format(name=dep.name), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {})
        version_files = releases.get(dep.current_version or "", [])
        for f in version_files:
            upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
            if upload_time:
                dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                return dt.astimezone(timezone.utc)
    except Exception:
        pass
    return None


def _age_entry(
    dep: ResolvedDep,
    session: Optional[requests.Session] = None,
    threshold_days: int = _OLD_THRESHOLD_DAYS,
) -> AgeEntry:
    release_date = _fetch_release_date(dep, session=session)
    if release_date is not None:
        now = datetime.now(timezone.utc)
        age_days = (now - release_date).days
        is_old = age_days >= threshold_days
    else:
        age_days = None
        is_old = False
    return AgeEntry(
        name=dep.name,
        version=dep.current_version or "",
        release_date=release_date,
        age_days=age_days,
        is_old=is_old,
    )


def build_age_report(
    report: AuditReport,
    session: Optional[requests.Session] = None,
    threshold_days: int = _OLD_THRESHOLD_DAYS,
) -> AgeReport:
    seen: set = set()
    entries: List[AgeEntry] = []
    for fa in report.files:
        for dep in fa.deps:
            key = (dep.name.lower().replace("-", "_"), dep.current_version or "")
            if key in seen:
                continue
            seen.add(key)
            entries.append(_age_entry(dep, session=session, threshold_days=threshold_days))
    return AgeReport(entries=entries)
