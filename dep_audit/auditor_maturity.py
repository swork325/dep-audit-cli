"""Maturity assessment: evaluate how mature each dependency is based on
version number, release history, and age of the project on PyPI."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class MaturityEntry:
    name: str
    current_version: str
    first_release_date: Optional[datetime]
    total_releases: int
    is_mature: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "current_version": self.current_version,
            "first_release_date": (
                self.first_release_date.isoformat() if self.first_release_date else None
            ),
            "total_releases": self.total_releases,
            "is_mature": self.is_mature,
            "reason": self.reason,
        }


@dataclass
class MaturityReport:
    entries: list[MaturityEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def immature_count(self) -> int:
        return sum(1 for e in self.entries if not e.is_mature)

    def find(self, name: str) -> Optional[MaturityEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None


_MATURE_RELEASE_THRESHOLD = 5
_MATURE_AGE_DAYS = 180


def _fetch_pypi_maturity(name: str, session: requests.Session) -> tuple[Optional[datetime], int]:
    """Return (first_release_date, total_releases) from PyPI."""
    try:
        resp = session.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {})
        total = len(releases)
        dates = []
        for version_files in releases.values():
            for f in version_files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        dates.append(dt)
                    except ValueError:
                        pass
        first = min(dates) if dates else None
        return first, total
    except Exception:
        return None, 0


def _assess(first_release_date: Optional[datetime], total_releases: int) -> tuple[bool, str]:
    now = datetime.now(timezone.utc)
    if total_releases == 0:
        return False, "no release data available"
    if total_releases < _MATURE_RELEASE_THRESHOLD:
        return False, f"only {total_releases} release(s) published"
    if first_release_date is not None:
        age_days = (now - first_release_date).days
        if age_days < _MATURE_AGE_DAYS:
            return False, f"project is only {age_days} days old"
    return True, "sufficient releases and project age"


def build_maturity_report(
    report: AuditReport,
    session: Optional[requests.Session] = None,
) -> MaturityReport:
    if session is None:
        session = requests.Session()
    seen: dict[str, MaturityEntry] = {}
    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower().replace("-", "_")
            if key in seen:
                continue
            first, total = _fetch_pypi_maturity(dep.name, session)
            mature, reason = _assess(first, total)
            seen[key] = MaturityEntry(
                name=dep.name,
                current_version=dep.current_version or "",
                first_release_date=first,
                total_releases=total,
                is_mature=mature,
                reason=reason,
            )
    return MaturityReport(entries=list(seen.values()))
