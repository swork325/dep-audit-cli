"""Audit package commit/release activity to detect abandoned dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_INACTIVE_DAYS = 365  # default threshold


@dataclass
class ActivityEntry:
    name: str
    version: str
    last_release: Optional[datetime]
    days_since_release: Optional[int]
    is_inactive: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "last_release": self.last_release.isoformat() if self.last_release else None,
            "days_since_release": self.days_since_release,
            "is_inactive": self.is_inactive,
        }


@dataclass
class ActivityReport:
    entries: List[ActivityEntry] = field(default_factory=list)

    def total(self) -> int:
        return len(self.entries)

    def inactive_count(self) -> int:
        return sum(1 for e in self.entries if e.is_inactive)

    def inactive_only(self) -> List[ActivityEntry]:
        return [e for e in self.entries if e.is_inactive]


def _fetch_last_release(name: str, session: requests.Session) -> Optional[datetime]:
    try:
        resp = session.get(_PYPI_URL.format(name=name), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {})
        dates = []
        for files in releases.values():
            for f in files:
                upload = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload:
                    try:
                        dates.append(datetime.fromisoformat(upload.rstrip("Z")).replace(tzinfo=timezone.utc))
                    except ValueError:
                        pass
        return max(dates) if dates else None
    except Exception:
        return None


def _assess(dep: ResolvedDep, last_release: Optional[datetime], threshold_days: int) -> ActivityEntry:
    now = datetime.now(timezone.utc)
    days = (now - last_release).days if last_release else None
    inactive = days is not None and days > threshold_days
    return ActivityEntry(
        name=dep.name,
        version=dep.current_version or "",
        last_release=last_release,
        days_since_release=days,
        is_inactive=inactive,
    )


def build_activity_report(
    report: AuditReport,
    threshold_days: int = _INACTIVE_DAYS,
    session: Optional[requests.Session] = None,
) -> ActivityReport:
    session = session or requests.Session()
    seen: dict = {}
    entries: List[ActivityEntry] = []
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key not in seen:
                last = _fetch_last_release(dep.name, session)
                entry = _assess(dep, last, threshold_days)
                seen[key] = entry
            entries.append(seen[key])
    return ActivityReport(entries=entries)
