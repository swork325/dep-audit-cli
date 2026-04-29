"""Check whether packages appear to be actively maintained."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_STALE_DAYS = 365  # default threshold: 1 year without a release


@dataclass
class MaintainerEntry:
    name: str
    latest_version: str
    last_release_date: Optional[datetime]
    days_since_release: Optional[int]
    is_maintained: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "latest_version": self.latest_version,
            "last_release_date": self.last_release_date.isoformat() if self.last_release_date else None,
            "days_since_release": self.days_since_release,
            "is_maintained": self.is_maintained,
        }


@dataclass
class MaintainerReport:
    entries: List[MaintainerEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def unmaintained_count(self) -> int:
        return sum(1 for e in self.entries if not e.is_maintained)

    def unmaintained(self) -> List[MaintainerEntry]:
        return [e for e in self.entries if not e.is_maintained]


def _fetch_last_release_date(name: str, session: requests.Session) -> Optional[datetime]:
    try:
        resp = session.get(_PYPI_URL.format(name=name), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {})
        latest = data.get("info", {}).get("version", "")
        upload_times = [
            item["upload_time_iso_8601"]
            for item in releases.get(latest, [])
            if "upload_time_iso_8601" in item
        ]
        if not upload_times:
            return None
        latest_time = max(upload_times)
        return datetime.fromisoformat(latest_time.replace("Z", "+00:00"))
    except Exception:
        return None


def check_maintainer(dep: ResolvedDep, session: requests.Session, stale_days: int = _STALE_DAYS) -> MaintainerEntry:
    last_date = _fetch_last_release_date(dep.name, session)
    days = None
    if last_date is not None:
        now = datetime.now(tz=timezone.utc)
        days = (now - last_date).days
    is_maintained = (days is not None) and (days <= stale_days)
    return MaintainerEntry(
        name=dep.name,
        latest_version=dep.latest or dep.installed,
        last_release_date=last_date,
        days_since_release=days,
        is_maintained=is_maintained,
    )


def build_maintainer_report(
    report: AuditReport,
    session: Optional[requests.Session] = None,
    stale_days: int = _STALE_DAYS,
) -> MaintainerReport:
    if session is None:
        session = requests.Session()
    seen: set = set()
    entries: List[MaintainerEntry] = []
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key not in seen:
                seen.add(key)
                entries.append(check_maintainer(dep, session, stale_days))
    return MaintainerReport(entries=entries)
