"""Fetch and report download popularity stats for dependencies via PyPI Stats API."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List

import requests

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_STATS_URL = "https://pypistats.org/api/packages/{name}/recent"
_TIMEOUT = 8


@dataclass
class PopularityEntry:
    name: str
    version: str
    last_month: Optional[int]
    last_week: Optional[int]
    last_day: Optional[int]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "last_month": self.last_month,
            "last_week": self.last_week,
            "last_day": self.last_day,
        }


@dataclass
class PopularityReport:
    entries: List[PopularityEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    def find(self, name: str) -> Optional[PopularityEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None

    def top(self, n: int = 5) -> List[PopularityEntry]:
        """Return top-n entries sorted by last_month downloads descending."""
        sortable = [e for e in self.entries if e.last_month is not None]
        return sorted(sortable, key=lambda e: e.last_month, reverse=True)[:n]  # type: ignore[arg-type]


def fetch_popularity(dep: ResolvedDep, session: Optional[requests.Session] = None) -> Optional[PopularityEntry]:
    sess = session or requests.Session()
    url = _STATS_URL.format(name=dep.name.lower().replace("_", "-"))
    try:
        resp = sess.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return PopularityEntry(
            name=dep.name,
            version=dep.version,
            last_month=data.get("last_month"),
            last_week=data.get("last_week"),
            last_day=data.get("last_day"),
        )
    except Exception:
        return None


def build_popularity_report(
    report: AuditReport,
    session: Optional[requests.Session] = None,
) -> PopularityReport:
    seen: set[str] = set()
    entries: List[PopularityEntry] = []
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key in seen:
                continue
            seen.add(key)
            entry = fetch_popularity(dep, session=session)
            if entry is not None:
                entries.append(entry)
    return PopularityReport(entries=entries)
