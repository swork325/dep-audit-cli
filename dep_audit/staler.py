"""Staleness detection: flag deps that haven't been updated in N days."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class StaleDep:
    dep: ResolvedDep
    days_since_release: int
    threshold_days: int

    @property
    def is_stale(self) -> bool:
        return self.days_since_release >= self.threshold_days


@dataclass
class StalenessReport:
    stale: List[StaleDep] = field(default_factory=list)
    fresh: List[StaleDep] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.stale) + len(self.fresh)

    @property
    def stale_count(self) -> int:
        return len(self.stale)

    @property
    def stale_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.stale_count / self.total


def _days_since(publish_date: datetime) -> int:
    now = datetime.now(tz=timezone.utc)
    if publish_date.tzinfo is None:
        publish_date = publish_date.replace(tzinfo=timezone.utc)
    delta = now - publish_date
    return max(0, delta.days)


def classify_dep(
    dep: ResolvedDep,
    publish_date: Optional[datetime],
    threshold_days: int,
) -> Optional[StaleDep]:
    """Return a StaleDep if publish_date is known, else None."""
    if publish_date is None:
        return None
    days = _days_since(publish_date)
    return StaleDep(dep=dep, days_since_release=days, threshold_days=threshold_days)


def build_staleness_report(
    deps: List[ResolvedDep],
    publish_dates: dict,  # {dep.name: datetime | None}
    threshold_days: int = 365,
) -> StalenessReport:
    """Build a StalenessReport for a flat list of ResolvedDep objects."""
    report = StalenessReport()
    for dep in deps:
        date = publish_dates.get(dep.name)
        classified = classify_dep(dep, date, threshold_days)
        if classified is None:
            continue
        if classified.is_stale:
            report.stale.append(classified)
        else:
            report.fresh.append(classified)
    return report
