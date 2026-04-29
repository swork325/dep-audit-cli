"""Freshness audit: flag deps whose latest version is significantly newer."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from packaging.version import Version, InvalidVersion

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class FreshnessEntry:
    name: str
    current: Optional[str]
    latest: Optional[str]
    major_behind: int = 0
    minor_behind: int = 0
    stale: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "current": self.current,
            "latest": self.latest,
            "major_behind": self.major_behind,
            "minor_behind": self.minor_behind,
            "stale": self.stale,
        }


@dataclass
class FreshnessReport:
    entries: List[FreshnessEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def stale_count(self) -> int:
        return sum(1 for e in self.entries if e.stale)

    @property
    def stale_entries(self) -> List[FreshnessEntry]:
        return [e for e in self.entries if e.stale]


def _version_distance(current: str, latest: str) -> tuple[int, int]:
    """Return (major_behind, minor_behind) between current and latest."""
    try:
        cur = Version(current)
        lat = Version(latest)
    except (InvalidVersion, TypeError):
        return 0, 0
    if lat <= cur:
        return 0, 0
    major_behind = lat.major - cur.major
    if major_behind > 0:
        return major_behind, 0
    minor_behind = lat.minor - cur.minor
    return 0, max(minor_behind, 0)


def _make_entry(dep: ResolvedDep, major_threshold: int, minor_threshold: int) -> FreshnessEntry:
    major_behind, minor_behind = _version_distance(
        dep.current_version or "", dep.latest_version or ""
    )
    stale = major_behind >= major_threshold or minor_behind >= minor_threshold
    return FreshnessEntry(
        name=dep.name,
        current=dep.current_version,
        latest=dep.latest_version,
        major_behind=major_behind,
        minor_behind=minor_behind,
        stale=stale,
    )


def build_freshness_report(
    report: AuditReport,
    major_threshold: int = 1,
    minor_threshold: int = 3,
) -> FreshnessReport:
    """Analyse all deps in *report* and return a FreshnessReport."""
    seen: set[str] = set()
    entries: List[FreshnessEntry] = []
    for file_audit in report.files:
        for dep in file_audit.deps:
            key = (dep.name, dep.current_version, dep.latest_version)
            if key in seen:
                continue
            seen.add(key)
            entries.append(_make_entry(dep, major_threshold, minor_threshold))
    return FreshnessReport(entries=entries)
