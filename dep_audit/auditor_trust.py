"""Trust scoring for dependencies based on download counts, release age, and known status."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import requests

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport


@dataclass
class TrustEntry:
    name: str
    version: str
    monthly_downloads: Optional[int]
    release_count: int
    trusted: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "monthly_downloads": self.monthly_downloads,
            "release_count": self.release_count,
            "trusted": self.trusted,
            "reason": self.reason,
        }


@dataclass
class TrustReport:
    entries: list[TrustEntry] = field(default_factory=list)

    def total(self) -> int:
        return len(self.entries)

    def untrusted_count(self) -> int:
        return sum(1 for e in self.entries if not e.trusted)

    def find(self, name: str) -> Optional[TrustEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None


_DOWNLOAD_THRESHOLD = 1_000
_RELEASE_THRESHOLD = 3


def _fetch_stats(name: str, session: requests.Session) -> dict:
    try:
        resp = session.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {})
        release_count = len(releases)
        return {"release_count": release_count}
    except Exception:
        return {"release_count": 0}


def _assess_trust(release_count: int, monthly_downloads: Optional[int]) -> tuple[bool, str]:
    if release_count < _RELEASE_THRESHOLD:
        return False, f"only {release_count} release(s) on PyPI"
    if monthly_downloads is not None and monthly_downloads < _DOWNLOAD_THRESHOLD:
        return False, f"low monthly downloads ({monthly_downloads})"
    return True, "meets trust thresholds"


def build_trust_report(report: AuditReport, session: Optional[requests.Session] = None) -> TrustReport:
    if session is None:
        session = requests.Session()

    seen: dict[str, TrustEntry] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower().replace("-", "_")
            if key in seen:
                continue
            stats = _fetch_stats(dep.name, session)
            release_count = stats["release_count"]
            monthly_downloads: Optional[int] = None
            trusted, reason = _assess_trust(release_count, monthly_downloads)
            entry = TrustEntry(
                name=dep.name,
                version=dep.current_version or "",
                monthly_downloads=monthly_downloads,
                release_count=release_count,
                trusted=trusted,
                reason=reason,
            )
            seen[key] = entry

    return TrustReport(entries=list(seen.values()))
