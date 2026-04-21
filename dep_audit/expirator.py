"""Expirator: detect dependencies whose support or maintenance window has ended.

A dependency is considered 'expired' when its latest release on PyPI has not
been updated for longer than a configurable number of days *and* the project
has been explicitly marked as inactive (no new releases, archived, or the
release date is beyond the expiry threshold).

This module complements the staler module: staler flags deps that *you* haven't
updated; expirator flags deps that *upstream* has abandoned.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport

# Default: if a package has had no release in 2 years, treat it as expired.
_DEFAULT_THRESHOLD_DAYS = 730


@dataclass
class ExpiredDep:
    """A dependency flagged as potentially abandoned upstream."""

    dep: ResolvedDep
    latest_release_date: Optional[datetime.datetime]
    days_since_release: Optional[int]
    threshold_days: int

    @property
    def is_expired(self) -> bool:
        """Return True when the upstream release age exceeds the threshold."""
        if self.days_since_release is None:
            return False
        return self.days_since_release >= self.threshold_days


@dataclass
class ExpirationReport:
    """Aggregated expiration results for all scanned dependencies."""

    entries: List[ExpiredDep] = field(default_factory=list)
    threshold_days: int = _DEFAULT_THRESHOLD_DAYS

    @property
    def total(self) -> int:
        """Total number of dependencies evaluated."""
        return len(self.entries)

    @property
    def expired_count(self) -> int:
        """Number of dependencies classified as expired."""
        return sum(1 for e in self.entries if e.is_expired)

    @property
    def expired(self) -> List[ExpiredDep]:
        """Return only the expired entries."""
        return [e for e in self.entries if e.is_expired]


def _fetch_latest_release_date(
    package: str, session: Optional[requests.Session] = None
) -> Optional[datetime.datetime]:
    """Query PyPI for the upload time of the most recent release of *package*.

    Returns a timezone-aware datetime or None if the information is unavailable.
    """
    sess = session or requests.Session()
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        resp = sess.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:  # network errors, JSON parse errors, etc.
        return None

    # 'releases' maps version -> list of upload dicts; pick the newest version.
    releases: Dict[str, list] = data.get("releases", {})
    if not releases:
        return None

    latest_date: Optional[datetime.datetime] = None
    for file_list in releases.values():
        for upload in file_list:
            upload_time_str = upload.get("upload_time_iso_8601") or upload.get("upload_time")
            if not upload_time_str:
                continue
            try:
                # Normalise to a naive UTC datetime for simple comparison.
                dt = datetime.datetime.fromisoformat(
                    upload_time_str.replace("Z", "+00:00")
                ).replace(tzinfo=None)
                if latest_date is None or dt > latest_date:
                    latest_date = dt
            except ValueError:
                continue

    return latest_date


def check_expiration(
    dep: ResolvedDep,
    threshold_days: int = _DEFAULT_THRESHOLD_DAYS,
    session: Optional[requests.Session] = None,
) -> ExpiredDep:
    """Return an :class:`ExpiredDep` for *dep* using the given threshold."""
    release_date = _fetch_latest_release_date(dep.name, session=session)
    if release_date is not None:
        delta = datetime.datetime.utcnow() - release_date
        days = delta.days
    else:
        days = None

    return ExpiredDep(
        dep=dep,
        latest_release_date=release_date,
        days_since_release=days,
        threshold_days=threshold_days,
    )


def build_expiration_report(
    report: AuditReport,
    threshold_days: int = _DEFAULT_THRESHOLD_DAYS,
    session: Optional[requests.Session] = None,
) -> ExpirationReport:
    """Build an :class:`ExpirationReport` for every dependency in *report*.

    Duplicate package names are deduplicated so that PyPI is queried only once
    per package regardless of how many requirement files reference it.
    """
    seen: Dict[str, ExpiredDep] = {}
    entries: List[ExpiredDep] = []

    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower()
            if key not in seen:
                entry = check_expiration(dep, threshold_days=threshold_days, session=session)
                seen[key] = entry
            entries.append(seen[key])

    return ExpirationReport(entries=entries, threshold_days=threshold_days)
