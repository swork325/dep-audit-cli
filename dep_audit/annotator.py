"""Annotate dependencies with human-readable age labels based on version publish dates."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from dep_audit.resolver import ResolvedDep


@dataclass
class AnnotatedDep:
    dep: ResolvedDep
    published_at: Optional[datetime] = None
    age_days: Optional[int] = None
    age_label: str = "unknown"


def _age_label(days: int) -> str:
    if days < 30:
        return "fresh"
    if days < 180:
        return "recent"
    if days < 365:
        return "aging"
    return "stale"


def fetch_publish_date(
    name: str,
    version: str,
    session: Optional[requests.Session] = None,
) -> Optional[datetime]:
    """Return the upload time for *name*==*version* from PyPI, or None on error."""
    s = session or requests.Session()
    try:
        resp = s.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        urls = data.get("urls") or []
        if not urls:
            return None
        raw = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time")
        if not raw:
            return None
        raw = raw.rstrip("Z")
        dt = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def annotate_dep(
    dep: ResolvedDep,
    session: Optional[requests.Session] = None,
) -> AnnotatedDep:
    """Fetch publish date for dep's current version and return an AnnotatedDep."""
    if dep.current_version is None:
        return AnnotatedDep(dep=dep)
    published = fetch_publish_date(dep.name, dep.current_version, session=session)
    if published is None:
        return AnnotatedDep(dep=dep)
    now = datetime.now(tz=timezone.utc)
    age_days = (now - published).days
    return AnnotatedDep(
        dep=dep,
        published_at=published,
        age_days=age_days,
        age_label=_age_label(age_days),
    )


def annotate_all(
    deps: list[ResolvedDep],
    session: Optional[requests.Session] = None,
) -> list[AnnotatedDep]:
    s = session or requests.Session()
    return [annotate_dep(d, session=s) for d in deps]
