"""Fetch and expose package metadata (home page, summary, author) from PyPI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List

import requests

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport


@dataclass
class PackageMeta:
    name: str
    version: str
    summary: Optional[str] = None
    home_page: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "home_page": self.home_page,
            "author": self.author,
            "license": self.license,
        }


@dataclass
class MetaReport:
    entries: List[PackageMeta] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    def find(self, name: str) -> Optional[PackageMeta]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None

    def with_home_page(self) -> List[PackageMeta]:
        return [e for e in self.entries if e.home_page]


def fetch_meta(
    dep: ResolvedDep,
    session: Optional[requests.Session] = None,
) -> Optional[PackageMeta]:
    """Fetch metadata for a single resolved dependency from PyPI."""
    s = session or requests.Session()
    version = dep.pinned or dep.latest
    if not version:
        return None
    url = f"https://pypi.org/pypi/{dep.name}/{version}/json"
    try:
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
        info = resp.json().get("info", {})
        return PackageMeta(
            name=dep.name,
            version=version,
            summary=info.get("summary") or None,
            home_page=info.get("home_page") or None,
            author=info.get("author") or None,
            license=info.get("license") or None,
        )
    except Exception:
        return None


def build_meta_report(
    report: AuditReport,
    session: Optional[requests.Session] = None,
) -> MetaReport:
    """Build a MetaReport by fetching metadata for every unique dep in the audit."""
    seen: set[str] = set()
    entries: List[PackageMeta] = []
    s = session or requests.Session()
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key in seen:
                continue
            seen.add(key)
            meta = fetch_meta(dep, session=s)
            if meta is not None:
                entries.append(meta)
    return MetaReport(entries=entries)
